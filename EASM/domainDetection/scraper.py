import aiohttp
from bs4 import BeautifulSoup
import sys
import json
import asyncio
import re
from urllib.parse import urlparse, urljoin
import traceback
from fake_useragent import UserAgent
from domainDetection.dcclasses import next_id
from pathlib import Path
import toml

config_path = Path(__file__).parent.parent / "config.toml"
with open(config_path, "r") as file:
    config = toml.load(file)

first_link = True
id = 0

def crawl(url, depth, restriction, json_path):
    crawled_urls = []
    json_data = []
    try:
        with open(json_path, "r") as json_file:
            content = json_file.read()
            if content:
                json_data = json.loads(content)
                print(f"Loaded {json_data} from {json_path}")
    except (json.JSONDecodeError, FileNotFoundError):
        # If file doesn't exist or is empty, start with an empty list
        json_data = []
    if "www." not in url:
        if "://" in url:
            url = url.split("://", 1)[1]
        url_http = f"https://www.{url}"

    elif "://" not in url:
        url_http = f"https://{url}"
    else:
        url_http = url
    # Check to restrict to specific domain
    if restriction == url:
        print("restriction==url")
    elif restriction == "None":
        print("restriction is None")
    else:
        print("restriction!=url")

    asyncio.run(async_main(url_http, url, depth, restriction, crawled_urls, json_data, json_path))

    with open(json_path, "w", encoding="utf-8") as json_file:
        json.dump(json_data, json_file, indent=4, separators=(",", ": "))


async def async_main(url, original_url, depth, restriction, crawled_urls, json_data, json_path):
    headers = {
        "User-Agent": UserAgent().random,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        await async_visit(
            url, original_url, depth, restriction, crawled_urls, session, json_data, json_path
        )


async def async_visit(
    url, original_url, depth, restriction, crawled_urls, session, json_data, json_path
):
    if "://" not in url:
        url = f"https://www.{url}"
    if restriction not in url:
        print("Url not in restriction scope")
        return
    if url in crawled_urls:
        print("Url in crawled_urls")
        return
    elif depth == -1:
        print("Limitless depth")
        crawled_urls.append(url)
    elif depth == 0:
        print("Depth is smaller than or equal to 0")
        return
    else:
        crawled_urls.append(url)
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            html_content = await response.text()
        absolute_links = find_absolute_links(
            html_content, original_url, json_data, url, json_path, restriction  # Pass json_data
        )
        tasks = []
        for link in absolute_links:
            if restriction.lower() in url.lower():
                print(f"restriction {restriction.lower()} in url {url.lower()}")
                if depth == -1:
                    tasks.append(
                        async_visit(
                            link,
                            original_url,
                            depth,
                            restriction,
                            crawled_urls,
                            session,
                            json_data, json_path
                        )
                    )
                elif depth > 0:
                    depth = depth - 1
                    tasks.append(
                        async_visit(
                            link,
                            original_url,
                            depth,
                            restriction,
                            crawled_urls,
                            session,
                            json_data, json_path
                        )
                    )
            elif restriction == "None":
                if depth == -1:
                    tasks.append(
                        async_visit(
                            link,
                            original_url,
                            depth,
                            restriction,
                            crawled_urls,
                            session,
                            json_data, json_path
                        )
                    )
                elif depth > 0:
                    depth = depth - 1
                    tasks.append(
                        async_visit(
                            link,
                            original_url,
                            depth,
                            restriction,
                            crawled_urls,
                            session,
                            json_data, json_path
                        )
                    )
            elif restriction not in url:
                print(f"{restriction} not in {url}")
                return
        await asyncio.gather(*tasks)
    except aiohttp.ClientError as e:
        print(f"HTTP-error: {e}")
        return
    except Exception:
        print(traceback.format_exc())
        return


def find_absolute_links(
    html_content, original_url, json_data, url, json_path, restriction
):  # find all absolute links
    soup = BeautifulSoup(html_content, "html.parser")
    links = [a.get("href") for a in soup.find_all("a") if a.get("href") is not None]
    links.append(original_url)
    absolute_links = []
    for link in links:
        output(link, original_url, json_data, json_path, restriction)  # Pass json_data
        parsed_link = urlparse(link)
        if parsed_link.scheme not in ["http", "https"]:
            link = urljoin(url, link)
        absolute_links.append(link)
    return absolute_links


def output(link, original_url, json_data, json_path, restriction):
    global first_link
    global id
    if "." not in link:
        link = f"{original_url}{link}"
    if restriction != "None":
        if restriction not in link:
            print(f"{restriction} not in {link}")
            return
    data_type = ""
    regex = r"\b[A-Za-z0-9._%+-:]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"  # Check if link is email
    if re.fullmatch(regex, str(link)):
        data_type = "email"
    else:
        data_type = "website"
        # The json_data is now passed in, no need to read from file here
    # last_id logic needs to be adjusted to find the max ID in the current list
    if not first_link:
        id += 1
    if not config["domaindetection"]["evaluation"]["sesearch-on"] and first_link:
        first_link = False
        id = 0
    if isinstance(json_data, list) and json_data and first_link:
        first_link = False
        id = next_id(json_path)
    if len(json_data) == 0 and first_link:
        first_link = False
        id = 0
    present = False
    if isinstance(json_data, list):
        # Use the corrected duplicate check comparing link_data
        link_data = ""
        if "." not in link:
            if "://" not in original_url:
                link_data = f"https://{original_url}{link}"
            else:
                link_data = f"{original_url}{link}"
        else:
            link_data = link

        for element in json_data:
            if element.get("data") == link_data:  # Use .get() for safer access
                present = True
                break

    # Re-calculate link_data here as it's used in the duplicate check
    link_data = ""
    if "." not in link:
        if "://" not in original_url:
            link_data = f"https://{original_url}{link}"
        else:
            link_data = f"{original_url}{link}"
    else:
        link_data = link

    if link is not None and link != "#" and present is False:
        json_data = json_data.append(
            {
                "id": id,
                "connected-site": original_url,
                "type": data_type,
                "data": link_data,
            }
        )


if __name__ == "__main__":
    args = sys.argv[1:]
    url = sys.argv[1]  # the url to be scraped
    depth = int(sys.argv[2])  # the scraping depth (how many links deep)
    restriction = sys.argv[3]  # restriction on which urls can be scraped further
    json_path = sys.argv[4]

    crawl(url, depth, restriction, json_path)