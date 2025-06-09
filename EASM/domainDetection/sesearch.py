from dotenv import load_dotenv
import requests
import os
import sys
import toml
from domainDetection.dcclasses import next_id, uneval_jsonify, UnevaluatedDomain
import json
from pathlib import Path

config_path = Path(__file__).parent.parent / "config.toml"
with open(config_path, "r") as file:
    config = toml.load(file)


def get_response(query):
    # Load .env from the domainDetection directory
    env_path = Path(__file__).parent / ".env"
    load_dotenv(env_path)
    BRAVE_KEY = os.getenv("BRAVE_KEY")
    
    # Check if API key is available and valid
    if not BRAVE_KEY or BRAVE_KEY == "your_brave_api_key_here" or BRAVE_KEY == "[Your Brave API key]":
        print(f"[WARNING] Brave API key not configured, skipping search for: {query}")
        return {"web": {"results": []}}  # Return empty results structure
    
    brave_headers = {
        "Accept": "application/json",
        "X-Subscription-Token": BRAVE_KEY,
    }
    API_url = f"https://api.search.brave.com/res/v1/web/search?q={query}"
    print(API_url)
    
    try:
        response = requests.get(API_url, headers=brave_headers)
        return response.json()
    
    except Exception as e:
        print(f"[WARNING] Brave search failed: {e}")
        return {"web": {"results": []}}  # Return empty results structure


def sesearch(
    search_string, company_id, country="ALL", count="20", owner_test=False, prep_path=""
):
    search_string = search_string.replace(" ", "+")
    goggle = config["domaindetection"]["sesearch"]["goggle-url"]
    query = f"{search_string}&country={country}&count={count}&result_filter=web&goggles={goggle}"
    response = get_response(query)
    if not owner_test:
        file_path = config["filepaths"]["unevaluated-list"]
        results = []
        try:
            for result in response["web"]["results"]:
                id = next_id(file_path)
                domain = result["url"]
                if "://" in domain:
                    domain = domain.split("://", 1)[1]
                if "www." in domain:
                    domain = domain.split("www.", 1)[1]
                if "/" in domain:
                    domain = domain.split("/", 1)[0]
                uneval = UnevaluatedDomain(
                    id=id, company_id=int(company_id), domain=domain
                )
                loop_continue = False
                with open(
                    config["filepaths"]["unevaluated-list"], "r", encoding="utf-8"
                ) as file:
                    data = json.load(file)
                for item in data:
                    if domain in item["domain"]:
                        loop_continue = True
                if loop_continue:
                    continue
                uneval_jsonify(uneval, file_path)
                results.append(result["url"])
        except Exception as e:
            print(e)
    else:
        file_path = prep_path
        results = []
        try:
            for result in response["web"]["results"]:
                id = next_id(file_path)
                result_dict = {
                    "id": id,
                    "connected-site": search_string,
                    "type": "website",
                    "data": result["url"],
                }
                results.append(result_dict)
                with open(prep_path, "w", encoding="utf-8") as file:
                    print(results)
                    json.dump(results, file, indent=4)
        except Exception as e:
            print(e)
    return results


if __name__ == "__main__":
    args = sys.argv[1:]
    search_string = sys.argv[1]
    company_id = sys.argv[2]
    country = sys.argv[3] if len(args) > 2 else "ALL"
    count = sys.argv[4] if len(args) > 2 else 20

    sesearch(search_string, company_id, country, count)
