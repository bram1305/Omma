import json
import sys
import requests
import toml
from domainDetection.dcclasses import (
    company_pythonify,
    UnevaluatedDomain,
    uneval_pythonify,
    next_id,
    EvaluatedDomain,
    eval_jsonify,
)
from cleanco import basename
from domainDetection.scraper import crawl
from bs4 import BeautifulSoup
import re
from fake_useragent import UserAgent
from rapidfuzz import fuzz
import math
import time
from domainDetection.sesearch import sesearch
import os
from requests.adapters import HTTPAdapter
from pathlib import Path

config_path = Path(__file__).parent.parent / "config.toml"
with open(config_path, "r") as file:
    config = toml.load(file)


def initiate(uneval_id):
    #with open("../config.toml", "r") as file:
    #    config = toml.load(file)
    uneval_json = config["filepaths"]["unevaluated-list"]
    company_json = config["filepaths"]["companies-list"]
    eval_json = config["filepaths"]["evaluated-list"]
    uneval = uneval_pythonify(uneval_id, uneval_json)
    company = company_pythonify("id", uneval.company_id, company_json)

    def remove_unevaluated():
        with open(uneval_json, "r", encoding="utf-8") as file:
            data = json.load(file)
        new_data = []
        for obj in data:
            if int(obj.get("id")) != int(uneval_id):
                print(obj.get("id"))
                new_data.append(obj)
            else:
                continue
        with open(uneval_json, "w", encoding="utf-8") as file:
            json.dump(new_data, file, indent=4)
        return None

    for domain in company.domains:
        if domain in uneval.domain:
            remove_unevaluated()
    if "www." in uneval.domain:
        cleaned_domain = uneval.domain.split("www.", 1)[1]
    elif "://" in uneval.domain:
        cleaned_domain = uneval.domain.split("://", 1)[1]
    else:
        cleaned_domain = uneval.domain
    if "/" in cleaned_domain:
        cleaned_domain = cleaned_domain.split("/", 1)[0]
    stats = start_evaluation(uneval)
    likely = stats[0]
    probability_factor = stats[1]
    stats_list = stats[2]
    warning = stats[3]
    eval_id = next_id(eval_json)
    evaluated = EvaluatedDomain(
        id=eval_id,
        domain=cleaned_domain,
        company_id=company.id,
        like_score=probability_factor,
        owned=likely,
        stats=stats_list,
        warning=warning,
    )
    eval_jsonify(evaluated, eval_json)
    print(stats)
    remove_unevaluated()
    return stats


def start_evaluation(uneval: UnevaluatedDomain):
    #with open("../config.toml", "r") as file:
    #    config = toml.load(file)
    json_prep_prep_path = ""
    if "www." in uneval.domain:
        json_prep_prep_path = f"{uneval.domain.split("www.", 1)[1]}"
    elif "https://" in uneval.domain:
        json_prep_prep_path = f"{uneval.domain.split("://", 1)[1]}"
    elif "http://" in uneval.domain:
        json_prep_prep_path = f"{uneval.domain.split("://", 1)[1]}"
    if json_prep_prep_path == "":
        json_prep_prep_path = uneval.domain
    json_prep_path = f"{json_prep_prep_path.split(".", 1)[0]}_prep_crawl.json"
    print(json_prep_path)
    company = company_pythonify(
        "id", uneval.company_id, config["filepaths"]["companies-list"]
    )
    try:
        with open(json_prep_path, "x", encoding="utf-8") as file:
            json.dump([], file)
    except:
        pass
    if config["domaindetection"]["evaluation"]["sesearch-on"] is True:
        sesearch_plug(uneval.domain, json_prep_path)
    prep(uneval.domain, json_prep_path)

    with open(json_prep_path, "r", encoding="utf-8") as file:
        scraped_list = json.load(file)
    stats = []
    # Here we'll add the stats to one list, but first we make sure we convert the scores_list to an average of all scores
    for scraped in scraped_list:
        stat = filter_scraped(uneval, scraped, company)
        if stat is None:
            continue
        for item in stat:
            isd = isinstance(item, dict)
            if isd is False:
                continue
            elif item["count"] == 0:
                continue
            av = 0
            for score in item["scores_list"]:
                av += score
            item["scores_list"] = av / item["count"]
        stats.append(stat)
    print(evaluate(stats))
    os.remove(json_prep_path)
    return evaluate(stats)


def sesearch_plug(full_url, json_prep_path):
    if "www." in full_url:
        edited_url = full_url.split("www.", 1)[1]
    elif "://" in full_url:
        edited_url = full_url.split("://", 1)[1]
    else:
        edited_url = full_url
    if "/" in edited_url:
        edited_url = edited_url.split("/", 1)[0]
    dom_list = sesearch(
        f"{edited_url} site:{edited_url}", 11, owner_test=True, prep_path=json_prep_path
    )
    json_list = []
"""    with open(json_prep_path, "r") as file:
        json_list = json.load(file)
    for item in dom_list:
        id = next_id(json_prep_path)
        item_data = {
            "id": id,
            "connected-site": full_url,
            "type": "website",
            "data": item,
        }
        json_list.append(item_data)
    with open(json_prep_path, "w") as file:
        json.dump(json_list, file, indent=4, separators=(",", ": "))"""


def filter_scraped(uneval: UnevaluatedDomain, scraped, company):
    page = None
    if uneval.domain not in scraped["data"]:
        pass
    elif "email" in scraped["type"]:
        pass
    else:
        page = pull_page(scraped["data"])
        print(page)
    if page is None:
        pass
    else:
        page_normal = normalize(page.text)
        page_normal_space = normalize(page.text, space_removal=False)

        # Now we can start testing each page for the data in the company object
        stats = []
        # Test for full company name (fuzzy, low tolerance)
        stats.append(
            test(
                page_normal,
                company.name.lower(),
                exact=False,
                low_tolerance=True,
                fcn=True,
            )
        )
        # Test for cleaned company name (fuzzy, low tolerance)
        stats.append(
            test(
                page_normal,
                basename(company.name).lower(),
                exact=False,
                low_tolerance=True,
            )
        )
        # Test for address (fuzzy, high tolerance)
        stats.append(
            test(page_normal, company.addresses, exact=False, low_tolerance=False)
        )
        # Test for phones (fuzzy, low tolerance)
        stats.append(test(page_normal, company.phones, exact=False, low_tolerance=True))
        # Test for domains (exact)
        stats.append(test(page.text, company.domains, exact=True))
        # Test for emails (exact)
        stats.append(test(page.text, company.emails, exact=True))
        # Test for socials (exact)
        stats.append(test(page.text, company.socials, exact=True))
        # Test for VAT-number (exact)
        stats.append(test(page_normal, normalize(company.vat_number), exact=True))
        # Add total word count of page for averages
        stats.append(len(page_normal_space.split(" ")))
        return stats
        """
        per webpage found, we get:
        stats= [
            full company name
            cleaned company name
            address
            phones
            domains
            emails
            socials
            vat-number
            total word count
        ]
        """


def test(
    page, test, exact: bool = False, low_tolerance: bool = True, fcn: bool = False
):
    l = isinstance(test, list)
    if l is True:
        count = 0
        fuzzed = {"count": 0, "scores_list": []}
        for item in test:
            if exact is False:
                data = fuzz_match(page, item, low_tolerance, fcn)
                fuzzed["count"] += data["count"]
                for score in data["scores_list"]:
                    fuzzed["scores_list"].append(score)
                # fuzz_match will deal with typos, tolerance can be set to low or high

            count += str(page).count(str(item))
        if exact is False:
            return fuzzed
        if exact is True:
            return count
    else:
        if exact is False:
            return fuzz_match(page, test, low_tolerance, fcn)
            # fuzz_match will deal with typos, tolerance can be set to low or high
        return str(page).count(str(test))


def fuzz_match(page, test, low_tolerance: bool = True, fcn: bool = False):
    #with open("../config.toml", "r") as file:
    #    config = toml.load(file)
    if low_tolerance is True:
        tolerance_threshold = config["domaindetection"]["evaluation"][
            "low-tolerance-threshold"
        ]
    if fcn is True:
        if tolerance_threshold + 0.1 <= 1.0:
            tolerance_threshold += 0.1
    else:
        tolerance_threshold = config["domaindetection"]["evaluation"][
            "high-tolerance-threshold"
        ]
    window_size = len(test) + int(
        config["domaindetection"]["evaluation"]["window-factor"] * len(test)
    )
    matches = []
    scores = []
    final_scores = []
    count = 0
    for i in range(0, len(page) - window_size + 1):
        window = page[i : i + window_size]
        score = fuzz.partial_ratio(test, window)
        if score < 20:
            continue
        scores.append(score)
        matches.append((i, i + window_size, score))
    merged = merge_fuzz_matches(matches)
    for match in merged:
        if match[2] < tolerance_threshold:
            continue
        final_scores.append(match[2])
        count += 1
    return {"count": count, "scores_list": final_scores}
    """
    Per fuzzy_match execution, we get:
    {
        count
        scores_list
    }
    Where count is total amount of matches and scores_list
    holds a list with all recorded scores.
    """


def merge_fuzz_matches(matches: list[tuple[int, int, float]]):
    if not matches:
        return []
    matches.sort()
    merged = [matches[0]]
    for start, end, score in matches[1:]:
        last_start, last_end, last_score = merged[-1]

        if start <= last_end and start > last_start:
            new_end = max(end, last_end)
            new_score = max(score, last_score)
            merged[-1] = (last_start, new_end, new_score)
        else:
            merged.append((start, end, score))

    return merged


def pull_page(domain, max_retries=5, initial_delay=1):
    headers = {"User-Agent": UserAgent().random}
    retries = 0
    delay = initial_delay
    if "www" not in domain and "://" not in domain:
        domain = f"www.{domain}"
    if "://" not in domain:
        domain = f"https://{domain}"

    while retries < max_retries:
        try:
            response = requests.get(domain, headers=headers, timeout=5)

            if response.status_code == 200:
                print(f"Successfully fetched {domain} (Status: {response.status_code})")
                return response
            elif response.status_code == 429:
                print(
                    f"Rate limited (Status: 429) for {domain}. Retrying in {delay} seconds... (Attempt {retries + 1}/{max_retries})"
                )
                time.sleep(delay)
                retries += 1
                delay *= 2  # Exponential backoff (double delay each time)
            else:
                print(
                    f"Request failed for {domain} with status code: {response.status_code}"
                )
                return None  # Exit on non-200, non-429 errors

        except requests.exceptions.RequestException as e:
            print(
                f"Request error for {domain}: {e}. Retrying... (Attempt {retries + 1}/{max_retries})"
            )
            time.sleep(delay)
            retries += 1
            delay *= 2  # Exponential backoff

    print(f"Failed to retrieve {domain} after {max_retries} retries.")
    return None


def prep(domain, json_file_path):
    restriction = None
    if "http" in domain:
        restriction = domain.split("://", 1)[1]
    if "www" in domain:
        restriction = domain.split("www.", 1)[1]
    if not restriction:
        restriction = domain
    crawl(domain, 10, restriction.split("/", 1)[0], json_file_path)


def normalize(text, space_removal: bool = True):
    soup = BeautifulSoup(text, "html.parser")
    normal_text = soup.get_text()
    normal_text = re.sub(r"[\r|\n|\r\n]+", "", normal_text)
    if space_removal is True:
        normal_text = normal_text.replace(" ", "")
    normal_text = normal_text.lower()
    return normal_text


def evaluate(stats):
    #with open("../config.toml", "r") as file:
    #    config = toml.load(file)
    t_full_cname = 0
    t_ccname = 0
    t_address = 0
    t_phones = 0
    t_domains = 0
    t_emails = 0
    t_socials = 0
    t_vat = 0
    t_word_count = 1
    for item in stats:
        t_full_cname += item[0]["count"]
        t_ccname += item[1]["count"]
        t_address += item[2]["count"]
        t_phones += item[3]["count"]
        t_domains += item[4]
        t_emails += item[5]
        t_socials += item[6]
        t_vat += item[7]
        t_word_count += item[8]
    fcname_ratio = t_full_cname / t_word_count
    ccname_ratio = (t_ccname - t_full_cname) / t_word_count
    address_ratio = t_address / t_word_count
    phones_ratio = t_phones / t_word_count
    power = config["domaindetection"]["evaluation"]["full-name-sensitivity"]
    full_name_sensitivity = (
        config["domaindetection"]["evaluation"]["full-name-sensitivity"]
    ) * math.pow(10.0, power)
    cleaned_name_sensitivity = config["domaindetection"]["evaluation"][
        "cleaned-name-sensitivity"
    ] * math.pow(10.0, power)
    address_sensitivity = config["domaindetection"]["evaluation"][
        "address-sensitivity"
    ] * math.pow(10.0, power)
    phone_sensitivity = config["domaindetection"]["evaluation"][
        "phone-sensitivity"
    ] * math.pow(10.0, power)
    domain_sensitivity = config["domaindetection"]["evaluation"][
        "domain-sensitivity"
    ] * math.pow(10.0, power)
    email_sensitivity = config["domaindetection"]["evaluation"][
        "email-sensitivity"
    ] * math.pow(10.0, power)
    social_sensitivity = config["domaindetection"]["evaluation"][
        "social-sensitivity"
    ] * math.pow(10.0, power)
    vat_sensitivity = config["domaindetection"]["evaluation"][
        "vat-sensitivity"
    ] * math.pow(10.0, power)

    # Component for full company name
    component_full_name = 1.0 - math.exp(-full_name_sensitivity * fcname_ratio)

    # Component for cleaned company name
    component_cleaned_name = 1.0 - math.exp(-cleaned_name_sensitivity * ccname_ratio)

    # Component for addresses
    component_addresses = 1.0 - math.exp(-address_sensitivity * address_ratio)

    # Component for phone numbers
    component_phone_numbers = 1.0 - math.exp(-phone_sensitivity * phones_ratio)

    # Component for domains
    component_domains = 1.0 - math.exp(-domain_sensitivity * t_domains)

    # Component for emails
    component_emails = 1.0 - math.exp(-email_sensitivity * t_domains)

    # Component for socials
    component_socials = 1.0 - math.exp(-social_sensitivity * t_domains)

    # Component for VAT
    component_vat = 1.0 - math.exp(-vat_sensitivity * t_domains)

    # --- Combine Components (Overall Score = 1 - Product(1 - Ci)) ---
    # Store components in a list
    components = [
        component_full_name,
        component_cleaned_name,
        component_addresses,
        component_phone_numbers,
        component_domains,
        component_emails,
        component_socials,
        component_vat,
    ]

    # Calculate the product of (1 - Ci) for all components
    product_of_one_minus_c = 1.0
    for c in components:
        # Multiply by (1.0 - c)
        # If any c is close to 1.0, (1-c) will be close to 0, driving the product towards 0.
        # Using 1.0 ensures float division.
        product_of_one_minus_c *= 1.0 - c

    # --- Calculate Overall Likelihood Score ---
    probability_factor = 1.0 - product_of_one_minus_c
    if (
        probability_factor
        > config["domaindetection"]["evaluation"]["likelihood-threshold"]
    ):
        likely = True
    else:
        likely = False
    if len(stats) < 10:
        warning_message = f"Warning: low amount ({len(stats)}) of pages scanned. Chances of false positives/negatives are higher."
    else:
        warning_message = f"{len(stats)} pages scanned. The score is merely an indication, always check out the website. False negatives may arise if a website does not contain enough instances of the known company data."
    return [likely, probability_factor, stats, warning_message]

    """
        per webpage found, we get the amount of times the following items occurred:
        stats= [
            full company name
            cleaned company name (no abbreviations like llc, inc, ...)
            address
            phones
            domains
            emails
            socials
            vat-number
            total word count
        ]
        """


if __name__ == "__main__":
    args = sys.argv[:1]
    uneval_id = sys.argv[1]
    uneval_json_file = sys.argv[2]
    pythonified_uneval = uneval_pythonify(uneval_id, uneval_json_file)
    data = str(initiate(uneval_id))
