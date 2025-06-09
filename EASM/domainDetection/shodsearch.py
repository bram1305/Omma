from dotenv import load_dotenv
import os
import shodan
import toml
from domainDetection.dcclasses import (
    company_pythonify,
    json_modification,
    JsonModOperation,
    next_id,
    UnevaluatedDomain,
    uneval_jsonify,
)
import json
from pathlib import Path

config_path = Path(__file__).parent.parent / "config.toml"
with open(config_path, "r") as file:
    config = toml.load(file)
# Commmon


def build_query(query_question, query_data):
    if isinstance(query_data, list):
        full_query_data = ""
        for item in query_data:
            full_query_data = full_query_data + "," + item
        if full_query_data[0] == ",":
            full_query_data = full_query_data[1:]
    else:
        full_query_data = query_data
    return f"{query_question}:{full_query_data}"


def search(query):
    # Load .env from the domainDetection directory
    env_path = Path(__file__).parent / ".env"
    load_dotenv(env_path)
    API_KEY = os.getenv("SHODAN_KEY")
    
    # Check if API key is available and valid
    if not API_KEY or API_KEY == "your_shodan_api_key_here" or API_KEY == "[Your Shodan API key]":
        print(f"[WARNING] Shodan API key not configured, skipping search for: {query}")
        return {"matches": []}  # Return empty results structure
    
    try:
        api = shodan.Shodan(API_KEY)
        results = api.search(query)
        return results
    except Exception as e:
        print(f"[WARNING] Shodan search failed: {e}")
        return {"matches": []}  # Return empty results structure


def filter_search(results, search_filter):
    filtered_results = []
    if search_filter is None:
        for result in results["matches"]:
            filtered_results.append(result)
    else:
        for result in results["matches"]:
            if isinstance(result.get(search_filter), list):
                result_list = result.get(search_filter)
                for item in result_list:
                    filtered_results.append(item)
            else:
                filtered_results.append(result.get(search_filter))
    return filtered_results


# Search new domains


def domain_finder(company_id):
    #with open("../config.toml", "r") as file:
    #    config = toml.load(file)
    company_json = config["filepaths"]["companies-list"]
    company = company_pythonify("id", company_id, company_json)
    query_data = company.shodan_orgnames
    if not query_data:
        return None  # Returns None if there are no orgnames in shodan.
    # print(query_data)
    search_results = search(build_query("org:", f"{query_data}"))
    # print(search_results)
    filtered_results = filter_search(search_results, "hostnames")
    print(filtered_results)
    uneval_json = config["filepaths"]["unevaluated-list"]
    goggle_file = (
        config["domaindetection"]["sesearch"]["goggle-dir"]
        + config["domaindetection"]["sesearch"]["goggle-name"]
    )
    for result in filtered_results:

        with open(goggle_file, "r", encoding="utf-8") as file:
            goggle_data = file.read()
        if result in goggle_data:
            continue
        if "www" in result:
            result = result.split("www.", 1)[1]
        loop_continue = False
        with open(uneval_json, "r", encoding="utf-8") as file:
            data = json.load(file)
            for item in data:
                if result in item["domain"]:
                    loop_continue = True
        if loop_continue:
            continue
        id = next_id(uneval_json)
        uneval = UnevaluatedDomain(id, company_id, result)
        uneval_jsonify(uneval, uneval_json)
    return filtered_results


# Add organizations


def org_adder(company_id):
    #with open("../config.toml", "r") as file:
    #    config = toml.load(file)
    company_json = config["filepaths"]["companies-list"]
    company = company_pythonify("id", company_id, company_json)
    query_data = company.domains
    search_results = search(build_query("hostname", query_data))
    filtered_results = filter_search(search_results, "org")
    unduplicate_results = []
    for result in filtered_results:
        if result not in unduplicate_results:
            unduplicate_results.append(result)
        else:
            continue
    for result in unduplicate_results:
        if result not in company.shodan_orgnames:
            json_modification(
                company_json,
                "id",
                company_id,
                "shodan-orgnames",
                JsonModOperation.APPEND,
                result,
            )
        else:
            continue
    return filtered_results


if __name__ == "__main__":
    print(org_adder(1))
    print(domain_finder(1))
