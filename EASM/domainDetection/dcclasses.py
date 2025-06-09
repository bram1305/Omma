from dataclasses import dataclass
import jmespath
import json
import traceback
from enum import Enum
import toml
from pathlib import Path


config_path = Path(__file__).parent.parent / "config.toml"
with open(config_path, "r") as file:
    config = toml.load(file)


#region Company


@dataclass
class Company:
    def __init__(
        self,
        id: int,
        name: str,
        addresses: list,
        phones: list,
        domains: list,
        emails: list,
        socials: list,
        vat_number: str,
        shodan_orgnames: list,
    ):
        self.id = id
        self.name = name
        self.addresses = addresses
        self.phones = phones
        self.domains = domains
        self.emails = emails
        self.socials = socials
        self.vat_number = vat_number
        self.shodan_orgnames = shodan_orgnames


def company_pythonify(company_field: str, company_value, company_json_file: str):
    with open(company_json_file, "r", encoding="utf-8") as file:
        companyl = json.load(file)
    if isinstance(company_value, int):
        query = f"[?{company_field} == `{company_value}`] | [0]"
    elif isinstance(company_value, str):
        query = f"[?{company_field} == '{company_value}'] | [0]"
    companyr = jmespath.search(query, companyl)
    print(companyr)
    if companyr:
        ncompany = Company(
            id=int(companyr.get("id")),
            name=str(companyr.get("name")),
            addresses=companyr.get("addresses", []),
            phones=companyr.get("phones", []),
            domains=companyr.get("domains", []),
            emails=companyr.get("emails", []),
            socials=companyr.get("socials", []),
            vat_number=str(companyr.get("VAT-number")),
            shodan_orgnames=companyr.get("shodan-orgnames", []),
        )
        return ncompany
    raise Exception("Company not found.")


def company_jsonlen(company_json_file):
    with open(company_json_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    return len(data)


def company_jsonify(company: Company, company_json_file):
    with open(company_json_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    company_dict = {
        "id": company.id,
        "name": company.name,
        "addresses": company.addresses,
        "phones": company.phones,
        "domains": company.domains,
        "emails": company.emails,
        "socials": company.socials,
        "VAT-number": company.vat_number,
        "shodan-orgnames": company.shodan_orgnames,
    }
    data.append(company_dict)
    with open(company_json_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)
    return json.dumps(company_dict)


#endregion


#region UnevaluatedDomain


@dataclass
class UnevaluatedDomain:
    def __init__(self, id: int, company_id: int, domain: str):
        self.id = id
        self.company_id = company_id
        self.domain = domain


def uneval_pythonify(uneval_id: int, uneval_json_file: str):
    try:
        with open(uneval_json_file, "r", encoding="utf-8") as file:
            unevall = json.load(file)
    except:
        with open(uneval_json_file, "w", encoding="utf-8") as file:
            unevall = "[]"
    query = f"[?id == `{uneval_id}`]"
    unevalr = jmespath.search(query, unevall)
    print(unevalr)
    if unevalr:
        nuneval = UnevaluatedDomain(
            id=int(unevalr[0].get("id")),
            company_id=int(unevalr[0].get("company-id")),
            domain=str(unevalr[0].get("domain")),
        )
        return nuneval
    print(unevalr)


def uneval_jsonlen(uneval_json_file):
    with open(uneval_json_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    return len(data)


def uneval_jsonify(uneval: UnevaluatedDomain, uneval_json_file):
    with open(uneval_json_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    uneval_dict = {
        "id": uneval.id,
        "company-id": uneval.company_id,
        "domain": uneval.domain,
    }
    data.append(uneval_dict)
    with open(uneval_json_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)
    return json.dumps(uneval_dict)


#endregion


#region EvaluatedDomain


@dataclass
class EvaluatedDomain:
    def __init__(
        self,
        id: int,
        company_id: str,
        domain: str,
        like_score: float,
        owned: bool,
        stats: list,
        warning: str,
        # reviewed: bool = False,
        # approved: bool = False,
    ):
        # If object passes like_score threshold, owned will be set true
        self.id = id
        self.company_id = company_id
        self.domain = domain
        self.like_score = like_score
        self.owned = owned
        self.stats = stats
        self.warning = warning
        self.reviewed = False  # If False: not yet reviewed by staff
        self.approved = False  # If False: rejected or unreviewed by staff

    def approve(self):
        self.reviewed = True
        self.approved = True
        pass

    def reject(self):
        self.reviewed = True
        self.approved = False
        pass


def eval_pythonify(eval_id: int, eval_json_file: str):
    with open(eval_json_file, "r", encoding="utf-8") as file:
        evall = json.load(file)
    query = f"[?id == `{eval_id}`] | [0]"
    evalr = jmespath.search(query, evall)
    print(eval_id)
    print(evall)
    print(query)
    print(evalr)
    if evalr:
        neval = EvaluatedDomain(
            id=int(evalr.get("id")),
            company_id=int(evalr.get("company-id")),
            domain=str(evalr.get("domain")),
            like_score=float(evalr.get("like-score")),
            owned=bool(evalr.get("owned")),
            stats=list(evalr.get("stats")),
            warning=str(evalr.get("warning")),
        )

        return neval
    raise Exception("Unevaluated domain not found.")


def eval_jsonlen(eval_json_file):
    with open(eval_json_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    return len(data)


def eval_jsonify(eval: EvaluatedDomain, eval_json_file):
    with open(eval_json_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    eval_dict = {
        "id": eval.id,
        "company-id": eval.company_id,
        "domain": eval.domain,
        "like-score": eval.like_score,
        "owned": eval.owned,
        "approved": eval.approved,
        "reviewed": eval.reviewed,
        "stats": eval.stats,
        "warning": eval.warning,
    }
    data.append(eval_dict)
    with open(eval_json_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)
    return json.dumps(eval_dict)


def approve_eval(eval_id, eval_file):
    eval = eval_pythonify(eval_id, eval_file)
    eval.approve()
    print(dir(eval))
    #with open(config_file, "r") as file:
    #    config = toml.load(file)
    companies_json = config["filepaths"]["companies-list"]
    json_modification(
        companies_json,
        "id",
        eval.company_id,
        "domains",
        JsonModOperation.APPEND,
        eval.domain,
    )
    print(f"Added evaluated domain to companies list. {eval.domain}")
    # goggle_update.update(eval.domain)
    remove_eval(eval_id, eval_file)
    print(f"Removed evaluated domain {eval.domain}from evaluated list.")
    print(f"Approved domain {eval.domain}")


def reject_eval(eval_id, eval_file):
    eval = eval_pythonify(eval_id, eval_file)
    eval.reject()
    # goggle_update.update(eval.domain)
    print(f"Updated goggle.")
    remove_eval(eval_id, eval_file)
    print(f"Removed evaluated domain {eval.domain} from evaluated list.")
    print(f"Rejected domain {eval.domain}")


def remove_eval(eval_id, eval_file):
    with open(eval_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    new_data = []
    for obj in data:
        if int(obj.get("id")) != int(eval_id):
            print(obj.get("id"))
            new_data.append(obj)
        else:
            continue
    with open(eval_file, "w", encoding="utf-8") as file:
        json.dump(new_data, file, indent=4)
    return None


#endregion


#region JsonModification


class JsonModOperation(Enum):
    OVERWRITE = 0
    REMOVEONE = 1
    REMOVEALL = 2
    APPEND = 3


def json_modification(
    json_file,
    key_field,
    key_value,
    change_field,
    change_operation: JsonModOperation,
    change_data,
):
    try:
        with open(json_file, "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        print("Json file not found, please check the path.")
        return data
    except IOError:
        print(
            "An error occured while reading the file, please check the error, and make sure the file is not corrupted;"
        )
        traceback.print_exc()
        return data
    except Exception as e:
        print(f"An error occured, please check the following error: {e}")
        traceback.print_exc()
        return data
    if not data:
        print(f"No data in {json_file}")
        return data
    for index, obj in enumerate(data):
        if key_field not in obj:
            print(
                f"Error: {key_field} is no field in object {obj} in the file {json_file}. Make sure all objects in the file have the same fields available."
            )
            return data
        if obj.get(key_field) == key_value:
            if change_field not in obj:
                print(
                    f"Error: {change_field} is not a field in object {obj} in the file {json_file}."
                )
                return data
            if isinstance(obj[change_field], list):
                if change_operation is JsonModOperation.OVERWRITE:
                    obj[f"{change_field}"] = change_data
                elif change_operation is JsonModOperation.APPEND:
                    obj[f"{change_field}"].append(change_data)
                elif change_operation is JsonModOperation.REMOVEALL:
                    obj[f"{change_field}"] = []
                elif change_operation is JsonModOperation.REMOVEONE:
                    obj[f"{change_field}"].remove(change_data)
                else:
                    print(f"Error: {change_operation} is not a valid operation.")
                    return data
            else:
                if change_operation is JsonModOperation.OVERWRITE:
                    obj[f"{change_field}"] = change_data
                elif change_operation is JsonModOperation.APPEND:
                    print(
                        f"Error: do not use APPEND operation on objects which are not lists."
                    )
                elif change_operation is JsonModOperation.REMOVEALL:
                    if isinstance(change_field, str):
                        obj[f"{change_field}"] = ""
                    else:
                        obj[f"{change_field}"] = data
                elif change_operation is JsonModOperation.REMOVEONE:
                    print(
                        f"Error: do not use REMOVEONE operation on objects which are not lists."
                    )
                    return data
                else:
                    print(f"Error: {change_operation} is not a valid operation.")
                    return data
        else:
            continue
    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)
    return data


def next_id(json_file):
    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    if not data:
        return 0
    ids = sorted([item["id"] for item in data if "id" in item])

    expected_id = 0
    for current_id in ids:
        if current_id == expected_id:
            expected_id += 1
        elif current_id > expected_id:
            return expected_id

    return expected_id
#endregion