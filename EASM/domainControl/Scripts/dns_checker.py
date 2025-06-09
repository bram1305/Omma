import dns.resolver
import requests
import json
from typing import List, Set
import time


def resolve_record(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=10)
        return [rdata.to_text() for rdata in answers]
    except Exception:
        return None


def get_subdomains_crtsh(domain: str) -> List[str]:
    """Get subdomains from crt.sh certificate transparency logs - MEMORY OPTIMIZED VERSION"""
    print(f"[INFO] Querying crt.sh for {domain}...")
    subdomains = set()
    
    try:
        # Multiple URL formats to try
        urls = [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://crt.sh/?Identity=%25.{domain}&output=json"
        ]
        
        for i, url in enumerate(urls, 1):
            print(f"[DEBUG] Trying crt.sh query {i}: {url}")
            try:
                # 🚀 MEMORY OPTIMIZATION: Shorter timeout and stream processing
                resp = requests.get(url, timeout=30, headers={
                    'User-Agent': 'Mozilla/5.0 (compatible; SubdomainScanner/1.0)'
                }, stream=True)
                
                print(f"[DEBUG] Response status: {resp.status_code}")
                
                if resp.status_code == 200:
                    # 🚀 MEMORY OPTIMIZATION: Process response in chunks to avoid loading all into memory
                    content = ""
                    for chunk in resp.iter_content(chunk_size=8192, decode_unicode=True):
                        content += chunk
                        # Limit total content size to prevent memory issues
                        if len(content) > 50 * 1024 * 1024:  # 50MB limit
                            print(f"[WARNING] Response too large for {domain}, truncating...")
                            break
                    
                    try:
                        data = json.loads(content)
                        print(f"[DEBUG] Found {len(data)} certificate entries")
                        
                        # 🚀 MEMORY OPTIMIZATION: Process entries in batches
                        batch_size = 1000
                        for i in range(0, len(data), batch_size):
                            batch = data[i:i+batch_size]
                            for entry in batch:
                                if 'name_value' in entry:
                                    names = entry['name_value'].split('\n')
                                    for name in names:
                                        name = name.strip().lower()
                                        if name.endswith(f'.{domain}') and name != domain:
                                            # Filter out wildcard and invalid entries
                                            if not name.startswith('*') and '\\' not in name:
                                                subdomains.add(name)
                                                
                                                # 🚀 MEMORY OPTIMIZATION: Limit total subdomains
                                                if len(subdomains) > 500:  # Limit to 500 subdomains
                                                    print(f"[INFO] Reached subdomain limit (500) for {domain}")
                                                    return list(subdomains)
                            
                            # Clear batch from memory
                            del batch
                        
                        # Clear data from memory
                        del data
                        break  # Success, no need to try other URLs
                            
                    except json.JSONDecodeError as e:
                        print(f"[ERROR] JSON decode error for {url}: {e}")
                        continue
                        
                else:
                    print(f"[WARNING] HTTP {resp.status_code} for {url}")
                    
            except requests.exceptions.Timeout:
                print(f"[WARNING] Timeout for crt.sh query {i}")
                continue
            except requests.exceptions.RequestException as e:
                print(f"[WARNING] Request error for crt.sh query {i}: {e}")
                continue
            except Exception as e:
                print(f"[ERROR] Unexpected error for crt.sh query {i}: {e}")
                continue
        
        print(f"[INFO] Found {len(subdomains)} unique subdomains for {domain}")
        return list(subdomains)
            
    except Exception as e:
        print(f"[ERROR] crt.sh lookup failed for {domain}: {e}")
        return []


def check_dns(domains, return_full_domain_list=False):
    results = {}
    all_domains = set()
    total = len(domains)

    for idx, domain in enumerate(domains, 1):
        print(f"[DNS] Processing domain {idx}/{total}: {domain}")
        
        # Basic DNS records
        entry = {
            "a_record": resolve_record(domain, "A"),
            "aaaa_record": resolve_record(domain, "AAAA"),
            "mx_record": resolve_record(domain, "MX"),
            "ns_record": resolve_record(domain, "NS"),
            "cname_record": resolve_record(domain, "CNAME"),
            "txt_record": resolve_record(domain, "TXT"),
            "soa_record": resolve_record(domain, "SOA"),
            "ptr_record": resolve_record(domain, "PTR"),
        }

        # Subdomain discovery via crt.sh
        print(f"[INFO] Starting subdomain discovery for {domain}")
        subdomains = get_subdomains_crtsh(domain)
        
        entry["subdomains"] = subdomains
        
        # Add to all domains
        all_domains.add(domain)
        all_domains.update(subdomains)
        
        results[domain] = entry
        
        print(f"[INFO] Domain {domain}: {len(subdomains)} subdomains found")

    print(f"[INFO] Total domains to process: {len(all_domains)}")
    
    if return_full_domain_list:
        return results, sorted(all_domains)
    return results 