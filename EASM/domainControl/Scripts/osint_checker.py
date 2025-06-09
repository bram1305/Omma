import whois
import socket
import dns.resolver
import dns.flags
import requests
import re
import subprocess
import time
import os
import json
import toml
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from domainControl.Scripts.utils import is_subdomain_redirecting_to_root
import socks
import stem
from stem import Signal
from stem.control import Controller

# 🚀 LOAD CONFIGURATION FOR DARKWEB SETTINGS
try:
    config_path = Path(__file__).parent.parent.parent / "config.toml"
    with open(config_path, "r") as file:
        config = toml.load(file)
    DARKWEB_ENABLED = config.get("domaincontrol", {}).get("darkweb-enabled", False)
    print(f"[INFO] Dark Web scanning: {'ENABLED' if DARKWEB_ENABLED else 'DISABLED'}")
except Exception as e:
    print(f"[WARNING] Could not load config, defaulting to DARKWEB_ENABLED=False: {e}")
    DARKWEB_ENABLED = False

def check_whois(domain: str) -> Dict[str, Any]:
    """
    Get WHOIS information for a domain, with subprocess fallback.
    """
    try:
        whois_info = whois.whois(domain)
        result = {
            "registrar": whois_info.registrar,
            "creation_date": None,
            "expiration_date": None
        }
        if whois_info.creation_date:
            if isinstance(whois_info.creation_date, list):
                result["creation_date"] = str(whois_info.creation_date[0])
            else:
                result["creation_date"] = str(whois_info.creation_date)
        if whois_info.expiration_date:
            if isinstance(whois_info.expiration_date, list):
                result["expiration_date"] = str(whois_info.expiration_date[0])
            else:
                result["expiration_date"] = str(whois_info.expiration_date)
        # Fallback als alles leeg is
        if not result["registrar"] and not result["creation_date"] and not result["expiration_date"]:
            raise Exception("Empty WHOIS")
        return result
    except Exception:
        # Fallback naar subprocess
        try:
            output = subprocess.check_output(['whois', domain], text=True, timeout=15)
            result = {"registrar": None, "creation_date": None, "expiration_date": None}
            for line in output.splitlines():
                if re.search(r'registrar:', line, re.IGNORECASE):
                    result["registrar"] = line.split(':', 1)[1].strip()
                elif re.search(r'creat(ed|ion)( date)?:', line, re.IGNORECASE):
                    result["creation_date"] = line.split(':', 1)[1].strip()
                elif re.search(r'expir(ation|y)( date)?:', line, re.IGNORECASE):
                    result["expiration_date"] = line.split(':', 1)[1].strip()
            return result
        except Exception:
            return {"registrar": None, "creation_date": None, "expiration_date": None}

def lookup_ipinfo(ip: str) -> Dict[str, Any]:
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "asn": data.get("org", "Unknown"),
                "country": data.get("country", "Unknown"),
                "region": data.get("region", "Unknown"),
                "city": data.get("city", "Unknown"),
                "loc": data.get("loc", "Unknown")
            }
        else:
            return {
                "asn": "Unknown",
                "country": "Unknown",
                "region": "Unknown",
                "city": "Unknown",
                "loc": "Unknown"
            }
    except Exception:
        return {
            "asn": "Unknown",
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "loc": "Unknown"
        }

def check_dnssec_and_email_security(domain: str) -> Tuple[Dict[str, bool], Dict[str, bool]]:
    dnssec_info = {"enabled": False}
    email_security = {"spf": False, "dmarc": False, "dkim": False}
    try:
        resolver = dns.resolver.Resolver()
        try:
            dns.resolver.resolve(domain, 'DS')
            dnssec_info["enabled"] = True
        except Exception:
            try:
                resolver.set_flags(dns.flags.RD | dns.flags.AD)
                answer = resolver.resolve(domain, 'A')
                if answer.response.flags & dns.flags.AD:
                    dnssec_info["enabled"] = True
            except Exception:
                pass
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            for record in spf_records:
                txt_data = record.to_text()
                if "v=spf1" in txt_data:
                    email_security["spf"] = True
                    break
        except Exception:
            pass
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for record in dmarc_records:
                txt_data = record.to_text()
                if "v=DMARC1" in txt_data:
                    email_security["dmarc"] = True
                    break
        except Exception:
            pass
        try:
            dkim_records = dns.resolver.resolve(f"default._domainkey.{domain}", 'TXT')
            for record in dkim_records:
                txt_data = record.to_text()
                if "v=DKIM1" in txt_data:
                    email_security["dkim"] = True
                    break
        except Exception:
            pass
    except Exception:
        pass
    return dnssec_info, email_security

def check_tor_connectivity():
    """Check if Tor is running and accessible"""
    try:
        session = create_tor_session()
        response = session.get("https://check.torproject.org", timeout=15)
        return "Congratulations" in response.text
    except Exception:
        return False

def create_tor_session():
    """Create a requests session that routes through Tor"""
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    return session

def renew_tor_ip():
    """Renew the Tor IP address"""
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            print("[INFO] Tor IP renewed")
            time.sleep(10)  # Wait for the IP to change
    except Exception as e:
        print(f"[WARNING] Failed to renew Tor IP: {e}")

def run_onionsearch(query: str) -> Dict[str, Any]:
    """
    Run OnionSearch to find .onion sites related to the query
    """
    try:
        # Controleer of OnionSearch geïnstalleerd is
        try:
            subprocess.run(["which", "onionsearch"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            print("[WARNING] OnionSearch is not installed, skipping")
            return {"status": "not_installed", "error": "OnionSearch is not installed"}
        
        # Probeer verschillende command line opties
        try:
            # Optie 1: --query parameter
            cmd = ["onionsearch", "--query", query]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.CalledProcessError:
            try:
                # Optie 2: -q parameter
                cmd = ["onionsearch", "-q", query]
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            except subprocess.CalledProcessError:
                # Fallback: geen parameters
                cmd = ["onionsearch", query]
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Zoek naar .onion URLs in de output
        onion_links = re.findall(r'https?://[a-zA-Z0-9]{16,56}\.onion\b', process.stdout)
        
        if onion_links:
            return {
                "status": "success",
                "onion_links": list(set(onion_links)),
                "count": len(set(onion_links))
            }
        else:
            return {
                "status": "no_results",
                "onion_links": [],
                "count": 0
            }
            
    except Exception as e:
        print(f"[WARNING] OnionSearch failed: {e}")
        return {"status": "error", "error": str(e)}

def run_deepdark_cti(query: str) -> Dict[str, Any]:
    """
    Run DeepDarkCTI to search for the query in leak sites and pastebins
    """
    try:
        # Check if darkdump.py is installed/available
        darkdump_path = "/root/darkdump/darkdump.py"
        if not os.path.exists(darkdump_path):
            print(f"[WARNING] Darkdump not found at {darkdump_path}, skipping")
            return {"status": "not_installed", "error": f"Darkdump not found at {darkdump_path}"}
        
        # Probeer verschillende command line opties
        try:
            # Optie 1: -q en -j parameters
            cmd = ["python3", darkdump_path, "-q", query, "-j"]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.CalledProcessError:
            try:
                # Optie 2: --query parameter
                cmd = ["python3", darkdump_path, "--query", query]
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            except subprocess.CalledProcessError:
                # Fallback: alleen query
                cmd = ["python3", darkdump_path, query]
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Zoek naar JSON output
        json_start = process.stdout.find('{')
        if json_start >= 0:
            json_data = process.stdout[json_start:]
            results = json.loads(json_data)
            return {
                "status": "success",
                "results": results,
                "count": len(results.get("results", []))
            }
        else:
            # Controleer of er resultaten zijn
            has_results = "No results found" not in process.stdout
            return {
                "status": "no_json" if has_results else "no_results",
                "has_data": has_results
            }
            
    except Exception as e:
        print(f"[WARNING] DeepDarkCTI failed: {e}")
        return {"status": "error", "error": str(e)}

def run_torcrawl(query: str, onion_links: List[str]) -> Dict[str, Any]:
    """
    Run TorCrawl to crawl .onion sites related to the query
    
    Args:
        query: The search query (e.g., domain name)
        onion_links: List of .onion links to crawl
        
    Returns:
        Dictionary with crawl results
    """
    try:
        # Check if TorCrawl is installed
        torcrawl_path = "/root/TorCrawl.py/torcrawl.py"
        if not os.path.exists(torcrawl_path):
            print(f"[WARNING] TorCrawl not found at {torcrawl_path}, skipping")
            return {"status": "not_installed", "error": f"TorCrawl not found at {torcrawl_path}"}
        
        if not onion_links:
            return {"status": "no_links", "error": "No onion links found to crawl"}
        
        # Limit the number of links to crawl
        onion_links = onion_links[:3]
        
        # Create a temporary file with the links
        temp_file = "/tmp/torcrawl_links.txt"
        with open(temp_file, "w") as f:
            for link in onion_links:
                f.write(f"{link}\n")
        
        # Run TorCrawl with the links file
        output_dir = "/tmp/torcrawl_output"
        os.makedirs(output_dir, exist_ok=True)
        
        # Probeer verschillende command line opties
        try:
            # Optie 1: -f, -o, -k, -d parameters
            cmd = [
                "python3", torcrawl_path,
                "-f", temp_file,
                "-o", output_dir,
                "-k", query,
                "-d", "1"  # Limit crawl depth
            ]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.CalledProcessError:
            try:
                # Optie 2: --file, --output, --keyword, --depth parameters
                cmd = [
                    "python3", torcrawl_path,
                    "--file", temp_file,
                    "--output", output_dir,
                    "--keyword", query,
                    "--depth", "1"
                ]
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            except subprocess.CalledProcessError:
                # Fallback: minimale parameters
                cmd = [
                    "python3", torcrawl_path,
                    "-f", temp_file,
                    "-o", output_dir
                ]
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Check for crawled content
        crawled_files = []
        for root, _, files in os.walk(output_dir):
            for file in files:
                if file.endswith(".html") or file.endswith(".txt"):
                    crawled_files.append(os.path.join(root, file))
        
        # Extract some data from crawled files
        crawl_data = []
        for file_path in crawled_files[:5]:  # Limit to first 5 files
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    # Extract title if HTML
                    title = None
                    if file_path.endswith(".html"):
                        title_match = re.search(r"<title>(.*?)</title>", content, re.IGNORECASE)
                        if title_match:
                            title = title_match.group(1)
                    
                    # Look for mentions of the query
                    query_mentions = content.lower().count(query.lower())
                    
                    crawl_data.append({
                        "file": os.path.basename(file_path),
                        "title": title,
                        "size_bytes": os.path.getsize(file_path),
                        "query_mentions": query_mentions
                    })
            except Exception as e:
                print(f"[WARNING] Error processing crawled file: {e}")
        
        return {
            "status": "success" if crawled_files else "no_results",
            "crawled_links": len(onion_links),
            "crawled_files": len(crawled_files),
            "crawl_data": crawl_data
        }
            
    except Exception as e:
        print(f"[WARNING] TorCrawl failed: {e}")
        return {"status": "error", "error": str(e)}

def check_onion_status_direct(onion_url: str) -> Dict[str, Any]:
    """Check status of an onion site directly via Tor"""
    try:
        session = create_tor_session()
        response = session.get(onion_url, timeout=30)
        return {
            "is_up": True,
            "status_code": response.status_code,
            "method": "direct_tor"
        }
    except Exception as e:
        return {
            "is_up": False,
            "error": str(e),
            "method": "direct_tor"
        }

def check_darkweb_for_domain(domain: str) -> Dict[str, Any]:
    """Check Dark Web for information about a domain"""
    
    # 🚀 CHECK IF DARKWEB IS ENABLED
    if not DARKWEB_ENABLED:
        print(f"[INFO] Dark Web scanning disabled in config - skipping for {domain}")
        return {
            "status": "disabled",
            "message": "Dark Web scanning disabled in configuration",
            "onionsearch": {"status": "disabled"},
            "deepdark_cti": {"status": "disabled"},
            "torcrawl": {"status": "disabled"},
            "onion_sites": {}
        }
    
    darkweb_results = {
        "onionsearch": {},
        "deepdark_cti": {},
        "torcrawl": {},
        "onion_sites": {}
    }
    
    # Check if Tor is running
    if not check_tor_connectivity():
        print("[WARNING] Tor is not running or not accessible")
        return {
            "status": "error",
            "error": "Tor is not running or not accessible",
            "onionsearch": {"status": "error", "error": "Tor not running"},
            "deepdark_cti": {"status": "error", "error": "Tor not running"},
            "torcrawl": {"status": "error", "error": "Tor not running"},
            "onion_sites": {}
        }
    
    # Run OnionSearch
    print(f"[INFO] Running OnionSearch...")
    darkweb_results["onionsearch"] = run_onionsearch(domain)
    
    # Run DeepDarkCTI
    print(f"[INFO] Running DeepDarkCTI...")
    darkweb_results["deepdark_cti"] = run_deepdark_cti(domain)
    
    # Get onion links from OnionSearch results
    onion_links = []
    if darkweb_results["onionsearch"].get("status") == "success":
        onion_links = darkweb_results["onionsearch"].get("onion_links", [])
    
    # Run TorCrawl if we have onion links
    if onion_links:
        print(f"[INFO] Running TorCrawl with {len(onion_links)} onion links")
        darkweb_results["torcrawl"] = run_torcrawl(domain, onion_links)
    else:
        darkweb_results["torcrawl"] = {"status": "skipped", "reason": "No onion links found"}
    
    # Check status of each .onion link
    print(f"[INFO] Checking status of {len(onion_links)} onion links")
    for i, link in enumerate(onion_links[:3]):  # Limit to 3 links
        print(f"[INFO] Checking onion link {i+1}/{min(len(onion_links), 3)}")
        status = check_onion_status_direct(link)
        darkweb_results["onion_sites"][link] = {
            "status": status
        }
        
        # Renew Tor IP after each .onion site to avoid rate limiting
        renew_tor_ip()
    
    # Add summary for quick analysis
    darkweb_results["summary"] = {
        "total_onion_links_found": len(onion_links),
        "active_onion_links": sum(1 for link, data in darkweb_results["onion_sites"].items() 
                                if data.get("status", {}).get("is_up", False)),
        "onionsearch_success": darkweb_results["onionsearch"].get("status") == "success",
        "deepdark_cti_success": darkweb_results["deepdark_cti"].get("status") == "success",
        "torcrawl_success": darkweb_results["torcrawl"].get("status") == "success"
    }
    
    return darkweb_results

def check_darkweb_for_email(email: str) -> Dict[str, Any]:
    """Check Dark Web for information about an email"""
    
    # 🚀 CHECK IF DARKWEB IS ENABLED
    if not DARKWEB_ENABLED:
        print(f"[INFO] Dark Web scanning disabled in config - skipping email check")
        return {
            "status": "disabled",
            "message": "Dark Web scanning disabled in configuration",
            "deepdark_cti": {"status": "disabled"}
        }
    
    darkweb_results = {
        "deepdark_cti": {}
    }
    
    # Check if Tor is running
    if not check_tor_connectivity():
        print("[WARNING] Tor is not running or not accessible")
        return {
            "status": "error",
            "error": "Tor is not running or not accessible",
            "deepdark_cti": {"status": "error", "error": "Tor not running"}
        }
    
    # Run DeepDarkCTI for email
    print(f"[INFO] Running DeepDarkCTI for email")
    darkweb_results["deepdark_cti"] = run_deepdark_cti(email)
    
    return darkweb_results

def gather_osint_data(domain: str, ip: str = None) -> Dict[str, Any]:
    """
    Gather OSINT data for a domain - MEMORY OPTIMIZED VERSION
    """
    print(f"[OSINT] Gathering intelligence for {domain}")
    
    # 🚀 MEMORY OPTIMIZATION: Limit data collection to essential items only
    osint_data = {
        "domain": domain,
        "ip": ip,
        "whois": {},
        "dns_info": {},
        "darkweb": {"status": "disabled" if not DARKWEB_ENABLED else "enabled"},
        "reputation": {},
        "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Basic domain validation
    if not domain or len(domain) > 253:  # RFC limit
        return {"error": "Invalid domain", "domain": domain}
    
    try:
        # 1. WHOIS Information (lightweight)
        print(f"[OSINT] Getting WHOIS for {domain}")
        try:
            whois_info = check_whois(domain)
            if whois_info:
                # Only store essential WHOIS data to save memory
                osint_data["whois"] = {
                    "registrar": str(whois_info["registrar"]) if whois_info["registrar"] else "Unknown",
                    "creation_date": str(whois_info["creation_date"]) if whois_info["creation_date"] else "Unknown",
                    "expiration_date": str(whois_info["expiration_date"]) if whois_info["expiration_date"] else "Unknown",
                    "status": str(whois_info.get("status", "Unknown"))
                }
        except Exception as e:
            print(f"[WARNING] WHOIS lookup failed: {e}")
            osint_data["whois"] = {"error": str(e)}

        # 2. DNS Information (essential only)
        print(f"[OSINT] Getting DNS info for {domain}")
        dns_info = {}
        
        # Get essential DNS records only
        for record_type in ["A", "MX", "NS"]:  # Reduced from more record types
            try:
                result = dns.resolver.resolve(domain, record_type)
                if result:
                    dns_info[record_type.lower()] = [str(r) for r in result[:3]]  # Limit to first 3 records
            except Exception as e:
                dns_info[record_type.lower()] = f"Error: {e}"
        
        osint_data["dns_info"] = dns_info

        # 3. Dark Web Analysis (only if enabled)
        if DARKWEB_ENABLED:
            print(f"[OSINT] Performing dark web analysis for {domain}")
            try:
                # Limit dark web analysis to prevent memory issues
                darkweb_results = {
                    "onion_search": run_onionsearch(domain),
                    "deepdark_cti": run_deepdark_cti(domain)
                }
                osint_data["darkweb"] = darkweb_results
            except Exception as e:
                print(f"[WARNING] Dark web analysis failed: {e}")
                osint_data["darkweb"] = {"error": str(e), "status": "failed"}
        else:
            print(f"[INFO] Skipping dark web risk analysis for {domain} - disabled in config")
            osint_data["darkweb"] = {"status": "disabled"}

        # 4. Basic Reputation Check (lightweight)
        print(f"[OSINT] Basic reputation check for {domain}")
        try:
            # Simple reputation indicators
            reputation = {
                "domain_age_days": 0,
                "has_mx_record": bool(dns_info.get("mx")),
                "has_ns_record": bool(dns_info.get("ns")),
                "whois_available": "error" not in osint_data["whois"]
            }
            
            # Calculate domain age if available
            if osint_data["whois"].get("creation_date") and osint_data["whois"]["creation_date"] != "Unknown":
                try:
                    from datetime import datetime
                    creation_str = str(osint_data["whois"]["creation_date"])
                    if creation_str and creation_str != "Unknown":
                        # Simple age calculation
                        reputation["domain_age_days"] = "calculated"
                except:
                    pass
            
            osint_data["reputation"] = reputation
            
        except Exception as e:
            print(f"[WARNING] Reputation check failed: {e}")
            osint_data["reputation"] = {"error": str(e)}

        print(f"[OSINT] Completed OSINT gathering for {domain}")
        return osint_data
        
    except Exception as e:
        print(f"[ERROR] OSINT gathering failed for {domain}: {e}")
    return {
            "domain": domain,
            "error": str(e),
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }