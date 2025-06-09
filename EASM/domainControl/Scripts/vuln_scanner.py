import subprocess
import json
import os
import requests
from typing import Dict, Any, List
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def create_domain_directory(domain: str) -> tuple:
    """Create directory structure for domain reports"""
    domain_safe = domain.replace(".", "_")
    # Use domainControl/Scripts/../Results/ path
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    domain_dir = os.path.join(script_dir, "Results", domain_safe)
    html_dir = os.path.join(domain_dir, "wapiti_html_reports")
    
    os.makedirs(domain_dir, exist_ok=True)
    os.makedirs(html_dir, exist_ok=True)
    
    return domain_dir, html_dir


def get_final_redirect_url(domain: str) -> str:
    """Get the final URL after all redirects"""
    try:
        response = requests.get(f"https://{domain}", 
                              allow_redirects=True, 
                              timeout=10, 
                              verify=False)
        return response.url.replace("https://", "").replace("http://", "").rstrip("/")
    except:
        return domain


def deduplicate_vulnerabilities(vulnerabilities: Dict[str, List]) -> Dict[str, List]:
    """Remove duplicate vulnerability entries"""
    deduplicated = {}
    
    for vuln_type, vuln_list in vulnerabilities.items():
        if not isinstance(vuln_list, list):
            deduplicated[vuln_type] = vuln_list
            continue
            
        seen = set()
        unique_vulns = []
        
        for vuln in vuln_list:
            if isinstance(vuln, dict):
                # Create a unique identifier for the vulnerability
                identifier = (
                    vuln.get("method", ""),
                    vuln.get("path", ""),
                    vuln.get("info", ""),
                    vuln.get("parameter", "")
                )
                
                if identifier not in seen:
                    seen.add(identifier)
                    unique_vulns.append(vuln)
            else:
                unique_vulns.append(vuln)
        
        deduplicated[vuln_type] = unique_vulns
    
    return deduplicated


def scan_single_domain(domain: str, parent_domain: str = None) -> Dict[str, Any]:
    """Scan a single domain with Wapiti"""
    try:
        # Check if this is a redirect to avoid duplicate scans
        final_url = get_final_redirect_url(domain)
        if parent_domain and final_url == get_final_redirect_url(parent_domain):
            print(f"[INFO] Skipping {domain} (redirects to {parent_domain})")
            return {
                "status": "redirect",
                "redirects_to": parent_domain,
                "message": f"Domain redirects to {parent_domain}"
            }
        
        # Determine output directory
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if parent_domain:
            parent_safe = parent_domain.replace(".", "_")
            main_dir = os.path.join(script_dir, "Results", parent_safe)
            html_dir = os.path.join(main_dir, "wapiti_html_reports")
        else:
            domain_safe = domain.replace(".", "_")
            main_dir = os.path.join(script_dir, "Results", domain_safe)
            html_dir = os.path.join(main_dir, "wapiti_html_reports")
        
        os.makedirs(main_dir, exist_ok=True)
        os.makedirs(html_dir, exist_ok=True)
        
        # Create output files
        domain_safe = domain.replace(".", "_")
        json_file = f"{main_dir}/{domain_safe}_wapiti.json"
        html_file = f"{html_dir}/{domain_safe}_wapiti.html"
        
        # Check if Wapiti is available
        try:
            subprocess.run(["wapiti", "--version"], capture_output=True, timeout=5)
        except:
            print(f"[WARNING] Wapiti not available for {domain}, using basic check")
            return basic_security_check(domain)
        
        # Run optimized Wapiti scan
        cmd = [
            "wapiti",
            "-u", f"https://{domain}",
            "--scope", "domain",
            "-m", "xss,sql,exec,file,backup,csp",
            "-f", "json",
            "-o", json_file,
            "--timeout", "10",
            "--max-scan-time", "120",
            "-d", "1",
            "--max-files-per-dir", "10",
            "--max-links-per-page", "20",
            "--max-parameters", "50"
        ]
        
        print(f"[WAPITI] Scanning {domain}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Generate HTML report separately with correct directory output
        cmd_html = [
            "wapiti",
            "-u", f"https://{domain}",
            "--scope", "domain",
            "-m", "xss,sql,exec,file,backup,csp",
            "-f", "html",
            "-o", html_dir,  # Output to directory, not file
            "--timeout", "10",
            "--max-scan-time", "120",  # Reduced from 180 to 120 seconds
            "-d", "1",  # Reduced depth from 2 to 1 to save memory
            "--max-files-per-dir", "10",  # Reduced from 20 to 10 files
            "--max-links-per-page", "20",  # Limit links per page
            "--max-parameters", "50"  # Limit parameters to scan
        ]
        
        print(f"[WAPITI] Generating HTML report for {domain}...")
        subprocess.run(cmd_html, capture_output=True, text=True, timeout=300)
        
        # Find the actual HTML report file
        html_report_path = None
        if os.path.exists(html_dir):
            for file in os.listdir(html_dir):
                if file.endswith('.html') and 'report' in file.lower():
                    html_report_path = os.path.join(html_dir, file)
                    break
            # If no report.html found, look for any HTML file
            if not html_report_path:
                for file in os.listdir(html_dir):
                    if file.endswith('.html'):
                        html_report_path = os.path.join(html_dir, file)
                        break
        
        # Parse results
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    scan_data = json.load(f)
                
                # Clean and deduplicate vulnerabilities
                vulnerabilities = scan_data.get("vulnerabilities", {})
                vulnerabilities = deduplicate_vulnerabilities(vulnerabilities)
                
                # Count total vulnerabilities
                total_vulns = sum(len(v) for v in vulnerabilities.values() if isinstance(v, list))
                
                return {
                    "status": "success",
                    "vulnerabilities": vulnerabilities,
                    "total_vulns": total_vulns,
                    "scan_info": scan_data.get("infos", {}),
                    "json_report": json_file,
                    "html_report": html_report_path
                }
                
            except Exception as e:
                print(f"[ERROR] Failed to parse Wapiti results for {domain}: {e}")
                return basic_security_check(domain)
        else:
            print(f"[WARNING] No Wapiti output found for {domain}")
            return basic_security_check(domain)
            
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Wapiti scan timed out for {domain}")
        return {"status": "timeout", "error": "Scan timed out after 5 minutes"}
    except Exception as e:
        print(f"[ERROR] Wapiti scan failed for {domain}: {e}")
        return basic_security_check(domain)


def parallel_wapiti_scan(domains: List[str], subdomains_dict: Dict[str, List[str]]) -> Dict[str, Any]:
    """Scan domains and subdomains in parallel with deduplication - MEMORY OPTIMIZED"""
    results = {}
    scan_tasks = []
    
    # Prepare scan tasks
    for domain in domains:
        scan_tasks.append((domain, None))  # Main domain
        
        if domain in subdomains_dict:
            for subdomain in subdomains_dict[domain]:
                scan_tasks.append((subdomain, domain))  # Subdomain with parent
    
    print(f"[INFO] Starting parallel vulnerability scans for {len(scan_tasks)} targets...")
    
    # 🚀 MEMORY OPTIMIZATION: Reduce workers from 4 to 2 to prevent OOM
    # Each Wapiti scan can use 500MB-1GB+ memory, so limit concurrent scans
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_to_domain = {
            executor.submit(scan_single_domain, domain, parent): domain 
            for domain, parent in scan_tasks
        }
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                results[domain] = future.result()
            except Exception as e:
                print(f"[ERROR] Scan failed for {domain}: {e}")
                results[domain] = {"status": "error", "error": str(e)}
    
    return results


def basic_security_check(domain: str) -> Dict[str, Any]:
    """Basic security check when Wapiti is not available"""
    try:
        response = requests.get(f"https://{domain}", timeout=10, verify=False)
        headers = response.headers
        
        security_issues = []
        
        # Check critical security headers
        if 'Strict-Transport-Security' not in headers:
            security_issues.append("Missing HSTS header")
        if 'X-Frame-Options' not in headers:
            security_issues.append("Missing X-Frame-Options")
        if 'Content-Security-Policy' not in headers:
            security_issues.append("Missing CSP header")
        if 'X-Content-Type-Options' not in headers:
            security_issues.append("Missing X-Content-Type-Options")
        
        return {
            "status": "basic_check",
            "security_issues": security_issues,
            "total_issues": len(security_issues),
            "response_code": response.status_code,
            "note": "Basic security check performed (Wapiti unavailable)"
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def detect_technologies_and_cves(domain: str) -> Dict[str, Any]:
    """Enhanced technology detection with header analysis"""
    try:
        response = requests.get(f"https://{domain}", timeout=10, verify=False)
        headers = response.headers
        
        technologies = []
        
        # Detect from headers
        if 'Server' in headers:
            server = headers['Server']
            technologies.append(f"Server: {server}")
            
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            technologies.append(f"Powered by: {powered_by}")
            
        if 'X-Generator' in headers:
            generator = headers['X-Generator']
            technologies.append(f"Generator: {generator}")
        
        # Detect from response content (basic)
        content = response.text.lower()
        if 'wordpress' in content:
            technologies.append("CMS: WordPress")
        elif 'drupal' in content:
            technologies.append("CMS: Drupal")
        elif 'joomla' in content:
            technologies.append("CMS: Joomla")
        
        return {
            "status": "success",
            "technologies": technologies,
            "cves": []  # CVE lookup would require external API integration
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "technologies": [],
            "cves": []
        }