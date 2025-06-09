import json
import os
import time
import ssl
import requests
import socket
import sys
import re
import toml
import gc  # 🚀 MEMORY OPTIMIZATION: Add garbage collection
from domainControl.Scripts.dns_checker import check_dns, resolve_record
from domainControl.Scripts.certificate_checker import check_certificates
from domainControl.Scripts.header_scanner import scan_headers, is_valid_url_domain
from domainControl.Scripts.vuln_scanner import parallel_wapiti_scan, detect_technologies_and_cves, get_final_redirect_url
from domainControl.Scripts.osint_checker import gather_osint_data
from domainControl.Scripts.warning_generator import generate_warnings_report, generate_individual_domain_warnings
import urllib3
import glob
from pathlib import Path

# Disable SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

# Use domainControl/Results/ for output
script_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(script_dir, "Results", "SingleDomainReport.json")

# 🚀 LOAD CONFIGURATION FOR DARKWEB SETTINGS
try:
    config_path = Path(__file__).parent.parent / "config.toml"
    with open(config_path, "r") as file:
        config = toml.load(file)
    DARKWEB_ENABLED = config.get("domaincontrol", {}).get("darkweb-enabled", False)
    WAPITI_ENABLED = config.get("domaincontrol", {}).get("wapiti-enabled", True)
    print(f"[INFO] Domain Control - Dark Web scanning: {'ENABLED' if DARKWEB_ENABLED else 'DISABLED'}")
    print(f"[INFO] Domain Control - Wapiti scanning: {'ENABLED' if WAPITI_ENABLED else 'DISABLED'}")
except Exception as e:
    print(f"[WARNING] Could not load config, defaulting to DARKWEB_ENABLED=False, WAPITI_ENABLED=False: {e}")
    DARKWEB_ENABLED = False
    WAPITI_ENABLED = False

RISICO_PRIORITIES = {
    "expired_cert": "high",
    "cert_soon_expired": "low",
    "cert_expires_soon": "medium",
    "no_issuer_info": "low",
    "no_hsts": "low",
    "self_signed": "high",
    "missing_dmarc": "low",
    "missing_spf": "low",
    "missing_dkim": "low",
    "email_leak_found": "high",
    "weak_ssl": "medium",
    "no_dnssec": "low",
    "security_issues": "medium",
    "missing_csp": "low",
    "missing_xframe": "low",
    "high_vulns": "high",
    "medium_vulns": "medium",
    "redirect_domain": "info"
}

def filter_subdomains(root_domain: str, subdomains: list) -> list:
    """Filter out root domain from subdomains list"""
    return [sub for sub in subdomains if sub != root_domain and sub.strip()]

def is_redirect_domain(domain: str, root_domain: str) -> bool:
    """Check if domain redirects to root domain"""
    try:
        final_url = get_final_redirect_url(domain)
        root_final_url = get_final_redirect_url(root_domain)
        return final_url == root_final_url and domain != root_domain
    except:
        return False

def analyse_risico(domain: str, cert_data: dict, osint_data: dict, headers: dict, web_vuln: dict, techs: dict, root_domain: str = None) -> tuple:
    """Enhanced risk analysis with better categorization"""
    
    # Check if this is a redirect domain
    if root_domain and is_redirect_domain(domain, root_domain):
        return [{"label": "redirect_domain", "priority": "info"}], "low"
    
    # Skip analysis if explicit redirect status
    if any("redirects_to" in data for data in [cert_data, osint_data, headers, web_vuln] if isinstance(data, dict)):
        return [{"label": "redirect_domain", "priority": "info"}], "low"
        
    labels = []
    
    # Certificate security analysis
    if isinstance(cert_data, dict):
        if cert_data.get("expired", False):
            labels.append("expired_cert")
    elif cert_data.get("days_left", 999) <= 7:
            labels.append("cert_expires_soon")
    elif cert_data.get("days_left", 999) <= 30:
            labels.append("cert_soon_expired")
            
    if cert_data.get("self_signed", False):
            labels.append("self_signed")
    if cert_data.get("hsts", True) is False:
            labels.append("no_hsts")
    
    # Header security analysis
    if isinstance(headers, dict):
        if not headers.get("csp", False):
            labels.append("missing_csp")
        if not headers.get("x_frame_options", False):
            labels.append("missing_xframe")
    
    # Email security analysis
    if isinstance(osint_data, dict):
        email_prot = osint_data.get("email_protection", {})
    if not email_prot.get("dmarc", False):
        labels.append("missing_dmarc")
    if not email_prot.get("spf", False):
        labels.append("missing_spf")
    if not email_prot.get("dkim", False):
        labels.append("missing_dkim")
    
    # DNSSEC analysis
    if not osint_data.get("dnssec", {}).get("enabled", True):
        labels.append("no_dnssec")
    
    # 🚀 CONDITIONAL DARK WEB ANALYSIS
    if DARKWEB_ENABLED:
        darkweb = osint_data.get("darkweb", {})
        if darkweb.get("deepdark_cti", {}).get("status") == "success":
            labels.append("email_leak_found")
    else:
        # Skip darkweb analysis when disabled
        print(f"[INFO] Skipping dark web risk analysis for {domain} - disabled in config")
    
    # Vulnerability analysis
    if isinstance(web_vuln, dict) and web_vuln.get("status") == "success":
        total_vulns = web_vuln.get("total_vulns", 0)
        if total_vulns > 20:
            labels.append("high_vulns")
        elif total_vulns > 8:
            labels.append("medium_vulns")
        
        # Check for specific high-risk vulnerabilities
        vulnerabilities = web_vuln.get("vulnerabilities", {})
        high_risk_vulns = ["SQL Injection", "Cross Site Scripting", "Command execution", "Path Traversal"]
        for vuln_type in high_risk_vulns:
            if vulnerabilities.get(vuln_type) and len(vulnerabilities[vuln_type]) > 0:
                labels.append("high_vulns")
                break
    
    # Basic security issues (only if wapiti is enabled)
    if isinstance(web_vuln, dict) and web_vuln.get("status") == "success" and web_vuln.get("security_issues"):
        if len(web_vuln["security_issues"]) > 0:
            labels.append("security_issues")
    
    # Remove duplicates and add priorities
    unique_labels = list(set(labels))
    labels_with_priority = [
        {"label": label, "priority": RISICO_PRIORITIES.get(label, "info")}
        for label in unique_labels
    ]
    
    # Calculate overall risk level
    prio_counts = {"high": 0, "medium": 0, "low": 0}
    for label_info in labels_with_priority:
        prio_counts[label_info["priority"]] += 1
    
    if prio_counts["high"] > 0:
        risico_niveau = "high"
    elif prio_counts["medium"] >= 5:
        risico_niveau = "high"
    elif prio_counts["medium"] >= 2:
        risico_niveau = "medium"
    elif prio_counts["medium"] > 0 or prio_counts["low"] >= 8:
        risico_niveau = "medium"
    else:
        risico_niveau = "low"
    
    return labels_with_priority, risico_niveau

def create_executive_summary(report: dict) -> dict:
    """Create executive summary for NWG Group"""
    total_domains = 0
    total_subdomains = 0
    risk_summary = {"high": 0, "medium": 0, "low": 0}
    critical_findings = []
    
    for domain, data in report["results"].items():
        total_domains += 1
        risk_level = data.get("risico_niveau", "low")
        risk_summary[risk_level] += 1
        
        # Check for critical findings
        for risk in data.get("risico_labels", []):
            if risk["priority"] == "high":
                critical_findings.append({
                    "domain": domain,
                    "issue": risk["label"],
                    "priority": risk["priority"]
                })
        
        # Count subdomains
        subdomains = data.get("subdomains", {})
        total_subdomains += len(subdomains)
        
        for sub_domain, sub_data in subdomains.items():
            sub_risk_level = sub_data.get("risico_niveau", "low")
            risk_summary[sub_risk_level] += 1
            
            for risk in sub_data.get("risico_labels", []):
                if risk["priority"] == "high":
                    critical_findings.append({
                        "domain": sub_domain,
                        "issue": risk["label"],
                        "priority": risk["priority"]
                    })
    
    return {
        "total_domains_scanned": total_domains,
        "total_subdomains_scanned": total_subdomains,
        "risk_distribution": risk_summary,
        "critical_findings_count": len(critical_findings),
        "critical_findings": critical_findings[:10],  # Top 10 critical findings
        "overall_security_posture": "high" if risk_summary["high"] > 0 else "medium" if risk_summary["medium"] > 0 else "good"
    }

def main(target_domain=None):
    start_time = time.time()
    
    if target_domain is None:
        if len(sys.argv) < 2:
            print("Usage: python domainControl.py <domain>")
            print("Example: python domainControl.py example.com")
            sys.exit(1)
        target_domain = sys.argv[1].strip().replace("www.", "")
    
    print(f"[INFO] Starting EASM scan for NWG Group: {target_domain}")
    domains = [target_domain]

    # Create main directory structure
    domain_safe = target_domain.replace(".", "_")
    # Use domainControl/Results/ directory for output
    main_dir = os.path.join(script_dir, "Results", domain_safe)
    os.makedirs(main_dir, exist_ok=True)
    print(f"[INFO] Created main directory: {main_dir}")

    # DNS check with subdomain discovery
    print("[INFO] Phase 1: DNS analysis and subdomain discovery...")
    dns_results, all_domains = check_dns(domains, return_full_domain_list=True)
    
    # Filter subdomains properly
    filtered_subdomains = {}
    for domain in dns_results:
        subs = filter_subdomains(domain, dns_results[domain].get("subdomains", []))
        filtered_subdomains[domain] = subs
    
    total_subdomains = sum(len(subs) for subs in filtered_subdomains.values())
    print(f"[INFO] Found {len(all_domains)} total domains ({total_subdomains} unique subdomains)")
    
    # 🚀 MEMORY OPTIMIZATION: Cleanup after DNS phase
    gc.collect()

    # SSL certificates
    print("[INFO] Phase 2: SSL certificate analysis...")
    ssl_results = {}
    for i, domain in enumerate(all_domains, 1):
        print(f"[SSL] {i}/{len(all_domains)}")
        try:
            ssl_results[domain] = check_certificates([domain], root_domains=domains)[domain]
        except Exception as e:
            print(f"[WARNING] SSL check failed for {domain}: {e}")
            ssl_results[domain] = {"error": str(e)}
    
    # 🚀 MEMORY OPTIMIZATION: Cleanup after SSL phase
    gc.collect()

    # Headers
    print("[INFO] Phase 3: HTTP security headers analysis...")
    header_results = {}
    valid_domains = []
    
    # Filter out malformed domains before processing
    for domain in all_domains:
        if is_valid_url_domain(domain):
            valid_domains.append(domain)
        else:
            print(f"[WARNING] Skipping malformed domain in headers analysis: {domain}")
            header_results[domain] = {"error": f"Invalid domain format: {domain}"}
    
    print(f"[INFO] Processing headers for {len(valid_domains)}/{len(all_domains)} valid domains")
    
    for i, domain in enumerate(valid_domains, 1):
        print(f"[HEADERS] {i}/{len(valid_domains)} - {domain}")
        try:
            header_results[domain] = scan_headers(domain)
        except Exception as e:
            print(f"[WARNING] Header scan failed for {domain}: {e}")
            header_results[domain] = {"error": str(e)}
    
    # 🚀 MEMORY OPTIMIZATION: Cleanup after headers phase
    gc.collect()

    # Vulnerabilities (parallel scanning)
    print("[INFO] Phase 4: Web vulnerability assessment...")
    if WAPITI_ENABLED:
        # Scan main domain AND subdomains for wapiti
        vuln_results = parallel_wapiti_scan(domains, filtered_subdomains)
        print("[INFO] Consolidating wapiti results...")
    else:
        print("[INFO] Wapiti scanning disabled - skipping vulnerability assessment")
        # Create empty vulnerability results for all domains
        vuln_results = {}
        for domain in all_domains:
            vuln_results[domain] = {
                "status": "disabled",
                "message": "Wapiti scanning disabled in configuration",
                "total_vulns": 0,
                "vulnerabilities": {},
                "security_issues": []
            }
    
    # Clean up individual subdomain wapiti files after consolidation
    print("[INFO] Consolidating wapiti results...")
    
    # 🚀 MEMORY OPTIMIZATION: Cleanup after vulnerability phase
    gc.collect()

    # Technologies
    print("[INFO] Phase 5: Technology stack detection...")
    tech_results = {}
    for i, domain in enumerate(all_domains, 1):
        print(f"[TECH] {i}/{len(all_domains)}")
        tech_results[domain] = detect_technologies_and_cves(domain)

    # OSINT
    print("[INFO] Phase 6: OSINT data collection...")
    osint_results = {}
    for i, domain in enumerate(all_domains, 1):
        print(f"[OSINT] {i}/{len(all_domains)}")
        try:
            ip = None
            if domain in dns_results and dns_results[domain].get("a_record"):
                ip = dns_results[domain]["a_record"][0]
            osint_results[domain] = gather_osint_data(domain, ip)
        except Exception as e:
            print(f"[WARNING] OSINT collection failed for {domain}: {e}")
            osint_results[domain] = {"error": str(e)}
    
    # 🚀 MEMORY OPTIMIZATION: Cleanup after OSINT phase
    gc.collect()

    # Build comprehensive report
    print("[INFO] Phase 7: Generating comprehensive report...")
    report = {
        "metadata": {
            "target_domain": target_domain,
            "scan_type": "EASM_Professional",
            "client": "NWG Group",
            "total_domains_checked": len(all_domains),
            "total_subdomains": total_subdomains,
            "execution_time_seconds": round(time.time() - start_time, 2),
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "directory_structure": {
                "main_directory": main_dir,
                "json_reports": f"{main_dir}/",
                "html_reports": f"{main_dir}/wapiti_html_reports/",
                "main_report": f"{main_dir}/{domain_safe}_complete_report.json"
            }
        },
        "results": {}
    }

    # Process main domain
    for domain in dns_results:
        cert_data = ssl_results.get(domain, {})
        headers = header_results.get(domain, {})
        vulns = vuln_results.get(domain, {})
        techs = tech_results.get(domain, {})
        osint = osint_results.get(domain, {})
        
        labels_with_priority, risico_niveau = analyse_risico(
            domain, cert_data, osint, headers, vulns, techs
        )

        report["results"][domain] = {
            "dns": dns_results[domain],
            "certificate": cert_data,
            "headers": headers,
            "web_vulnerabilities": vulns,
            "technologies": techs,
            "osint": osint,
            "risico_labels": labels_with_priority,
            "risico_niveau": risico_niveau,
            "subdomains": {},
        }

        # Process subdomains (filtered)
        for sub in filtered_subdomains.get(domain, []):
            sub_cert = ssl_results.get(sub, {})
            sub_headers = header_results.get(sub, {})
            sub_vulns = vuln_results.get(sub, {})
            sub_techs = tech_results.get(sub, {})
            sub_osint = osint_results.get(sub, {})
            
            sub_labels, sub_niveau = analyse_risico(
                sub, sub_cert, sub_osint, sub_headers, sub_vulns, sub_techs, domain
            )
            
            report["results"][domain]["subdomains"][sub] = {
                "dns": {
                    "a_record": resolve_record(sub, "A"),
                    "cname_record": resolve_record(sub, "CNAME"),
                },
                "certificate": sub_cert,
                "headers": sub_headers,
                "web_vulnerabilities": sub_vulns,
                "technologies": sub_techs,
                "osint": sub_osint,
                "risico_labels": sub_labels,
                "risico_niveau": sub_niveau,
            }

    # Add executive summary
    report["executive_summary"] = create_executive_summary(report)

    # Save comprehensive report
    output_file = f"{main_dir}/{domain_safe}_complete_report.json"
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str, ensure_ascii=False)

    # Generate executive warnings (Phase 8)
    print("[INFO] Phase 8: Generating executive security warnings...")
    try:
        # Generate ONE warning file per main domain that includes all subdomains
        scan_timestamp = report["metadata"]["scan_timestamp"]
        
        # Collect all warnings for the main domain and its subdomains
        all_domain_warnings = []
        
        for domain, domain_data in report["results"].items():
            domain_data["scan_timestamp"] = scan_timestamp
            
            # Add main domain warnings
            domain_warnings = generate_individual_domain_warnings(domain, domain_data, output_file, main_dir, return_warnings=True)
            if domain_warnings:
                all_domain_warnings.extend(domain_warnings)
            
            # Add subdomain warnings to the same collection
            for subdomain, subdomain_data in domain_data.get("subdomains", {}).items():
                # Skip redirect domains
                if subdomain_data.get("risico_niveau") == "low" and \
                   any(label.get("label") == "redirect_domain" for label in subdomain_data.get("risico_labels", [])):
                    continue
                    
                subdomain_data["scan_timestamp"] = scan_timestamp
                subdomain_warnings = generate_individual_domain_warnings(subdomain, subdomain_data, output_file, main_dir, return_warnings=True)
                if subdomain_warnings:
                    all_domain_warnings.extend(subdomain_warnings)
        
        # Save ONE consolidated warning file for the IT manager
        consolidated_warnings = {
            "metadata": {
                "target_domain": target_domain,
                "scan_timestamp": scan_timestamp,
                "total_warnings": len(all_domain_warnings),
                "client": "NWG Group"
            },
            "warnings": all_domain_warnings
        }
        
        warnings_file = f"{main_dir}/{domain_safe}_warning.json"
        with open(warnings_file, "w", encoding="utf-8") as f:
            json.dump(consolidated_warnings, f, indent=2, default=str, ensure_ascii=False)
        
        print(f"[SUCCESS] Consolidated warning file generated: {warnings_file}")
        
        # Clean up individual warning files (keep only consolidated one)
        print("[INFO] Cleaning up individual warning files...")
        for file in os.listdir(main_dir):
            if file.endswith("_warnings.json") and file != f"{domain_safe}_warning.json":
                warning_file_path = os.path.join(main_dir, file)
                if os.path.exists(warning_file_path):
                    os.remove(warning_file_path)
                    print(f"[CLEANUP] Removed individual warning file: {file}")
        
    except Exception as e:
        print(f"[WARNING] Failed to generate warnings: {e}")

    # Print professional summary
    print("\n" + "="*60)
    print(f"EASM SCAN COMPLETED FOR NWG GROUP")
    print("="*60)
    print(f"Target Domain: {target_domain}")
    print(f"Total Domains Scanned: {len(all_domains)}")
    print(f"Execution Time: {round(time.time() - start_time, 2)} seconds")
    print(f"Report Location: {output_file}")
    
    summary = report["executive_summary"]
    print(f"\nSecurity Posture: {summary['overall_security_posture'].upper()}")
    print(f"High Risk Domains: {summary['risk_distribution']['high']}")
    print(f"Medium Risk Domains: {summary['risk_distribution']['medium']}")
    print(f"Critical Findings: {summary['critical_findings_count']}")
    
    # Print warnings summary if available
    try:
        warnings_file = f"{main_dir}/{domain_safe}_warning.json"
        if os.path.exists(warnings_file):
            print(f"Consolidated Warning: {warnings_file}")
    except:
        pass
    
    print("="*60)
    
    print(f"[SUCCESS] ✅ EASM scan completed for {target_domain}")
    print(f"[INFO] 📊 Total execution time: {round(time.time() - start_time, 2)} seconds")
    print(f"[INFO] 📁 Reports saved to: {main_dir}")
    print(f"[INFO] 📋 Main report: {domain_safe}_complete_report.json")
    
    # 🚀 MEMORY OPTIMIZATION: Final cleanup
    gc.collect()
    
    return report

if __name__ == "__main__":
    main()