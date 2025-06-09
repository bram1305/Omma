#!/usr/bin/env python3
"""
Warning Generator for NWG Group EASM Reports
Generates executive-level warnings.json files for IT managers
"""

import json
import os
import glob
from datetime import datetime
from typing import Dict, List, Any

# Risk level priorities for filtering
CRITICAL_PRIORITIES = ["high", "medium"]
WARNING_DESCRIPTIONS = {
    "expired_cert": "🔴 SSL Certificate has EXPIRED - Immediate action required",
    "cert_soon_expired": "🟡 SSL Certificate expires within 7 days",
    "cert_expires_soon": "🟡 SSL Certificate expires within 30 days", 
    "self_signed": "🔴 Self-signed SSL certificate detected",
    "missing_dmarc": "🟡 Missing DMARC email protection",
    "missing_spf": "🟡 Missing SPF email protection",
    "missing_dkim": "🟡 Missing DKIM email protection",
    "email_leak_found": "🔴 Email addresses found on dark web",
    "weak_ssl": "🟡 Weak SSL configuration detected",
    "no_dnssec": "🟢 DNSSEC not enabled",
    "security_issues": "🟡 Security header issues detected",
    "missing_csp": "🟡 Missing Content Security Policy",
    "missing_xframe": "🟢 Missing X-Frame-Options header",
    "high_vulns": "🔴 High-severity vulnerabilities found",
    "medium_vulns": "🟡 Medium-severity vulnerabilities found",
    "no_hsts": "🟡 Missing HSTS security header",
    "redirect_domain": "ℹ️ Domain redirects to another domain"
}

REMEDIATION_ACTIONS = {
    "expired_cert": "Renew SSL certificate immediately to restore secure connections",
    "cert_soon_expired": "Schedule SSL certificate renewal within next 7 days",
    "cert_expires_soon": "Plan SSL certificate renewal within next 30 days",
    "self_signed": "Replace with proper CA-signed SSL certificate",
    "missing_dmarc": "Configure DMARC policy in DNS TXT records",
    "missing_spf": "Add SPF record to DNS to prevent email spoofing",
    "missing_dkim": "Configure DKIM signing for outbound emails",
    "email_leak_found": "Review compromised accounts and enforce password changes",
    "weak_ssl": "Update SSL/TLS configuration to use stronger ciphers",
    "no_dnssec": "Consider enabling DNSSEC for DNS security",
    "security_issues": "Review and implement missing security headers",
    "missing_csp": "Implement Content Security Policy to prevent XSS attacks",
    "missing_xframe": "Add X-Frame-Options header to prevent clickjacking",
    "high_vulns": "Patch high-severity vulnerabilities immediately",
    "medium_vulns": "Schedule patching of medium-severity vulnerabilities",
    "no_hsts": "Enable HSTS header to enforce HTTPS connections",
    "redirect_domain": "Verify redirect configuration is intentional"
}

def extract_vulnerability_details(vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract specific vulnerability details from Wapiti scan results"""
    vuln_details = []
    
    if vuln_data.get("status") == "success":
        vulnerabilities = vuln_data.get("vulnerabilities", {})
        
        for vuln_type, vuln_list in vulnerabilities.items():
            if isinstance(vuln_list, list) and len(vuln_list) > 0:
                for vuln in vuln_list:
                    if isinstance(vuln, dict):
                        vuln_details.append({
                            "type": vuln_type,
                            "severity": "High" if vuln_type in ["SQL Injection", "Cross Site Scripting", "Command execution"] else "Medium",
                            "path": vuln.get("path", "/"),
                            "method": vuln.get("method", "GET"),
                            "description": vuln.get("info", "No description available"),
                            "parameter": vuln.get("parameter", "")
                        })
    
    return vuln_details

def extract_certificate_details(cert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract certificate-specific details"""
    if not isinstance(cert_data, dict) or cert_data.get("redirects_to"):
        return {}
    
    details = {}
    if cert_data.get("expired"):
        details["expiry_date"] = cert_data.get("valid_to")
        details["days_expired"] = cert_data.get("days_expired", 0)
    elif cert_data.get("days_left", 999) <= 30:
        details["expiry_date"] = cert_data.get("valid_to")
        details["days_left"] = cert_data.get("days_left")
    
    if cert_data.get("self_signed"):
        details["issuer"] = "Self-signed"
    else:
        details["issuer"] = cert_data.get("issuer", "Unknown")
    
    return details

def generate_domain_warnings(domain: str, domain_data: Dict[str, Any], report_path: str) -> Dict[str, Any]:
    """Generate warnings for a single domain"""
    warnings = {
        "domain": domain,
        "risk_level": domain_data.get("risico_niveau", "unknown"),
        "scan_timestamp": domain_data.get("scan_timestamp", "unknown"),
        "critical_issues": [],
        "medium_issues": [],
        "vulnerabilities_found": [],
        "certificate_issues": {},
        "email_security_issues": [],
        "references": {
            "complete_report": report_path,
            "vulnerability_reports": [],
            "html_reports": []
        }
    }
    
    # Extract risk labels
    risk_labels = domain_data.get("risico_labels", [])
    
    for risk in risk_labels:
        label = risk.get("label", "")
        priority = risk.get("priority", "info")
        
        if priority in CRITICAL_PRIORITIES:
            issue = {
                "issue": label,
                "priority": priority,
                "description": WARNING_DESCRIPTIONS.get(label, f"Security issue: {label}"),
                "remediation": REMEDIATION_ACTIONS.get(label, "Review and address this security concern")
            }
            
            # Add specific details based on issue type
            if "cert" in label:
                cert_details = extract_certificate_details(domain_data.get("certificate", {}))
                if cert_details:
                    issue["details"] = cert_details
                    warnings["certificate_issues"] = cert_details
            
            elif label in ["missing_spf", "missing_dmarc", "missing_dkim"]:
                warnings["email_security_issues"].append({
                    "type": label.replace("missing_", "").upper(),
                    "status": "missing",
                    "impact": "Email spoofing vulnerability"
                })
            
            if priority == "high":
                warnings["critical_issues"].append(issue)
            else:
                warnings["medium_issues"].append(issue)
    
    # Extract vulnerability details
    vuln_data = domain_data.get("web_vulnerabilities", {})
    vuln_details = extract_vulnerability_details(vuln_data)
    warnings["vulnerabilities_found"] = vuln_details
    
    # Add report references
    if isinstance(vuln_data, dict):
        if vuln_data.get("json_report"):
            warnings["references"]["vulnerability_reports"].append(vuln_data["json_report"])
        if vuln_data.get("html_report"):
            warnings["references"]["html_reports"].append(vuln_data["html_report"])
    
    return warnings

def generate_individual_domain_warnings(domain: str, domain_data: Dict[str, Any], report_path: str, output_dir: str, return_warnings: bool = False):
    """Generate individual warnings file for a specific domain"""
    warnings = generate_domain_warnings(domain, domain_data, report_path)
    
    # If return_warnings is True, just return the warnings without writing files
    if return_warnings:
        return [warnings]  # Return as list for consistency with consolidated warnings
    
    # Create individual domain warning file
    domain_safe = domain.replace(".", "_")
    warnings_file = os.path.join(output_dir, f"{domain_safe}_warnings.json")
    
    individual_report = {
        "metadata": {
            "report_type": "Domain Security Warnings",
            "client": "NWG Group", 
            "domain": domain,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_timestamp": warnings["scan_timestamp"]
        },
        "warnings": warnings,
        "action_items": {
            "immediate": [issue for issue in warnings["critical_issues"] if "expired" in issue["issue"]],
            "this_week": [issue for issue in warnings["critical_issues"] if "soon" in issue["issue"]],
            "this_month": warnings["medium_issues"][:5]
        }
    }
    
    with open(warnings_file, 'w', encoding='utf-8') as f:
        json.dump(individual_report, f, indent=2, ensure_ascii=False)
    
    print(f"[INFO] Individual warnings generated: {warnings_file}")
    return warnings_file

def generate_warnings_report(results_dir: str = "Results", generate_individual: bool = True) -> Dict[str, Any]:
    """Generate comprehensive warnings report from all domain scans"""
    
    warnings_report = {
        "metadata": {
            "report_type": "Executive Security Warnings",
            "client": "NWG Group",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_domains": 0,
                "high_risk_domains": 0,
                "medium_risk_domains": 0,
                "total_critical_issues": 0,
                "total_vulnerabilities": 0
            }
        },
        "domain_warnings": {},
        "executive_summary": {
            "immediate_action_required": [],
            "schedule_within_week": [],
            "schedule_within_month": [],
            "top_security_concerns": []
        }
    }
    
    # Find all complete report files
    report_pattern = os.path.join(results_dir, "*", "*_complete_report.json")
    report_files = glob.glob(report_pattern)
    
    if not report_files:
        print(f"[WARNING] No complete reports found in {results_dir}")
        return warnings_report
    
    all_critical_issues = []
    all_medium_issues = []
    
    for report_file in report_files:
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            # Get the domain directory for individual warnings
            domain_dir = os.path.dirname(report_file)
            
            # Process main domains
            results = report_data.get("results", {})
            scan_timestamp = report_data.get("metadata", {}).get("scan_timestamp", "unknown")
            
            for domain, domain_data in results.items():
                domain_data["scan_timestamp"] = scan_timestamp
                domain_warnings = generate_domain_warnings(domain, domain_data, report_file)
                warnings_report["domain_warnings"][domain] = domain_warnings
                
                # Generate individual domain warnings if requested
                if generate_individual:
                    generate_individual_domain_warnings(domain, domain_data, report_file, domain_dir)
                
                # Update summary statistics
                warnings_report["metadata"]["summary"]["total_domains"] += 1
                
                risk_level = domain_data.get("risico_niveau", "low")
                if risk_level == "high":
                    warnings_report["metadata"]["summary"]["high_risk_domains"] += 1
                elif risk_level == "medium":
                    warnings_report["metadata"]["summary"]["medium_risk_domains"] += 1
                
                warnings_report["metadata"]["summary"]["total_critical_issues"] += len(domain_warnings["critical_issues"])
                warnings_report["metadata"]["summary"]["total_vulnerabilities"] += len(domain_warnings["vulnerabilities_found"])
                
                # Collect issues for executive summary
                all_critical_issues.extend([(domain, issue) for issue in domain_warnings["critical_issues"]])
                all_medium_issues.extend([(domain, issue) for issue in domain_warnings["medium_issues"]])
                
                # Process subdomains
                subdomains = domain_data.get("subdomains", {})
                for subdomain, subdomain_data in subdomains.items():
                    # Skip redirect domains
                    if subdomain_data.get("risico_niveau") == "low" and \
                       any(label.get("label") == "redirect_domain" for label in subdomain_data.get("risico_labels", [])):
                        continue
                    
                    subdomain_data["scan_timestamp"] = scan_timestamp
                    subdomain_warnings = generate_domain_warnings(subdomain, subdomain_data, report_file)
                    warnings_report["domain_warnings"][subdomain] = subdomain_warnings
                    
                    # Generate individual subdomain warnings if requested
                    if generate_individual:
                        generate_individual_domain_warnings(subdomain, subdomain_data, report_file, domain_dir)
                    
                    # Update statistics for subdomains too
                    sub_risk_level = subdomain_data.get("risico_niveau", "low")
                    if sub_risk_level == "high":
                        warnings_report["metadata"]["summary"]["high_risk_domains"] += 1
                    elif sub_risk_level == "medium":
                        warnings_report["metadata"]["summary"]["medium_risk_domains"] += 1
        
        except Exception as e:
            print(f"[ERROR] Failed to process report {report_file}: {e}")
    
    # Generate executive summary
    immediate_action = [item for item in all_critical_issues if "expired" in item[1]["issue"] or "high_vulns" in item[1]["issue"]]
    week_action = [item for item in all_critical_issues if "soon" in item[1]["issue"]]
    month_action = [item for item in all_medium_issues if "cert" in item[1]["issue"] or "missing" in item[1]["issue"]]
    
    warnings_report["executive_summary"]["immediate_action_required"] = [
        {"domain": domain, "issue": issue["description"]} for domain, issue in immediate_action[:5]
    ]
    warnings_report["executive_summary"]["schedule_within_week"] = [
        {"domain": domain, "issue": issue["description"]} for domain, issue in week_action[:5]
    ]
    warnings_report["executive_summary"]["schedule_within_month"] = [
        {"domain": domain, "issue": issue["description"]} for domain, issue in month_action[:5]
    ]
    
    # Top security concerns
    issue_counts = {}
    for domain, issue in all_critical_issues + all_medium_issues:
        issue_type = issue["issue"]
        issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1
    
    top_concerns = sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    warnings_report["executive_summary"]["top_security_concerns"] = [
        {"concern": WARNING_DESCRIPTIONS.get(concern, concern), "affected_domains": count}
        for concern, count in top_concerns
    ]
    
    return warnings_report

def main():
    """Main function to generate warnings report"""
    print("[INFO] Generating executive warnings report for NWG Group...")
    
    # Change to the correct directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    results_dir = os.path.join(parent_dir, "Results")
    
    if not os.path.exists(results_dir):
        print(f"[ERROR] Results directory not found: {results_dir}")
        return
    
    # Generate warnings report
    warnings_report = generate_warnings_report(results_dir, generate_individual=True)
    
    # Save executive warnings report
    warnings_file = os.path.join(results_dir, "executive_warnings.json")
    
    with open(warnings_file, 'w', encoding='utf-8') as f:
        json.dump(warnings_report, f, indent=2, ensure_ascii=False)
    
    print(f"[SUCCESS] Executive warnings report generated: {warnings_file}")
    
    # Print summary
    summary = warnings_report["metadata"]["summary"]
    print(f"\n{'='*60}")
    print(f"EXECUTIVE SECURITY WARNINGS SUMMARY")
    print(f"{'='*60}")
    print(f"Total Domains Scanned: {summary['total_domains']}")
    print(f"High Risk Domains: {summary['high_risk_domains']}")
    print(f"Medium Risk Domains: {summary['medium_risk_domains']}")
    print(f"Total Critical Issues: {summary['total_critical_issues']}")
    print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
    
    exec_summary = warnings_report["executive_summary"]
    if exec_summary["immediate_action_required"]:
        print(f"\n🔴 IMMEDIATE ACTION REQUIRED:")
        for item in exec_summary["immediate_action_required"]:
            print(f"   • {item['domain']}: {item['issue']}")
    
    if exec_summary["schedule_within_week"]:
        print(f"\n🟡 SCHEDULE WITHIN WEEK:")
        for item in exec_summary["schedule_within_week"]:
            print(f"   • {item['domain']}: {item['issue']}")
    
    print(f"{'='*60}")

if __name__ == "__main__":
    main() 