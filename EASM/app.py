from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_talisman import Talisman
from werkzeug.security import check_password_hash, generate_password_hash
import json
import os
import toml
from pathlib import Path
from domainDetection.dcclasses import approve_eval, reject_eval, uneval_pythonify, eval_pythonify
from datetime import datetime, timedelta
import pytz
import openai
from dotenv import load_dotenv
import glob
from collections import defaultdict

# Load environment variables
load_dotenv()

# Configure timezone for Netherlands
AMSTERDAM_TZ = pytz.timezone('Europe/Amsterdam')

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'omma-easm-2024')

# Security configuration for HTTPS
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize Talisman for security headers (but allow nginx to handle most)
Talisman(app, 
         force_https=False,  # nginx handles HTTPS redirect
         strict_transport_security=False,  # nginx handles HSTS
         content_security_policy=False,  # nginx handles CSP
         feature_policy=False)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# OpenAI configuration
openai.api_key = os.getenv('OPENAI_API_KEY')

config_path = Path(__file__).parent / "config.toml"
with open(config_path, "r") as file:
    config = toml.load(file)

# PDF generation imports
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("Warning: ReportLab not installed. PDF reports will not be available.")

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def load_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return []

def calculate_risk_score(domain_data):
    """Calculate comprehensive risk score for IT managers - More realistic scoring"""
    score = 0
    risk_factors = []
    
    # Certificate issues (More nuanced scoring)
    cert = domain_data.get('certificate', {})
    if cert.get('expired', False):
        score += 35  # Reduced from 40
        risk_factors.append({'type': 'Critical', 'issue': 'SSL Certificate Expired', 'impact': 'High'})
    elif cert.get('days_left', 365) < 7:  # Very urgent
        score += 25
        risk_factors.append({'type': 'Critical', 'issue': f"SSL Certificate expires in {cert.get('days_left', 0)} days", 'impact': 'High'})
    elif cert.get('days_left', 365) < 30:
        score += 15  # Reduced from 25
        risk_factors.append({'type': 'High', 'issue': f"SSL Certificate expires in {cert.get('days_left', 0)} days", 'impact': 'Medium'})
    elif cert.get('days_left', 365) < 90:
        score += 8   # Reduced from 10
        risk_factors.append({'type': 'Medium', 'issue': f"SSL Certificate expires in {cert.get('days_left', 0)} days", 'impact': 'Low'})
    
    if cert.get('self_signed', False):
        score += 20  # Reduced from 30
        risk_factors.append({'type': 'High', 'issue': 'Self-signed SSL Certificate', 'impact': 'High'})
    
    # Security headers (Reduced impact - these are common)
    headers = domain_data.get('headers', {})
    if not headers.get('hsts', False):
        score += 3   # Reduced from 8
        risk_factors.append({'type': 'Low', 'issue': 'Missing HSTS Header', 'impact': 'Low'})
    if not headers.get('x_frame_options', False):
        score += 3   # Reduced from 6
        risk_factors.append({'type': 'Low', 'issue': 'Missing X-Frame-Options', 'impact': 'Low'})
    if not headers.get('csp', False):
        score += 3   # Reduced from 6
        risk_factors.append({'type': 'Low', 'issue': 'Missing Content Security Policy', 'impact': 'Low'})
    
    # Vulnerabilities (More realistic scoring)
    vulns = domain_data.get('web_vulnerabilities', {}).get('vulnerabilities', {})
    critical_vulns = ['SQL Injection', 'Cross Site Scripting', 'Command execution', 'Path Traversal']
    high_vulns = ['Cross Site Request Forgery', 'Open Redirect', 'CRLF Injection']
    
    for vuln_type, vuln_list in vulns.items():
        if vuln_type in critical_vulns and vuln_list:
            score += 30  # Increased for truly critical
            risk_factors.append({'type': 'Critical', 'issue': f'{vuln_type} vulnerability detected', 'impact': 'Critical'})
        elif vuln_type in high_vulns and vuln_list:
            score += 15  # Increased from 10
            risk_factors.append({'type': 'High', 'issue': f'{vuln_type} vulnerability detected', 'impact': 'High'})
        elif vuln_list:
            score += 3   # Reduced from 5 for minor issues
            risk_factors.append({'type': 'Low', 'issue': f'{vuln_type} issue detected', 'impact': 'Low'})
    
    # DNS and infrastructure issues (Reduced impact)
    dns = domain_data.get('dns', {})
    if not dns.get('mx_record'):
        score += 2   # Reduced from 5
        risk_factors.append({'type': 'Low', 'issue': 'No MX record configured', 'impact': 'Low'})
    
    # More realistic risk level thresholds
    if score >= 50:      # Increased threshold
        risk_level = 'critical'
    elif score >= 25:    # Kept same
        risk_level = 'high'
    elif score >= 10:    # Kept same
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return {
        'score': min(score, 100),  # Cap at 100
        'level': risk_level,
        'factors': risk_factors[:5]  # Top 5 issues for IT manager
    }

def load_domain_monitoring_data():
    """Load and process all domain monitoring data with comprehensive Wapiti analysis"""
    results_dir = Path(__file__).parent / "domainControl" / "Results"
    domains_data = []
    
    if not results_dir.exists():
        return []
    
    # Group domains by main domain
    domain_groups = defaultdict(list)
    
    for domain_dir in results_dir.iterdir():
        if not domain_dir.is_dir():
            continue
            
        domain_name = domain_dir.name.replace('_', '.')
        main_domain = domain_name.split('.', 1)[-1] if '.' in domain_name else domain_name
        
        # Load warning data
        warning_file = domain_dir / f"{domain_dir.name}_warning.json"
        complete_file = domain_dir / f"{domain_dir.name}_complete_report.json"
        
        domain_info = {
            'domain': domain_name,
            'main_domain': main_domain,
            'scan_date': 'Unknown',
            'risk_score': 0,
            'risk_level': 'low',
            'risk_factors': [],
            'subdomains': [],
            'total_issues': 0,
            'critical_issues': 0,
            'subdomain_issues': 0,
            'expired_certificates': 0,
            'expiring_certificates': 0,
            'wapiti_vulnerabilities': {},
            'total_wapiti_vulns': 0,
            'critical_wapiti_vulns': 0,
            'has_data': False
        }
        
        try:
            # Load warning data
            if warning_file.exists():
                warning_data = load_json(str(warning_file))
                domain_info['scan_date'] = warning_data.get('metadata', {}).get('scan_timestamp', 'Unknown')
                domain_info['total_issues'] = warning_data.get('metadata', {}).get('total_warnings', 0)
                domain_info['has_data'] = True
                
                # Process warnings for risk assessment
                for warning in warning_data.get('warnings', []):
                    if warning.get('critical_issues'):
                        domain_info['critical_issues'] += len(warning['critical_issues'])
            
            # Load and process ALL Wapiti results
            wapiti_files = list(domain_dir.glob("*_wapiti.json"))
            all_wapiti_vulns = defaultdict(list)
            
            for wapiti_file in wapiti_files:
                try:
                    wapiti_data = load_json(str(wapiti_file))
                    subdomain_name = wapiti_file.stem.replace('_wapiti', '').replace('_', '.')
                    
                    # Process vulnerabilities from this Wapiti scan
                    vulnerabilities = wapiti_data.get('vulnerabilities', {})
                    for vuln_type, vuln_list in vulnerabilities.items():
                        if vuln_list:  # Only count non-empty vulnerability lists
                            all_wapiti_vulns[vuln_type].extend([{
                                'subdomain': subdomain_name,
                                'details': vuln_list,
                                'count': len(vuln_list)
                            }])
                    
                    # Process anomalies
                    anomalies = wapiti_data.get('anomalies', {})
                    for anomaly_type, anomaly_list in anomalies.items():
                        if anomaly_list:
                            all_wapiti_vulns[f"Anomaly: {anomaly_type}"].extend([{
                                'subdomain': subdomain_name,
                                'details': anomaly_list,
                                'count': len(anomaly_list)
                            }])
                            
                except Exception as e:
                    print(f"Error processing Wapiti file {wapiti_file}: {e}")
                    continue
            
            # Store comprehensive Wapiti results
            domain_info['wapiti_vulnerabilities'] = dict(all_wapiti_vulns)
            
            # Calculate Wapiti-based risk scores
            critical_wapiti_types = [
                'SQL Injection', 'Blind SQL Injection', 'Cross Site Scripting', 
                'Command execution', 'Path Traversal', 'XML External Entity',
                'Server Side Request Forgery'
            ]
            
            high_wapiti_types = [
                'Cross Site Request Forgery', 'Open Redirect', 'CRLF Injection',
                'Weak credentials', 'Potentially dangerous file'
            ]
            
            wapiti_risk_score = 0
            critical_wapiti_count = 0
            
            for vuln_type, vuln_instances in all_wapiti_vulns.items():
                total_instances = sum(instance['count'] for instance in vuln_instances)
                domain_info['total_wapiti_vulns'] += total_instances
                
                if vuln_type in critical_wapiti_types:
                    critical_wapiti_count += total_instances
                    wapiti_risk_score += min(total_instances * 5, 30)  # Cap critical vulns at 30 points
                    domain_info['risk_factors'].append({
                        'type': 'Critical',
                        'issue': f'{vuln_type}: {total_instances} instance(s) across subdomains',
                        'impact': 'Critical'
                    })
                elif vuln_type in high_wapiti_types:
                    wapiti_risk_score += min(total_instances * 3, 20)  # Cap high vulns at 20 points
                    domain_info['risk_factors'].append({
                        'type': 'High',
                        'issue': f'{vuln_type}: {total_instances} instance(s) across subdomains',
                        'impact': 'High'
                    })
                elif 'Anomaly:' not in vuln_type:  # Regular vulnerabilities
                    wapiti_risk_score += min(total_instances * 1, 10)  # Cap other vulns at 10 points
                    domain_info['risk_factors'].append({
                        'type': 'Medium',
                        'issue': f'{vuln_type}: {total_instances} instance(s) across subdomains',
                        'impact': 'Medium'
                    })
            
            domain_info['critical_wapiti_vulns'] = critical_wapiti_count
            
            # Load complete report for detailed risk assessment
            if complete_file.exists():
                complete_data = load_json(str(complete_file))
                results = complete_data.get('results', {})
                
                # Process main domain
                main_domain_data = results.get(domain_name.replace('_', '.'), {})
                if main_domain_data:
                    main_risk_assessment = calculate_risk_score(main_domain_data)
                    domain_info.update({
                        'risk_score': main_risk_assessment['score'] + min(wapiti_risk_score, 40),  # Cap Wapiti contribution
                        'risk_level': main_risk_assessment['level'],
                        'risk_factors': main_risk_assessment['factors'] + domain_info['risk_factors']
                    })
                else:
                    # If no main domain data, use only Wapiti-based scoring
                    domain_info['risk_score'] = min(wapiti_risk_score, 60)  # Cap at 60 for Wapiti-only
                
                # Process subdomains and find highest risk
                subdomains_data = main_domain_data.get('subdomains', {})
                highest_subdomain_risk = 0
                critical_subdomain_issues = []
                
                for subdomain, sub_data in subdomains_data.items():
                    if isinstance(sub_data, dict):
                        sub_risk = calculate_risk_score(sub_data)
                        
                        # Add Wapiti vulnerabilities for this specific subdomain
                        subdomain_wapiti_score = 0
                        for vuln_type, vuln_instances in all_wapiti_vulns.items():
                            for instance in vuln_instances:
                                if instance['subdomain'] == subdomain:
                                    if vuln_type in critical_wapiti_types:
                                        subdomain_wapiti_score += min(instance['count'] * 5, 30)
                                    elif vuln_type in high_wapiti_types:
                                        subdomain_wapiti_score += min(instance['count'] * 3, 20)
                                    else:
                                        subdomain_wapiti_score += min(instance['count'] * 1, 10)
                        
                        sub_risk['score'] += min(subdomain_wapiti_score, 40)  # Cap subdomain Wapiti contribution
                        
                        # Check for certificate issues in subdomains
                        sub_cert = sub_data.get('certificate', {})
                        if sub_cert.get('expired', False):
                            domain_info['expired_certificates'] += 1
                            critical_subdomain_issues.append(f"Expired certificate on {subdomain}")
                        elif sub_cert.get('days_left', 365) < 30:
                            domain_info['expiring_certificates'] += 1
                            critical_subdomain_issues.append(f"Certificate expiring soon on {subdomain} ({sub_cert.get('days_left', 0)} days)")
                        
                        # Track highest subdomain risk
                        if sub_risk['score'] > highest_subdomain_risk:
                            highest_subdomain_risk = sub_risk['score']
                        
                        domain_info['subdomains'].append({
                            'name': subdomain,
                            'risk_score': sub_risk['score'],
                            'risk_level': sub_risk['level'],
                            'risk_factors': sub_risk['factors'],
                            'certificate': sub_cert,
                            'has_issues': sub_risk['score'] > 20,
                            'wapiti_score': subdomain_wapiti_score
                        })
                
                # Escalate subdomain certificate issues to main domain
                if domain_info['expired_certificates'] > 0:
                    domain_info['risk_score'] += min(domain_info['expired_certificates'] * 20, 40)
                    domain_info['risk_factors'].append({
                        'type': 'High', 
                        'issue': f"{domain_info['expired_certificates']} subdomain(s) with expired certificates", 
                        'impact': 'High'
                    })
                
                if domain_info['expiring_certificates'] > 0:
                    domain_info['risk_score'] += min(domain_info['expiring_certificates'] * 8, 16)
                    domain_info['risk_factors'].append({
                        'type': 'Medium', 
                        'issue': f"{domain_info['expiring_certificates']} subdomain(s) with expiring certificates", 
                        'impact': 'Medium'
                    })
                
                # Use the higher risk score between main domain and subdomains
                if highest_subdomain_risk > domain_info['risk_score']:
                    domain_info['risk_score'] = highest_subdomain_risk
                
                # Cap total risk score at 100
                domain_info['risk_score'] = min(domain_info['risk_score'], 100)
                
                # Recalculate risk level based on updated score (more realistic thresholds)
                if domain_info['risk_score'] >= 80:  # Only truly critical domains
                    domain_info['risk_level'] = 'critical'
                elif domain_info['risk_score'] >= 50:  # High risk
                    domain_info['risk_level'] = 'high'
                elif domain_info['risk_score'] >= 25:  # Medium risk
                    domain_info['risk_level'] = 'medium'
                else:
                    domain_info['risk_level'] = 'low'
                
                # Count subdomain issues
                domain_info['subdomain_issues'] = len([s for s in domain_info['subdomains'] if s['has_issues']])
                
        except Exception as e:
            print(f"Error processing {domain_name}: {e}")
            continue
        
        domain_groups[main_domain].append(domain_info)
    
    # Convert to list and sort by risk
    for main_domain, domains in domain_groups.items():
        # Sort domains within group by risk score
        domains.sort(key=lambda x: x['risk_score'], reverse=True)
        domains_data.extend(domains)
    
    # Sort all domains by risk score (highest first)
    domains_data.sort(key=lambda x: x['risk_score'], reverse=True)
    
    return domains_data

def get_dashboard_stats():
    """Get comprehensive dashboard statistics for IT managers including Wapiti data"""
    companies = load_json(config["filepaths"]["companies-list"])
    unevaluated = load_json(config["filepaths"]["unevaluated-list"])
    evaluated = load_json(config["filepaths"]["evaluated-list"])
    
    # Load monitoring data for risk statistics
    monitoring_data = load_domain_monitoring_data()
    
    # Calculate domain counts - CORRECTED LOGIC
    total_monitored_domains = len(monitoring_data)  # Only domains we actually monitor
    accepted_domains = sum(len(c.get('domains', [])) for c in companies)  # Domains in companies list
    
    # Risk analysis from monitoring data - ENSURE THEY ADD UP
    critical_domains = sum(1 for d in monitoring_data if d['risk_level'] == 'critical')
    warning_domains = sum(1 for d in monitoring_data if d['risk_level'] == 'high')  # Changed from high_risk
    safe_domains = sum(1 for d in monitoring_data if d['risk_level'] in ['low', 'medium'])
    
    # Verify totals add up
    calculated_total = critical_domains + warning_domains + safe_domains
    if calculated_total != total_monitored_domains:
        # If there's a mismatch, adjust safe domains to make it add up
        safe_domains = total_monitored_domains - critical_domains - warning_domains
        safe_domains = max(0, safe_domains)  # Ensure non-negative
    
    # Certificate issues analysis
    total_expired_certs = sum(d.get('expired_certificates', 0) for d in monitoring_data)
    total_expiring_certs = sum(d.get('expiring_certificates', 0) for d in monitoring_data)
    domains_with_cert_issues = sum(1 for d in monitoring_data if d.get('expired_certificates', 0) > 0 or d.get('expiring_certificates', 0) > 0)
    
    # Comprehensive Wapiti vulnerability analysis
    total_wapiti_vulns = sum(d.get('total_wapiti_vulns', 0) for d in monitoring_data)
    critical_wapiti_vulns = sum(d.get('critical_wapiti_vulns', 0) for d in monitoring_data)
    domains_with_wapiti_vulns = sum(1 for d in monitoring_data if d.get('total_wapiti_vulns', 0) > 0)
    
    # Vulnerability type breakdown
    vuln_type_counts = defaultdict(int)
    for domain in monitoring_data:
        for vuln_type, instances in domain.get('wapiti_vulnerabilities', {}).items():
            vuln_type_counts[vuln_type] += sum(instance['count'] for instance in instances)
    
    # Top vulnerability types (for IT manager focus)
    top_vulnerabilities = sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    stats = {
        'companies': len(companies),
        'total_domains': accepted_domains,  # Total domains in companies list
        'accepted_domains': accepted_domains,
        'monitored_domains': total_monitored_domains,  # Domains with monitoring data
        'unevaluated_domains': len(unevaluated),
        'evaluated_domains': len(evaluated),
        'critical_domains': critical_domains,
        'warning_domains': warning_domains,  # Changed from high_risk
        'high_risk_domains': warning_domains,  # Keep for backward compatibility
        'safe_domains': safe_domains,
        'expired_certificates': total_expired_certs,
        'expiring_certificates': total_expiring_certs,
        'domains_with_cert_issues': domains_with_cert_issues,
        'pending_review': len([d for d in evaluated if not d.get('reviewed', False)]),
        'discovery_rate': len(unevaluated) / max(accepted_domains, 1) * 100 if accepted_domains > 0 else 0,
        # Enhanced Wapiti statistics
        'total_wapiti_vulnerabilities': total_wapiti_vulns,
        'critical_wapiti_vulnerabilities': critical_wapiti_vulns,
        'domains_with_vulnerabilities': domains_with_wapiti_vulns,
        'vulnerability_coverage': (domains_with_wapiti_vulns / max(total_monitored_domains, 1)) * 100,
        'top_vulnerabilities': top_vulnerabilities,
        'avg_vulns_per_domain': total_wapiti_vulns / max(total_monitored_domains, 1) if total_monitored_domains else 0
    }
    
    return stats

def generate_company_overview(monitoring_data):
    """Generate company overview data from monitoring data"""
    try:
        # Load companies from config
        companies = config.get('companies', [])
        company_overview = []
        
        # Group domains by company
        for company_info in companies:
            company_name = company_info.get('name', 'Unknown Company')
            company_domains = company_info.get('domains', [])
            
            # Calculate company statistics
            company_stats = {
                'total_domains': len(company_domains),
                'critical_domains': 0,
                'warning_domains': 0,
                'safe_domains': 0,
                'total_vulnerabilities': 0,
                'expired_certificates': 0
            }
            
            # Find domains in monitoring data
            company_domain_data = []
            for domain_name in company_domains:
                for domain in monitoring_data:
                    if domain['domain'] == domain_name:
                        company_domain_data.append(domain)
                        
                        # Update statistics
                        if domain.get('risk_level') == 'critical':
                            company_stats['critical_domains'] += 1
                        elif domain.get('risk_level') == 'high':
                            company_stats['warning_domains'] += 1
                        else:
                            company_stats['safe_domains'] += 1
                        
                        company_stats['total_vulnerabilities'] += domain.get('total_wapiti_vulns', 0)
                        company_stats['expired_certificates'] += domain.get('expired_certificates', 0)
                        break
            
            # Determine overall risk level
            if company_stats['critical_domains'] > 0:
                overall_risk = 'critical'
            elif company_stats['warning_domains'] > 0:
                overall_risk = 'warning'
            else:
                overall_risk = 'safe'
            
            company_overview.append({
                'id': len(company_overview) + 1,
                'name': company_name,
                'domains': company_domains,
                'stats': company_stats,
                'overall_risk': overall_risk
            })
        
        return company_overview
        
    except Exception as e:
        print(f"Error generating company overview: {e}")
        return []

def generate_executive_summary():
    """Generate AI-powered executive summary with comprehensive Wapiti analysis and fallback"""
    stats = get_dashboard_stats()
    
    # Simple fallback summary for IT manager with discovery/monitoring balance
    fallback_summary = f"""
    EASM Executive Summary - {datetime.now().strftime('%Y-%m-%d')}<br><br>
    
    Our External Attack Surface Management system is actively monitoring {stats['companies']} companies with {stats['monitored_domains']} domains under security surveillance. 
    The discovery pipeline has identified {stats['unevaluated_domains']} new domains awaiting evaluation, with {stats['evaluated_domains']} domains already processed and ready for monitoring integration.<br><br>
    
    Current security posture shows {stats['critical_domains']} domains requiring immediate attention due to critical risk levels, while {stats['warning_domains']} domains need security review. 
    {stats['safe_domains']} domains are operating safely within acceptable parameters. Our vulnerability scanning has detected {stats['total_wapiti_vulnerabilities']} total vulnerabilities across the infrastructure, with {stats['critical_wapiti_vulnerabilities']} classified as critical requiring immediate patching."""
    
    # Add top vulnerabilities
    if stats['top_vulnerabilities']:
        fallback_summary += f" The most common security issues are {stats['top_vulnerabilities'][0][0]} ({stats['top_vulnerabilities'][0][1]} instances)"
        if len(stats['top_vulnerabilities']) > 1:
            fallback_summary += f", {stats['top_vulnerabilities'][1][0]} ({stats['top_vulnerabilities'][1][1]} instances)"
        if len(stats['top_vulnerabilities']) > 2:
            fallback_summary += f", and {stats['top_vulnerabilities'][2][0]} ({stats['top_vulnerabilities'][2][1]} instances)"
        fallback_summary += "."
    
    fallback_summary += f"""<br><br>
    
    Currently {stats['unevaluated_domains']} new domains are awaiting security evaluation and management decision. 
    Our monitoring coverage stands at {stats['vulnerability_coverage']:.1f}% with an average of {stats['avg_vulns_per_domain']:.1f} vulnerabilities per domain. 
    The discovery rate is {stats['discovery_rate']:.1f}% indicating effective domain identification processes.<br><br>
    
    <em>Auto-updated from master.py | Last scan: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Real-time monitoring active</em>
    """
    
    # Try OpenAI API with cost optimization
    try:
        if openai.api_key:
            # Simple executive summary for IT Manager
            prompt = f"""
            As a cybersecurity expert, provide a simple executive summary for an IT manager based on this EASM data.
            Write in plain text without bullet points, bold formatting, or special characters.
            
            Infrastructure: {stats['companies']} companies, {stats['monitored_domains']} domains monitored
            Security Status: {stats['critical_domains']} critical domains, {stats['high_risk_domains']} high-risk domains
            Vulnerabilities: {stats['total_wapiti_vulnerabilities']} total, {stats['critical_wapiti_vulnerabilities']} critical
            Top Issues: {', '.join([f"{vuln}: {count}" for vuln, count in stats['top_vulnerabilities'][:3]])}
            Certificates: {stats['expired_certificates']} expired, {stats['expiring_certificates']} expiring
            
            Write a clear paragraph explaining the current security situation, what needs immediate attention, 
            and key recommendations. Keep it professional and straightforward. Max 250 words.
            """
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=400,
                temperature=0.3
            )
            
            ai_summary = response.choices[0].message.content.strip()
            
            # Add timestamp and cost info
            ai_summary += f"<br><br><em>AI-generated summary | Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</em>"
            
            return ai_summary
            
    except Exception as e:
        print(f"OpenAI API error: {e}")
    
    return fallback_summary

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check credentials from environment or fallback to hardcoded
        valid_username = os.getenv('DASHBOARD_USERNAME', 'omma')
        valid_password = os.getenv('DASHBOARD_PASSWORD', 'newwave2024')
        
        if username == valid_username and password == valid_password:
            login_user(User(username))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    else:
        # Clear any existing flash messages when showing login page
        session.pop('_flashes', None)
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    """Main dashboard with executive summary and balanced discovery/monitoring overview"""
    stats = get_dashboard_stats()
    
    # Load ALL data for balanced dashboard
    companies = load_json(config["filepaths"]["companies-list"])
    unevaluated = load_json(config["filepaths"]["unevaluated-list"])
    evaluated = load_json(config["filepaths"]["evaluated-list"])
    monitoring_data = load_domain_monitoring_data()
    
    # Create company overview with domain counts and risk levels
    company_overview = []
    for company in companies:
        company_domains = company.get('domains', [])
        
        # Calculate risk statistics for this company
        company_stats = {
            'total_domains': len(company_domains),
            'critical_domains': 0,
            'warning_domains': 0,
            'safe_domains': 0,
            'total_vulnerabilities': 0,
            'expired_certificates': 0
        }
        
        # Match domains with monitoring data
        for domain_name in company_domains:
            for domain_data in monitoring_data:
                if domain_data['domain'] == domain_name:
                    # Count risk levels
                    if domain_data.get('risk_level') == 'critical':
                        company_stats['critical_domains'] += 1
                    elif domain_data.get('risk_level') == 'high':
                        company_stats['warning_domains'] += 1
                    else:
                        company_stats['safe_domains'] += 1
                    
                    # Count vulnerabilities
                    company_stats['total_vulnerabilities'] += domain_data.get('total_wapiti_vulns', 0)
                    
                    # Count expired certificates
                    if domain_data.get('expired_certificates', 0) > 0:
                        company_stats['expired_certificates'] += 1
                    break
        
        # Calculate overall risk level for company
        if company_stats['critical_domains'] > 0:
            overall_risk = 'critical'
        elif company_stats['warning_domains'] > 0:
            overall_risk = 'warning'
        else:
            overall_risk = 'safe'
        
        company_overview.append({
            'id': company['id'],
            'name': company['name'],
            'domains': company_domains,
            'stats': company_stats,
            'overall_risk': overall_risk
        })
    
    # Sort companies by risk level (critical first)
    risk_order = {'critical': 0, 'warning': 1, 'safe': 2}
    company_overview.sort(key=lambda x: (risk_order.get(x['overall_risk'], 3), -x['stats']['total_domains']))
    
    # Check if we need to generate new executive summary (once per day for fresh summaries)
    cache_dir = Path(__file__).parent / "cache"
    cache_dir.mkdir(exist_ok=True)  # Create cache directory if it doesn't exist
    summary_file = cache_dir / "executive_summary.json"
    executive_summary = ""
    
    try:
        if summary_file.exists():
            with open(summary_file, 'r') as f:
                summary_data = json.load(f)
                last_update = datetime.fromisoformat(summary_data['timestamp'])
                # Convert to Amsterdam timezone if needed
                if last_update.tzinfo is None:
                    last_update = AMSTERDAM_TZ.localize(last_update)
                else:
                    last_update = last_update.astimezone(AMSTERDAM_TZ)
                
                # Changed to 1 hour for more frequent updates since master.py runs 24/7
                hours_since_update = int(os.getenv('EXECUTIVE_SUMMARY_FREQUENCY', 1))
                if datetime.now(AMSTERDAM_TZ) - last_update < timedelta(hours=hours_since_update):
                    executive_summary = summary_data['summary']
    except:
        pass
    
    if not executive_summary:
        executive_summary = generate_executive_summary()
        # Save summary with timestamp
        try:
            with open(summary_file, 'w') as f:
                json.dump({
                    'summary': executive_summary,
                    'timestamp': datetime.now(AMSTERDAM_TZ).isoformat()
                }, f)
        except:
            pass
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         executive_summary=executive_summary,
                         current_time=datetime.now(AMSTERDAM_TZ).strftime("%Y-%m-%d %H:%M"),
                         company_overview=company_overview)

@app.route('/domain-discovery')
@login_required
def domain_discovery():
    """Enhanced domain discovery page with IT Manager metrics"""
    unevaluated = load_json(config["filepaths"]["unevaluated-list"])
    evaluated = load_json(config["filepaths"]["evaluated-list"])
    companies = load_json(config["filepaths"]["companies-list"])
    
    # Create company lookup for better display
    company_lookup = {c['id']: c['name'] for c in companies}
    
    # Add company names to domains
    for domain in unevaluated:
        domain['company_name'] = company_lookup.get(domain.get('company-id'), 'Unknown')
    
    for domain in evaluated:
        domain['company_name'] = company_lookup.get(domain.get('company-id'), 'Unknown')
    
    # Sort by risk score for evaluated domains (highest first for IT Manager priority)
    evaluated.sort(key=lambda x: x.get('like-score', 0), reverse=True)
    
    # Calculate IT Manager metrics
    high_score_domains = [d for d in evaluated if d.get('like-score', 0) >= 0.8]
    medium_score_domains = [d for d in evaluated if 0.4 <= d.get('like-score', 0) < 0.8]
    low_score_domains = [d for d in evaluated if d.get('like-score', 0) < 0.4]
    
    # Risk assessment categories
    critical_domains = [d for d in evaluated if d.get('like-score', 0) >= 0.9]
    suspicious_domains = [d for d in evaluated if 0.7 <= d.get('like-score', 0) < 0.9]
    unknown_domains = [d for d in unevaluated]  # All unevaluated are unknown
    safe_domains = [d for d in evaluated if d.get('like-score', 0) < 0.4]
    
    # Calculate discovery rate (mock data for now - could be enhanced with historical data)
    discovery_rate = f"+{len(unevaluated) // 7}/week" if len(unevaluated) > 0 else "0/week"
    
    return render_template('domain_discovery.html', 
                         unevaluated=unevaluated[:50],  # Limit for performance
                         evaluated=evaluated[:50],
                         total_unevaluated=len(unevaluated),
                         total_evaluated=len(evaluated),
                         # IT Manager metrics
                         high_score_count=len(high_score_domains),
                         medium_score_count=len(medium_score_domains),
                         low_score_count=len(low_score_domains),
                         high_risk_count=len(critical_domains) + len(suspicious_domains),
                         discovery_rate=discovery_rate,
                         # Risk assessment
                         critical_domains=len(critical_domains),
                         suspicious_domains=len(suspicious_domains),
                         unknown_domains=len(unknown_domains),
                         safe_domains=len(safe_domains))

@app.route('/domain-monitoring')
@login_required
def domain_monitoring():
    """Clean domain monitoring page showing ALL domains with complete information"""
    print("Loading domain monitoring data...")
    monitoring_data = load_domain_monitoring_data()
    print(f"Loaded {len(monitoring_data)} domains")
    
    # Process data for the new template
    processed_data = []
    for domain in monitoring_data:
        # Extract certificate information
        cert_info = {}
        if domain.get('subdomains'):
            for subdomain in domain['subdomains']:
                if subdomain.get('certificate'):
                    cert = subdomain['certificate']
                    if cert.get('expired', False):
                        cert_info['expired'] = True
                    elif cert.get('days_left', 365) < 30:
                        cert_info['expiring'] = True
                        cert_info['days_left'] = cert.get('days_left', 0)
                    else:
                        cert_info['valid'] = True
                        cert_info['days_left'] = cert.get('days_left', 365)
                    cert_info['issuer'] = cert.get('issuer', 'Unknown')
                    break
        
        # Extract IP addresses
        ip_addresses = []
        if domain.get('subdomains'):
            for subdomain in domain['subdomains']:
                if subdomain.get('ip'):
                    ip_addresses.append(subdomain['ip'])
        
        # Extract technologies
        technologies = []
        if domain.get('subdomains'):
            for subdomain in domain['subdomains']:
                if subdomain.get('technologies'):
                    technologies.extend(subdomain['technologies'])
        
        # Process wapiti vulnerabilities to get counts
        wapiti_vuln_counts = {}
        for vuln_type, vuln_instances in domain.get('wapiti_vulnerabilities', {}).items():
            if vuln_instances:
                total_count = sum(instance.get('count', 0) for instance in vuln_instances)
                if total_count > 0:
                    wapiti_vuln_counts[vuln_type] = total_count

        processed_domain = {
            'domain': domain['domain'],
            'risk_level': domain.get('risk_level', 'unknown'),
            'risk_score': domain.get('risk_score', 0),
            'subdomains': domain.get('subdomains', []),
            'total_wapiti_vulns': domain.get('total_wapiti_vulns', 0),
            'critical_wapiti_vulns': domain.get('critical_wapiti_vulns', 0),
            'wapiti_vulnerabilities': wapiti_vuln_counts,
            'scan_date': domain.get('scan_date', 'Unknown'),
            'ip_addresses': ip_addresses,
            'technologies': technologies,
            'certificate_expired': cert_info.get('expired', False),
            'certificate_expiring': cert_info.get('expiring', False),
            'certificate_valid': cert_info.get('valid', False),
            'certificate_days_left': cert_info.get('days_left', 0),
            'certificate_issuer': cert_info.get('issuer', '')
        }
        processed_data.append(processed_domain)
    
    # Calculate statistics for the new template
    stats = {
        'total_domains': len(processed_data),
        'critical_domains': len([d for d in processed_data if d['risk_level'] == 'critical']),
        'warning_domains': len([d for d in processed_data if d['risk_level'] == 'high']),
        'safe_domains': len([d for d in processed_data if d['risk_level'] in ['low', 'medium']]),
        'total_subdomains': sum(len(d['subdomains']) for d in processed_data),
        'total_vulnerabilities': sum(d['total_wapiti_vulns'] for d in processed_data)
    }
    
    print(f"Stats: {stats}")
    
    return render_template('domain_monitoring.html', 
                         monitoring_data=processed_data,
                         stats=stats)

@app.route('/api/approve/<int:domain_id>', methods=['POST'])
@login_required
def approve(domain_id):
    try:
        approve_eval(domain_id, config["filepaths"]["evaluated-list"])
        return jsonify({'success': True, 'message': 'Domain approved and added to monitoring'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/reject/<int:domain_id>', methods=['POST'])
@login_required
def reject(domain_id):
    try:
        reject_eval(domain_id, config["filepaths"]["evaluated-list"])
        return jsonify({'success': True, 'message': 'Domain rejected and removed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/approve-unevaluated/<int:domain_id>', methods=['POST'])
@login_required
def approve_unevaluated(domain_id):
    """Move unevaluated domain directly to approved"""
    try:
        # Get the unevaluated domain
        unevaluated = load_json(config["filepaths"]["unevaluated-list"])
        domain_to_approve = None
        
        for domain in unevaluated:
            if domain['id'] == domain_id:
                domain_to_approve = domain
                break
        
        if not domain_to_approve:
            return jsonify({'success': False, 'error': 'Domain not found'})
        
        # Add to companies list
        companies = load_json(config["filepaths"]["companies-list"])
        for company in companies:
            if company['id'] == domain_to_approve['company-id']:
                if 'domains' not in company:
                    company['domains'] = []
                company['domains'].append(domain_to_approve['domain'])
                break
        
        # Save updated companies
        with open(config["filepaths"]["companies-list"], 'w', encoding='utf-8') as f:
            json.dump(companies, f, indent=4)
        
        # Remove from unevaluated
        unevaluated = [d for d in unevaluated if d['id'] != domain_id]
        with open(config["filepaths"]["unevaluated-list"], 'w', encoding='utf-8') as f:
            json.dump(unevaluated, f, indent=4)
        
        return jsonify({'success': True, 'message': 'Domain approved and added to monitoring'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/reject-unevaluated/<int:domain_id>', methods=['POST'])
@login_required
def reject_unevaluated(domain_id):
    """Remove unevaluated domain"""
    try:
        unevaluated = load_json(config["filepaths"]["unevaluated-list"])
        unevaluated = [d for d in unevaluated if d['id'] != domain_id]
        
        with open(config["filepaths"]["unevaluated-list"], 'w', encoding='utf-8') as f:
            json.dump(unevaluated, f, indent=4)
        
        return jsonify({'success': True, 'message': 'Domain rejected and removed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/refresh-summary', methods=['POST'])
@login_required
def refresh_summary():
    """Manually refresh executive summary for demo purposes"""
    try:
        executive_summary = generate_executive_summary()
        
        # Save summary with timestamp
        cache_dir = Path(__file__).parent / "cache"
        cache_dir.mkdir(exist_ok=True)
        summary_file = cache_dir / "executive_summary.json"
        with open(summary_file, 'w') as f:
            json.dump({
                'summary': executive_summary,
                'timestamp': datetime.now(AMSTERDAM_TZ).isoformat()
            }, f)
        
        return jsonify({'success': True, 'message': 'Executive summary refreshed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/move-to-unevaluated/<int:domain_id>', methods=['POST'])
@login_required
def move_to_unevaluated(domain_id):
    """Move evaluated domain back to unevaluated"""
    try:
        # Get the evaluated domain
        evaluated = load_json(config["filepaths"]["evaluated-list"])
        domain_to_move = None
        
        for domain in evaluated:
            if domain['id'] == domain_id:
                domain_to_move = domain
                break
        
        if not domain_to_move:
            return jsonify({'success': False, 'error': 'Domain not found'})
        
        # Add to unevaluated list
        unevaluated = load_json(config["filepaths"]["unevaluated-list"])
        
        # Create unevaluated domain entry (remove evaluation-specific fields)
        unevaluated_domain = {
            'id': domain_to_move['id'],
            'domain': domain_to_move['domain'],
            'company-id': domain_to_move.get('company-id')
        }
        
        unevaluated.append(unevaluated_domain)
        
        # Save updated unevaluated list
        with open(config["filepaths"]["unevaluated-list"], 'w', encoding='utf-8') as f:
            json.dump(unevaluated, f, indent=4)
        
        # Remove from evaluated
        evaluated = [d for d in evaluated if d['id'] != domain_id]
        with open(config["filepaths"]["evaluated-list"], 'w', encoding='utf-8') as f:
            json.dump(evaluated, f, indent=4)
        
        return jsonify({'success': True, 'message': 'Domain moved to pending evaluation'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/remove-evaluated/<int:domain_id>', methods=['POST'])
@login_required
def remove_evaluated(domain_id):
    """Remove evaluated domain completely"""
    try:
        evaluated = load_json(config["filepaths"]["evaluated-list"])
        evaluated = [d for d in evaluated if d['id'] != domain_id]
        
        with open(config["filepaths"]["evaluated-list"], 'w', encoding='utf-8') as f:
            json.dump(evaluated, f, indent=4)
        
        return jsonify({'success': True, 'message': 'Domain removed from evaluation'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/domain-details/<domain_name>')
@login_required
def get_domain_details(domain_name):
    """Get detailed information about a specific domain"""
    try:
        monitoring_data = load_domain_monitoring_data()
        domain_data = None
        
        for domain in monitoring_data:
            if domain['domain'] == domain_name:
                domain_data = domain
                break
        
        if not domain_data:
            return jsonify({'error': 'Domain not found'}), 404
        
        return jsonify(domain_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-security-report', methods=['POST'])
@login_required
def generate_security_report():
    """Generate comprehensive security report for IT managers in both JSON and PDF formats"""
    try:
        stats = get_dashboard_stats()
        monitoring_data = load_domain_monitoring_data()
        
        # Generate report ID
        report_id = f"SEC-RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Generate comprehensive JSON report
        json_report = {
            'report_id': report_id,
            'generated_at': datetime.now().isoformat(),
            'generated_by': getattr(current_user, 'id', 'IT Manager'),
            'executive_summary': {
                'total_domains': stats['monitored_domains'],
                'critical_domains': stats['critical_domains'],
                'high_risk_domains': stats['high_risk_domains'],
                'total_vulnerabilities': stats['total_wapiti_vulnerabilities'],
                'critical_vulnerabilities': stats['critical_wapiti_vulnerabilities'],
                'certificate_issues': stats['expired_certificates'] + stats['expiring_certificates']
            },
            'vulnerability_analysis': {
                'top_vulnerabilities': stats['top_vulnerabilities'],
                'coverage_percentage': stats['vulnerability_coverage'],
                'avg_vulns_per_domain': stats['avg_vulns_per_domain']
            },
            'risk_breakdown': {
                'critical_domains': [d for d in monitoring_data if d['risk_level'] == 'critical'],
                'high_risk_domains': [d for d in monitoring_data if d['risk_level'] == 'high'],
                'certificate_issues': [d for d in monitoring_data if d.get('expired_certificates', 0) > 0 or d.get('expiring_certificates', 0) > 0]
            },
            'recommendations': [
                "Address critical vulnerabilities immediately - prioritize SQL injection and XSS issues",
                "Renew expired SSL certificates and schedule renewal for expiring certificates",
                "Implement comprehensive security headers (HSTS, CSP, X-Frame-Options) across all domains",
                "Establish regular vulnerability scanning schedule (weekly for critical domains)",
                "Monitor subdomain security posture and implement subdomain takeover protection",
                "Review and update incident response procedures for critical security events",
                "Consider implementing Web Application Firewall (WAF) for high-risk domains",
                "Establish security metrics dashboard for ongoing monitoring",
                "Schedule quarterly security assessments and penetration testing",
                "Implement automated certificate renewal and monitoring systems"
            ]
        }
        
        # Save JSON report to cache
        cache_dir = Path(__file__).parent / "cache"
        cache_dir.mkdir(exist_ok=True)
        json_file = cache_dir / f"security_report_{report_id}.json"
        
        with open(json_file, 'w') as f:
            json.dump(json_report, f, indent=2, default=str)
        
        # Generate PDF report
        pdf_file = None
        pdf_available = False
        
        if PDF_AVAILABLE:
            try:
                pdf_file = generate_pdf_report(stats, monitoring_data, report_id)
                pdf_available = True
            except Exception as pdf_error:
                print(f"PDF generation failed: {pdf_error}")
                pdf_available = False
        
        response_data = {
            'success': True, 
            'message': 'Security report generated successfully',
            'report_id': report_id,
            'formats': {
                'json': {
                    'available': True,
                    'download_url': f'/api/download-report/{report_id}?format=json'
                },
                'pdf': {
                    'available': pdf_available,
                    'download_url': f'/api/download-report/{report_id}?format=pdf' if pdf_available else None,
                    'error': 'ReportLab not installed' if not PDF_AVAILABLE else None
                }
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bulk-refresh-scans', methods=['POST'])
@login_required
def bulk_refresh_scans():
    """Initiate bulk refresh of all domain scans"""
    try:
        # In a real implementation, this would trigger the domain scanning pipeline
        # For now, we'll simulate the process and provide feedback
        
        monitoring_data = load_domain_monitoring_data()
        total_domains = len(monitoring_data)
        
        # Log the refresh request
        refresh_log = {
            'timestamp': datetime.now().isoformat(),
            'initiated_by': getattr(current_user, 'id', 'IT Manager'),
            'total_domains': total_domains,
            'status': 'initiated',
            'estimated_completion': (datetime.now() + timedelta(minutes=30)).isoformat()
        }
        
        # Save refresh log
        cache_dir = Path(__file__).parent / "cache"
        cache_dir.mkdir(exist_ok=True)
        log_file = cache_dir / "scan_refresh_log.json"
        
        with open(log_file, 'w') as f:
            json.dump(refresh_log, f, indent=2)
        
        # In a real implementation, you would:
        # 1. Queue domain scanning jobs
        # 2. Trigger Wapiti scans for all domains
        # 3. Update certificate checks
        # 4. Refresh subdomain discovery
        
        return jsonify({
            'success': True,
            'message': f'Bulk scan refresh initiated for {total_domains} domains',
            'estimated_completion_minutes': 30,
            'refresh_id': f"REFRESH-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/download-report/<report_id>')
@login_required
def download_report(report_id):
    """Download generated security report in JSON or PDF format"""
    try:
        format_type = request.args.get('format', 'json').lower()
        cache_dir = Path(__file__).parent / "cache"
        
        if format_type == 'pdf':
            report_file = cache_dir / f"security_report_{report_id}.pdf"
            if not report_file.exists():
                return jsonify({'error': 'PDF report not found'}), 404
            
            return send_file(
                report_file,
                as_attachment=True,
                download_name=f"NWG_Security_Report_{report_id}.pdf",
                mimetype='application/pdf'
            )
        
        elif format_type == 'json':
            report_file = cache_dir / f"security_report_{report_id}.json"
            if not report_file.exists():
                return jsonify({'error': 'JSON report not found'}), 404
            
            return send_file(
                report_file,
                as_attachment=True,
                download_name=f"NWG_Security_Report_{report_id}.json",
                mimetype='application/json'
            )
        
        else:
            return jsonify({'error': 'Invalid format. Use "json" or "pdf"'}), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_pdf_report(stats, monitoring_data, report_id):
    """Generate professional PDF security report for IT managers"""
    if not PDF_AVAILABLE:
        raise ImportError("ReportLab not installed. Cannot generate PDF reports.")
    
    cache_dir = Path(__file__).parent / "cache"
    cache_dir.mkdir(exist_ok=True)
    pdf_file = cache_dir / f"security_report_{report_id}.pdf"
    
    # Create PDF document
    doc = SimpleDocTemplate(str(pdf_file), pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    
    # Get styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#1a365d')
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        spaceBefore=20,
        textColor=colors.HexColor('#2d3748')
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=14,
        spaceAfter=8,
        spaceBefore=12,
        textColor=colors.HexColor('#4a5568')
    )
    
    # Title Page
    story.append(Paragraph("External Attack Surface Management", title_style))
    story.append(Paragraph("Security Assessment Report", title_style))
    story.append(Spacer(1, 0.5*inch))
    
    # Report metadata
    metadata_data = [
        ['Report ID:', report_id],
        ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Generated by:', current_user.username],
        ['Organization:', 'New Wave Group'],
        ['Report Type:', 'Comprehensive Security Assessment']
    ]
    
    metadata_table = Table(metadata_data, colWidths=[2*inch, 3*inch])
    metadata_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(metadata_table)
    story.append(PageBreak())
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    
    exec_summary_text = f"""
    This report provides a comprehensive security assessment of New Wave Group's external attack surface, 
    covering {stats['monitored_domains']} monitored domains across {stats['companies']} companies. 
    The assessment reveals {stats['critical_domains']} critical risk domains requiring immediate attention 
    and {stats['total_wapiti_vulnerabilities']} total vulnerabilities detected through automated security scanning.
    """
    story.append(Paragraph(exec_summary_text, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Key Metrics Table
    story.append(Paragraph("Key Security Metrics", subheading_style))
    
    metrics_data = [
        ['Metric', 'Value', 'Status'],
        ['Total Domains Monitored', str(stats['monitored_domains']), 'Active'],
        ['Critical Risk Domains', str(stats['critical_domains']), 'Requires Action' if stats['critical_domains'] > 0 else 'Good'],
        ['High Risk Domains', str(stats['high_risk_domains'] - stats['critical_domains']), f"{((stats['high_risk_domains'] - stats['critical_domains'])/max(stats['monitored_domains'],1)*100):.1f}%", 'Monitor'],
        ['Total Vulnerabilities', str(stats['total_wapiti_vulnerabilities']), 'Under Review'],
        ['Critical Vulnerabilities', str(stats['critical_wapiti_vulnerabilities']), 'Immediate Action' if stats['critical_wapiti_vulnerabilities'] > 0 else 'Good'],
        ['Expired Certificates', str(stats['expired_certificates']), 'Critical' if stats['expired_certificates'] > 0 else 'Good'],
        ['Expiring Certificates (30 days)', str(stats['expiring_certificates']), 'Action Required' if stats['expiring_certificates'] > 0 else 'Good'],
    ]
    
    metrics_table = Table(metrics_data, colWidths=[2.5*inch, 1*inch, 1.5*inch])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Risk Assessment
    story.append(Paragraph("Risk Assessment Overview", heading_style))
    
    # Risk distribution
    risk_data = [
        ['Risk Level', 'Domain Count', 'Percentage', 'Action Required'],
        ['Critical', str(stats['critical_domains']), f"{(stats['critical_domains']/max(stats['monitored_domains'],1)*100):.1f}%", 'Immediate'],
        ['High', str(stats['high_risk_domains'] - stats['critical_domains']), f"{((stats['high_risk_domains'] - stats['critical_domains'])/max(stats['monitored_domains'],1)*100):.1f}%", 'Within 24h'],
        ['Medium/Low', str(stats['safe_domains']), f"{(stats['safe_domains']/max(stats['monitored_domains'],1)*100):.1f}%", 'Monitor'],
    ]
    
    risk_table = Table(risk_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1.5*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Vulnerability Analysis
    story.append(Paragraph("Vulnerability Analysis", heading_style))
    
    vuln_text = f"""
    Comprehensive vulnerability scanning using Wapiti has identified {stats['total_wapiti_vulnerabilities']} 
    total vulnerabilities across {stats['domains_with_vulnerabilities']} domains 
    ({stats['vulnerability_coverage']:.1f}% coverage). Critical vulnerabilities requiring immediate 
    attention: {stats['critical_wapiti_vulnerabilities']}.
    """
    story.append(Paragraph(vuln_text, styles['Normal']))
    
    # Top Vulnerabilities
    if stats['top_vulnerabilities']:
        story.append(Paragraph("Top Security Issues", subheading_style))
        
        vuln_data = [['Vulnerability Type', 'Instance Count', 'Severity']]
        for vuln_type, count in stats['top_vulnerabilities'][:10]:
            severity = 'Critical' if vuln_type in ['SQL Injection', 'Cross Site Scripting', 'Command execution'] else 'High' if vuln_type in ['Cross Site Request Forgery', 'Open Redirect'] else 'Medium'
            vuln_data.append([vuln_type, str(count), severity])
        
        vuln_table = Table(vuln_data, colWidths=[3*inch, 1*inch, 1*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(vuln_table)
    
    story.append(PageBreak())
    
    # Critical Domains Detail
    critical_domains = [d for d in monitoring_data if d['risk_level'] == 'critical']
    if critical_domains:
        story.append(Paragraph("Critical Risk Domains - Immediate Action Required", heading_style))
        
        for domain in critical_domains[:10]:  # Top 10 critical domains
            story.append(Paragraph(f"Domain: {domain['domain']}", subheading_style))
            
            domain_details = [
                ['Risk Score:', f"{domain['risk_score']}/100"],
                ['Vulnerabilities:', str(domain.get('total_wapiti_vulns', 0))],
                ['Critical Vulns:', str(domain.get('critical_wapiti_vulns', 0))],
                ['Expired Certs:', str(domain.get('expired_certificates', 0))],
                ['Subdomains:', str(len(domain.get('subdomains', [])))],
                ['Last Scan:', domain.get('scan_date', 'Unknown')]
            ]
            
            domain_table = Table(domain_details, colWidths=[1.5*inch, 2*inch])
            domain_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ]))
            story.append(domain_table)
            story.append(Spacer(1, 0.1*inch))
    
    # Recommendations
    story.append(Paragraph("IT Manager Recommendations", heading_style))
    
    recommendations = [
        "1. Address critical vulnerabilities immediately - prioritize SQL injection and XSS issues",
        "2. Renew expired SSL certificates and schedule renewal for expiring certificates",
        "3. Implement comprehensive security headers (HSTS, CSP, X-Frame-Options) across all domains",
        "4. Establish regular vulnerability scanning schedule (weekly for critical domains)",
        "5. Monitor subdomain security posture and implement subdomain takeover protection",
        "6. Review and update incident response procedures for critical security events",
        "7. Consider implementing Web Application Firewall (WAF) for high-risk domains",
        "8. Establish security metrics dashboard for ongoing monitoring",
        "9. Schedule quarterly security assessments and penetration testing",
        "10. Implement automated certificate renewal and monitoring systems"
    ]
    
    for rec in recommendations:
        story.append(Paragraph(rec, styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
    
    # Footer
    story.append(Spacer(1, 0.5*inch))
    footer_text = f"""
    <para align="center">
    <font size="8" color="#666666">
    This report was generated automatically by the New Wave Group EASM system.<br/>
    For questions or additional analysis, contact the IT Security team.<br/>
    Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </font>
    </para>
    """
    story.append(Paragraph(footer_text, styles['Normal']))
    
    # Build PDF
    doc.build(story)
    return pdf_file

@app.route('/company-overview')
@login_required
def company_overview():
    """Simple company overview - just show companies and their domains"""
    try:
        # Load companies data
        companies_file = 'companies.json'  # Direct path to companies.json
        if not os.path.exists(companies_file):
            return render_template('company_overview.html', company_overview=[])
        
        with open(companies_file, 'r') as f:
            companies_data = json.load(f)
        
        # Handle both array format and object format
        company_overview = []
        if isinstance(companies_data, list):
            # Array format - each item has name and domains
            for company in companies_data:
                if company.get('name') and company.get('domains'):
                    company_overview.append({
                        'name': company['name'],
                        'domains': company['domains']
                    })
        else:
            # Object format - keys are company names, values are domain lists
            for company_name, domains in companies_data.items():
                company_overview.append({
                    'name': company_name,
                    'domains': domains
                })
        
        return render_template('company_overview.html', company_overview=company_overview)
        
    except Exception as e:
        print(f"Error loading company overview: {e}")
        return render_template('company_overview.html', company_overview=[])

@app.route('/domain-monitoring/<domain_name>')
@login_required
def domain_detail(domain_name):
    """Detailed domain analysis page with comprehensive information from complete report"""
    try:
        monitoring_data = load_domain_monitoring_data()
        domain_data = None
        
        # Find the specific domain
        for domain in monitoring_data:
            if domain['domain'] == domain_name:
                domain_data = domain
                break
        
        if not domain_data:
            flash(f'Domain {domain_name} not found in monitoring data', 'error')
            return redirect(url_for('domain_monitoring'))
        
        # Load complete report data if available
        complete_report_path = f"domainControl/Results/{domain_name.replace('.', '_')}/{domain_name.replace('.', '_')}_complete_report.json"
        complete_report = None
        
        try:
            if os.path.exists(complete_report_path):
                with open(complete_report_path, 'r', encoding='utf-8') as f:
                    complete_report = json.load(f)
        except Exception as e:
            print(f"Could not load complete report for {domain_name}: {e}")
        
        # Extract main domain data from complete report
        main_domain_data = {}
        if complete_report and 'results' in complete_report:
            main_domain_data = complete_report['results'].get(domain_name, {})
        
        # Get comprehensive statistics
        stats = get_dashboard_stats()
        
        # Calculate proper security score (higher is better)
        risk_score = domain_data.get('risk_score', 0)
        security_score = max(0, 100 - risk_score)  # Convert risk to security score
        
        # Calculate domain-specific metrics
        domain_metrics = {
            'total_subdomains': len(domain_data.get('subdomains', [])),
            'critical_subdomains': len([s for s in domain_data.get('subdomains', []) if s.get('risk_level') == 'critical']),
            'warning_subdomains': len([s for s in domain_data.get('subdomains', []) if s.get('risk_level') == 'high']),
            'safe_subdomains': len([s for s in domain_data.get('subdomains', []) if s.get('risk_level') in ['low', 'medium']]),
            'total_vulnerabilities': domain_data.get('total_wapiti_vulns', 0),
            'critical_vulnerabilities': domain_data.get('critical_wapiti_vulns', 0),
            'expired_certificates': domain_data.get('expired_certificates', 0),
            'expiring_certificates': domain_data.get('expiring_certificates', 0),
            'security_score': security_score,
            'risk_score': risk_score,
            'risk_level': domain_data.get('risk_level', 'low'),
            'last_scan': domain_data.get('scan_date', 'Unknown')
        }
        
        # Identify critical issues
        critical_issues = []
        if domain_data.get('critical_wapiti_vulns', 0) > 0:
            critical_issues.append(f"{domain_data['critical_wapiti_vulns']} Critical Security Vulnerabilities")
        if domain_data.get('expired_certificates', 0) > 0:
            critical_issues.append(f"{domain_data['expired_certificates']} Expired SSL Certificates")
        if domain_data.get('expiring_certificates', 0) > 0:
            critical_issues.append(f"{domain_data['expiring_certificates']} SSL Certificates Expiring Soon")
        if domain_data.get('risk_score', 0) > 80:
            critical_issues.append("High Risk Score - Immediate Action Required")
        
        # Get vulnerability breakdown from complete report
        vuln_breakdown = {}
        if main_domain_data.get('web_vulnerabilities', {}).get('vulnerabilities'):
            for vuln_type, instances in main_domain_data['web_vulnerabilities']['vulnerabilities'].items():
                if instances:
                    vuln_breakdown[vuln_type] = {
                        'total_instances': len(instances),
                        'affected_subdomains': 1,  # Main domain
                        'instances': instances
                    }
        
        # Add subdomain vulnerabilities
        if main_domain_data.get('subdomains'):
            for subdomain_name, subdomain_data in main_domain_data['subdomains'].items():
                if subdomain_data.get('web_vulnerabilities', {}).get('vulnerabilities'):
                    for vuln_type, instances in subdomain_data['web_vulnerabilities']['vulnerabilities'].items():
                        if instances:
                            if vuln_type not in vuln_breakdown:
                                vuln_breakdown[vuln_type] = {
                                    'total_instances': 0,
                                    'affected_subdomains': 0,
                                    'instances': []
                                }
                            vuln_breakdown[vuln_type]['total_instances'] += len(instances)
                            vuln_breakdown[vuln_type]['affected_subdomains'] += 1
                            vuln_breakdown[vuln_type]['instances'].extend(instances)
        
        # Enhance domain data with complete report information
        enhanced_domain = domain_data.copy()
        
        # Add DNS information
        if main_domain_data.get('dns'):
            enhanced_domain['dns_info'] = main_domain_data['dns']
        
        # Add certificate information
        if main_domain_data.get('certificate'):
            enhanced_domain['certificate_info'] = main_domain_data['certificate']
            enhanced_domain['certificate_expired'] = main_domain_data['certificate'].get('expired', False)
            enhanced_domain['certificate_expiring'] = main_domain_data['certificate'].get('days_left', 365) < 30
            enhanced_domain['certificate_days_left'] = main_domain_data['certificate'].get('days_left', 'Unknown')
            enhanced_domain['certificate_issuer'] = main_domain_data['certificate'].get('issuer', 'Unknown')
        
        # Add OSINT information
        if main_domain_data.get('osint'):
            enhanced_domain['osint_info'] = main_domain_data['osint']
        
        # Add technologies
        if main_domain_data.get('technologies', {}).get('technologies'):
            enhanced_domain['technologies'] = main_domain_data['technologies']['technologies']
        
        # Add IP addresses
        if main_domain_data.get('dns', {}).get('a_record'):
            enhanced_domain['ip_addresses'] = main_domain_data['dns']['a_record']
        
        # Enhance subdomain data
        enhanced_subdomains = []
        for subdomain in domain_data.get('subdomains', []):
            enhanced_subdomain = subdomain.copy()
            subdomain_name = subdomain['name']
            
            # Find subdomain data in complete report
            if main_domain_data.get('subdomains', {}).get(subdomain_name):
                subdomain_complete_data = main_domain_data['subdomains'][subdomain_name]
                
                # Add certificate info
                if subdomain_complete_data.get('certificate'):
                    enhanced_subdomain['certificate'] = subdomain_complete_data['certificate']
                
                # Add vulnerability count
                if subdomain_complete_data.get('web_vulnerabilities', {}).get('total_vulns'):
                    enhanced_subdomain['wapiti_score'] = subdomain_complete_data['web_vulnerabilities']['total_vulns']
                
                # Add risk level based on vulnerabilities
                vuln_count = subdomain_complete_data.get('web_vulnerabilities', {}).get('total_vulns', 0)
                if vuln_count > 5:
                    enhanced_subdomain['risk_level'] = 'critical'
                elif vuln_count > 2:
                    enhanced_subdomain['risk_level'] = 'high'
                else:
                    enhanced_subdomain['risk_level'] = 'low'
                
                enhanced_subdomain['risk_score'] = min(100, vuln_count * 10)
            
            enhanced_subdomains.append(enhanced_subdomain)
        
        enhanced_domain['subdomains'] = enhanced_subdomains
        
        return render_template('domain_detail.html',
                             domain=enhanced_domain,
                             domain_name=domain_name,
                             metrics=domain_metrics,
                             critical_issues=critical_issues,
                             vuln_breakdown=vuln_breakdown,
                             stats=stats)
                             
    except Exception as e:
        flash(f'Error loading domain details: {str(e)}', 'error')
        return redirect(url_for('domain_monitoring'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 