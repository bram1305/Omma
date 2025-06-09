import re
from domainControl.Scripts.utils import is_subdomain_redirecting_to_root
import requests


def is_valid_url_domain(domain):
    """
    Validate if a domain string is a proper domain and not a malformed URL.
    """
    # Remove any protocol prefix
    domain = domain.replace('https://', '').replace('http://', '')
    
    # Check for obvious malformed URLs with phone numbers or invalid characters
    if re.search(r'tel:|comtel:|:\+\d+', domain):
        return False
    
    # Check for basic domain structure
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain.split('/')[0]):
        return False
    
    # Additional checks for suspicious patterns
    if '%20' in domain or '+' in domain or ' ' in domain:
        return False
        
    return True


def scan_headers(domain, root_domain=None):
    # Validate domain before processing
    if not is_valid_url_domain(domain):
        print(f"[WARNING] Skipping malformed domain: {domain}")
        return {
            "error": f"Invalid domain format: {domain}",
            "hsts": False,
            "x_frame_options": False,
            "csp": False,
            "server": "Unknown",
        }
    
    # Check if subdomain redirects to root
    if root_domain and domain != root_domain:
        if is_subdomain_redirecting_to_root(domain, root_domain):
            return {"redirects_to": root_domain}
    
    try:
        print(f"[HEADERS] Scanning headers for: {domain}")
        response = requests.head(f"https://{domain}", timeout=5, allow_redirects=False)
        headers = response.headers
        return {
            "hsts": "strict-transport-security" in headers,
            "x_frame_options": "x-frame-options" in headers,
            "csp": "content-security-policy" in headers,
            "server": headers.get("Server", "Unknown"),
        }
    except requests.exceptions.Timeout:
        print(f"[WARNING] Timeout scanning headers for {domain}")
        return {
            "error": f"Timeout connecting to {domain}",
            "hsts": False,
            "x_frame_options": False,
            "csp": False,
            "server": "Unknown",
        }
    except Exception as e:
        print(f"[WARNING] Error scanning headers for {domain}: {e}")
        return {
            "error": str(e),
            "hsts": False,
            "x_frame_options": False,
            "csp": False,
            "server": "Unknown",
        }