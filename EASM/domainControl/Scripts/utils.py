import requests
from typing import Optional, Dict, Any
import urllib3
import re

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_url_domain(domain: str) -> bool:
    """
    Validate if a domain string is a proper domain and not a malformed URL.
    """
    if not domain:
        return False
        
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

def get_final_redirect_url(domain: str) -> Optional[str]:
    """
    Get the final URL after all redirects for a given domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        str: The final domain after redirects, or original domain if error
    """
    # Validate domain first
    if not is_valid_url_domain(domain):
        print(f"[WARNING] Invalid domain format: {domain}")
        return domain
        
    try:
        # Try HTTPS first
        response = requests.get(
            f"https://{domain}", 
            allow_redirects=True, 
            timeout=5,  # Reduced timeout
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (EASM Scanner)'}
        )
        final_url = response.url.replace("https://", "").replace("http://", "").rstrip("/")
        
        # Remove www. for comparison if present
        if final_url.startswith("www."):
            final_url = final_url[4:]
            
        return final_url
        
    except requests.exceptions.Timeout:
        print(f"[WARNING] Timeout connecting to {domain}")
        return domain
    except requests.exceptions.SSLError:
        # Try HTTP if HTTPS fails
        try:
            response = requests.get(
                f"http://{domain}", 
                allow_redirects=True, 
                timeout=5,  # Reduced timeout
                headers={'User-Agent': 'Mozilla/5.0 (EASM Scanner)'}
            )
            final_url = response.url.replace("https://", "").replace("http://", "").rstrip("/")
            
            if final_url.startswith("www."):
                final_url = final_url[4:]
                
            return final_url
        except:
            return domain
    except Exception as e:
        print(f"[WARNING] Error getting redirect URL for {domain}: {e}")
        return domain


def is_subdomain_redirecting_to_root(subdomain: str, root_domain: str) -> bool:
    """
    Check if a subdomain redirects to the root domain.
    
    Args:
        subdomain (str): The subdomain to check
        root_domain (str): The root domain to compare against
        
    Returns:
        bool: True if subdomain redirects to root domain
    """
    # Validate both domains first
    if not is_valid_url_domain(subdomain) or not is_valid_url_domain(root_domain):
        print(f"[WARNING] Invalid domain format in redirect check: {subdomain} -> {root_domain}")
        return False
        
    try:
        subdomain_final = get_final_redirect_url(subdomain)
        root_final = get_final_redirect_url(root_domain)
        
        # Normalize domains for comparison
        subdomain_clean = subdomain_final.replace("www.", "") if subdomain_final else subdomain
        root_clean = root_final.replace("www.", "") if root_final else root_domain
        
        return subdomain_clean == root_clean and subdomain != root_domain
        
    except Exception as e:
        print(f"[WARNING] Error checking redirect for {subdomain}: {e}")
        return False


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain by removing protocol and www prefix.
    
    Args:
        domain (str): Domain to normalize
        
    Returns:
        str: Normalized domain
    """
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.rstrip("/")
    
    if domain.startswith("www."):
        domain = domain[4:]
        
    return domain


def safe_get_nested_value(data: Dict[Any, Any], keys: list, default=None):
    """
    Safely get a nested value from a dictionary.
    
    Args:
        data (dict): The dictionary to search
        keys (list): List of keys to traverse
        default: Default value if key path doesn't exist
        
    Returns:
        The value at the key path, or default if not found
    """
    try:
        for key in keys:
            data = data[key]
        return data
    except (KeyError, TypeError):
        return default


def format_risk_level(risk_level: str) -> str:
    """
    Format risk level for display.
    
    Args:
        risk_level (str): Risk level (high, medium, low)
        
    Returns:
        str: Formatted risk level with emoji
    """
    risk_emojis = {
        "high": "🔴 HIGH",
        "medium": "🟡 MEDIUM", 
        "low": "🟢 LOW",
        "info": "ℹ️ INFO"
    }
    return risk_emojis.get(risk_level.lower(), f"❓ {risk_level.upper()}")


def create_safe_filename(domain: str) -> str:
    """
    Create a safe filename from a domain name.
    
    Args:
        domain (str): Domain name
        
    Returns:
        str: Safe filename
    """
    return domain.replace(".", "_").replace(":", "_").replace("/", "_")


def validate_domain(domain: str) -> bool:
    """
    Basic domain validation.
    
    Args:
        domain (str): Domain to validate
        
    Returns:
        bool: True if domain appears valid
    """
    if not domain or len(domain) < 3:
            return False
        
    # Remove protocol if present
    domain = normalize_domain(domain)
    
    # Basic checks
    if " " in domain or ".." in domain:
            return False
        
    # Must contain at least one dot
    if "." not in domain:
        return False
        
    # Must not start or end with dot or dash
    if domain.startswith(".") or domain.endswith(".") or domain.startswith("-") or domain.endswith("-"):
        return False
        
    return True


def get_domain_info_summary(domain_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a summary of domain information for quick overview.
    
    Args:
        domain_data (dict): Complete domain scan data
        
    Returns:
        dict: Summary information
    """
    summary = {
        "domain": domain_data.get("domain", "unknown"),
        "risk_level": domain_data.get("risico_niveau", "unknown"),
        "total_risks": len(domain_data.get("risico_labels", [])),
        "has_ssl": bool(domain_data.get("certificate", {}).get("valid_from")),
        "ssl_expires_soon": domain_data.get("certificate", {}).get("days_left", 999) < 30,
        "has_vulnerabilities": domain_data.get("web_vulnerabilities", {}).get("total_vulns", 0) > 0,
        "technology_count": len(domain_data.get("technologies", {}).get("technologies", [])),
        "subdomain_count": len(domain_data.get("subdomains", {}))
    }
    
    return summary