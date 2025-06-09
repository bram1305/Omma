import ssl
import socket
import datetime
import requests
import urllib3
from urllib.parse import urlparse
from domainControl.Scripts.utils import is_subdomain_redirecting_to_root
import OpenSSL.crypto
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_certificates(domains, root_domains=None):
    results = {}
    seen = set()
    total = len(domains)
    
    # Build map of subdomain to root_domain for redirect checks
    subdomain_to_root = {}
    if root_domains:
        for domain in domains:
            for root in root_domains:
                if domain != root and domain.endswith(f".{root}"):
                    subdomain_to_root[domain] = root
                    break

    def check(domain, idx):
        if domain in seen:
            return None
        seen.add(domain)
        
        # Check if subdomain redirects to root
        if domain in subdomain_to_root:
            root = subdomain_to_root[domain]
            if is_subdomain_redirecting_to_root(domain, root):
                print(f"[SSL] {idx}/{total} - Skipping {domain} (redirects to {root})")
                return domain, {"redirects_to": root}
        
        print(f"[SSL] {idx}/{total} - {domain}")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, 443))
                tls_version = s.version()

                # Server SSL info opvragen (indien mogelijk)
                server_ssl_info = s.cipher()
                cipher_name = server_ssl_info[0] if server_ssl_info else "Onbekend"
                protocol_version = server_ssl_info[1] if server_ssl_info else "Onbekend"

                der_cert = s.getpeercert(binary_form=True)
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                x509 = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM, pem_cert
                )

                valid_from = datetime.datetime.strptime(
                    x509.get_notBefore().decode("ascii"), "%Y%m%d%H%M%SZ"
                )
                valid_to = datetime.datetime.strptime(
                    x509.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ"
                )
                now = datetime.datetime.utcnow()
                expired = now > valid_to
                issuer = (
                    dict(x509.get_issuer().get_components())
                    .get(b"O", b"")
                    .decode(errors="ignore")
                    or "Onbekend"
                )
                self_signed = issuer == ""

                try:
                    response = requests.get(
                        f"https://{domain}", timeout=10, verify=False
                    )
                    headers = response.headers
                    hsts = "strict-transport-security" in headers
                    server = headers.get("Server", "Onbekend")
                except:
                    hsts = False
                    server = "Onbekend"

                return domain, {
                    "valid_from": valid_from.strftime("%Y-%m-%d"),
                    "valid_to": valid_to.strftime("%Y-%m-%d"),
                    "expired": expired,
                    "days_left": (valid_to - now).days if not expired else 0,
                    "days_expired": (now - valid_to).days if expired else 0,
                    "issuer": issuer,
                    "self_signed": self_signed,
                    "hsts": hsts,
                    "server_header": server,
                    "tls_version": tls_version,
                    "ssl_cipher": cipher_name,
                    "ssl_protocol_version": protocol_version,
                }

        except Exception as e:
            return domain, {"error": str(e)}

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(check, domain, i): domain
            for i, domain in enumerate(domains, 1)
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                domain, cert = result
                results[domain] = cert

    return results