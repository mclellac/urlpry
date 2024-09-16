# inspector.py

from dns_utils import DNSUtils
from http_utils import HTTPUtils
from ssl_utils import SSLUtils
from waf_utils import WAFUtils
from whois_utils import WhoisUtils
from subdomain_utils import SubdomainUtils
from geo_utils import GeoUtils
from typing import Optional, List
from service_utils import ServiceUtils
from traceroute_utils import TracerouteUtils



class URLInspector:
    def __init__(self, url: str, dns_server: Optional[str] = None):
        self.url = url
        self.dns_server = dns_server
        self.fqdn_info = self.extract_full_and_domain(url)
        self.fqdn = self.fqdn_info["fqdn"]
        self.domain = self.fqdn_info["domain"]

    def extract_full_and_domain(self, url: str):
        from urllib.parse import urlparse
        import tldextract
        fqdn = urlparse(url).hostname
        domain_parts = tldextract.extract(fqdn)
        return {"fqdn": fqdn, "domain": f"{domain_parts.domain}.{domain_parts.suffix}"}

    def get_dns_records(self):
        """
        Get DNS records for both the FQDN and domain (TXT records are on the domain).
        """
        dns_records = DNSUtils.get_dns_records(self.fqdn, self.domain, self.dns_server)
        return dns_records

    def get_http_info(self):
        """
        Get HTTP response information, such as headers and HTML metadata.
        """
        return HTTPUtils.get_http_info(self.url)

    def get_ssl_certificate(self):
        """
        Get SSL certificate details for the FQDN.
        """
        return SSLUtils.get_ssl_certificate(self.fqdn)

    def detect_cdn(self):
        """
        Detect if a CDN is being used based on CNAME records or server headers.
        """
        return WAFUtils.detect_cdn(self.fqdn)

    def detect_waf(self, http_info):
        """
        Detect WAF using a combination of header checks, HTML error patterns, and Telnet detection.
        """
        return WAFUtils.detect_waf(http_info, self.fqdn)

    def enumerate_subdomains(self):
        """
        Enumerate subdomains using crt.sh.
        """
        return SubdomainUtils.enumerate_subdomains(self.domain)
    
    def scan_ports(self, ports=None):
        """
        Scan common ports to see if they are open.
        """
        if ports is None:
            ports = [80, 443, 21, 22, 25, 53, 110, 143, 3000, 3306, 8080, 8443, 5432]
        return DNSUtils.scan_ports(self.fqdn, ports)

    def check_ssl_pinning(self):
        """
        Check if SSL pinning is enabled for the domain.
        """
        return SSLUtils.check_ssl_pinning(self.url)

    def perform_traceroute(self):
        return TracerouteUtils.traceroute(self.fqdn)
     
    def get_whois_info(self):
        """
        Get WHOIS information for the domain using WhoisUtils.
        """
        return WhoisUtils.get_whois_info(self.domain)

    def get_ip_geolocation(self):
        try:
            ip_address = DNSUtils.resolve_ip(self.fqdn)
            return GeoUtils.get_ip_geolocation(ip_address)
        except ValueError as e:
            return {"Error": str(e)}


    def check_security_headers(self):
        """
        Checks for common security headers in the HTTP response.
        """
        http_info = self.get_http_info()
        security_headers = http_info.get("Security Headers", {})
        return security_headers

    def analyze_ssl_tls(self):
        """
        Analyzes SSL/TLS configuration for the FQDN.
        """
        return SSLUtils.get_ssl_certificate_details(self.fqdn)

    def check_dnssec(self):
        """
        Checks if DNSSEC is enabled for the domain.
        """
        return DNSUtils.check_dnssec(self.domain)

    def traceroute(self):
        return TracerouteUtils.traceroute(self.fqdn)
    
    def perform_server_fingerprinting(self):
        """
        Perform server fingerprinting based on HTTP headers, SSL details, and other data points.
        """
        http_info = self.get_http_info()
        ssl_certificate = self.get_ssl_certificate()

        server_info = {
            "Server Header": http_info.get("General", {}).get("Server", "Unknown"),
            "X-Powered-By": http_info.get("General", {}).get("X-Powered-By", "Unknown"),
            "SSL Subject": ssl_certificate.get("Subject", "Unknown"),
            "SSL Issuer": ssl_certificate.get("Issuer", "Unknown"),
        }
        return server_info
    
    def detect_load_balancers(self):
        """
        Detect if a load balancer is in use based on headers, cookies, and server behaviors.
        """
        http_info = self.get_http_info()
        headers = http_info.get("General", {})
        detected_load_balancers = []

        # Common load balancer headers and indicative values
        load_balancer_headers = {
            "X-Forwarded-For": None,  # Presence indicates a proxy or load balancer
            "X-Forwarded-Host": None,
            "X-Forwarded-Server": None,
            "X-Load-Balancer": None,
            "X-Proxy-ID": None,
            "X-Varnish": None,
            "Via": None,
            "X-Powered-By": ["HAProxy"],
            "X-Haproxy-Server-State": None,
            "X-Haproxy-Backend": None,
            "X-Cache": None,  # Varnish, Squid, others
            "X-Cache-Hits": None,
            "X-Azure-Ref": None,  # Azure Load Balancer
            "X-Akamai-Transformed": None,  # Akamai
            "X-CDN": None,
            "F5-STATS": None,
            "X-Cnection": ["close"],  # F5 BIG-IP
            "X-NewRelic-App-Data": None,
            "Set-Cookie": ["AWSELB", "AWSALB", "BIGipServer", "F5_fullWT", "CitrixNS", "DT", "dtCookie"],
        }

        # Check headers for load balancer indicators
        for header, indicative_values in load_balancer_headers.items():
            for hdr, value in headers.items():
                if hdr.lower() == header.lower():
                    header_value = value
                    if indicative_values:
                        if isinstance(indicative_values, list):
                            for indicative_value in indicative_values:
                                if indicative_value.lower() in header_value.lower():
                                    detected_load_balancers.append(f"{header} indicates {indicative_value}")
                        else:
                            if indicative_values.lower() in header_value.lower():
                                detected_load_balancers.append(f"{header} indicates {indicative_values}")
                    else:
                        detected_load_balancers.append(f"{header} present")

        # Analyze Server header
        server_header = headers.get("Server", "")
        server_header_lower = server_header.lower()
        server_signatures = {
            "HAProxy": "haproxy",
            "Varnish": "varnish",
            "Cloudflare": "cloudflare",
            "Akamai": "akamai",
            "F5 BIG-IP": "bigip",
            "Citrix NetScaler": "netscaler",
            "IBM WebSphere": "websphere",
            "Barracuda": "barracuda",
            "DDoS-GUARD": "ddos-guard",
            "ArvanCloud": "arvancloud",
        }
        for lb_name, signature in server_signatures.items():
            if signature in server_header_lower:
                detected_load_balancers.append(f"{lb_name} detected via Server header")

        # Analyze Set-Cookie header for load balancer cookies
        set_cookie = headers.get("Set-Cookie", "")
        load_balancer_cookies = [
            "AWSELB", "AWSALB", "BIGipServer", "F5_fullWT", "CitrixNS", "X-Mapping-", "dtCookie", "TS", "Persist", "rd"
        ]
        for cookie_name in load_balancer_cookies:
            if cookie_name in set_cookie:
                detected_load_balancers.append(f"Cookie '{cookie_name}' indicates a load balancer")

        # Check for specific behaviors or headers
        if "X-Haproxy-Server-State" in headers:
            detected_load_balancers.append("HAProxy detected via X-Haproxy-Server-State header")
        if "X-Varnish" in headers or "X-Cache" in headers:
            detected_load_balancers.append("Varnish Cache detected via headers")
        if "F5-STATS" in headers:
            detected_load_balancers.append("F5 BIG-IP detected via F5-STATS header")
        if "Via" in headers:
            via_header = headers.get("Via", "").lower()
            if "varnish" in via_header:
                detected_load_balancers.append("Varnish detected via Via header")
            elif "haproxy" in via_header:
                detected_load_balancers.append("HAProxy detected via Via header")

        # Analyze other indicative headers
        if "X-Azure-Ref" in headers:
            detected_load_balancers.append("Azure Load Balancer detected via X-Azure-Ref header")
        if "X-Cnection" in headers and headers["X-Cnection"].lower() == "close":
            detected_load_balancers.append("F5 BIG-IP detected via X-Cnection header")
        if "X-CDN" in headers:
            detected_load_balancers.append(f"CDN detected via X-CDN header: {headers['X-CDN']}")

        # Check for known load balancer technologies in cookies
        if set_cookie:
            cookies = set_cookie.split(';')
            for cookie in cookies:
                for lb_cookie in load_balancer_cookies:
                    if lb_cookie.lower() in cookie.lower():
                        detected_load_balancers.append(f"Cookie '{cookie.strip()}' indicates a load balancer")
                        break  # Avoid duplicate entries

        # Deduplicate the detected load balancers
        detected_load_balancers = list(set(detected_load_balancers))

        if detected_load_balancers:
            return ", ".join(detected_load_balancers)
        else:
            return "No Load Balancer Detected"

    def detect_third_party_services(self):
        """
        Detect third-party services (like Google Analytics, ad networks) from JavaScript files and embedded content.
        """
        js_files = HTTPUtils.extract_javascript_files(self.url)
        third_party_services = []

        # Common third-party services
        service_patterns = {
            "Google Analytics": "www.google-analytics.com",
            "Facebook": "connect.facebook.net",
            "Twitter": "platform.twitter.com",
            "Google Ads": "pagead2.googlesyndication.com",
            "DoubleClick": "securepubads.g.doubleclick.net",
            "Hotjar": "static.hotjar.com",
        }

        for js_file in js_files:
            for service, pattern in service_patterns.items():
                if pattern in js_file:
                    third_party_services.append(service)

        return third_party_services if third_party_services else "No third-party services detected"
    
    def grab_service_banners(self, ports: Optional[List[int]] = None):
        """
        Grab service banners from specified ports.
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5900, 8080]
        ip_address = DNSUtils.resolve_ip(self.fqdn)
        if "Could not resolve" in ip_address:
            return {"Error": ip_address}
        return ServiceUtils.grab_banners(ip_address, ports)

    def search_sensitive_keywords(self, keywords: Optional[List[str]] = None):
        """
        Search for sensitive keywords within the site's content.
        """
        if keywords is None:
            keywords = ["password", "secret", "api_key", "token", "admin", "credentials"]
        return HTTPUtils.search_keywords(self.url, keywords)
