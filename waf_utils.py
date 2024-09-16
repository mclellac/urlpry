# waf_utils.py

import requests
import socket
from typing import Optional, Dict
from dns_utils import DNSUtils


class WAFUtils:

    @staticmethod
    def detect_waf(http_info: dict, fqdn: str) -> str:
        """
        Detects the presence of a WAF by analyzing HTTP headers and error messages.

        Args:
            http_info (dict): HTTP response information.
            fqdn (str): Fully Qualified Domain Name.

        Returns:
            str: The name of the detected WAF or "No WAF detected".
        """
        waf_headers = {
            "Cloudflare": ["cf-ray", "cf-request-id"],
            "Incapsula": ["x-iinfo", "x-visid"],
            "F5 BIG-IP": ["x-waf", "x-wa-info", "x-cnection"],
            "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id"],
            "Barracuda": ["x-barracuda"],
            "StackPath": ["x-stackpath-request-id", "x-stackpath-proxy"],
            "Sucuri": ["x-sucuri-id"],
            "Fortinet": ["x-fortinet"],
            "Imperva": ["x-cdn", "x-sd-request-id"],
            "Akamai": ["akamai-error", "akamai-origin-hop"],
        }

        waf_error_patterns = {
            "Cloudflare": ["Attention Required", "Cloudflare"],
            "Akamai": ["Reference #", "Access Denied"],
            "F5 BIG-IP": ["Request Blocked", "The page cannot be displayed"],
            "AWS WAF": ["403 Forbidden", "Request blocked"],
            "Incapsula": ["Incapsula incident ID", "Access denied"],
            "Sucuri": ["Sucuri WebSite Firewall"],
            "Fortinet": ["Access to this web site is blocked", "FortiGuard"],
            "Imperva": ["Request denied", "Imperva"],
            "Barracuda": ["Barracuda Network Access"],
        }

        # Check for WAF-related headers in the HTTP response
        headers = http_info.get("General", {})
        for waf_name, header_keys in waf_headers.items():
            if any(header.lower() in (h.lower() for h in headers) for header in header_keys):
                return f"{waf_name} detected via HTTP headers"

        # Check for WAF-specific error messages in the response content
        html_content = http_info.get("Content", "")
        detected_waf = WAFUtils.identify_waf_by_error_message(html_content, waf_error_patterns)
        if detected_waf:
            return f"{detected_waf} detected via error message"

        # Akamai Pragma header detection
        akamai_waf = WAFUtils.detect_akamai_waf(fqdn)
        if akamai_waf:
            return akamai_waf

        # Analyze headers from a raw socket connection
        telnet_headers = WAFUtils.telnet_cdn_waf_detection(fqdn)
        if telnet_headers and "Error" not in telnet_headers:
            for waf_name, header_keys in waf_headers.items():
                if any(header.lower() in telnet_headers for header in header_keys):
                    return f"{waf_name} detected via raw socket headers"

        return "No WAF detected"

    @staticmethod
    def detect_akamai_waf(fqdn: str) -> Optional[str]:
        """
        Detects Akamai WAF by sending a request with a specific Pragma header.

        Args:
            fqdn (str): Fully Qualified Domain Name.

        Returns:
            Optional[str]: Detection message if Akamai WAF is detected, else None.
        """
        akamai_headers = {"Pragma": "akamai-x-get-extracted-values"}
        try:
            response = requests.get(f"http://{fqdn}", headers=akamai_headers, timeout=5)
            if "x-akamai-session-info" in response.headers and "waf" in response.headers["x-akamai-session-info"].lower():
                return "Akamai WAF detected via akamai-x-get-extracted-values Pragma header"
        except requests.RequestException:
            pass
        return None

    @staticmethod
    def identify_waf_by_error_message(response_text: str, waf_error_patterns: dict) -> Optional[str]:
        """
        Matches response text against known WAF error patterns to identify the WAF.

        Args:
            response_text (str): The HTML content of the response.
            waf_error_patterns (dict): Dictionary of WAF names and their error patterns.

        Returns:
            Optional[str]: The name of the detected WAF or None.
        """
        for waf_name, patterns in waf_error_patterns.items():
            for pattern in patterns:
                if pattern.lower() in response_text.lower():
                    return waf_name
        return None

    @staticmethod
    def detect_cdn(fqdn: str) -> str:
        """
        Detects if a CDN is being used by checking the CNAME or HTTP headers.

        Args:
            fqdn (str): Fully Qualified Domain Name.

        Returns:
            str: The name of the detected CDN or "No CDN detected".
        """
        cdn_providers = {
            "Cloudflare": ["cloudflare"],
            "Akamai": ["akamai", "akamaitechnologies"],
            "Fastly": ["fastly"],
            "Incapsula": ["incapsula"],
            "StackPath": ["stackpath", "highwinds"],
            "CDN77": ["cdn77"],
            "CloudFront": ["cloudfront"],
            "Azure": ["azure"],
            "Google": ["google"],
            "CacheFly": ["cachefly"],
        }

        # Check CNAME records for CDN indicators
        cname_record = DNSUtils.safe_resolve_cname(fqdn)
        if cname_record:
            for provider_name, keywords in cdn_providers.items():
                if any(keyword in cname_record.lower() for keyword in keywords):
                    return f"{provider_name} CDN detected via CNAME"

        # Analyze headers from a raw socket connection
        telnet_headers = WAFUtils.telnet_cdn_waf_detection(fqdn)
        if telnet_headers and "Error" not in telnet_headers:
            server_header = telnet_headers.get("server", "").lower()
            for provider_name, keywords in cdn_providers.items():
                if any(keyword in server_header for keyword in keywords):
                    return f"{provider_name} CDN detected via Server header"

        return "No CDN detected"

    @staticmethod
    def telnet_cdn_waf_detection(fqdn: str, port: int = 80) -> Dict[str, str]:
        """
        Uses a raw socket connection to retrieve HTTP headers for analysis.

        Args:
            fqdn (str): Fully Qualified Domain Name.
            port (int): Port number to connect to.

        Returns:
            Dict[str, str]: A dictionary of HTTP headers or an error message.
        """
        try:
            with socket.create_connection((fqdn, port), timeout=5) as sock:
                request = f"GET / HTTP/1.1\r\nHost: {fqdn}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode())
                response = b""
                while True:
                    part = sock.recv(4096)
                    if not part:
                        break
                    response += part
                    if b"\r\n\r\n" in response:
                        break
                header_text = response.decode("iso-8859-1", errors="ignore").split("\r\n\r\n")[0]
                headers = header_text.split("\r\n")[1:]
                header_dict = {
                    header.split(":", 1)[0].strip().lower(): header.split(":", 1)[1].strip()
                    for header in headers if ":" in header
                }
                return header_dict
        except (socket.timeout, socket.error) as e:
            return {"Error": str(e)}

###
# Disabling as a default. Will readd when ported to use plugins or something toggleable
###
#    @staticmethod
#    def simulate_attack_request(fqdn: str, waf_error_patterns: dict) -> str:
#        """
#        Simulate an attack request (e.g., SQL injection or XSS) to check if a WAF blocks it, 
#        and match against known WAF error patterns.
#        """
#        attack_payloads = [
#            "' OR '1'='1",  # SQL Injection
#            "<script>alert('XSS')</script>",  # XSS
#            "../../../../etc/passwd",  # Directory Traversal
#            "UNION SELECT NULL --",  # SQL Injection (UNION)
#            "1%27%20AND%201=1--",  # SQL Injection (URL encoded)
#            "<img src='x' onerror='alert(1)'>"  # XSS (image tag)
#        ]
#
#        try:
#            for payload in attack_payloads:
#                response = requests.get(f"http://{fqdn}", params={"q": payload}, timeout=5)
#
#                # Check response code or content for WAF indications
#                if response.status_code == 403:
#                    return WAFUtils.identify_waf_by_error_message(response.text, waf_error_patterns)
#
#                # Also inspect response content for any known error messages
#                detected_waf = WAFUtils.identify_waf_by_error_message(response.text, waf_error_patterns)
#                if detected_waf:
#                    return detected_waf
#
#        except requests.RequestException:
#            pass
#        return ""
