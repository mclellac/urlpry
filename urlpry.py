#!/usr/bin/env python3
# urlpry.py

import argparse
import json
from rich.console import Console
from inspector import URLInspector
from http_utils import HTTPUtils

console = Console()

def format_dict(data, indent_level: int = 0):
    indent = '    ' * indent_level
    if not data:
        return "No data available."
    
    if isinstance(data, list):
        return "\n".join(f"{indent}- {item}" for item in data)
    
    if isinstance(data, dict):
        formatted_output = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                formatted_output.append(f"{indent}{key}:")
                formatted_output.append(format_dict(value, indent_level + 1))
            else:
                formatted_output.append(f"{indent}{key}: {value}")
        return "\n".join(formatted_output)
    
    return str(data)

def print_info(output, json_output=False):
    if json_output:
        console.print(json.dumps(output, indent=2))
    else:
        for section, data in output.items():
            console.print(f"[bold yellow]{section}[/bold yellow]:")
            if isinstance(data, (dict, list)):
                console.print(format_dict(data))
            else:
                console.print(data)
            console.print("\n")

def main():
    parser = argparse.ArgumentParser(description="URL inspection tool")
    parser.add_argument("url", help="The URL to inspect")
    parser.add_argument("--dns-server", help="Use a custom DNS server for lookups (e.g., @8.8.8.8)")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    args = parser.parse_args()

    dns_server = args.dns_server.lstrip('@') if args.dns_server else None

    inspector = URLInspector(args.url, dns_server=dns_server)
    output = {}

    # Wrap each method call in a try-except block
    try:
        dns_records = inspector.get_dns_records()
    except Exception as e:
        dns_records = {"Error": str(e)}
    output["DNS Records"] = dns_records

    try:
        http_info = inspector.get_http_info()
    except Exception as e:
        http_info = {"Error": str(e)}
    output["HTTP Information"] = http_info

    try:
        ssl_certificate = inspector.get_ssl_certificate()
    except Exception as e:
        ssl_certificate = {"Error": str(e)}
    output["SSL Certificate Information"] = ssl_certificate

    try:
        waf_info = inspector.detect_waf(http_info)
    except Exception as e:
        waf_info = {"Error": str(e)}
    output["WAF Information"] = waf_info

    try:
        cdn_info = inspector.detect_cdn()
    except Exception as e:
        cdn_info = {"Error": str(e)}
    output["CDN Information"] = cdn_info

    try:
        subdomains = inspector.enumerate_subdomains()
    except Exception as e:
        subdomains = {"Error": str(e)}
    output["Subdomains"] = subdomains

    try:
        js_files = HTTPUtils.extract_javascript_files(args.url)
    except Exception as e:
        js_files = {"Error": str(e)}
    output["JavaScript Files"] = js_files

    try:
        whois_info = inspector.get_whois_info()
    except Exception as e:
        whois_info = {"Error": str(e)}
    output["WHOIS Information"] = whois_info

    try:
        geo_location = inspector.get_ip_geolocation()
    except Exception as e:
        geo_location = {"Error": str(e)}
    output["IP Geolocation"] = geo_location

    try:
        security_headers = inspector.check_security_headers()
    except Exception as e:
        security_headers = {"Error": str(e)}
    output["Security Headers"] = security_headers

    try:
        ssl_tls_analysis = inspector.analyze_ssl_tls()
    except Exception as e:
        ssl_tls_analysis = {"Error": str(e)}
    output["SSL/TLS Analysis"] = ssl_tls_analysis

    try:
        dnssec_status = inspector.check_dnssec()
    except Exception as e:
        dnssec_status = {"Error": str(e)}
    output["DNSSEC Status"] = dnssec_status

    try:
        server_fingerprinting = inspector.perform_server_fingerprinting()
    except Exception as e:
        server_fingerprinting = {"Error": str(e)}
    output["Server Fingerprinting"] = server_fingerprinting

    try:
        load_balancer_detection = inspector.detect_load_balancers()
    except Exception as e:
        load_balancer_detection = {"Error": str(e)}
    output["Load Balancer Detection"] = load_balancer_detection

    try:
        third_party_services = inspector.detect_third_party_services()
    except Exception as e:
        third_party_services = {"Error": str(e)}
    output["Third-Party Services"] = third_party_services

    print_info(output, json_output=args.json)

if __name__ == "__main__":
    main()
