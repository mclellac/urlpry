# urlpry - URL Inspection Tool

`urlpry` is a URL inspection tool designed to gather information about websites. It performs DNS lookups, WAF detection, CDN analysis, WHOIS lookups, subdomain enumeration, SSL certificate inspection, and more. It's designed to help security researchers, developers, and system administrators gather relevant information for security assessments or general web analytics.

## Features

- DNS record resolution (A, CNAME, TXT, PTR, MX, etc.)
- Subdomain enumeration via `crt.sh`
- SSL certificate inspection
- WAF (Web Application Firewall) detection (including Akamai, Cloudflare, and others)
- CDN detection
- WHOIS lookup
- IP geolocation
- HTTP response and headers analysis
- JavaScript file extraction
- Traceroute support
- Simulated WAF detection via attack payloads (SQLi, XSS, etc.)

## Installation

### Prerequisites

- Python 3.8+

### Install Dependencies

You can install the required dependencies with the following command:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python urlpry.py https://example.com/test
```

### Optional Arguments

```
--json: Outputs results in JSON format for easy parsing.
--dns-server @<server>: Uses a custom DNS server for lookups (e.g., 8.8.8.8 for Google's public DNS).
```

### Disclaimer

`urlpry` is intended for legal and ethical purposes. Ensure you have permission to inspect and gather information about the target URLs.