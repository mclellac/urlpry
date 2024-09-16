import socket
import dns.resolver
from typing import List, Union, Dict, Optional


class DNSUtils:
    
    @staticmethod
    def configure_resolver(dns_server: Optional[str] = None):
        """
        Configures a DNS resolver. If a DNS server is provided (e.g., '8.8.8.8'),
        it will use that DNS server for lookups; otherwise, it will use the system default.
        """
        resolver = dns.resolver.Resolver()
        if dns_server:
            resolver.nameservers = [dns_server]
        return resolver

    @staticmethod
    def ip_to_reverse_name(ip_address: str) -> str:
        return '.'.join(reversed(ip_address.split('.'))) + '.in-addr.arpa'

    @staticmethod
    def safe_resolve_dns(fqdn: str, record_type: str, dns_server: Optional[str] = None) -> Union[List[str], str]:
        try:
            resolver = DNSUtils.configure_resolver(dns_server)
            resolver.lifetime = 5
            result = resolver.resolve(fqdn, record_type)
            return [str(rdata) for rdata in result]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return f"No {record_type} record found"
        except dns.exception.Timeout:
            return f"{record_type} query timed out"
        except dns.exception.DNSException as e:
            return f"Error resolving {record_type}: {str(e)}"

    @staticmethod
    def safe_resolve_cname(fqdn: str, dns_server: Optional[str] = None) -> Union[str, None]:
        try:
            resolver = DNSUtils.configure_resolver(dns_server)
            answers = resolver.resolve(fqdn, "CNAME")
            return str(answers[0].target).strip(".").lower()
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.DNSException:
            return None

    @staticmethod
    def get_dns_records(fqdn: str, domain: str, dns_server: Optional[str] = None) -> Dict[str, Union[List[str], str]]:
        ip_address = socket.gethostbyname(fqdn)
        reverse_name = DNSUtils.ip_to_reverse_name(ip_address)
        return {
            "CNAME": DNSUtils.safe_resolve_dns(fqdn, "CNAME", dns_server),
            "TXT": DNSUtils.safe_resolve_dns(domain, "TXT", dns_server),
            "PTR": DNSUtils.safe_resolve_dns(reverse_name, "PTR", dns_server),
            "IP Address": ip_address,
        }

    @staticmethod
    def get_additional_dns_records(fqdn: str, dns_server: Optional[str] = None) -> Dict[str, Union[List[str], str]]:
        return {
            "MX": DNSUtils.safe_resolve_dns(fqdn, "MX", dns_server),
            "NS": DNSUtils.safe_resolve_dns(fqdn, "NS", dns_server),
            "SOA": DNSUtils.safe_resolve_dns(fqdn, "SOA", dns_server),
            "AAAA": DNSUtils.safe_resolve_dns(fqdn, "AAAA", dns_server),
        }

    @staticmethod
    def scan_ports(host: str, ports: List[int], dns_server: Optional[str] = None) -> Union[List[int], str]:
        result = DNSUtils.safe_resolve_dns(host, "A", dns_server)
        if isinstance(result, list):
            ip = result[0]
        else:
            return f"Could not resolve {host} to an IP address: {result}"
        open_ports = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        return open_ports


    @staticmethod
    def resolve_ip(fqdn: str) -> str:
        try:
            return socket.gethostbyname(fqdn)
        except socket.gaierror as e:
            raise ValueError(f"Could not resolve IP for {fqdn}: {e}")


    @staticmethod
    def check_dnssec(domain: str) -> str:
        try:
            dns.resolver.resolve(domain, 'DNSKEY')
            return "DNSSEC is enabled"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return "DNSSEC not enabled"
        except dns.exception.DNSException as e:
            return f"Error checking DNSSEC: {str(e)}"