# ssl_utils.py

import socket
import requests
import ssl
from typing import List, Dict, Union
import datetime



class SSLUtils:      

    @staticmethod
    def get_ssl_certificate(fqdn: str) -> Dict[str, Union[Dict, List[str], str]]:
        try:
            pem_cert = ssl.get_server_certificate((fqdn, 443))
            cert_dict = ssl._ssl._test_decode_cert(pem_cert)
            return {
                "Subject": dict(x[0] for x in cert_dict["subject"]),
                "Issuer": dict(x[0] for x in cert_dict["issuer"]),
                "Valid From": cert_dict["notBefore"],
                "Valid To": cert_dict["notAfter"],
                "SAN": cert_dict.get("subjectAltName", []),
            }
        except Exception as e:
            return {"Error": str(e)}          

    @staticmethod
    def get_ssl_certificate_details(fqdn: str) -> dict:
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=fqdn)
            conn.connect((fqdn, 443))
            cert = conn.getpeercert()
                
            return {
                "Subject": dict(x[0] for x in cert['subject']),
                "Issuer": dict(x[0] for x in cert['issuer']),
                "Valid From": cert['notBefore'],
                "Valid To": cert['notAfter'],
                "SAN": [entry[1] for entry in cert.get("subjectAltName", [])],
                "Signature Algorithm": cert.get('signatureAlgorithm', 'Unknown'),
            }
        except Exception as e:
            return {"Error": str(e)}


    @staticmethod
    def check_ssl_pinning(url: str) -> str:
        try:
            response = requests.head(url, allow_redirects=True)
            return response.headers.get("Public-Key-Pins", "No SSL Pinning detected")
        except requests.RequestException as e:
            return f"Error checking SSL Pinning: {str(e)}"

    @staticmethod
    def check_ssl_health(fqdn: str) -> Dict[str, str]:
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=fqdn)
            conn.connect((fqdn, 443))
            cert = conn.getpeercert()
            valid_from = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            valid_to = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            current_time = datetime.datetime.utcnow()
            expiry_status = "Valid" if valid_to > current_time else "Expired"
            return {
                "SSL Certificate Valid From": valid_from.isoformat(),
                "SSL Certificate Valid To": valid_to.isoformat(),
                "SSL Expiry Status": expiry_status,
            }
        except Exception as e:
            return {"Error": str(e)}
