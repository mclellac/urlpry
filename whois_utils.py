# whois_utils.py

import whois
from datetime import datetime

class WhoisUtils:
    @staticmethod
    def get_whois_info(domain: str) -> dict:
        """
        Fetches WHOIS information for a given domain.

        Args:
            domain (str): The domain for which to get WHOIS info.

        Returns:
            dict: A dictionary containing WHOIS information.
        """
        try:
            fqdn_info = whois.whois(domain)

            def clean_field(field):
                """Convert field to a string or handle list/datetime values correctly."""
                if isinstance(field, list):
                    field = ', '.join([str(item) for item in field])
                elif isinstance(field, datetime):
                    field = field.strftime("%Y-%m-%d %H:%M:%S")
                return str(field) if field else None

            # Map the fields returned by whois.whois() to our desired output
            whois_info = {
                # Domain Details
                "Domain Name": clean_field(fqdn_info.get('domain_name')),
                "Registrar": clean_field(fqdn_info.get('registrar')),
                "Whois Server": clean_field(fqdn_info.get('whois_server')),
                "Referral URL": clean_field(fqdn_info.get('referral_url')),
                "Updated Date": clean_field(fqdn_info.get('updated_date')),
                "Creation Date": clean_field(fqdn_info.get('creation_date')),
                "Expiration Date": clean_field(fqdn_info.get('expiration_date')),
                "Name Servers": clean_field(fqdn_info.get('name_servers')),
                "Status": clean_field(fqdn_info.get('status')),
                "Emails": clean_field(fqdn_info.get('emails')),
                "DNSSEC": clean_field(fqdn_info.get('dnssec')),

                # Registrant Information
                "Registrant Name": clean_field(fqdn_info.get('name')),
                "Registrant Organization": clean_field(fqdn_info.get('org')),
                "Registrant Street": clean_field(fqdn_info.get('address')),
                "Registrant City": clean_field(fqdn_info.get('city')),
                "Registrant State/Province": clean_field(fqdn_info.get('state')),
                "Registrant Postal Code": clean_field(fqdn_info.get('zipcode')),
                "Registrant Country": clean_field(fqdn_info.get('country')),
            }

            # Remove None or empty fields from the dictionary
            whois_info = {k: v for k, v in whois_info.items() if v}

            return whois_info

        except Exception as e:
            return {"Error": f"An error occurred while fetching WHOIS information: {str(e)}"}
