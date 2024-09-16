# subdomain_utils.py

import requests

class SubdomainUtils:

    @staticmethod
    def enumerate_subdomains(domain: str) -> str:
        """
        Enumerate subdomains by querying crt.sh for certificates.
        The subdomains will be returned as a single comma-separated string.
        """
        try:
            response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if response.status_code == 200:
                # crt.sh can return multiple JSON documents, handle them appropriately
                crt_data = response.json()

                # Collect and deduplicate subdomains, avoiding wildcard domains
                subdomains = set()
                for entry in crt_data:
                    if 'name_value' in entry:
                        # Handle the case where `name_value` is a single string or a multi-line string
                        names = entry["name_value"].split("\n")  # In case of multiple subdomains in one entry
                        for name in names:
                            if not name.startswith("*"):
                                subdomains.add(name.strip().lower())

                # Join subdomains into a single string, separated by a comma and a space
                return ", ".join(sorted(subdomains)) if subdomains else "No subdomains found"
            return "No subdomains found"
        except requests.RequestException as e:
            return f"Error fetching subdomains: {str(e)}"