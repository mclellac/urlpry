# geo_utils.py

import requests

class GeoUtils:
    
    @staticmethod
    def get_ip_geolocation(ip: str):
        """
        Fetch geolocation data for a given IP address.
        """
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            return response.json()
        except requests.RequestException as e:
            return {"Error": str(e)}
