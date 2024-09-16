# http_utils.py

from typing import List, Dict, Optional, Union
import requests
from bs4 import BeautifulSoup

class HTTPUtils:
    
    @staticmethod
    def get_http_info(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Union[Dict, str, int, float]]:
        try:
            response = requests.get(url, headers=headers, allow_redirects=True)
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Get common security headers
            security_headers = {
                "Strict-Transport-Security": response.headers.get("Strict-Transport-Security", "Not Present"),
                "X-Frame-Options": response.headers.get("X-Frame-Options", "Not Present"),
                "X-Content-Type-Options": response.headers.get("X-Content-Type-Options", "Not Present"),
                "X-XSS-Protection": response.headers.get("X-XSS-Protection", "Not Present"),
                "Content-Security-Policy": response.headers.get("Content-Security-Policy", "Not Present"),
                "Referrer-Policy": response.headers.get("Referrer-Policy", "Not Present"),
            }

            return {
                "General": dict(response.headers),
                "Security Headers": security_headers,
                "Status Code": response.status_code,
                "Final URL": response.url,
                "Content-Type": response.headers.get("Content-Type"),
                "Server": response.headers.get("Server"),
                "HTML Info": {
                    "Title": soup.title.string if soup.title else "No title",
                    "Forms": len(soup.find_all("form")),
                    "Buttons": len(soup.find_all("button")),
                },
            }
        except requests.RequestException as e:
            return {"Error": str(e)}

    @staticmethod
    def extract_javascript_files(url: str) -> Union[List[str], Dict[str, str]]:
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            return [script.get("src") for script in soup.find_all("script") if script.get("src")]
        except requests.RequestException as e:
            return {"Error": str(e)}

    @staticmethod
    def get_internal_links(url: str, domain: str) -> List[str]:
        """
        Extracts all internal links from the given URL.
        """
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            links = set()
            for link_tag in soup.find_all('a', href=True):
                href = link_tag['href']
                parsed_href = requests.utils.urlparse(href)
                if parsed_href.netloc == '' or domain in parsed_href.netloc:
                    full_url = requests.compat.urljoin(url, href)
                    links.add(full_url)
            return list(links)
        except requests.RequestException:
            return []

    @staticmethod
    def search_keywords_in_content(content: str, keywords: List[str]) -> List[str]:
        """
        Searches for keywords in the provided content.
        """
        found_keywords = []
        content_lower = content.lower()
        for keyword in keywords:
            if keyword.lower() in content_lower:
                found_keywords.append(keyword)
        return found_keywords

    @staticmethod
    def search_keywords(url: str, keywords: List[str], max_depth: int = 2) -> Dict[str, List[str]]:
        """
        Crawls the website starting from the given URL and searches for sensitive keywords.
        """
        from collections import deque

        visited = set()
        queue = deque([(url, 0)])
        found_keywords = {}

        while queue:
            current_url, depth = queue.popleft()
            if depth > max_depth or current_url in visited:
                continue
            visited.add(current_url)
            try:
                response = requests.get(current_url)
                if response.status_code == 200:
                    content = response.text
                    matches = HTTPUtils.search_keywords_in_content(content, keywords)
                    if matches:
                        found_keywords[current_url] = matches
                    if depth < max_depth:
                        internal_links = HTTPUtils.get_internal_links(current_url, requests.utils.urlparse(url).netloc)
                        for link in internal_links:
                            if link not in visited:
                                queue.append((link, depth + 1))
            except requests.RequestException:
                continue
        return found_keywords
