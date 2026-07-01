"""
PhishRadar - Multi-Hop Network Routing Inspection Engine
"""
import requests
from urllib.parse import urljoin
from utils.validators import is_valid_url

class RedirectChecker:
    @staticmethod
    def trace_chain(target_url: str, timeout: int = 4, max_redirects: int = 10) -> list[str]:
        """
        Traces intermediate path hops safely without executing target client scripts.
        """
        if not is_valid_url(target_url):
            return [target_url]

        chain = [target_url]
        current_url = target_url
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishRadar/2.0'
        }

        try:
            while len(chain) <= max_redirects:
                response = requests.head(
                    current_url, 
                    headers=headers, 
                    timeout=timeout, 
                    allow_redirects=False
                )
                if response.status_code == 405:
                    response = requests.get(
                        current_url,
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=False
                    )

                if response.status_code in (301, 302, 303, 307, 308) and 'Location' in response.headers:
                    next_url = response.headers['Location']
                    
                    if next_url.startswith('/'):
                        next_url = urljoin(current_url, next_url)
                        
                    if next_url in chain:
                        break
                        
                    chain.append(next_url)
                    current_url = next_url
                else:
                    break
        except requests.RequestException:
            pass
            
        return chain