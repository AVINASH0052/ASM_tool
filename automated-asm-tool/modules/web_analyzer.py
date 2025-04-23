import logging
import socket
import warnings
import requests
import ssl
from Wappalyzer import Wappalyzer, WebPage

# Website technology identification
# Analyzes headers, SSL, and tech stack
class WebAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.url = f"https://{domain}"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.wappalyzer = Wappalyzer.latest()

    def check_headers(self):
        try:
            resp = requests.get(self.url, timeout=10, verify=False)
            return dict(resp.headers)
        except requests.exceptions.RequestException as e:
            logging.error(f"Connection failed: {str(e)}")
            return {}

    def detect_tech_stack(self):
        """Identify web technologies using Wappalyzer"""
        try:
            response = requests.get(
                self.url, 
                timeout=10, 
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
            )
            
            tech_data = {"technologies": []}
            
            # Get basic server info from headers
            server = response.headers.get('Server')
            if server:
                tech_data["technologies"].append({
                    "name": f"Server: {server}",
                    "type": "webserver",
                    "confidence": 100
                })

            # Only run full analysis on successful responses
            if response.status_code == 200:
                webpage = WebPage(response.url, response.text, response.headers)
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    technologies = self.wappalyzer.analyze_with_versions_and_categories(webpage)
                
                for tech, details in technologies.items():
                    tech_data["technologies"].append({
                        "name": tech,
                        "versions": details.get('versions', []),
                        "categories": details.get('categories', []),
                        "confidence": details.get('confidence', 100)
                    })
            
            return tech_data
            
        except Exception as e:
            logging.error(f"Tech detection failed: {str(e)}")
            return {"technologies": []}

    def get_server_info(self, headers):
        """Extract server information from headers"""
        server_info = []
        if 'Server' in headers:
            server_info.append({
                "name": f"Web Server: {headers['Server']}",
                "type": "webserver",
                "confidence": 90
            })
        if 'X-Powered-By' in headers:
            server_info.append({
                "name": f"Powered By: {headers['X-Powered-By']}",
                "type": "framework",
                "confidence": 80
            })
        return server_info

    def get_ssl_info(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
            return {
                "issuer": dict(x[0] for x in cert['issuer']),
                "expiration": cert['notAfter'],
                "protocol": ssl.OPENSSL_VERSION,
                "cipher": cipher[0] if cipher else None
            }
        except Exception as e:
            logging.error(f"SSL analysis failed: {str(e)}")
            return {}

    def analyze(self):
        """Compile complete web infrastructure report"""
        try:
            response = requests.get(
                self.url,
                timeout=10,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
            )
            headers = dict(response.headers)
            
            return {
                "tech_stack": {
                    "header_based": self.get_server_info(headers),
                    "wappalyzer": self.detect_tech_stack().get("technologies", [])
                },
                "headers": headers,
                "ssl": self.get_ssl_info(),
                "status_code": response.status_code
            }
        except Exception as e:
            logging.error(f"Web analysis failed: {str(e)}")
            return {
                "tech_stack": [],
                "headers": {},
                "ssl": {}
            }