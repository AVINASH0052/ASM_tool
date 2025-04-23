import os
import re
import subprocess
import json
import tempfile
import requests
import logging
from urllib3.exceptions import InsecureRequestWarning
from utils.helpers import load_config

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Subdomain enumeration using Amass and certificate logs
# Finds hidden/related domains and services
class SubdomainEnumerator:
    def __init__(self, domain):
        self.config = load_config()
        self.domain = domain.lower()
        self.validation_regex = re.compile(
            r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
        )
        self.live_subdomains = []
        self.timeout = 30  # timeout
        self.user_agent = "ASM-Tool/1.0 (+https://github.com/your-repo)"
        
    def _validate_subdomain(self, subdomain):
        """Handle byte/string conversion"""
        if isinstance(subdomain, bytes):
            subdomain = subdomain.decode('utf-8').strip()
        return (subdomain.lower().endswith(f".{self.domain}") 
                and bool(self.validation_regex.match(subdomain)))

    def _read_results(self, file_handler):
        """Explicit encoding handling"""
        return [
            line.strip() for line in file_handler.read().decode('utf-8').splitlines()
            if self._validate_subdomain(line)
        ]
        
    # modules/subdomain_enum.py
    def run_amass(self):
        """Use Amass tool for subdomain discovery"""
        try:
            with tempfile.NamedTemporaryFile() as tmpfile:
                config_path = self.config.get('amass_config', 'config/amass.ini')
                timeout = self.config.get('amass_timeout', 1200)  # 20min default
                
                process = subprocess.Popen(
                    ['amass', 'enum', '-d', self.domain, 
                    '-config', config_path, '-o', tmpfile.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                try:
                    stdout, stderr = process.communicate(timeout=timeout)
                    if process.returncode != 0:
                        logging.warning(f"Amass partial output: {stderr[:200]}")
                    
                    # Read whatever results we have
                    tmpfile.seek(0)
                    return self._read_results(tmpfile)
                    
                except subprocess.TimeoutExpired:
                    logging.warning("Amass timed out - using partial results")
                    process.kill()
                    tmpfile.seek(0)
                    return self._read_results(tmpfile)
                    
        except Exception as e:
            logging.error(f"Amass execution failed: {str(e)}")
            return []
        
    def check_live_subdomains(self, subdomains):
        """Verify active subdomains through HTTP checks"""
        alive = []
        session = requests.Session()
        session.headers.update({'User-Agent': self.user_agent})
        
        for sub in subdomains:
            try:
                # Try HTTPS first
                resp = session.get(
                    f"https://{sub}",
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                if resp.status_code < 400:
                    alive.append(sub)
                    continue
            except:
                pass
            
            try:
                # Fallback to HTTP
                resp = session.get(
                    f"http://{sub}",
                    timeout=self.timeout,
                    allow_redirects=True
                )
                if resp.status_code < 400:
                    alive.append(sub)
            except:
                continue
                
        return alive

    def enumerate(self):
        """Combine multiple discovery methods"""
        subdomains = self.run_amass()
        
        # Add and clean crt.sh results
        try:
            crt_sh_results = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=30
            ).json()
            
            cleaned = []
            for entry in crt_sh_results:
                names = entry['name_value'].split('\n')
                for name in names:
                    if self.domain in name and '*' not in name:
                        cleaned.append(name.strip().lower())
            
            subdomains += cleaned
            
        except Exception as e:
            logging.error(f"Certificate transparency check failed: {str(e)}")
        
        # Validate subdomains
        valid_subdomains = []
        domain_parts = self.domain.split('.')
        for sub in subdomains:
            try:
                # Basic validation
                if sub.count('.') < 1:
                    continue
                if not re.match(r"^[a-z0-9\-\.]+$", sub):
                    continue
                if sub.endswith('.' + self.domain):
                    valid_subdomains.append(sub)
            except:
                continue
        
        # Deduplicate and sort
        valid_subdomains = sorted(list(set(valid_subdomains)))
        
        # Check live subdomains
        self.live_subdomains = self.check_live_subdomains(valid_subdomains)
        
        return {
            "all_subdomains": valid_subdomains,
            "live_subdomains": self.live_subdomains
        }
        
    def _read_results(self, file_handler):
        """Parse results with validation"""
        results = []
        for line in file_handler:
            line = line.strip().lower()
            if self._validate_subdomain(line):
                results.append(line)
        return list(set(results))