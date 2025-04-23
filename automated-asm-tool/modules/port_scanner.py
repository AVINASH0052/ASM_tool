import nmap
import socket
import logging

# Network port scanning using nmap
# Identifies open ports and running services
class PortScanner:
    def __init__(self, domain):
        self.domain = domain
        self.nm = nmap.PortScanner()
        self.ip = socket.gethostbyname(domain)
        self.timeout = 600  # 10 minutes max
        self.scan_args = '-sT -T4 --top-ports 1000 --open'  # TCP Connect scan

    def scan(self):
        """Main port scanning operation"""
        try:
            logging.info(f"Resolving IP for {self.domain}")
            self.ip = socket.gethostbyname(self.domain)
            logging.info(f"Scanning {self.domain} ({self.ip})")
            
            self.nm.scan(
                hosts=self.ip,
                arguments='-sT -T4 --top-ports 100 --open',
                timeout=300
            )
            
            return self._parse_results()
        except socket.gaierror:
            logging.error("DNS resolution failed")
            return []
        except Exception as e:
            logging.error(f"Scan error: {str(e)}")
            return []

    def _parse_results(self):
        """Convert nmap results to structured format"""
        results = []
        if self.ip not in self.nm.all_hosts():
            return results

        for proto in self.nm[self.ip].all_protocols():
            for port in self.nm[self.ip][proto].keys():
                service = self.nm[self.ip][proto][port]
                results.append({
                    "port": port,
                    "protocol": proto,
                    "service": service['name'],
                    "version": service['version']
                })
        return results