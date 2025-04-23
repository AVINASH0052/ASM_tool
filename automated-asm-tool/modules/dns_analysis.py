import logging
import dns.resolver
import whois
from datetime import datetime

# DNS record analysis and WHOIS lookup
# Identifies domain registration and server config
class DNSAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

    def get_records(self, record_type):
        """Fetch specific DNS records (A, MX, TXT etc.)"""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            if record_type == 'MX':
                return [f"{r.preference} {r.exchange.to_text()}" for r in answers]
            return [r.to_text() for r in answers]
        except dns.resolver.NoAnswer:
            return []
        except Exception as e:
            logging.error(f"DNS {record_type} lookup failed: {str(e)}")
            return []

    def get_whois(self):
        """Get domain registration details"""
        try:
            w = whois.whois(self.domain)
            
            def parse_date(dates):
                """Handle list dates and convert to ISO format"""
                if not dates:
                    return "N/A"
                if isinstance(dates, list):
                    return min([d.isoformat() for d in dates if d]).split('T')[0]
                return dates.isoformat().split('T')[0]
                
            return {
                "registrar": w.registrar or "Unknown",
                "creation_date": parse_date(w.creation_date),
                "expiration_date": parse_date(w.expiration_date),
                "name_servers": list(set([ns.lower() for ns in w.name_servers])) 
                if w.name_servers else [],
                "last_updated": parse_date(w.last_updated)
            }
        except Exception as e:
            logging.error(f"WHOIS failed: {str(e)}")
            return {
                "registrar": "Error",
                "creation_date": "Error",
                "expiration_date": "Error",
                "name_servers": []
            }

    def analyze(self):
        """Compile complete DNS investigation report"""
        return {
            "A": self.get_records('A'),
            "AAAA": self.get_records('AAAA'),
            "MX": self.get_records('MX'),
            "NS": self.get_records('NS'),
            "TXT": self.get_records('TXT'),
            "WHOIS": self.get_whois()
        }