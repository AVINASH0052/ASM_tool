import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import argparse
import logging
import sys
import json
from datetime import datetime
from modules.subdomain_enum import SubdomainEnumerator
from modules.dns_analysis import DNSAnalyzer
from modules.port_scanner import PortScanner
from modules.web_analyzer import WebAnalyzer
from modules.vulnerability_check import VulnerabilityChecker
from modules.ai_analysis import AIAnalyzer
from utils.helpers import (
    load_config,
    read_domains,
    generate_report,
    validate_config
)

if __name__ != "__main__":
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

def setup_logger(verbose):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=log_level
    )

def run_scan(domain, verbose=False):
    """Execute full scan pipeline for a single domain"""
    findings = {"domain": domain, "scan_date": datetime.now().isoformat()}
    
    try:
        # Subdomain enumeration
        logging.info(f"Starting subdomain enumeration for {domain}")
        sub_enum = SubdomainEnumerator(domain)
        subdomains = sub_enum.enumerate()
        findings.update({
            "subdomains": subdomains["live_subdomains"],
            "all_subdomains": subdomains["all_subdomains"]
        })
    except Exception as e:
        logging.error(f"Subdomain enumeration failed: {str(e)}")

    try:
        # DNS Analysis
        logging.info(f"Running DNS analysis for {domain}")
        dns = DNSAnalyzer(domain)
        findings["dns_records"] = dns.analyze()
    except Exception as e:
        logging.error(f"DNS analysis failed: {str(e)}")

    try:
        # Port Scanning
        logging.info(f"Scanning ports for {domain}")
        scanner = PortScanner(domain)
        findings["open_ports"] = scanner.scan()
    except Exception as e:
        logging.error(f"Port scanning failed: {str(e)}")

    try:
        # Web Analysis
        logging.info(f"Analyzing web infrastructure for {domain}")
        web = WebAnalyzer(domain)
        web_data = web.analyze()
        findings.update({
            "tech_stack": web_data.get("tech_stack", []),
            "headers": web_data.get("headers", {}),
            "ssl_info": web_data.get("ssl", {})
        })
    except Exception as e:
        logging.error(f"Web analysis failed: {str(e)}")

    try:
        # Vulnerability Checks
        logging.info(f"Checking vulnerabilities for {domain}")
        vuln = VulnerabilityChecker(domain)
        vuln_data = vuln.scan()
        findings.update({
            "osint_findings": vuln_data.get("breaches", []),
            "sensitive_paths": vuln_data.get("sensitive_paths", [])
        })
    except Exception as e:
        logging.error(f"Vulnerability check failed: {str(e)}")

    try:
        # AI Risk Analysis
        logging.info(f"Generating risk assessment for {domain}")
        ai = AIAnalyzer()
        risk_data = ai.analyze_risk(findings)
        findings.update({
            "risk_score": risk_data.get("risk_score", 0),
            "risk_summary": risk_data.get("summary", ""),
            "recommendations": risk_data.get("recommendations", [])
        })
    except Exception as e:
        logging.error(f"AI analysis failed: {str(e)}")

    return findings

def main():
    parser = argparse.ArgumentParser(
        description="Automated Attack Surface Monitoring Tool"
    )
    parser.add_argument(
        "-i", "--input",
        default="input.csv",
        help="Input CSV file with domains"
    )
    parser.add_argument(
        "-o", "--output",
        default="outputs",
        help="Output directory for reports"
    )
    parser.add_argument(
        "-f", "--format",
        default="json",
        choices=["json", "html", "md"],
        help="Output report format"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()
    setup_logger(args.verbose)

    try:
        validate_config(load_config())
        domains = read_domains(args.input)
        
        if not domains:
            logging.error("No domains found in input file")
            sys.exit(1)

        for domain in domains:
            logging.info(f"Starting scan for {domain}")
            report = run_scan(domain, args.verbose)
            output_path = generate_report(domain, report, args.output)
            logging.info(f"Report generated: {output_path}")

    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()