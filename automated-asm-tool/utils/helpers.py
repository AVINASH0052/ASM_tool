import os
import csv
import json
import yaml
from datetime import datetime

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), '../config/api_keys.yaml')
    with open(config_path) as f:
        return yaml.safe_load(f)

def read_domains(input_file):
    domains = []
    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domains.append(row['domain'])
    return domains

def generate_report(domain, data, output_dir="outputs"):
    """Save report to file and return path"""
    # Create output directory if needed
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{domain}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    # Ensure consistent structure
    required_fields = {
        'osint_findings': list,
        'sensitive_paths': list,
        'dns_records': dict,
        'open_ports': list
    }
    
    for field, ftype in required_fields.items():
        if field not in data or not isinstance(data[field], ftype):
            data[field] = ftype()
    
    # Write to file
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    
    return filepath

def validate_config(config):
    required_keys = ['nvidia']
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")
    return True

import socket

def check_internet():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        return True
    except OSError:
        return False