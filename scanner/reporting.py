# scanner/reporting.py

import sys
import socket
from netaddr import IPNetwork, iter_iprange

# Define the default color map for use in print_result
try:
    from .config import COLOR_MAP
except ImportError:
    # Define a fallback if config is not yet ready
    COLOR_MAP = {"CRITICAL": "", "HIGH": "", "MEDIUM": "", "LOW": "", "INFO": "", "ERROR": "", "WARNING": "", "ENDC": ""}


def print_result(ip, port, service, risk, message):
    """Prints a formatted scan result or system message to the console (used by main.py)."""
    color = COLOR_MAP.get(risk.upper(), COLOR_MAP["INFO"])
    endc = COLOR_MAP["ENDC"]
    
    # Format port and service for display
    port_str = f":{port:<5}" if port else "      "
    service_str = f"({service.upper():<8})" if service else "          "
    
    output = f"{color}[{ip:<15}{port_str}] {service_str} {risk.upper():<8} | {message}{endc}"
    print(output)


def parse_targets(target_string):
    """
    Parses a string of IPs, CIDR, or IP ranges into a list of individual IP addresses.
    (Used by main.py and app.py)
    """
    ip_list = []
    
    for item in target_string.split(','):
        item = item.strip()
        
        if not item:
            continue

        try:
            # Handle CIDR (e.g., 192.168.1.0/24)
            if '/' in item:
                # Exclude network and broadcast addresses
                for ip in IPNetwork(item).hosts():
                    ip_list.append(str(ip))
            # Handle IP range (e.g., 192.168.1.1-192.168.1.10)
            elif '-' in item:
                start, end = item.split('-')
                for ip in iter_iprange(start.strip(), end.strip()):
                    ip_list.append(str(ip))
            # Handle single IP address
            elif socket.inet_aton(item):
                ip_list.append(item)

        except Exception as e:
            print_result("System", 0, "Error", "CRITICAL", f"Invalid target format '{item}'. Error: {e}")
            return []

    if not ip_list:
        print_result("System", 0, "Error", "CRITICAL", "No valid targets found.")
        return []

    # Remove duplicates and return
    return sorted(list(set(ip_list)))