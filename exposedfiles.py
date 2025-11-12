# exposedfiles.py

import requests
from typing import Dict, List, Any

# A list of common files/directories to check for public exposure
SENSITIVE_PATHS = [
    # --- Generic Web Server & App Config Files (Original List) ---
    '/robots.txt',          # Often discloses internal directory structure
    '/.git/HEAD',           # Indicates exposed .git directory
    '/.env',                # Environmental variables, keys, passwords
    '/config.json',         # Configuration files
    '/wp-config.php',       # WordPress configuration (very sensitive)
    '/admin/',              # Default admin interface URL
    '/phpinfo.php',         # Debugging file, exposes configuration info
    '/server-status',       # Apache status info
    '/config/settings.yml', # Common YAML config file
    
    # --- Expanded Generic Config Paths ---
    '/config.ini',          # INI configuration files
    '/configuration.xml',   # XML configuration files
    '/settings.xml',        # Settings files
    '/passwords.txt',       # Plaintext password dumps
    '/credentials.txt',     # Plaintext credentials
    '/backup.zip',          # Website/device backups
    '/database.sql',        # Database dumps (e.g., SQLite, MySQL)
    
    # --- Common Router/IoT Configuration Paths ---
    '/rom-0',               # Common path for router firmware/configuration backups (often used by TP-Link, D-Link, etc.)
    '/settings.bin',        # Binary settings file
    '/backupcfg.bin',       # Binary backup config
    '/current.cfg',         # Current device configuration
    '/etc/shadow',          # Linux password file (highly sensitive if exposed)
    '/etc/passwd',          # Linux user file (sensitive if exposed)
    '/etc/config/network',  # OpenWrt/Linux network config
]

# Disable requests warnings for local/self-signed cert checks
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def check_exposed_files(ip: str, port: int, paths: List[str] = SENSITIVE_PATHS) -> List[Dict[str, str]]:
    """
    Attempts to access common sensitive file paths on a web server.
    
    Returns a list of dictionaries for successfully accessed (exposed) files.
    """
    exposed_files = []
    
    # Check both HTTP (default) and HTTPS if port is 443 or a common HTTPS port
    protocols_to_check = ['http']
    if port in [443, 8443]:
        # If 443 or 8443, we should ONLY check HTTPS
        protocols_to_check = ['https']
    elif port in [80, 8080, 8081]:
        # For standard/non-standard HTTP ports, only check HTTP
        protocols_to_check = ['http']

    print(f"    -> Checking {len(paths)} common paths on {ip}:{port}...")

    for path in paths:
        for proto in protocols_to_check:
            url = f"{proto}://{ip}:{port}{path}"
            
            try:
                # Set a short timeout (3 seconds)
                response = requests.get(
                    url, 
                    timeout=3, 
                    verify=False, # Do not verify SSL certs for local checks
                    allow_redirects=True # Follow redirects
                )
                
                # Revised Logic: An exposed file is confirmed by a success status code (2xx) or a redirect (3xx).
                if 200 <= response.status_code < 400:
                    
                    print(f"    [!] EXPOSED: {url} (Status: {response.status_code}, Length: {len(response.text)})")
                    exposed_files.append({
                        'url': url,
                        'path': path,
                        'status_code': response.status_code,
                    })
                    # Stop checking other protocols for the same path if found
                    break 
                        
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.ConnectionError:
                # Skip if the connection fails (e.g., trying HTTPS on a pure HTTP port)
                pass
            except Exception:
                pass
            
    return exposed_files

def check_for_exposed_files(ip: str, fingerprint_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Checks the device for common exposed files on detected web services.
    """
    found_exposed_files = []
    tcp_services = fingerprint_data.get('tcp_services', {})
    
    if not tcp_services:
        return found_exposed_files

    # Identify relevant web ports
    # NOTE: You may want to expand the list of ports in fingerprint.py if devices use custom ports
    web_ports = [p for p in tcp_services.keys() if p in [80, 443, 8080, 8081, 8443]]
    
    if not web_ports:
        return found_exposed_files
        
    print(f"\n[+] Starting Exposed File Check for {ip} on port(s): {', '.join(map(str, web_ports))}...")

    # Iterate through all open web ports
    for port in web_ports:
        results = check_exposed_files(ip, port)
        found_exposed_files.extend(results)
            
    return found_exposed_files