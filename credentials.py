# credentials.py (CORRECTED to include 'port' in successful credential dictionaries)

import requests
from requests.auth import HTTPBasicAuth
from typing import Dict, List, Any
# For SSH checking
import paramiko # Requires: pip install paramiko
import socket
import time

# A list of common default credential pairs (username, password)
DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('user', 'user'),
    ('root', 'toor'),
    ('admin', 'password'),
    ('guest', 'guest'),
    ('ubnt', 'ubnt'),       # Common Ubiquiti/network gear default
    ('changeme', 'changeme'), # Common IoT default
    ('supervisor', 'supervisor'), # Common DVR/NVR default
]

# --- SSH CREDENTIAL CHECK ---

def check_ssh_auth(ip: str, port: int, credentials: List[tuple]) -> List[Dict[str, str]]:
    """
    Attempts to log in to an SSH service using default credentials.
    
    Returns a list of dictionaries with successfully logged in credentials, including the port.
    """
    successful_creds = []
    
    try:
        # Initialize client setup
        client = paramiko.SSHClient()
        # Allows auto-adding new host keys for an auditing tool
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print(f"    -> Checking SSH Auth on {ip}:{port} with {len(credentials)} default pair(s)...")

        for username, password in credentials:
            try:
                # Attempt connection with a short timeout
                client.connect(
                    hostname=ip, 
                    port=port, 
                    username=username, 
                    password=password, 
                    timeout=5,
                    allow_agent=False,
                    look_for_keys=False
                )
                
                # --- SUCCESS HANDLING: ADDED 'port' KEY HERE ---
                print(f"    [!] FOUND Weak/Default Credentials for SSH: {username}:{password}")
                successful_creds.append({
                    'service': 'SSH', # Set a clean service name
                    'username': username,
                    'password': password,
                    'status': 'Login Successful',
                    'port': port # <-- FIXED: Include the port
                })
                
                # Close the connection
                try:
                    client.close()
                except Exception:
                    pass
                
                # Stop checking for other credentials once one is found
                break 
                
            # --- INNER FAILURE/ERROR HANDLING ---
            except paramiko.AuthenticationException:
                # Credentials failed - skip silently
                pass 
            except paramiko.SSHException:
                # Catch general SSH protocol errors
                pass
            except socket.timeout:
                print(f"    - Timeout connecting to {ip}:{port}")
            except Exception:
                # Catch other connection-related errors silently
                pass
                
    except Exception:
        # Outer catch: Guarantees a list is returned even on setup failure
        pass
            
    # Always return the list (which may be empty)
    return successful_creds

# --- HTTP Basic Auth Placeholder ---
def check_http_basic_auth(ip: str, port: int, credentials: List[tuple]) -> List[Dict[str, str]]:
    """
    Placeholder function for checking HTTP Basic Authentication.
    NOTE: This logic is required for the main function to run without error.
    """
    successful_creds = []
    # Actual implementation using requests.get(url, auth=HTTPBasicAuth(u, p)) goes here.
    # The dictionary returned by this function should also include the 'port' key 
    # for any successful login (just like check_ssh_auth).
    
    # Simple placeholder to prevent NameError
    return successful_creds


# --- Main Check Function ---

def check_weak_credentials(ip: str, fingerprint_data: Dict[str, Any], custom_creds: List[tuple] = None) -> List[Dict[str, str]]:
    """
    Checks the device for weak/default credentials across detected services.
    """
    all_creds_to_check = DEFAULT_CREDENTIALS
    if custom_creds:
        all_creds_to_check.extend(custom_creds)

    found_weak_credentials = []
    tcp_services = fingerprint_data.get('tcp_services', {})
    
    if not tcp_services:
        return found_weak_credentials

    # Suppressing this print statement to adhere to the final summary report request from main.py
    # print(f"\n[+] Starting Weak Credential Check for {ip}...")

    # Iterate through all open ports
    for port, banner in tcp_services.items():
        
        # 1. SSH CHECK (Port 22)
        if port == 22:
            # print(f"  -> Service Banner: {banner} on port {port}")
            results = check_ssh_auth(ip, port, all_creds_to_check)
            found_weak_credentials.extend(results)
        
        # 2. HTTP BASIC AUTH CHECK (Common Web Ports)
        elif port in [80, 8080, 8081, 8443]:
            # Skip port 443 for simple HTTP check
            if port == 443 or any(kw in banner.lower() for kw in ['https', 'ssl', 'tls']):
                 # print(f"    - Skipping port {port} (Likely HTTPS) for simple HTTP check.")
                 continue
                 
            # print(f"  -> Service Banner: {banner} on port {port}")
            results = check_http_basic_auth(ip, port, all_creds_to_check)
            found_weak_credentials.extend(results)
            
        # TODO: Consider adding checks for Telnet (port 23) if needed.
        
    return found_weak_credentials