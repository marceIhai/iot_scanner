# app.py

import os
import sys
import json
from datetime import datetime
from flask import Flask, render_template, url_for, redirect, current_app
from typing import Dict, List, Any

# ==============================================================================
# ⚠️ CRITICAL IMPORT SECTION
# Ensure all your scanning logic files are present and importable.
# The following modules must be in the same directory as app.py:
# discover.py, fingerprint.py, vulnmatch.py, credentials.py, exposedfiles.py, report.py
# ==============================================================================
try:
    import discover as discover
    import fingerprint as fingerprint 
    import vulnmatch as vulnmatch 
    import credentials as credentials 
    import exposedfiles as exposedfiles 
    import report as report # Your provided report.py
except ImportError as e:
    print(f"CRITICAL ERROR: Failed to import a required scanning module: {e}")
    print("Please ensure all scanning scripts (e.g., discover.py) are in the same directory.")
    sys.exit(1)


# --- Configuration ---
app = Flask(__name__)
REPORT_DIR = 'scan_reports'

# Ensure the report directory exists
os.makedirs(REPORT_DIR, exist_ok=True)

# --- Utility Functions ---

def find_latest_report_path() -> str | None:
    """Finds the path to the most recently created scan report JSON file."""
    if not os.path.exists(REPORT_DIR):
        return None
        
    try:
        # Filter for JSON files starting with 'scan_report_'
        list_of_files = [
            os.path.join(REPORT_DIR, f) 
            for f in os.listdir(REPORT_DIR) 
            if f.startswith('scan_report_') and f.endswith('.json')
        ]
        
        if not list_of_files:
            return None
            
        # Sort files by creation time
        latest_file = max(list_of_files, key=os.path.getctime)
        return latest_file
        
    except Exception:
        return None


def load_latest_report() -> Dict[str, Any] | None:
    """Loads and returns the data from the latest scan report file."""
    latest_path = find_latest_report_path()
    
    if latest_path and os.path.exists(latest_path):
        try:
            with open(latest_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {latest_path}")
            return None
    return None

def process_host_overview_for_html(report_data: dict) -> dict:
    """Reformats the 'host_overview' section for cleaner rendering in report.html."""
    if 'host_overview' not in report_data:
        return report_data

    processed_hosts = []
    for host in report_data['host_overview']:
        # Host overview section in report.py saves nested fp_data, we need to flatten it
        # for better Jinja access in report.html.
        fp_data = host.pop('fp_data', {}) 
        host['hostname'] = fp_data.get('hostname', f"host-{host['ip'].split('.')[-1]}")
        host['os_fingerprint'] = fp_data.get('os', 'Unknown')
        host['tcp_services'] = fp_data.get('tcp_services', {})
        processed_hosts.append(host)

    report_data['host_overview'] = processed_hosts
    return report_data

# --- Blocking Scan Logic (Integrated from main.py) ---

def perform_network_scan() -> dict:
    """
    PERFORMS THE FULL SCAN. This function BLOCKS the entire Flask app 
    until it completes.
    """
    
    print("\n[FLASK] Starting blocking network scan...")
    
    try:
        # Check for scapy dependency
        from scapy.all import Ether 
    except ImportError:
        return {'status': 'error', 'message': "Scapy is not installed. Please run 'pip install scapy'."}

    # 1. Identify Subnet
    subnet_cidr = discover.get_started() 
    if not subnet_cidr:
        return {'status': 'error', 'message': "Cannot identify local subnet. Aborting scan."}

    # 2. Scan Subnet & Count Hosts
    active_devices = discover.scan_subnet(subnet_cidr)
    hosts_found = len(active_devices)

    if hosts_found == 0:
        return {'status': 'success', 'message': "No active devices found. Scan complete."}

    # 3. Silent Analysis & Data Collection
    all_vuln_matches = []
    all_weak_creds = []
    all_exposed_files = []
    scanned_device_data = []

    for i, device in enumerate(active_devices):
        ip = device['ip']
        mac = device['mac']
        vendor = discover.oui_lookup(mac) 
        
        # Fingerprint
        fp_data = fingerprint.get_full_fingerprint(ip) 
        device_data = {'ip': ip, 'mac': mac, 'vendor': vendor, 'fp_data': fp_data}
        scanned_device_data.append(device_data)

        # Vulnerability Matching
        if fp_data.get('tcp_services'):
            vulnerabilities = vulnmatch.match_vulnerabilities(fp_data['tcp_services'])
            for banner, vulns in vulnerabilities.items():
                for vuln in vulns:
                    all_vuln_matches.append({'ip': ip, **vuln, 'banner': banner})
        
        # Weak Credentials Check
        weak_creds = credentials.check_weak_credentials(ip=ip, fingerprint_data=fp_data)
        for cred in weak_creds:
            all_weak_creds.append({'ip': ip, **cred})
            
        # Exposed Files Check
        exposed_files_found = exposedfiles.check_for_exposed_files(ip=ip, fingerprint_data=fp_data)
        for file_data in exposed_files_found:
            all_exposed_files.append({'ip': ip, **file_data})

    # 4. Final Report Generation and Saving
    total_issues = len(all_vuln_matches) + len(all_weak_creds) + len(all_exposed_files)

    report_data = report.create_report_data(
        hosts_found, total_issues, scanned_device_data,
        all_vuln_matches, all_weak_creds, all_exposed_files
    )
    
    # Save the report to a timestamped JSON file
    report.save_report_to_json(report_data)

    print(f"[FLASK] Scan complete for {hosts_found} hosts.")
    return {'status': 'success', 'message': f"Scan complete. Report saved for {hosts_found} hosts."}


# --- Flask Routes ---

@app.route('/')
def index():
    """Home page - shows latest summary and start scan button."""
    report_data = load_latest_report()
    return render_template('index.html', report=report_data)

@app.route('/start-scan', methods=['POST'])
def start_new_scan():
    """
    Initiates the scan. This request will BLOCK the server until the scan is complete.
    """
    
    # Set a simple 'running' status flag to show a message before the blocking call
    app.config['SCAN_RUNNING'] = True
    app.config['SCAN_MESSAGE'] = f"Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. Server is BLOCKED until scan is complete..."

    # The blocking call:
    perform_network_scan()

    # Clear the running flag and update the message after the scan finishes
    app.config['SCAN_RUNNING'] = False
    app.config['SCAN_MESSAGE'] = 'Scan completed successfully.'
    
    # Redirect immediately to the report page as the scan is done.
    return redirect(url_for('view_report'))

@app.route('/scan-status')
def scan_status():
    """
    The status page for the blocking model. 
    It will only show the 'running' message if the user navigates here 
    while /start-scan is still executing in the background (or manually).
    """
    status = {
        'running': app.config.get('SCAN_RUNNING', False),
        'message': app.config.get('SCAN_MESSAGE', 'No scan in progress.')
    }
    
    # If the scan is not running and a report exists, redirect to the report
    if not status['running'] and find_latest_report_path():
        return redirect(url_for('view_report'))

    return render_template('scan_status.html', scan_status=status)


@app.route('/report')
def view_report():
    """Page to view the detailed HTML report."""
    report_data = load_latest_report()
    if report_data:
        processed_report = process_host_overview_for_html(report_data)
        return render_template('report.html', report=processed_report, error=None)
    else:
        # The 'error' variable is used in report.html to display a message
        return render_template('report.html', report=None, error="No scan report available. Please run a scan first.")

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/education')
def education_page():
    return render_template('education.html')


# --- Run App ---
if __name__ == '__main__':
    # Initialize config flags
    app.config['SCAN_RUNNING'] = False
    app.config['SCAN_MESSAGE'] = 'Server initialized.'
    
    # NOTE: Running with debug=True is single-threaded, which reinforces the 
    # blocking nature of the integrated scan.
    app.run(debug=True, host='0.0.0.0', port=5000)