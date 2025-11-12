# main.py (UPDATED to use report.py for JSON output)

import sys
import os
import discover as discover
import fingerprint as fingerprint 
import vulnmatch as vulnmatch 
import credentials as credentials 
import exposedfiles as exposedfiles 
import report as report # <-- NEW IMPORT
from typing import Dict, List, Any

# Ensure a reasonable width for the final report separators
total_width = 70 

def main():
    """
    Main function to start and manage the network discovery tool,
    with a focus on simple progress and a final summary report,
    including JSON output.
    """
    
    # 1. INITIAL SETUP & VALIDATION
    print("======================================================================")
    print("🚀 Network Discovery Tool - Running with Security Analysis")
    print("======================================================================")

    try:
        # Check for required library before starting the main logic
        from scapy.all import ARP, Ether, srp, DNS, Raw, DNSQR, IP, TCP, UDP, ICMP
    except ImportError:
        print("\n[!!!] CRITICAL ERROR: The 'scapy' library is not installed.")
        print("Please install it using: 'pip install scapy'")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!!!] An unexpected error occurred during scapy check: {e}")
        sys.exit(1)
        
    # --- Step 1: Identify Subnet ---
    print("\n[+] Identifying local subnet...")
    subnet_cidr = discover.get_started() 
    
    if not subnet_cidr:
        print("\n[!] Cannot proceed without a valid local IP and subnet.")
        sys.exit(1)

    # Check for root privileges on Linux/macOS
    if os.name != 'nt' and os.geteuid() != 0:
        print("\n[!!!] CRITICAL ERROR: Scapy requires root/administrator privileges.")
        print("Please run this script with 'sudo'.")
        sys.exit(1)

    # --- Step 2: Scan Subnet & Count Hosts ---
    print("\n[+] Scanning subnet for active hosts...")
    active_devices = discover.scan_subnet(subnet_cidr)
    hosts_found = len(active_devices)

    if hosts_found == 0:
        print("\n[!] No active devices found (besides likely yourself) responded to the scan. Exiting.")
        sys.exit(0)

    # Show initial successful count
    print(f"✅ Found {hosts_found} active host(s). Starting security analysis...")

    # --- Step 3: Silent Analysis & Data Collection ---
    
    all_vuln_matches = []
    all_weak_creds = []
    all_exposed_files = []
    scanned_device_data = []

    # Iterate through all discovered devices
    for i, device in enumerate(active_devices):
        ip = device['ip']
        mac = device['mac']
        
        # Use the correct function name oui_lookup
        vendor = discover.oui_lookup(mac) 
        
        # Show progress for each device being analyzed
        print(f"  [Progress] Analyzing host {i+1} of {hosts_found}: {ip}...")
        
        # 1. Fingerprint
        fp_data = fingerprint.get_full_fingerprint(ip) 
        
        # Store all data for the final report
        device_data = {
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'fp_data': fp_data 
        }
        scanned_device_data.append(device_data)

        # 2. Vulnerability Matching (Collect results)
        if fp_data.get('tcp_services'):
            vulnerabilities = vulnmatch.match_vulnerabilities(fp_data['tcp_services'])
            
            for banner, vulns in vulnerabilities.items():
                for vuln in vulns:
                    all_vuln_matches.append({
                        'ip': ip, 
                        **vuln,
                        'banner': banner
                    })
        
        # 3. Weak Credentials Check (Collect results)
        weak_creds = credentials.check_weak_credentials(ip=ip, fingerprint_data=fp_data)
        for cred in weak_creds:
            all_weak_creds.append({
                'ip': ip,
                **cred
            })
            
        # 4. Exposed Files Check (Collect results)
        exposed_files_found = exposedfiles.check_for_exposed_files(ip=ip, fingerprint_data=fp_data)
        for file_data in exposed_files_found:
            all_exposed_files.append({
                'ip': ip,
                **file_data
            })

    # --- Step 4: Final Summary Report ---
    
    # Calculate totals
    total_vulns = len(all_vuln_matches)
    total_creds = len(all_weak_creds)
    total_files = len(all_exposed_files)
    total_issues = total_vulns + total_creds + total_files

    print("\n" * 2)
    print("#" * total_width)
    print(f"## 🏆 SCAN COMPLETE - FINAL SECURITY REPORT ({hosts_found} Hosts Scanned)")
    print("#" * total_width)
    
    # Summary Header
    print(f"| Hosts Found: {hosts_found:<10} | Total Issues Found: {total_issues:<10} |")
    print("-" * total_width)

    # --- SECTION A: Host Overview ---
    print(f"## 💻 A. HOST OVERVIEW ({hosts_found} Devices)")
    
    print(f"{'IP Address':<18}{'MAC Address':<18}{'Vendor':<20}{'OS Guess':<12}")
    print("-" * total_width)
    for device in scanned_device_data:
        ip = device['ip']
        mac = device['mac']
        vendor = device.get('vendor', 'N/A')
        os_guess = device['fp_data'].get('os', 'N/A')
        
        print(f"{ip:<18}{mac:<18}{vendor:<20}{os_guess:<12}")

    print("-" * total_width)

    # --- SECTION B: Detailed Vulnerability Matches ---
    print(f"## 🔴 B. VULNERABILITY MATCHES ({total_vulns} findings)")
    if all_vuln_matches:
        ip_to_vulns = {}
        for vuln in all_vuln_matches:
            ip_to_vulns.setdefault(vuln['ip'], []).append(vuln)

        for ip, vulns in ip_to_vulns.items():
            print(f"\n   > Host **{ip}** (Found {len(vulns)} vulnerability match(es)):")
            for vuln in vulns:
                print(f"     - **CVE**: {vuln['cve_id']}")
                print(f"       - Matched Banner: '{vuln['banner']}'")
                print(f"       - Description: {vuln['description']}")
    else:
        print("   ✅ No known service vulnerabilities found.")

    print("-" * total_width)

    # --- SECTION C: Weak/Default Credentials ---
    print(f"## 🔑 C. WEAK/DEFAULT CREDENTIALS ({total_creds} findings)")
    if all_weak_creds:
        ip_to_creds = {}
        for cred in all_weak_creds:
            ip_to_creds.setdefault(cred['ip'], []).append(cred)
            
        for ip, creds in ip_to_creds.items():
            print(f"\n   > Host **{ip}** (Found {len(creds)} successful login(s)):")
            for cred in creds:
                # SAFE ACCESS: Use .get('port', 'N/A')
                port_value = cred.get('port', 'N/A')
                print(f"     - **Service**: {cred['service']} on Port {port_value}")
                print(f"       - Login: {cred['username']}:{cred['password']}")
    else:
        print("   ✅ No weak/default credentials found.")

    print("-" * total_width)

    # --- SECTION D: Exposed Sensitive Files ---
    print(f"## 📄 D. EXPOSED SENSITIVE FILES ({total_files} findings)")
    if all_exposed_files:
        ip_to_files = {}
        for file_data in all_exposed_files:
            ip_to_files.setdefault(file_data['ip'], []).append(file_data)
            
        for ip, files in ip_to_files.items():
            print(f"\n   > Host **{ip}** (Found {len(files)} exposed file(s)):")
            for file_data in files:
                print(f"     - **URL**: {file_data['url']}")
                print(f"       - Status Code: {file_data['status_code']}")
    else:
        print("   ✅ No commonly exposed sensitive files found.")

    print("\n" + "#" * total_width)

    # --- JSON Saving (New Feature) ---
    print("\n[+] Generating JSON report...")
    report_data = report.create_report_data(
        hosts_found,
        total_issues,
        scanned_device_data,
        all_vuln_matches,
        all_weak_creds,
        all_exposed_files
    )
    
    filepath = report.save_report_to_json(report_data)
    print(f"✅ Report saved successfully to: {filepath}")
    
if __name__ == "__main__":
    main()