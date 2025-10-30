import argparse
import sys
import os
import time

# Adjust Python Path to ensure relative imports work correctly
# This is necessary because the scanner files are in a subdirectory
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Imports from scanner and project root
from scanner.scanner import PortScanner
from scanner.database import initialize_db
from scanner.reporting import parse_targets, print_result
from scanner.config import DEFAULT_PORTS, MAX_THREADS
from scanner.analyzer import VulnerabilityAnalyzer 

def main():
    """
    Main function to parse arguments, initialize components, and start the scan.
    """
    
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="IoT Vulnerability Scanner: Discovers open ports, grabs banners, and checks for known CVEs and weak credentials.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        'target', 
        type=str, 
        help="Target IP(s) or CIDR range (e.g., '192.168.1.1', '192.168.1.0/24', or '192.168.1.1,192.168.1.2')."
    )
    
    parser.add_argument(
        '-p', '--ports', 
        type=str, 
        default=f"{','.join(map(str, DEFAULT_PORTS))}", 
        help=f"Ports to scan (e.g., '21,80,443' or '1-1024'). Default: {', '.join(map(str, DEFAULT_PORTS))}."
    )
    
    parser.add_argument(
        '-t', '--threads', 
        type=int, 
        default=MAX_THREADS, 
        help=f"Maximum number of concurrent threads. Default: {MAX_THREADS}."
    )
    
    args = parser.parse_args()
    
    # --- Initialization ---
    start_time = time.time()
    
    # 1. Initialize the Database (Ensures iot_vulns.db exists)
    print_result("System", 0, "Database", "INFO", "Initializing local vulnerability database...")
    initialize_db() 
    print_result("System", 0, "Database", "INFO", "Database initialization complete.")

    # 2. Parse Targets
    targets = parse_targets(args.target)
    if not targets:
        sys.exit(1)
        
    # 3. Parse Ports
    try:
        # Handle port ranges (e.g., '1-1024') or comma-separated lists
        port_list = []
        for item in args.ports.split(','):
            if '-' in item:
                start, end = map(int, item.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(item))
        
        # Remove duplicates and sort
        ports = sorted(list(set(p for p in port_list if 1 <= p <= 65535)))
        
        if not ports:
            print_result("System", 0, "Error", "WARNING", "No valid ports selected.")
            sys.exit(1)
            
    except ValueError:
        print_result("System", 0, "Error", "WARNING", "Invalid port format. Use '80,443' or '1-1024'.")
        sys.exit(1)
    
    
    # --- Scanning ---
    
    # 4. Create and Start Scanner
    scanner = PortScanner(targets, ports)
    scanner.start_scan()
    
    end_time = time.time()

    # --- Analysis & Reporting ---
    raw_results = scanner.get_results() # Get all results from the scanner
    if raw_results:
        analyzer = VulnerabilityAnalyzer()
        final_findings = analyzer.analyze_scan_results(raw_results) 

        print("\n" + "="*80)
        print("VULNERABILITY AND CREDENTIAL ANALYSIS REPORT".center(80))
        print("="*80)
        
        if final_findings:
            for finding in final_findings:
                # Assuming print_result is a function that can format and print this data
                print_result(
                    ip=finding.get('ip', 'N/A'), 
                    port=finding.get('port', 0), 
                    service=finding.get('service', 'N/A'), 
                    risk=finding.get('risk', 'LOW'), 
                    message=f"Multiple Findings: {', '.join([d['description'] for d in finding.get('details', [])])}"
                )
        else:
            print_result("System", 0, "Analysis", "INFO", "No vulnerabilities or weak credentials found.")
    
    # --- Final Report ---
    print(f"\n[SUMMARY] Scan finished in {end_time - start_time:.2f} seconds.")
    print(f"[SUMMARY] Total targets scanned: {len(targets)}")
    # Note: Accessing the results property is more reliable than using a separate get_results() call if available
    print(f"[SUMMARY] Total open ports found: {len([r for r in scanner.results if r.get('status') == 'OPEN'])}")
    
if __name__ == '__main__':
    main()