# report.py

import json
from datetime import datetime
import os
from typing import Dict, List, Any

# Define the default output directory for reports
OUTPUT_DIR = "scan_reports"

def create_report_data(
    hosts_found: int,
    total_issues: int,
    scanned_device_data: List[Dict[str, Any]],
    all_vuln_matches: List[Dict[str, Any]],
    all_weak_creds: List[Dict[str, Any]],
    all_exposed_files: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Assembles all scan results into a single, structured dictionary.
    """
    
    # Simple summary of all findings
    summary = {
        'timestamp': datetime.now().isoformat(),
        'hosts_found': hosts_found,
        'total_issues_found': total_issues,
        'vulnerability_matches_count': len(all_vuln_matches),
        'weak_credentials_count': len(all_weak_creds),
        'exposed_files_count': len(all_exposed_files),
    }

    # Detailed report sections
    report_data = {
        'summary': summary,
        'host_overview': scanned_device_data,
        'vulnerability_matches': all_vuln_matches,
        'weak_credentials': all_weak_creds,
        'exposed_files': all_exposed_files
    }
    
    return report_data

def save_report_to_json(report_data: Dict[str, Any]) -> str:
    """
    Saves the structured report data to a timestamped JSON file.

    Returns the full path to the saved file.
    """
    # 1. Ensure the output directory exists
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    # 2. Create a unique filename based on the timestamp
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp_str}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)

    try:
        # 3. Write the data to the JSON file
        with open(filepath, 'w') as f:
            # Use indent=4 for human-readable output
            json.dump(report_data, f, indent=4)
            
        return filepath
        
    except IOError as e:
        print(f"[!!!] Error saving report to JSON file: {e}")
        return "Error saving file."
    except Exception as e:
        print(f"[!!!] An unexpected error occurred during JSON saving: {e}")
        return "Error saving file."