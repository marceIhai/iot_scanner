# utils.py

import os
import json
from typing import Dict, Any

REPORT_DIR = 'scan_reports'

def find_latest_report_path() -> str | None:
    """
    Finds the full path to the most recently created scan report JSON file
    in the REPORT_DIR.
    """
    if not os.path.exists(REPORT_DIR):
        return None
        
    try:
        # List all files and filter for JSON files starting with 'scan_report_'
        list_of_files = [
            os.path.join(REPORT_DIR, f) 
            for f in os.listdir(REPORT_DIR) 
            if f.startswith('scan_report_') and f.endswith('.json')
        ]
        
        if not list_of_files:
            return None
            
        # Sort files by creation time (stat.st_ctime) and get the newest one
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