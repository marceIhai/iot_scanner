import json
import sys
import os
import argparse
import re
from typing import Optional, Dict, Any, List

# --- Path Adjustment ---
# Ensures the script can find scanner.database when run directly
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = current_dir
sys.path.insert(0, project_root)
# -------------------------------------------------------------

# Imports from scanner/database.py
try:
    from scanner.database import add_vulnerability, initialize_db, DB_PATH 
except ImportError as e:
    # If this fails, the core database file is missing or broken.
    print(f"FATAL ERROR: Could not import database utility: {e}. Ensure scanner/database.py is correct.", file=sys.stderr)
    sys.exit(1)


def clean_cpe_part(part: str) -> str:
    """
    Cleans up a single CPE part by removing wildcards, common generics, and non-essential characters.
    """
    if part in ['*', '-', 'n', 'a', 'any', 'none']:
        return ''
    # Only allow letters, numbers, dots, and hyphens/underscores (common in versions/products)
    cleaned = re.sub(r'[^a-zA-Z0-9._-]', '', part)
    return cleaned.strip()


def find_first_cpe_uri(data: Any) -> Optional[str]:
    """
    Recursively searches the CVE data structure for the first valid CPE URI 
    (starting with 'cpe:2.3:'). This handles both NVD 1.1 and 2.0 structures.
    """
    
    # Base case: If data is a string
    if isinstance(data, str) and data.startswith('cpe:2.3:'):
        return data

    # Recursive case: If data is a dictionary
    elif isinstance(data, dict):
        for key, value in data.items():
            # Check for common CPE keys in new NVD format
            if key in ['cpe', 'criteria', 'cpe23Uri'] and isinstance(value, str) and value.startswith('cpe:2.3:'):
                return value
            
            # Recurse into nested structures
            result = find_first_cpe_uri(value)
            if result:
                return result
    
    # Recursive case: If data is a list
    elif isinstance(data, list):
        for item in data:
            result = find_first_cpe_uri(item)
            if result:
                return result
    
    return None


def extract_keyword_from_cpe(cve_data: Dict[str, Any]) -> Optional[str]:
    """
    Extracts the highest-quality, cleaned product/version keyword from the CPE string.
    """
    cpe_uri = find_first_cpe_uri(cve_data)
    
    if not cpe_uri:
        return None

    # CPE format: cpe:2.3:a:vendor:product:version:update:...
    parts = cpe_uri.split(':')
    
    if len(parts) >= 6:
        vendor = clean_cpe_part(parts[3]).lower()
        product = clean_cpe_part(parts[4]).lower()
        version = clean_cpe_part(parts[5]).lower()
        
        # 1. Prioritize Product/Version (e.g., 'vsftpd/3.0.3')
        if product and version:
            return f"{product}/{version}"
        # 2. Fallback to just Product name
        elif product:
            return product
        # 3. Fallback to just Vendor (if product is not specific)
        elif vendor:
            return vendor
    
    return None


def parse_and_insert_cve_json(filename: str):
    """
    Loads the JSON file and inserts vulnerabilities into the database.
    """
    abs_filename = os.path.abspath(filename)
    
    if not os.path.exists(abs_filename):
        print(f"Error: Input file not found: {abs_filename}", file=sys.stderr)
        return

    # Ensure DB is ready before starting
    initialize_db() 
    
    print(f"DEBUG: Database file expected at: {DB_PATH}")
    
    successful_inserts = 0
    skipped_count = 0
    total_processed = 0

    print(f"{os.linesep}--- Starting JSON import from {abs_filename} ---")
    
    try:
        with open(abs_filename, 'r', encoding='utf-8') as f:
            data = json.load(f)

        cve_list = data.get('vulnerabilities', [])
        if not cve_list:
             # Fallback for older NVD 1.1 format which starts with "CVE_Items"
             cve_list = data.get('CVE_Items', [])

        for entry in cve_list:
            total_processed += 1
            
            # For NVD 2.0, the CVE object is nested inside the entry
            cve_data = entry.get('cve', entry) 
            cve_id = cve_data.get('id', 'N/A')
            
            # Extract English description
            descriptions = cve_data.get('descriptions', [])
            description_text = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 
                                    'No English description available.')

            banner_keyword = extract_keyword_from_cpe(cve_data) 
            
            if not banner_keyword:
                # If no usable CPE keyword is found, skip
                skipped_count += 1
                continue
            
            # Ensure the keyword is not excessively long
            keyword_to_insert = banner_keyword.strip()
            if len(keyword_to_insert) > 100:
                 keyword_to_insert = keyword_to_insert[:100] 

            if add_vulnerability(keyword_to_insert, cve_id.strip(), description_text.strip()):
                successful_inserts += 1
                if successful_inserts % 100 == 0:
                    sys.stdout.write(f"Progress: {successful_inserts} items inserted...\r")
                    sys.stdout.flush()
            else:
                skipped_count += 1
        
        sys.stdout.write(f"Progress: {successful_inserts} items inserted...{os.linesep}")
        sys.stdout.flush()

    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON file {abs_filename}. Check file format.", file=sys.stderr)
        return
    except Exception as e:
        print(f"An unexpected error occurred during import: {e}", file=sys.stderr)
        return
        
    print(f"--- JSON Import Complete ---")
    print(f"Total entries processed: {total_processed}")
    print(f"Successfully added: {successful_inserts} new vulnerability entries.")
    print(f"Skipped (existing or incomplete data): {skipped_count} entries.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Utility to import CVE JSON data into the local SQLite database.")
    parser.add_argument("filename", help="Path to the external JSON file (e.g., nvd_export.json).")
    
    args = parser.parse_args()
    parse_and_insert_cve_json(args.filename)