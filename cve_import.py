import json
import sys
import os
import argparse
import re
import sqlite3
from typing import Optional, Dict, Any, List

current_dir = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(current_dir, 'vulnerabilities.db')

def initialize_db():
    """Ensures the SQLite database and the 'vulnerabilities' table exist."""
    print(f"[*] Initializing database table at {DB_PATH}...")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # The table structure uses banner_keyword as the PRIMARY KEY to prevent duplicates
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                banner_keyword TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                description TEXT
            )
        """)
        conn.commit()
        conn.close()
        print("[+] Database table 'vulnerabilities' ready.")
        return True
    except sqlite3.Error as e:
        print(f"[!] FATAL DB Error: {e}", file=sys.stderr)
        return False


# --- Utility Functions ---

def clean_cpe_part(part: str) -> str:
    if part in ['*', '-', 'n', 'a', 'any', 'none', ':-', '0', 'x']:
        return ''
    # Only allow letters, numbers, dots, and hyphens/underscores
    cleaned = re.sub(r'[^a-zA-Z0-9._-]', '', part)
    return cleaned.strip()


def find_first_cpe_uri(data: Any) -> Optional[str]:
    if isinstance(data, str) and data.startswith('cpe:2.3:'):
        return data

    elif isinstance(data, dict):
        for key, value in data.items():
            if key in ['cpe23Uri', 'criteria'] and isinstance(value, str) and value.startswith('cpe:2.3:'):
                return value
            result = find_first_cpe_uri(value)
            if result:
                return result
    
    elif isinstance(data, list):
        for item in data:
            result = find_first_cpe_uri(item)
            if result:
                return result
    
    return None

def extract_keyword_from_cpe(cve_data: Dict[str, Any]) -> Optional[str]:
    cpe_uri = find_first_cpe_uri(cve_data)
    
    if not cpe_uri:
        return None

    parts = cpe_uri.split(':')
    
    # We require at least 6 parts (cpe, 2.3, a, vendor, product, version)
    if len(parts) >= 6:
        # Product is parts[4], Version is parts[5]
        product = clean_cpe_part(parts[4]).lower().replace('_', ' ').replace('-', ' ')
        version = clean_cpe_part(parts[5]).lower()
        
        # --- RELAXED LOGIC ---
        is_generic_placeholder = (version in ['any', '0', 'x', 'z', 'na', '1.0', '1.0.0'])

        if product:
            # 1. If the version is specific (not a known generic placeholder), use both.
            if version and not is_generic_placeholder and len(version) > 1:
                final_keyword = f"{product} {version}"
                return final_keyword
            # 2. If the version IS generic (or missing), use ONLY the product name.
            # This captures ancient, unpatched software like vsFTPd 2.3.4.
            else: 
                return product # <-- This re-introduces generic product keywords
        
    return None

def parse_and_insert_cve_json(filename: str):
    """
    Loads the JSON file and inserts vulnerabilities into the database using batching.
    """
    abs_filename = os.path.abspath(filename)
    
    if not os.path.exists(abs_filename):
        print(f"[E] Error: Input file not found: {abs_filename}", file=sys.stderr)
        return

    # Initialize the database (this will create it if it doesn't exist)
    if not initialize_db():
        return

    print(f"{os.linesep}--- Starting JSON import from {abs_filename} ---")
    
    try:
        with open(abs_filename, 'r', encoding='utf-8') as f:
            data = json.load(f)

        cve_list = data.get('vulnerabilities', data.get('CVE_Items', []))
        
        if not cve_list:
            print("[i] JSON file appears to be empty or does not contain 'vulnerabilities' or 'CVE_Items' keys.")
            return

        total_processed = len(cve_list)
        print(f"[i] Found {total_processed} CVE entries to process.")
        
        # --- BATCHING CONFIGURATION ---
        BATCH_SIZE = 500
        records_to_insert = []
        
        # Use a temporary connection for the batch operation
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        for i, entry in enumerate(cve_list):
            
            cve_data = entry.get('cve', entry) 
            cve_id = cve_data.get('id', cve_data.get('CVE_data_meta', {}).get('ID', 'N/A'))
            
            # Extract English description (best effort)
            description_text = 'No English description available.'
            try:
                descriptions = cve_data.get('descriptions', [])
                description_text = next((d['value'] for d in descriptions if d.get('lang') == 'en'), description_text)
                
                if description_text == 'No English description available.':
                    desc_data = cve_data.get('description', {}).get('description_data', [])
                    description_text = next((d['value'] for d in desc_data if d.get('lang') == 'en'), desc_data[0]['value'])

            except Exception:
                pass

            # --- KEYWORD GENERATION (Using the relaxed product/version logic) ---
            banner_keyword = extract_keyword_from_cpe(cve_data) 
            
            if not banner_keyword:
                # Skips entries with no identifiable product
                continue
            
            # Truncate keyword and description
            keyword_to_insert = banner_keyword[:100]
            description_to_insert = description_text.strip()[:255]

            # Prepare record for batch insertion
            records_to_insert.append((keyword_to_insert, cve_id.strip(), description_to_insert))
            
            # Execute batch insert
            if len(records_to_insert) >= BATCH_SIZE:
                # Use INSERT OR IGNORE to handle duplicate banner_keywords gracefully
                cursor.executemany("""
                    INSERT OR IGNORE INTO vulnerabilities (banner_keyword, cve_id, description) 
                    VALUES (?, ?, ?)
                """, records_to_insert)
                
                conn.commit()
                records_to_insert = []
                
                sys.stdout.write(f"Progress: {i+1}/{total_processed} items processed...\r")
                sys.stdout.flush()

        # Final commit for any remaining records
        if records_to_insert:
            cursor.executemany("""
                INSERT OR IGNORE INTO vulnerabilities (banner_keyword, cve_id, description) 
                VALUES (?, ?, ?)
            """, records_to_insert)
            conn.commit()
            
        # Get the final count of records in the database
        final_inserted_count = cursor.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

        sys.stdout.write(f"Progress: {total_processed}/{total_processed} items processed.{os.linesep}")
        sys.stdout.flush()
        
    except sqlite3.Error as e:
        print(f"[E] Database Transaction Error: {e}", file=sys.stderr)
    except json.JSONDecodeError:
        print(f"[E] Error: Could not decode JSON file {abs_filename}. Check file format.", file=sys.stderr)
    except Exception as e:
        print(f"[E] An unexpected error occurred during import: {e}", file=sys.stderr)
    finally:
        if 'conn' in locals() and conn:
            conn.close()

    print(f"--- JSON Import Complete ---")
    print(f"Total entries processed: {total_processed}")
    print(f"Current total vulnerability entries in DB: {final_inserted_count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Utility to import CVE JSON data into the local SQLite database.")
    parser.add_argument("filename", help="Path to the external JSON file (e.g., nvd_export.json).")
    
    args = parser.parse_args()
    parse_and_insert_cve_json(args.filename)