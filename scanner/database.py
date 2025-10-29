import sqlite3
import os
import sys

# --- Configuration ---
DB_FILE = 'vulnerabilities.db'
INITIAL_VULNERABILITIES = [
    # (Banner_Keyword, CVE_ID, Description)
    ("GoAhead/2.5.0", "CVE-2017-17518", "GoAhead web server RCE (pre-2.5.1)."),
    ("GoAhead/3.6.5", "CVE-2021-46487", "GoAhead web server authenticated RCE."),
    ("BusyBox v1.1.1", "CVE-2016-7406", "Multiple vulnerabilities in older BusyBox versions."),
    ("vsftpd 2.3.4", "CVE-2011-0762", "vsftpd backdoor vulnerability."),
    ("Firmware v1.0.0", "CVE-2023-9999", "Highly outdated device firmware (Check vendor site)."),
    ("D-Link DIR-605L", "HIGH_RISK", "Known RCE vulnerability in specific router model."),
]

def initialize_db():
    """
    Creates the SQLite database file and populates the vulnerability table if it doesn't exist.
    """
    # Connect to the database file (creates it if it doesn't exist)
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Create table for vulnerabilities
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                banner_keyword TEXT NOT NULL UNIQUE,
                cve_id TEXT NOT NULL,
                description TEXT
            );
        """)
        conn.commit()

        # Check if table is empty and populate it
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        if cursor.fetchone()[0] == 0:
            print(f"[*] Populating initial vulnerability database: {DB_FILE}")
            cursor.executemany("""
                INSERT OR IGNORE INTO vulnerabilities (banner_keyword, cve_id, description)
                VALUES (?, ?, ?)
            """, INITIAL_VULNERABILITIES)
            conn.commit()
            
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}", file=sys.stderr)
    finally:
        if conn:
            conn.close()

def search_vulnerability_db(keyword):
    """
    Searches the database for a vulnerability match based on a banner keyword.
    
    Args:
        keyword (str): A service banner or software version string.
        
    Returns:
        tuple or None: (cve_id, description) if found, otherwise None.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Use LIKE for case-insensitive partial matching
        # NOTE: This uses the banner_keyword *from the database* as the match string.
        # This is a robust way to match "vsftpd 2.3.4" (DB) against a banner like 
        # "220 (vsftpd 2.3.4) ready." (Scan result).
        
        cursor.execute("""
            SELECT cve_id, description FROM vulnerabilities 
            WHERE ? LIKE '%' || banner_keyword || '%' COLLATE NOCASE
            LIMIT 1;
        """, (keyword,))
        
        return cursor.fetchone() # Returns (cve_id, description) or None
        
    except sqlite3.Error as e:
        print(f"Database query error: {e}", file=sys.stderr)
        return None
    finally:
        if conn:
            conn.close()

# Initialize the database immediately when the module is loaded
initialize_db()