import sqlite3
import os
import sys

# The database file is expected in the project root
DB_NAME = 'vulnerabilities.db'
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_NAME)

if not os.path.exists(DB_PATH):
    print(f"Error: Database file not found at: {DB_PATH}", file=sys.stderr)
    sys.exit(1)

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Query the total count in the vulnerabilities table
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    total_vulns = cursor.fetchone()[0]
    
    # Query the total count in the default_credentials table
    cursor.execute("SELECT COUNT(*) FROM default_credentials")
    total_creds = cursor.fetchone()[0]
    
    conn.close()
    
    print("\n" + "="*50)
    print(f"✅ Database Verification Complete")
    print("="*50)
    print(f"File Path: {DB_PATH}")
    print(f"Total Vulnerability Entries: {total_vulns}")
    print(f"Total Default Credential Entries: {total_creds}")
    print("="*50)

except sqlite3.Error as e:
    print(f"SQLite Error: Could not read database file. Check permissions. Error: {e}", file=sys.stderr)
except Exception as e:
    print(f"An unexpected error occurred: {e}", file=sys.stderr)