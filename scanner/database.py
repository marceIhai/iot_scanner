import sqlite3
import os
import sys

# Define the path to the database file
DB_NAME = 'vulnerabilities.db'
# This path construction correctly finds the DB one level up from the 'scanner' directory
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', DB_NAME)

def initialize_db():
    """Initializes the SQLite database and creates the necessary tables."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Table for known vulnerabilities (CVEs)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                banner_keyword TEXT NOT NULL UNIQUE,
                cve_id TEXT NOT NULL,
                description TEXT
            );
        """)
        
        # Table for default credentials
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS default_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                UNIQUE(username, password)
            );
        """)

        # Add initial weak credentials
        initial_credentials = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', '123456'),
            ('ubnt', 'ubnt')
        ]
        
        for user, pwd in initial_credentials:
            try:
                cursor.execute("INSERT INTO default_credentials (username, password) VALUES (?, ?)", (user, pwd))
            except sqlite3.IntegrityError:
                pass 

        conn.commit()
        conn.close()
    
    except sqlite3.Error as e:
        # In a real app, you would log this instead of printing to stderr
        print(f"Database error during initialization: {e}", file=sys.stderr)


def add_vulnerability(banner_keyword: str, cve_id: str, description: str) -> bool:
    """Inserts a new CVE entry. Used by cve_import.py."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR IGNORE INTO vulnerabilities (banner_keyword, cve_id, description)
            VALUES (?, ?, ?)
        """, (banner_keyword, cve_id, description))
        
        conn.commit()
        return cursor.rowcount > 0 
        
    except sqlite3.Error as e:
        print(f"Database error while adding vulnerability: {e}", file=sys.stderr)
        return False


def get_vulnerabilities_by_keyword(keyword: str):
    """Retrieves all vulnerabilities matching a partial banner keyword."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT cve_id, description FROM vulnerabilities 
            WHERE banner_keyword LIKE ?
        """, (f'%{keyword}%',))
        
        results = [{'cve_id': row[0], 'description': row[1]} for row in cursor.fetchall()]
        conn.close()
        return results
        
    except sqlite3.Error as e:
        print(f"Database error while getting vulnerabilities: {e}", file=sys.stderr)
        return []

def get_all_credentials():
    """Retrieves all default credentials."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT username, password FROM default_credentials")
        
        results = [{'username': row[0], 'password': row[1]} for row in cursor.fetchall()]
        conn.close()
        return results
        
    except sqlite3.Error as e:
        print(f"Database error while getting credentials: {e}", file=sys.stderr)
        return []

# Initialize DB when the module is imported
if __name__ != '__main__':
    initialize_db()