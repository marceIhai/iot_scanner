# vulnmatch.py

import sqlite3
from typing import Dict, List, Any

def match_vulnerabilities(tcp_services: Dict[int, str], db_path: str = "vulnerabilities.db") -> Dict[str, List[Dict[str, str]]]:
    """
    Matches captured service banners against a vulnerabilities database.

    Args:
        tcp_services: A dictionary where key is the port (int) and value is the banner (str).
        db_path: Path to the SQLite vulnerability database file.

    Returns:
        A dictionary mapping the banner string to a list of matching vulnerabilities.
    """
    vulnerability_matches: Dict[str, List[Dict[str, str]]] = {}
    
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # We need to process each unique banner string just once
        unique_banners = set(tcp_services.values())
        
        print(f"[*] Checking {len(unique_banners)} unique banners against {db_path}...")

        for banner in unique_banners:
            # Clean and normalize the banner for robust matching (e.g., removing version numbers)
            # Example: For 'SSH-2.0-dropbear_2012.55', we want to check for 'dropbear' or '2012.55'
            
            # The simplest form of matching is using the whole banner, but for better results,
            # we'll look for any word in the banner that matches a keyword in the DB.
            # However, for a simple solution, we'll assume the DB keyword covers the relevant part.
            
            # Use SQLite's LIKE operator for case-insensitive partial matching.
            # The query searches for a keyword that is contained within the banner,
            # OR the banner contains the keyword.
            
            # We'll search for the keyword in the banner:
            query = """
                SELECT cve_id, description, banner_keyword
                FROM vulnerabilities
                WHERE INSTR(?, banner_keyword) > 0  -- banner contains the keyword
            """
            
            # If the database structure allowed for better matching, we would use a more complex query.
            # Assuming the banner_keyword is the part of the banner we need (e.g., 'dropbear_2012.55')
            # Let's use a simpler, broader query for the first iteration:
            
            query = """
                SELECT cve_id, description, banner_keyword
                FROM vulnerabilities
                WHERE ? LIKE '%' || banner_keyword || '%'
            """
            
            # Execute the query with the banner as the input parameter
            cursor.execute(query, (banner,))
            results = cursor.fetchall()

            if results:
                # Store all found vulnerabilities for this specific banner
                vulnerability_matches[banner] = []
                for result in results:
                    vulnerability_matches[banner].append({
                        'cve_id': result[0],
                        'description': result[1],
                        'matched_keyword': result[2]
                    })
        
    except sqlite3.OperationalError as e:
        print(f"[!!!] SQLite Error: Could not read from table 'vulnerabilities'. Check table or column names: {e}")
    except sqlite3.Error as e:
        print(f"[!!!] SQLite Database Error: {e}")
    except Exception as e:
        print(f"[!!!] General Error during vulnerability matching: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()
            
    return vulnerability_matches