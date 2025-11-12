# oui_parser.py

import re
import pprint

INPUT_FILE = "oui.txt"
OUTPUT_VAR_NAME = "OUI_DATABASE"

def parse_oui_file(filename):
    """
    Reads the raw IEEE oui.txt file and returns a dictionary 
    mapping the MAC prefix (OUI) to the company name.
    """
    oui_data = {}
    
    # Regex to find lines like: 00-00-00   (hex)		XEROX CORPORATION
    # It captures the OUI (Group 1) and the company name (Group 2)
    # The pattern looks for the hex block, ignores the '(hex)' and tabs, 
    # and then captures the remaining text as the company name.
    pattern = re.compile(r'\s*([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)')

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    # OUI prefix: 00-00-00 -> 00:00:00
                    oui = match.group(1).replace('-', ':')
                    # Company name: Trim whitespace
                    company = match.group(2).strip()
                    
                    if company:
                        oui_data[oui] = company
    except FileNotFoundError:
        print(f"Error: Input file '{filename}' not found. Did you save it?")
        return None
        
    return oui_data

if __name__ == "__main__":
    print(f"Starting OUI parsing from {INPUT_FILE}...")
    
    database = parse_oui_file(INPUT_FILE)
    
    if database:
        print(f"Successfully parsed {len(database)} entries.")
        print("\n--- COPY THE DICTIONARY BELOW AND PASTE IT INTO oui_db.py ---")
        
        # Print the dictionary in a format suitable for Python code
        print(f"{OUTPUT_VAR_NAME} = {{")
        # Use pprint to print the dict entries cleanly
        for key, value in database.items():
            # Escape quotes in company names
            safe_value = value.replace("'", "\\'")
            print(f"    '{key}': '{safe_value}',")
        print("}")
        print("----------------------------------------------------------------")