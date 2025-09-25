# Simple CVE matcher

def match_cves(cve_db, banner):
    """
    Checks if any entry in cve_db matches the device banner.
    
    cve_db: list of dicts, e.g. [{"banner": "vulnerable_device", "cve": "CVE-1234-5678"}]
    banner: string grabbed from device
    """
    if not banner:
        return []
    matched = []
    for entry in cve_db:
        if entry["banner"].lower() in banner.lower():
            matched.append(entry)
    return matched