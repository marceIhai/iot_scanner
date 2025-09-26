import re
from .cve_fetcher import fetch_cves
from .cve_db import load_cve_db

def match_cves(cve_db, banner):
    """
    Try to match static CVE DB first.
    If not found, query NVD API.
    """
    if not banner:
        return []

    banner = banner.lower()
    matches = []

    # Static database lookup first
    for entry in cve_db:
        product = entry["product"].lower()
        version = entry["version"].lower()

        if product in banner and version in banner:
            matches.extend(entry["cves"])

    # Dynamic NVD lookup if nothing found
    if not matches:
        for entry in cve_db:
            product = entry["product"]
            version = entry["version"]
            if product.lower() in banner and version.lower() in banner:
                matches.extend(fetch_cves(product, version))

    return matches
