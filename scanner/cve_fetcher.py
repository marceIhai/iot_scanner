# cve_fetcher.py
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves(product, version, limit=5, api_key=None):
    """
    Fetch CVEs from NVD API for a given product and version.
    Returns a list of CVE IDs.
    """
    query = f"{product} {version}"
    params = {"keywordSearch": query, "resultsPerPage": limit}
    headers = {}

    if api_key:
        headers["apiKey"] = api_key

    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            cves.append(cve_id)

        return cves
    except Exception as e:
        print(f"[ERROR] Fetch failed for {product} {version}: {e}")
        return []
