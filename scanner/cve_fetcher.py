import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"

def fetch_cves(keyword, max_results=20):
    """
    Fetch CVEs from NVD API for a given keyword (product or vendor).
    Returns a list of CVE dictionaries.
    """
    params = {
        "keyword": keyword,
        "resultsPerPage": max_results
    }
    response = requests.get(NVD_API_URL, params=params)
    response.raise_for_status()  # will raise an error if request fails
    data = response.json()
    cves = []
    for item in data.get("result", {}).get("CVE_Items", []):
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        cvss_score = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
        cves.append({
            "id": cve_id,
            "description": description,
            "cvss": cvss_score
        })
    return cves
