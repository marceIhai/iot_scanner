import threading
from concurrent.futures import ThreadPoolExecutor

from .config import COLOR_MAP, COMMON_PORTS, DEFAULT_CREDENTIALS
from .reporting import print_summary
from .analyzer import VulnerabilityAnalyzer

# --- MOCK SCAN RESULTS ---
# This dictionary simulates the raw output from a PortScanner run.
MOCK_RESULTS = [
    # 1. Critical: HTTP Weak Credential (Should trigger WEAK_CRED)
    {'ip': '192.168.1.10', 'port': 80, 'risk_category': 'WEAK_CRED', 'protocol': 'HTTP', 'username': 'admin', 'password': '123', 'banner': 'Server: Lighttpd/1.4.35'},
    
    # 2. Critical: Outdated Firmware/Banner (Should trigger VULN_MATCH)
    {'ip': '192.168.1.20', 'port': 21, 'risk_category': 'OPEN_PORT', 'protocol': 'TCP', 'banner': '220 vsFTPd 2.3.4 ready.'},
    
    # 3. High Risk: Known Vulnerable Web Server (Should trigger VULN_MATCH)
    {'ip': '192.168.1.30', 'port': 8080, 'risk_category': 'OPEN_PORT', 'protocol': 'TCP', 'banner': 'HTTP/1.1 200 OK Server: GoAhead/3.6.5'},
    
    # 4. Low Risk: Generic Open Port
    {'ip': '192.168.1.40', 'port': 22, 'risk_category': 'OPEN_PORT', 'protocol': 'TCP', 'banner': 'SSH-2.0-OpenSSH_7.4'},
    
    # 5. Low Risk: Silent Protocol (e.g., MQTT broker)
    {'ip': '192.168.1.50', 'port': 1883, 'risk_category': 'OPEN_PORT', 'protocol': 'TCP', 'banner': ''},
    
    # 6. Critical: Firmware Version Match (Should trigger VULN_MATCH)
    {'ip': '192.168.1.60', 'port': 80, 'risk_category': 'OPEN_PORT', 'protocol': 'HTTP', 'banner': 'HTTP/1.1 200 OK Server: Firmware v1.0.0'},
]


def handle_mock_execution(mock_results):
    """
    Bypasses the PortScanner and feeds mock results directly into the Analyzer and Reporter.
    """
    analyzer = VulnerabilityAnalyzer()
    
    print(f"\n{COLOR_MAP['HEADER']}--- RUNNING MOCK SCAN ---{COLOR_MAP['END']}")
    print(f"{COLOR_MAP['SUCCESS']}* Bypassing network connection. Using pre-defined results.{COLOR_MAP['END']}")

    # The analyzer processes the raw mock results
    all_results = analyzer.analyze_results(mock_results)

    # Print the final report
    print_summary(all_results)
    
    return all_results
