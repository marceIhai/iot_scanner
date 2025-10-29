# scanner/analyzer.py

import sys
from .config import COLOR_MAP
from .reporting import print_result
from .database import search_vulnerability_db

class VulnerabilityAnalyzer:
    """
    Analyzes scan results (open ports, service banners, and credential checks)
    to identify vulnerabilities and potential risks.
    """

    def analyze_results(self, scan_results):
        """
        Processes the list of results from PortScanner and correlates them
        with known vulnerabilities.

        Args:
            scan_results (list): A list of dictionaries, where each dict 
                                 represents a finding (open port, weak login, etc.).
        
        Returns:
            list: A structured list of comprehensive findings.
        """
        
        # Structure for the final report
        comprehensive_findings = []
        
        for result in scan_results:
            finding = {
                "ip": result.get("ip"),
                "port": result.get("port"),
                "status": result.get("status"),
                "risk": "LOW",
                "details": []
            }
            
            # --- 1. Check for Weak Credentials ---
            if result.get("status") == "WEAK_CREDENTIALS":
                finding['risk'] = "HIGH"
                finding['details'].append({
                    "type": "Authentication Bypass",
                    "description": f"Successfully logged in using default credentials: {result.get('username')}:{result.get('password')}",
                    "cve": "N/A - Default Setup Risk"
                })

            # --- 2. Check Service Banner Against SQLite DB ---
            elif result.get("banner"):
                banner = result['banner']
                
                # Query the SQLite database using the banner as a keyword
                vulnerability = search_vulnerability_db(banner)
                
                if vulnerability:
                    cve_id, description = vulnerability
                    
                    # Mark risk based on successful database match
                    finding['risk'] = "CRITICAL" if "RCE" in description or "HIGH" in cve_id else "MEDIUM"
                    finding['details'].append({
                        "type": "Known Vulnerability (Banner Match)",
                        "description": f"Service identified as '{banner}'. Known vulnerability detected: {description}",
                        "cve": cve_id
                    })

            # Add finding only if it poses a risk or has detailed results
            if finding['risk'] != "LOW" or finding['details']:
                comprehensive_findings.append(finding)
                
        return comprehensive_findings

    def print_summary(self, summary):
        """
        Prints the final, organized summary of vulnerabilities to the console.
        """
        
        # Group by risk level for prioritized reporting
        risk_groups = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": []
        }
        
        for finding in summary:
            risk_groups[finding['risk']].append(finding)
            
        print(f"\n{COLOR_MAP['HEADER']}--- VULNERABILITY ANALYSIS SUMMARY ---{COLOR_MAP['END']}")
        
        total_findings = sum(len(group) for group in risk_groups.values())
        if total_findings == 0:
            print(f"{COLOR_MAP['SUCCESS']}No significant vulnerabilities or default credentials found.{COLOR_MAP['END']}")
            return

        # Print risks in order of severity
        for risk_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            findings = risk_groups[risk_level]
            if not findings:
                continue

            # Determine the color based on the risk level
            color = COLOR_MAP['ERROR'] if risk_level in ["CRITICAL", "HIGH"] else COLOR_MAP['WARNING']

            print(f"\n{color}--- {risk_level} RISKS ({len(findings)}) ---{COLOR_MAP['END']}")
            
            for finding in findings:
                ip_port = f"{finding['ip']}:{finding['port']}" if finding['port'] else finding['ip']
                print(f"  [{color}{finding['risk']}{COLOR_MAP['END']}] Target: {ip_port}")
                
                for detail in finding['details']:
                    cve_str = f" (CVE: {detail['cve']})" if detail['cve'] and detail['cve'] != 'N/A' else ""
                    print(f"    - Type: {detail['type']}")
                    print(f"      Detail: {detail['description']}{cve_str}")
                print("-" * 30)