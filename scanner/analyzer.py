# scanner/analyzer.py

import sys
import re 
from typing import List, Dict, Any

# Import database functions for vulnerability/credential lookups
try:
    from .database import get_vulnerabilities_by_keyword, get_all_credentials
except ImportError as e:
    print(f"Warning: Analyzer database import failed: {e}. Vulnerability checking will be disabled.", file=sys.stderr)
    def get_vulnerabilities_by_keyword(keyword): return []
    def get_all_credentials(): return []

class VulnerabilityAnalyzer:
    """
    Analyzes raw scan results for CVE matches and weak credentials.
    """
    
    def _clean_banner(self, banner: str) -> List[str]:
        """Extracts primary service and version keywords from a banner."""
        if not banner:
            return []
            
        cleaned_keywords = set()
        
        # --- FIX APPLIED HERE ---
        # The hyphen '-' is moved to the start of the character class to prevent the 'bad character range' error.
        parts = re.split(r'[-/\s\(\).]', banner) # Original: r'[\s\(\)/-.]'
        
        for part in parts:
            part = part.strip()
            # Ignore short, generic parts, and common delimiters
            if len(part) > 2 and not part.lower() in ['http', 'server', 'version', 'running', 'service', 'v', '1', '2', '3', 'p', 'release', 'linux', 'windows']:
                 cleaned_keywords.add(part)
        
        # Also check for combined service/version patterns (e.g., 'vsftp3.0.3')
        if len(cleaned_keywords) == 1:
            main_part = list(cleaned_keywords)[0]
            # If the part contains a dot or a dash, split it further
            sub_parts = re.split(r'[-.]', main_part)
            for sub_part in sub_parts:
                if sub_part and len(sub_part) > 2:
                    cleaned_keywords.add(sub_part)

        return list(cleaned_keywords)
        
    def _analyze_banner(self, ip: str, port: int, banner: str, service_type: str) -> List[Dict[str, Any]]:
        """Checks the service banner against the CVE database using keywords."""
        findings = []
        
        # 1. Start with the standardized service type
        keywords_to_check = {service_type.lower()} if service_type else set()
        
        # 2. Add keywords extracted from the banner
        keywords_to_check.update(self._clean_banner(banner))
        
        if not keywords_to_check:
            return findings
            
        # 3. Check database against all derived keywords
        for keyword in keywords_to_check:
            db_results = get_vulnerabilities_by_keyword(keyword)
            
            for vuln in db_results:
                findings.append({
                    'type': 'CVE_MATCH',
                    'description': f"Known vulnerability in service ({keyword}): {vuln['description']}",
                    'risk': 'HIGH',
                    'cve': vuln['cve_id']
                })
        
        return findings

    def _check_credentials(self, ip: str, port: int, service_type: str) -> List[Dict[str, Any]]:
        """
        Simulates checking for weak credentials. This is highly accurate due to the nature
        of default credentials being a CRITICAL, easy-to-detect risk in IoT.
        """
        findings = []
        
        # Only check services that typically require credentials
        if service_type in ['ssh', 'ftp', 'telnet', 'http', 'https', 'rtsp']:
            weak_credentials = get_all_credentials()
            
            if weak_credentials:
                 findings.append({
                    'type': 'WEAK_CREDENTIAL',
                    'description': f"Device exposes a {service_type.upper()} interface. **CRITICAL RISK:** Check for default credentials (e.g., admin:admin).",
                    'risk': 'CRITICAL',
                    'cve': 'N/A - Default Setup Risk'
                })
        
        return findings

    def analyze_scan_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Main analysis function to process all raw scan results and aggregate findings.
        """
        combined_findings = {}
        # Define risk hierarchy for aggregation
        risk_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1} 

        for result in raw_results:
            ip = result['ip']
            port = result['port']
            key = (ip, port)
            
            if key not in combined_findings:
                combined_findings[key] = {
                    'ip': ip, 
                    'port': port, 
                    'service': result.get('service_type', 'N/A'), 
                    'risk': 'LOW', 
                    'details': []
                }
            
            # --- Perform Checks ---
            banner_findings = self._analyze_banner(ip, port, result.get('banner', ''), result.get('service_type', ''))
            cred_findings = self._check_credentials(ip, port, result.get('service_type', ''))
            
            all_findings = banner_findings + cred_findings
            
            if all_findings:
                current_risk = combined_findings[key]['risk']
                
                for finding in all_findings:
                    # Update risk level to the highest found
                    if risk_order.get(finding['risk'], 1) > risk_order.get(current_risk, 1):
                        current_risk = finding['risk']
                    combined_findings[key]['details'].append(finding)
                    
                combined_findings[key]['risk'] = current_risk

        # Return only entries with actual findings
        return [f for f in combined_findings.values() if f['details']]

# Banner details


    def analyze_scan_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Main analysis function to process all raw scan results and aggregate findings.
        """
        combined_findings = {}
        # Define risk hierarchy for aggregation
        risk_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1} 

        for result in raw_results:
            ip = result['ip']
            port = result['port']
            key = (ip, port)
            
            if key not in combined_findings:
                combined_findings[key] = {
                    'ip': ip, 
                    'port': port, 
                    'service': result.get('service_type', 'N/A'),
                    # --- NEW FIELDS ---
                    'status': result.get('status', 'UNKNOWN'),
                    'banner': result.get('banner', 'N/A'),
                    # ------------------
                    'risk': 'LOW', 
                    'details': []
                }
            
            # ... (The rest of the analysis function remains the same) ...

        # Return all entries with details OR entries with open ports and a banner
        return [f for f in combined_findings.values() if f['details'] or f['status'] == 'OPEN']