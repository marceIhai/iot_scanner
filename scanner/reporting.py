import ipaddress
import sys
from .config import COLOR_MAP

def parse_targets(target):
    """
    Parses a single IP or an IP range (e.g., 192.168.1.1-192.168.1.254) into a list of IPs.
    """
    if '-' in target:
        try:
            start_ip, end_ip = target.split('-')
            start = int(ipaddress.IPv4Address(start_ip))
            end = int(ipaddress.IPv4Address(end_ip))
            if start > end:
                print(f"{COLOR_MAP.get('FAIL', '')}Start IP must be before End IP.{COLOR_MAP.get('END', '')}", file=sys.stderr)
                return []
            
            # Generate the list of IPs in the range
            targets = [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
            return targets
        except ipaddress.AddressValueError:
            return [] # Invalid IP format
        except Exception:
            return []
    else:
        # Check if it is a single valid IP
        try:
            ipaddress.IPv4Address(target)
            return [target]
        except ipaddress.AddressValueError:
            return []

def print_result(ip, port, description, risk_level="WARNING"):
    """
    Prints a single scan result with color coding based on risk level.
    """
    color = COLOR_MAP.get(f"RISK_{risk_level.upper()}", COLOR_MAP["WARNING"])
    end_color = COLOR_MAP["END"]
    
    print(f"[{color}{risk_level.upper():^6}{end_color}] {ip}:{port} - {description}")


def print_summary(results):
    """
    Prints the final summary of all discovered vulnerabilities and issues.
    """
    weak_cred_count = len([r for r in results if r.get('risk_category') == 'WEAK_CRED'])
    vuln_match_count = len([r for r in results if r.get('risk_category') == 'VULN_MATCH'])
    
    print(f"\n{COLOR_MAP['HEADER']}--- SCAN SUMMARY ---{COLOR_MAP['END']}")
    
    # 1. Weak Credentials
    if weak_cred_count > 0:
        print(f"\n{COLOR_MAP['FAIL']}>> WEAK CREDENTIALS DISCOVERED ({weak_cred_count}) <<{COLOR_MAP['END']}")
        for r in results:
            if r.get('risk_category') == 'WEAK_CRED':
                print_result(
                    ip=r['ip'],
                    port=r['port'],
                    description=f"SUCCESSFUL LOGIN with {r['username']}:{r['password']} (Protocol: {r['protocol']})",
                    risk_level="HIGH"
                )
    
    # 2. Deeper Vulnerability Matches
    if vuln_match_count > 0:
        print(f"\n{COLOR_MAP['WARNING']}>> DEEPER VULNERABILITY MATCHES ({vuln_match_count}) <<{COLOR_MAP['END']}")
        for r in results:
            if r.get('risk_category') == 'VULN_MATCH':
                print_result(
                    ip=r['ip'],
                    port=r['port'],
                    description=f"Match on '{r['banner_match']}': {r['cve_id']} - {r['cve_desc']}",
                    risk_level="MEDIUM"
                )

    # 3. Open Ports Found (General Info)
    open_ports = [r for r in results if r.get('risk_category') == 'OPEN_PORT']
    if open_ports:
        print(f"\n{COLOR_MAP['HEADER']}>> OPEN PORTS FOUND ({len(open_ports)}) <<{COLOR_MAP['END']}")
        for r in open_ports:
            print_result(
                ip=r['ip'],
                port=r['port'],
                description=f"Port open. Banner: '{r.get('banner', 'N/A')[:40]}'",
                risk_level="LOW"
            )
    
    if weak_cred_count + vuln_match_count == 0 and len(open_ports) > 0:
        print(f"\n{COLOR_MAP['SUCCESS']}No critical vulnerabilities found, but {len(open_ports)} ports were open.{COLOR_MAP['END']}")
    elif weak_cred_count + vuln_match_count > 0:
        print(f"\n{COLOR_MAP['FAIL']}!!! CRITICAL RISKS IDENTIFIED. See HIGH/MEDIUM flags above. !!!{COLOR_MAP['END']}")
    else:
        print(f"\n{COLOR_MAP['SUCCESS']}Scan complete. No issues or open ports found.{COLOR_MAP['END']}")
