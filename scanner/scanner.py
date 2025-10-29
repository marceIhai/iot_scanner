import socket
import base64
import sys
from .config import DEFAULT_TIMEOUT, COMMON_PORTS, DEFAULT_CREDENTIALS
from .reporting import print_result # Used here just for debugging/immediate feedback, but mainly for modularity

# PortScanner class handles all network interactions
class PortScanner:
    def __init__(self, timeout, ports_to_scan, credentials):
        self.timeout = timeout
        self.ports_to_scan = ports_to_scan
        self.credentials = credentials

    def _get_banner(self, s, port):
        """Attempts to read a service banner from the socket."""
        try:
            # Send a basic request for HTTP or wait for banner for others
            if port in [80, 8080]:
                # Minimal HTTP request to force a banner/response
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            
            # Receive up to 1024 bytes
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
        except socket.timeout:
            return ""
        except Exception:
            return ""

    def _check_http_auth(self, ip, port, banner):
        """Actively checks for default HTTP Basic Authentication credentials."""
        for username, password in self.credentials:
            try:
                # Prepare Basic Auth header
                auth_str = f"{username}:{password}"
                auth_encoded = base64.b64encode(auth_str.encode()).decode()
                
                # Construct the HTTP request with the Authorization header
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {ip}\r\n"
                    f"Authorization: Basic {auth_encoded}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((ip, port))
                s.sendall(request.encode())
                
                response = s.recv(1024).decode('utf-8', errors='ignore')
                s.close()
                
                # If the response indicates success (200 OK), default creds worked.
                if "200 OK" in response:
                    return {
                        'ip': ip,
                        'port': port,
                        'risk_category': 'WEAK_CRED',
                        'protocol': 'HTTP',
                        'username': username,
                        'password': password
                    }
            except Exception:
                continue # Failed attempt, try next credential pair
        return None

    def _check_mqtt_auth(self, ip, port, banner):
        """
        Simulates an MQTT check. Since full MQTT packet construction is complex,
        we flag the open port and check for a silent banner for educational purposes.
        """
        if port in [1883, 8883] and not banner:
            # If the port is open and gives no banner, it's likely a silent protocol like MQTT.
            # Flagging it for manual weak credential analysis.
            return {
                'ip': ip,
                'port': port,
                'risk_category': 'OPEN_PORT',
                'protocol': 'MQTT',
                'banner': 'MQTT Broker (Silent Banner)',
                'description': 'MQTT port open, recommend checking for anonymous access and weak credentials.'
            }
        return None

    def scan_target(self, ip):
        """
        Scans all defined ports on a single IP address and runs checks.
        Returns a list of dictionaries for any discovered issues.
        """
        results = []
        for port in self.ports_to_scan:
            try:
                # 1. Port Check
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((ip, port))
                
                # Port is open
                
                # 2. Banner Grabbing
                banner = self._get_banner(s, port)
                
                # 3. Active Checks (HTTP and MQTT)
                active_result = None
                
                if port in [80, 443, 8080]:
                    active_result = self._check_http_auth(ip, port, banner)
                
                # if not active_result and port in [1883, 8883]:
                #    active_result = self._check_mqtt_auth(ip, port, banner)

                if active_result and active_result.get('risk_category') == 'WEAK_CRED':
                    results.append(active_result)
                
                # If no critical weak credential found, record the open port
                if not any(r.get('risk_category') == 'WEAK_CRED' for r in results):
                    results.append({
                        'ip': ip,
                        'port': port,
                        'risk_category': 'OPEN_PORT',
                        'protocol': 'TCP',
                        'banner': banner
                    })

                s.close()
                
            except socket.error:
                # Port is closed or connection failed
                pass
            except Exception as e:
                # General error handling
                # In a real tool, this would be logged extensively
                pass
        
        return results
