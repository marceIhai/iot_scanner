import socket
import netaddr
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# --- Local imports ---
from .config import COMMON_PORTS, DEFAULT_TIMEOUT, MAX_THREADS, DEFAULT_CREDENTIALS
from .reporting import print_result, parse_targets 

class PortScanner:
    """
    Handles network scanning, port status checks, and banner grabbing.
    """
    def __init__(self, targets, ports_to_scan=COMMON_PORTS, timeout=DEFAULT_TIMEOUT, credentials=DEFAULT_CREDENTIALS):
        """Initializes the scanner with targets and configuration."""
        self.targets = targets
        self.ports_to_scan = ports_to_scan
        self.timeout = timeout
        self.credentials = credentials
        self.results = []
        self.executor = ThreadPoolExecutor(max_workers=MAX_THREADS)
        
    def _check_credentials(self, ip, port, service_type):
        """
        Placeholder for weak credential check. This function is mostly a placeholder 
        in PortScanner but is called by the Analyzer. It is kept here for clarity 
        but the main logic is in analyzer.py.
        """
        return None

    def _grab_banner(self, ip, port, s):
        """Attempts to grab a service banner using protocol-specific probes."""
        
        try:
            s.settimeout(1.0) # Set a consistent timeout for reading
            
            # --- Protocol Probes ---
            if port in [80, 443, 8080]:
                # HTTP/HTTPS: Send a basic request to get server headers
                request = b"GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: IoTScanner\r\n\r\n" % ip.encode()
                s.sendall(request)
                
            elif port == 22:
                # SSH: Banner is usually sent immediately, or after a specific client greeting
                # The simple 's.recv' below should capture it if the connection succeeds.
                pass
                
            # --- Receive Banner ---
            banner = s.recv(4096).decode('utf-8', errors='ignore').strip()
            
            if not banner:
                return "No banner received"
                
            # Clean up the banner for better matching
            # For HTTP, extract the first line (HTTP status) and the Server header
            if port in [80, 443, 8080]:
                lines = banner.split('\n')
                server_header = next((line for line in lines if line.lower().startswith('server:')), None)
                
                if server_header:
                    # e.g., "Server: Apache/2.4.6 (CentOS)
                    return server_header.strip()
                elif lines:
                    # Return the first line (e.g., HTTP/1.0 200 OK)
                    return lines[0].strip()
            
            # For other protocols, return the first few lines
            return "\n".join(banner.split('\n')[:2]).strip()
            
        except socket.timeout:
            return "Read timeout"
        except Exception:
            return "No banner received or protocol error"


    def scan_port(self, ip, port):
        """Connects to a single port to check status and grab a banner."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = {'ip': ip, 'port': port, 'status': 'CLOSED', 'banner': '', 'service_type': ''}
        
        try:
            # 1. Connect to the port
            if sock.connect_ex((ip, port)) == 0:
                result['status'] = 'OPEN'
                
                # Use a wrapper for TLS/SSL (e.g., 443) before grabbing the banner
                current_sock = sock
                if port in [443, 8443]:
                    try:
                        # Attempt to wrap the socket for secure connection
                        current_sock = ssl.wrap_socket(sock, do_handshake_on_connect=False)
                        current_sock.settimeout(self.timeout)
                        current_sock.connect((ip, port))
                        current_sock.do_handshake()
                        result['service_type'] = 'https'
                    except (ssl.SSLError, socket.timeout):
                        # If SSL handshake fails, it might still be a plaintext HTTP or a different service
                        current_sock = sock
                        result['service_type'] = 'http'
                    except Exception:
                        current_sock = sock
                
                # 3. Grab Banner
                result['banner'] = self._grab_banner(ip, port, current_sock)
                
                # 4. Determine service type (refine based on common port)
                if port == 21: result['service_type'] = 'ftp'
                elif port == 22: result['service_type'] = 'ssh'
                elif port == 23: result['service_type'] = 'telnet'
                elif port == 80 and not result['service_type']: result['service_type'] = 'http'
                elif port == 443 and not result['service_type']: result['service_type'] = 'https'
                elif port == 8080: result['service_type'] = 'http-alt'
                elif port == 8443: result['service_type'] = 'https-alt'
                
                print_result(ip, port, result['service_type'], "INFO", f"Port is open. Banner: {result['banner'][:50]}...")
            
        except socket.error as e:
            print_result(ip, port, '', "ERROR", f"Socket Error: {e}")
        except Exception as e:
            print_result(ip, port, '', "ERROR", f"Unexpected Error: {e}")
        finally:
            sock.close()
            
        return result if result['status'] == 'OPEN' else None

    # (scan_target, start_scan, and get_results methods remain unchanged)

    def scan_target(self, ip):
        """Scans all defined ports for a single IP address concurrently."""
        print_result(ip, 0, "System", "INFO", f"Starting scan for {ip}...")
        
        target_results = []
        future_to_port = {
            self.executor.submit(self.scan_port, ip, port): port 
            for port in self.ports_to_scan
        }
        
        # Collect results as they complete
        for future in future_to_port:
            port_result = future.result()
            if port_result:
                target_results.append(port_result)
        
        print_result(ip, 0, "System", "INFO", f"Scan finished for {ip}.")
        return target_results

    def start_scan(self):
        """Initiates the scan across all targets."""
        print_result("System", 0, "Scanner", "INFO", f"Starting scan on {len(self.targets)} targets...")
        
        future_to_ip = {
            self.executor.submit(self.scan_target, ip): ip
            for ip in self.targets
        }

        # Collect results from all targets
        for future in future_to_ip:
            ip_results = future.result()
            if ip_results:
                self.results.extend(ip_results)
                
        print_result("System", 0, "Scanner", "INFO", "All target scans complete.")
        
    def get_results(self):
        """Returns the accumulated scan results."""
        return self.results