# fingerprint.py

import socket
from typing import Dict, Any, List
# Import necessary Scapy layers, including DNS and CoAP
from scapy.all import IP, TCP, UDP, ICMP, sr, sr1, DNS, DNSQR, Raw 

# Expanded common ports to include standard services and common IoT ports
COMMON_PORTS = [
    21, 22, 23, 80, 443, 8080, # Standard Ports
    554,    # RTSP (IP Cameras)
    1883,   # MQTT (Unencrypted)
    8883,   # MQTTS (Encrypted)
    8000, 8081, 8443 # Alt Web/API Ports
]

# Common UDP ports for IoT
COMMON_UDP_PORTS = {
    53: 'DNS',     # DNS - Requires a payload
    5683: 'CoAP',   # CoAP - Requires a payload (e.g., Ping)
    161: 'SNMP',    # SNMP - Basic scan
}

# --- Protocol Payloads ---
# Removed DNS_PAYLOAD global variable to fix Scapy import/slicing error.
# The DNS packet fragment will be created inline in udp_scan_enhanced.

# CoAP Ping: A CoAP message with code 0.00 (Empty) and type 1 (Confirmable)
# This acts as a reliable CoAP Ping
COAP_PAYLOAD = b'\x44\x00\x12\x34\x00\x00\x00\x00' # Simple CoAP Ping message (Version 1, Type Confirmable, Code Empty)

def grab_tcp_banner(ip: str, port: int, timeout: float = 0.5) -> str:
    """
    Attempts to perform a simple TCP connection to an IP:PORT and grab the
    first few lines of data (the banner).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Return the first line of the banner
            return banner.split('\n')[0].replace('\r', '').strip()
            
    except ConnectionRefusedError:
        return "Port Closed"
    except socket.timeout:
        return "Timeout"
    except Exception as e:
        return f"Error: {type(e).__name__}"

def service_scan(ip: str) -> Dict[str, Any]:
    """
    Performs TCP SYN scan on common ports and grabs banners for open ports.
    Also extracts TCP Initial Window Size for advanced fingerprinting.
    """
    print(f"[*] Scanning TCP services on {ip} for ports {list(COMMON_PORTS)}...")
    
    tcp_results: Dict[int, Dict[str, Any]] = {}
    
    answered_packets, _ = sr(
        IP(dst=ip)/TCP(dport=COMMON_PORTS, flags="S"), 
        timeout=1, 
        verbose=False
    )
    
    if answered_packets:
        for _, received_packet in answered_packets:
            if received_packet.haslayer(TCP) and received_packet[TCP].flags & 0x12 == 0x12:
                open_port = received_packet[TCP].sport
                window_size = received_packet[TCP].window 
                
                banner = grab_tcp_banner(ip, open_port)
                
                if banner and not banner.startswith(("Port Closed", "Timeout", "Error")):
                    tcp_results[open_port] = {
                        'banner': banner,
                        'window_size': window_size
                    }
                    
    services = {port: data['banner'] for port, data in tcp_results.items()}
    window_sizes = {port: data['window_size'] for port, data in tcp_results.items()}
    
    return {'services': services, 'window_sizes': window_sizes}

def udp_scan_enhanced(ip: str) -> Dict[int, str]:
    """
    Performs an enhanced UDP scan using protocol-specific payloads for better accuracy.
    """
    print(f"[*] Scanning UDP services on {ip} for ports {list(COMMON_UDP_PORTS.keys())}...")
    
    open_udp_ports: Dict[int, str] = {}
    
    for port, service_name in COMMON_UDP_PORTS.items():
        payload = None
        
        # 1. Determine the payload based on the port/service
        if port == 53 and service_name == 'DNS':
            # NEW: Create DNS packet fragment inline
            payload = DNS(rd=1, qd=DNSQR(qname="iot.scan"))
        elif port == 5683 and service_name == 'CoAP':
            # Use the raw CoAP Ping payload
            payload = Raw(load=COAP_PAYLOAD) 
        # For other services (like SNMP 161), payload remains None
        
        # 2. Construct the packet
        if payload is not None:
            packet = IP(dst=ip)/UDP(dport=port)/payload
        else:
             packet = IP(dst=ip)/UDP(dport=port)
            
        # 3. Send and receive
        resp = sr1(packet, timeout=0.5, verbose=False)

        if resp is None:
            # No reply often means the port is OPEN or filtered
            open_udp_ports[port] = f"Open/Filtered ({service_name} - No Reply)"
            
        elif resp.haslayer(ICMP) and resp[ICMP].type == 3 and resp[ICMP].code == 3:
            # ICMP Port Unreachable: Port is closed (do nothing)
            pass
        
        # 4. Check for a definitive protocol response
        elif resp.haslayer(DNS) and port == 53:
            # Received a DNS reply packet
            open_udp_ports[port] = f"Open (DNS Server)"
        elif resp.haslayer(UDP) and port == 5683 and len(resp[UDP].payload.load) > 0:
            # Received a UDP packet with a non-empty payload on CoAP port (likely a response)
            open_udp_ports[port] = f"Open (CoAP Endpoint)"
        elif resp.haslayer(UDP) and resp[UDP].sport == port:
             # Received a UDP packet from the same port (for services without known Scapy layers)
             open_udp_ports[port] = f"Open (UDP Service)"
            
    return open_udp_ports

def os_fingerprint_basic(ip: str, timeout: float = 0.5) -> str:
    """
    Performs a very basic, non-invasive OS fingerprint based on TTL (Time-To-Live).
    """
    try:
        packet = IP(dst=ip)/ICMP()
        resp = sr1(packet, timeout=timeout, verbose=False)

        if resp is None:
            return "No Response (ICMP Filtered)"
        
        ttl = resp.ttl
        
        if ttl <= 64:
            return f"Linux/Unix/macOS (TTL <= 64, actual: {ttl})"
        elif ttl <= 128:
            return f"Windows (TTL <= 128, actual: {ttl})"
        elif ttl <= 255:
            return f"Router/Older OS (TTL <= 255, actual: {ttl})"
        else:
            return f"Unknown (TTL: {ttl})"

    except Exception as e:
        return f"Fingerprint Error: {type(e).__name__}"

def hostname_lookup(ip: str) -> str:
    """
    Performs a reverse DNS lookup to get the device's hostname.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.strip()
    except socket.error:
        return "N/A"

def get_full_fingerprint(ip: str) -> Dict[str, Any]:
    """
    Combines all fingerprinting and service scanning for a device.
    """
    hostname = hostname_lookup(ip)
    os_info = os_fingerprint_basic(ip)
    
    tcp_data = service_scan(ip)
    
    # Use the enhanced UDP scan function
    udp_ports = udp_scan_enhanced(ip) 
    
    return {
        'hostname': hostname,
        'os': os_info,
        'tcp_services': tcp_data['services'],
        'tcp_window_sizes': tcp_data['window_sizes'], 
        'udp_ports': udp_ports,
    }