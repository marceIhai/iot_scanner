# discover.py

import socket
from ipaddress import ip_network
from scapy.all import ARP, Ether, srp
from typing import Optional, List, Dict
import re # Import re for a robust split of the vendor name


def get_started() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        subnet = str(ip_network(f'{local_ip}/24', strict=False))
        print(f"[*] Local IP: {local_ip}")
        print(f"[*] Subnet identified: {subnet}")
        return subnet
        
    except OSError:
        print("[!] Could not determine local IP address. Check network connection.")
        return None

def scan_subnet(subnet_cidr: str) -> List[Dict[str, str]]:
    print(f"[*] Starting scan for devices on {subnet_cidr}...")
    
    # 1. Create the ARP request packet
    # pdst is the destination IP range (the whole subnet)
    arp_request = ARP(pdst=subnet_cidr)
    
    # 2. Create the Ethernet broadcast frame
    # dst="ff:ff:ff:ff:ff:ff" ensures the packet is sent to all devices
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # 3. Stack the packets (Ethernet -> ARP)
    packet = ether_frame / arp_request
    
    # 4. Send and receive packets (srp returns answered and unanswered packets)
    # timeout is set to 2 seconds for a quicker scan
    result = srp(packet, timeout=2, verbose=False)[0]
    
    devices_up = []
    
    # 5. Process the responses
    for sent, received in result:
        devices_up.append({
            'ip': received.psrc, 
            'mac': received.hwsrc
        })
        
    return devices_up
    
def oui_lookup(mac_address: str, oui_db_path: str = "oui.txt") -> str:
    # Initialize cache on first run
    if not hasattr(oui_lookup, 'oui_data'):
        oui_lookup.oui_data = {}
        try:
            with open(oui_db_path, 'r', encoding='utf-8') as f:
                # The OUI database has entries like 'A473AB (base 16)   Extreme Networks Headquarters'
                # We'll use the (base 16) lines for consistent parsing.
                for line in f:
                    if "(base 16)" in line:
                        # Split the line by whitespace
                        parts = line.split()
                        if len(parts) >= 4 and parts[1] == '(base' and parts[2] == '16)':
                            # OUI is the first part, converted to uppercase
                            oui = parts[0].upper()
                            # Vendor name is everything after the '(base 16)' part
                            vendor_name = " ".join(parts[3:]).strip()
                            # Store the OUI without dashes for easy lookup
                            if oui and vendor_name:
                                oui_lookup.oui_data[oui] = vendor_name
        except FileNotFoundError:
            print(f"[!] OUI database file '{oui_db_path}' not found. OUI lookup disabled.")
            oui_lookup.oui_data = {} # Set to empty to prevent re-trying
            return "OUI DB Not Found"
        except Exception as e:
            print(f"[!] An error occurred while loading OUI database: {e}")
            oui_lookup.oui_data = {}
            return "OUI DB Error"

    # If the database is empty or failed to load
    if not oui_lookup.oui_data:
        return "Unknown Vendor (DB Failed)"

    # Normalize the input MAC address and extract the OUI (first 6 hex digits)
    # MAC addresses from scapy are typically lowercase with colons, e.g., 'aa:bb:cc:dd:ee:ff'
    normalized_mac = mac_address.replace(':', '').replace('-', '').upper()
    oui_key = normalized_mac[:6]
    
    # Perform the lookup and return the result or a default string
    return oui_lookup.oui_data.get(oui_key, "Unknown Vendor")