# scanner/discover.py
import subprocess
import platform
from .portscan import scan_host

def ping_sweep(subnet="192.168.1.0/24"):
    live_hosts = []
    base_ip = subnet.rsplit('.', 1)[0]
    
    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", ip]
        response = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if response == 0:
            live_hosts.append(ip)
    return live_hosts

