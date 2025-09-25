import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from .cve_match import match_cves  # use relative import

def tcp_connect(host, port, timeout=1.5):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return s
    except:
        try:
            s.close()
        except:
            pass
        return None

def grab_banner(host, port, timeout=1.5):
    try:
        s = tcp_connect(host, port, timeout)
        if not s:
            return None
        banner = None
        try:
            data = s.recv(4096)
            if data:
                banner = data.decode(errors='ignore').strip()
        except:
            pass
        # HTTP fallback
        if port in (80, 8080, 8000):
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
                data = s.recv(8192)
                banner = data.decode(errors='ignore').strip()
            except:
                pass
        s.close()
        return banner
    except:
        return None

def scan_host(host, ports=[22, 80, 443, 8080], creds=None, cve_db=[]):
    results = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(tcp_connect, host, p): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            s = fut.result()
            entry = {'port': port, 'open': False, 'banner': None, 'cves': []}
            if s:
                entry['open'] = True
                try:
                    s.close()
                except:
                    pass
                banner = grab_banner(host, port)
                entry['banner'] = banner
                entry['cves'] = match_cves(cve_db, banner)
            results.append(entry)
    return results