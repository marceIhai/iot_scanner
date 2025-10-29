# --- Network Configuration ---
DEFAULT_TIMEOUT = 1.0  # Seconds to wait for a socket connection
SCAN_PORTS = 100 # Number of common ports to scan (e.g., top 100)

COMMON_PORTS = [
    21,    # FTP
    23,    # Telnet
    80,    # HTTP
    443,   # HTTPS
    8080,  # Alternate HTTP
    22,    # SSH
    5900,  # VNC
    1883,  # MQTT (unsecured)
    8883,  # MQTT (secured)
    3306,  # MySQL
    5000,  # Common UPnP/API port
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("user", "user"),
    ("root", "root"),
    ("admin", "123456"),
    ("guest", "guest"),
]

# --- Console Colors (ANSI) ---
COLOR_MAP = {
    "HEADER": "\033[95m",
    "SUCCESS": "\033[92m",
    "WARNING": "\033[93m",
    "FAIL": "\033[91m",
    "RISK_HIGH": "\033[41m\033[97m",  # Red Background, White Text
    "RISK_MEDIUM": "\033[43m\033[30m", # Yellow Background, Black Text
    "END": "\033[0m"
}
