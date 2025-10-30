# --- SCANNING CONFIGURATION ---
# Default timeout in seconds for TCP connection attempts
DEFAULT_TIMEOUT = 1.0 
SCAN_TIMEOUT = DEFAULT_TIMEOUT # Alias to fix ImportError in scanner.scanner.py

# Maximum number of concurrent threads for scanning targets (used by main.py CLI)
MAX_THREADS = 50 

# --- PORT LISTS ---
# Common ports to scan by default (used by both app.py and main.py)
COMMON_PORTS = [21, 22, 23, 80, 443, 8080, 8443, 2000, 5000, 554, 1900]
DEFAULT_PORTS = COMMON_PORTS # Alias used by main.py

# --- WEAK CREDENTIALS ---
# List of default username/password tuples for brute-force login checks
DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('root', 'root'),
    ('admin', '123456'),
    ('ubnt', 'ubnt'),
    ('guest', 'guest'),
    ('user', 'user'),
    ('pi', 'raspberry'),
    ('super', '1234')
]

# --- COLOR MAP (for CLI output in main.py) ---
COLOR_MAP = {
    "CRITICAL": "\033[91m", # Red
    "HIGH": "\033[93m",     # Yellow
    "MEDIUM": "\033[94m",   # Blue
    "LOW": "\033[92m",      # Green
    "INFO": "\033[96m",     # Cyan
    "ENDC": "\033[0m",      # Reset (end color code)
}