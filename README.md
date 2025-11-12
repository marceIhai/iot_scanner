# 🚀 Network Discovery and Security Audit Tool

This tool is a Python-based Command Line Interface (CLI) application designed to scan a local network, identify active devices, perform detailed service fingerprinting, and conduct a basic security audit.

The CLI is optimized to provide a clean progress bar during the scan and consolidate all security findings into a single, comprehensive summary report at the end.

Project Structure:

.
├── lwiv_scanner.py         # Main execution script and CLI interface
├── vulnerabilities.db      # Simple, text-based vulnerability database (banner keyword matching)
└── functions/
    ├── __init__.py         # (empty file to make the directory a Python package)
    ├── discovery.py        # Host discovery logic (ICMP/Ping)
    ├── scanning.py         # Port scanning and banner grabbing logic
    ├── fingerprinting.py   # Vulnerability matching (DB lookup)
    └── credentials.py      # Weak credential checking simulation


## ✨ Features

The scanner utilizes several modules to perform a multi-layered analysis:

* **Subnet Discovery (ARP Scanning):** Automatically identifies the local subnet and performs an efficient ARP scan to find all active hosts.
* **Enhanced Fingerprinting:** Performs TCP/UDP port scanning and service banner grabbing on common ports to identify running services (e.g., HTTP, SSH, MQTT).
* **Basic OS Guessing:** Attempts to identify the operating system (e.g., Linux, Windows) based on ICMP Time-To-Live (TTL) values.
* **Vulnerability Matching:** Matches captured service banners against a local SQLite vulnerability database (`vulnerabilities.db`) to flag potential known exposures (CVEs).
* **Weak Credentials Check:** Attempts to log in to services (e.g., SSH and basic HTTP authentication) using a predefined list of common/default credentials.
* **Exposed Files Check:** Probes detected web services for common sensitive files and configuration paths (e.g., `.env`, `robots.txt`, configuration backups).


## 🛠️ Requirements and Setup

### Prerequisites

This tool requires **Python 3.x** and **root/administrator privileges** to run, as the underlying network scanning library (`scapy`) requires raw socket access.

* **Linux/macOS:** Run with `sudo python3 main.py`.
* **Windows:** Run with an elevated Command Prompt/PowerShell.

### Installation

1.  **Clone or Download** the project files.
2.  **Install Dependencies** using the provided `requirements.txt`:

    pip install -r requirements.txt

## 🏃 Usage

Simply execute the main script. The tool will automatically detect your subnet and begin scanning.

sudo python3 main.py