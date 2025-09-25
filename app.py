from flask import Flask, request, render_template
from scanner.portscan import scan_host
from scanner.discover import ping_sweep
import webbrowser
import threading

app = Flask(__name__)

# Example CVE database (replace with your real data)
cve_db = [
    {"banner": "vulnerable_device", "cve": "CVE-1234-5678"}
]

@app.route("/discover", methods=["GET"])
def discover():
    live_hosts = ping_sweep("192.168.1.0/24")  # set your subnet
    devices = [{"ip": ip} for ip in live_hosts]
    return render_template("discover.html", devices=devices)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        host = request.form.get("host")
        ports = request.form.get("ports")
        if not host:
            return "Please enter a host!"
        try:
            ports = [int(p.strip()) for p in ports.split(",")] if ports else [22, 80, 443, 8080]
        except:
            return "Ports must be numbers separated by commas!"
        
        results = scan_host(host, ports=ports, cve_db=cve_db)
        return render_template("results.html", host=host, results=results)
    
    return render_template("index.html")

def open_browser():
    webbrowser.open("http://127.0.0.1:5000/")

if __name__ == "__main__":
    # Open browser in a separate thread so Flask can start
    threading.Timer(1, open_browser).start()
    app.run(debug=True)