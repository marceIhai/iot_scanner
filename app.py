import sys
import json
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, render_template_string, request, jsonify

# --- Absolute imports for scanner modules ---
from scanner.config import (
    DEFAULT_TIMEOUT,
    COMMON_PORTS,
    DEFAULT_CREDENTIALS,
    COLOR_MAP,
)
from scanner.reporting import parse_targets
from scanner.scanner import PortScanner
from scanner.analyzer import VulnerabilityAnalyzer
from scanner.mock_data import handle_mock_execution, MOCK_RESULTS 
from scanner.database import initialize_db # ADDED: Import initialize_db


# --- Flask App Setup ---
app = Flask(__name__)

# Executor for running scan tasks in background threads
executor = ThreadPoolExecutor(max_workers=5)

# Initialize database on startup so the VulnerabilityAnalyzer can read it.
initialize_db() # ADDED: Initialize the DB before running the app


# --- HTML Template for the Web Interface ---
# (HTML content is truncated for brevity but is included in the full response)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Vulnerability Scanner</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #f7f7f7; }
        .card { background-color: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05); }
        .result-critical { background-color: #fee2e2; border-left: 4px solid #ef4444; }
        .result-high { background-color: #fef3c7; border-left: 4px solid #f59e0b; }
        .result-medium { background-color: #dbeafe; border-left: 4px solid #3b82f6; }
        .result-low { background-color: #ecfdf5; border-left: 4px solid #10b981; }
        .btn-primary { 
            background-color: #4f46e5; color: white; transition: background-color 0.3s;
            border-radius: 8px; padding: 10px 15px; font-weight: 600;
        }
        .btn-primary:hover { background-color: #4338ca; }
    </style>
</head>
<body class="p-4 md:p-8">

    <div class="max-w-4xl mx-auto">
        <h1 class="text-3xl font-bold text-gray-800 mb-6 flex items-center">
            IoT Vulnerability Scanner
            <svg class="w-6 h-6 ml-3 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v3h8z"></path></svg>
        </h1>
        
        <div class="card p-6 mb-8">
            <form id="scanForm" action="/" method="POST" class="flex flex-col md:flex-row space-y-3 md:space-y-0 md:space-x-3">
                <input 
                    type="text" 
                    name="target" 
                    id="target" 
                    placeholder="Enter IP or Range (e.g., 192.168.1.1 or 192.168.1.1-254)"
                    class="flex-grow p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500"
                    required
                >
                <button type="submit" id="scanButton" class="btn-primary">
                    <span id="buttonText">Start Scan</span>
                </button>
                <button type="button" id="mockButton" class="btn-primary bg-green-500 hover:bg-green-600" onclick="runMock()">
                    Run Mock Test
                </button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Note: Scanning large ranges may take time and consume server resources.</p>
        </div>

        <div id="resultsSection" class="hidden">
            <h2 class="text-2xl font-semibold text-gray-700 mb-4">Scan Results</h2>
            <div id="resultsContainer" class="space-y-4">
                </div>
            <div id="noResults" class="hidden card p-4 text-center text-gray-500">
                No critical vulnerabilities or weak credentials found.
            </div>
        </div>

        <div id="loading" class="hidden text-center card p-4">
            <svg class="animate-spin h-5 w-5 text-indigo-500 mx-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <p class="mt-2 text-indigo-500">Scanning in progress... Please wait.</p>
        </div>
        
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const scanForm = document.getElementById('scanForm');
            const targetInput = document.getElementById('target');
            const scanButton = document.getElementById('scanButton');
            const buttonText = document.getElementById('buttonText');
            const loading = document.getElementById('loading');
            const resultsSection = document.getElementById('resultsSection');
            const resultsContainer = document.getElementById('resultsContainer');
            const noResults = document.getElementById('noResults');

            function showLoading() {
                loading.classList.remove('hidden');
                resultsSection.classList.add('hidden');
                scanButton.disabled = true;
                buttonText.textContent = 'Scanning...';
            }

            function hideLoading() {
                loading.classList.add('hidden');
                scanButton.disabled = false;
                buttonText.textContent = 'Start Scan';
            }
            
            function runMock() {
                // We use a simple fetch call instead of form submission for clean AJAX handling
                startScan(null, true);
            }
            window.runMock = runMock; // Expose to global scope for button click

            scanForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                startScan(targetInput.value.trim(), false);
            });
            
            async function startScan(target, isMock) {
                if (!target && !isMock) {
                    console.error('Validation Error: Please enter a target IP or range.');
                    return;
                }
                
                showLoading();

                let url = '/scan';
                let data = {};

                if (isMock) {
                    url = '/scan?mock=true';
                } else {
                    data = { target: target };
                }
                
                try {
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: isMock ? JSON.stringify({}) : JSON.stringify(data),
                    });

                    // Handle non-200 responses
                    if (!response.ok) {
                        const errorText = await response.text(); // Read as text in case it's not JSON
                        let errorMessage = `Server returned status ${response.status}`;
                        try {
                            const errorData = JSON.parse(errorText);
                            errorMessage = errorData.error || errorMessage;
                        } catch {
                            // If not JSON, use the raw text
                            errorMessage = errorText;
                        }
                        throw new Error(errorMessage);
                    }
                    
                    const resultData = await response.json();
                    
                    hideLoading();
                    displayResults(resultData.results);

                } catch (error) {
                    console.error('Scan Error:', error);
                    hideLoading();
                    resultsContainer.innerHTML = `<div class="card p-4 bg-red-100 text-red-700 font-medium">Error: ${error.message || 'An unknown error occurred during the scan.'}</div>`;
                    resultsSection.classList.remove('hidden');
                }
            }
            
            function getRiskClass(risk) {
                switch(risk) {
                    case 'CRITICAL': return 'result-critical';
                    case 'HIGH': return 'result-high';
                    case 'MEDIUM': return 'result-medium';
                    default: return 'result-low';
                }
            }

            function displayResults(results) {
                resultsContainer.innerHTML = '';
                if (!results || results.length === 0) {
                    noResults.classList.remove('hidden');
                    resultsSection.classList.remove('hidden');
                    return;
                }
                
                noResults.classList.add('hidden');
                resultsSection.classList.remove('hidden');

                results.forEach(finding => {
                    const riskClass = getRiskClass(finding.risk);
                    
                    const detailsHtml = finding.details.map(detail => {
                        const cve = detail.cve && detail.cve !== 'N/A - Default Setup Risk' ? `<span class="font-mono text-xs bg-gray-200 px-1 rounded ml-1">${detail.cve}</span>` : '';
                        
                        return `
                            <li class="mt-2 ml-4 list-disc text-gray-700">
                                <span class="font-medium">${detail.type}:</span> ${detail.description}${cve}
                            </li>
                        `;
                    }).join('');

                    const portInfo = finding.port ? `Port: ${finding.port}` : '';
                    
                    const resultCard = `
                        <div class="card p-4 ${riskClass}">
                            <div class="flex justify-between items-start mb-2">
                                <span class="font-bold text-lg text-gray-800">${finding.ip}</span>
                                <span class="px-3 py-1 text-sm font-semibold rounded-full 
                                    ${finding.risk === 'CRITICAL' ? 'bg-red-500 text-white' : 
                                      finding.risk === 'HIGH' ? 'bg-orange-500 text-white' : 
                                      finding.risk === 'MEDIUM' ? 'bg-blue-500 text-white' : 'bg-green-500 text-white'}
                                ">
                                    ${finding.risk}
                                </span>
                            </div>
                            ${portInfo ? `<p class="text-sm text-gray-600 mb-2">${portInfo}</p>` : ''}
                            <ul class="list-none space-y-1">
                                ${detailsHtml}
                            </ul>
                        </div>
                    `;
                    resultsContainer.innerHTML += resultCard;
                });
            }
        });
    </script>
</body>
</html>
"""


# --- Core Logic Functions ---

def run_scan_logic(target):
    """Orchestrates the live scanning process."""
    all_results = []
    
    # 1. Parse targets
    try:
        targets = parse_targets(target)
        if not targets:
            return {"error": f"Invalid target specified: {target}"}
    except Exception:
        return {"error": f"Error parsing target range: {target}. Format must be IP or IP-IP."}

    # 2. Setup Scanner
    scanner = PortScanner(
        targets=targets,
        timeout=DEFAULT_TIMEOUT,
        ports_to_scan=COMMON_PORTS,
        credentials=DEFAULT_CREDENTIALS
    )

    # 3. Execute Scan concurrently
    # Note: Using the global ThreadPoolExecutor defined above
    future_to_ip = {executor.submit(scanner.scan_target, ip): ip for ip in targets}
    
    for future in future_to_ip:
        try:
            results = future.result()
            if results:
                all_results.extend(results)
        except Exception as e:
            # Log error but continue with scan results
            print(f"Error scanning {future_to_ip[future]}: {e}", file=sys.stderr)

    # 4. Analyze and Report
    if all_results:
        analyzer = VulnerabilityAnalyzer()
        summary = analyzer.analyze_scan_results(all_results) 
        return {"results": summary}
    
    return {"results": []} # No issues found


# --- Flask Routes ---

@app.route('/', methods=['GET'])
def index():
    """Renders the HTML interface (only handles GET requests)."""
    
    # We rely on JavaScript/AJAX to send all scan requests to the /scan endpoint.
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def run_scan_route():
    """API endpoint to trigger the scan logic."""
    
    # Check for mock flag in query params
    is_mock = request.args.get('mock') == 'true'
    
    if is_mock:
        # Run mock execution and return structured data
        results = handle_mock_execution(MOCK_RESULTS)
        return jsonify({"results": results})

    # --- Handle Live Scan ---
    try:
        # Get target from JSON body (used by modern JS fetch)
        data = request.get_json()
        target = data.get('target')

        if not target:
            return jsonify({"error": "Target IP address or range is required."}), 400
        
        # Run the core scan logic
        response = run_scan_logic(target)
        
        if "error" in response:
            return jsonify(response), 400
            
        # Return results to the frontend
        return jsonify(response)
        
    except Exception as e:
        print(f"Unhandled error in scan route: {e}", file=sys.stderr)
        return jsonify({"error": f"An unhandled server error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    # Ensure debug=True is used cautiously in production
    app.run(host='0.0.0.0', port=5000, debug=True)