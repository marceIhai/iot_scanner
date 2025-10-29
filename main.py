import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

# Absolute imports for modules inside the 'scanner' package
from scanner.config import (
    DEFAULT_TIMEOUT,
    COMMON_PORTS,
    COLOR_MAP,
    DEFAULT_CREDENTIALS,
)
from scanner.reporting import parse_targets, print_summary
from scanner.scanner import PortScanner
from scanner.analyzer import VulnerabilityAnalyzer
# --- FIX: Import MOCK_RESULTS here ---
from scanner.mock_data import handle_mock_execution, MOCK_RESULTS

def main():
    """
    Handles command-line arguments and orchestrates the scanning process.
    """
    parser = argparse.ArgumentParser(
        description="Lightweight IoT Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py 192.168.1.1\n"
            "  python main.py 192.168.1.1-192.168.1.254\n"
            "  python main.py --mock"
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="IP address or IP range (e.g., 10.0.0.1-10.0.0.10).",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run in mock mode, skipping network access and using test data.",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads for scanning (default: 50).",
    )

    args = parser.parse_args()
    all_results = []

    # --- Execution Control ---

    if args.mock:
        # 1. Run Mock Execution
        print(f"{COLOR_MAP['HEADER']}--- RUNNING MOCK SCAN (NETWORK SKIPPED) ---{COLOR_MAP['END']}")
        # --- FIX: Pass MOCK_RESULTS to the function ---
        all_results = handle_mock_execution(MOCK_RESULTS) 

    elif args.target:
        # 2. Run Live Execution
        print(f"{COLOR_MAP['HEADER']}--- STARTING LIVE SCAN ---{COLOR_MAP['END']}")
        targets = parse_targets(args.target)
        if not targets:
            sys.exit(f"{COLOR_MAP['ERROR']}Invalid target specified: {args.target}{COLOR_MAP['END']}")

        scanner = PortScanner(
            timeout=DEFAULT_TIMEOUT,
            ports_to_scan=COMMON_PORTS,
            credentials=DEFAULT_CREDENTIALS
        )

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            # map the scan_target function across all IP targets
            futures = [executor.submit(scanner.scan_target, ip) for ip in targets]
            for future in futures:
                try:
                    results = future.result()
                    if results:
                        all_results.extend(results)
                except Exception as e:
                    # In a real tool, we would log this
                    print(f"{COLOR_MAP['ERROR']}Error during scan: {e}{COLOR_MAP['END']}", file=sys.stderr)

    else:
        # 3. No target or mock flag provided
        parser.print_help()
        sys.exit()

    # --- Analysis and Reporting ---

    if all_results:
        analyzer = VulnerabilityAnalyzer()
        summary = analyzer.analyze_results(all_results)
        print_summary(summary)
    elif args.target:
        print(f"\n{COLOR_MAP['SUCCESS']}Scan complete. No issues found on the target(s).{COLOR_MAP['END']}")


if __name__ == "__main__":
    main()
