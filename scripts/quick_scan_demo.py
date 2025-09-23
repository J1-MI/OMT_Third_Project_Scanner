
"""
Quick wrapper to run an nmap scan via existing scan_runner.py and then parse the produced XML.
Usage (from project root):
  # dry-run
  python .\scripts\quick_scan_demo.py --profile safe_operational --target demo.testfire.net
  # actual run
  python .\scripts\quick_scan_demo.py --profile recon_aggressive --target demo.testfire.net --run

This script:
 - calls python scripts/scan_runner.py <profile> <target> [--run]
 - finds the latest XML in nmap_outputs and invokes nmap_parser.py on it
 - prints a small summary to stdout
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTDIR = ROOT / "nmap_outputs"
SCAN_RUNNER = ROOT / "scripts" / "scan_runner.py"
PARSER = ROOT / "scripts" / "nmap_parser.py"

def run_scan(profile, target, do_run=False):
    cmd = [sys.executable, str(SCAN_RUNNER), profile, target]
    if do_run:
        cmd.append("--run")
    print("Running:", " ".join(cmd))
    # This will block until scan_runner finishes (nmap may take long)
    subprocess.run(cmd, check=True)

def find_latest_xml():
    xmls = sorted(OUTDIR.glob("*.xml"), key=lambda p: p.stat().st_mtime, reverse=True)
    return xmls[0] if xmls else None

def parse_xml(xml_path):
    if not xml_path:
        print("No XML found to parse.")
        return
    cmd = [sys.executable, str(PARSER), str(xml_path)]
    print("Parsing:", xml_path.name)
    subprocess.run(cmd, check=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--profile", required=True, help="scan profile name (safe_operational / recon_aggressive / ...)")
    p.add_argument("--target", required=True, help="target hostname or IP")
    p.add_argument("--run", action="store_true", help="actually run nmap (otherwise dry-run)")
    args = p.parse_args()

    # Run scan
    run_scan(args.profile, args.target, do_run=args.run)

    # wait a little for xml file to be written (if running)
    if args.run:
        # poll for new xml (timeout after some time)
        timeout = 60  # seconds (increase for bigger scans)
        waited = 0
        last = find_latest_xml()
        while waited < timeout:
            time.sleep(1)
            waited += 1
            latest = find_latest_xml()
            if latest and latest != last:
                parse_xml(latest)
                break
        else:
            print("Timed out waiting for XML (increase timeout or check nmap_outputs).")
    else:
        # dry run: still try to find the most recent xml if any and parse
        latest = find_latest_xml()
        if latest:
            parse_xml(latest)
        else:
            print("Dry-run completed; no xml to parse (expected).")

if __name__ == "__main__":
    main()
