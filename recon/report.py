"""
report.py - Saves scan results to a JSON file.
The JSON format makes it easy to pipe into other tools
or build dashboards on top of it.
"""

import json
import os
from recon.utils import log


class ReportWriter:
    def __init__(self, output_file="report.json"):
        self.output_file = output_file

    def save(self, data):
        """Write the full scan result dictionary to disk as pretty JSON."""
        summary = self._build_summary(data)
        data["summary"] = summary

        try:
            with open(self.output_file, "w") as f:
                json.dump(data, f, indent=4)
            self._print_summary(summary)
        except IOError as e:
            log("ERROR", f"Could not write report: {e}")

    def _build_summary(self, data):
        open_ports = [p for p in data.get("ports", []) if p.get("state") == "open"]
        risky_ports = [p for p in open_ports if p["port"] in (21, 23, 3389, 5900, 6379, 27017, 9200)]

        return {
            "total_subdomains": len(data.get("subdomains", [])),
            "total_open_ports": len(open_ports),
            "risky_ports": [f"{p['port']} ({p['service']})" for p in risky_ports],
            "total_dirs_found": len(data.get("directories", [])),
            "dirs_403_or_401": len([
                d for d in data.get("directories", [])
                if d.get("status") in (401, 403)
            ]),
            "server_errors": len([
                d for d in data.get("directories", [])
                if d.get("status") == 500
            ])
        }

    def _print_summary(self, summary):
        print("\n" + "=" * 50)
        print("  SCAN SUMMARY")
        print("=" * 50)
        print(f"  Subdomains found   : {summary['total_subdomains']}")
        print(f"  Open ports         : {summary['total_open_ports']}")
        if summary["risky_ports"]:
            print(f"  ⚠  Risky ports    : {', '.join(summary['risky_ports'])}")
        print(f"  Directories found  : {summary['total_dirs_found']}")
        print(f"  Auth-protected     : {summary['dirs_403_or_401']}")
        print(f"  Server errors (500): {summary['server_errors']}")
        print("=" * 50 + "\n")
