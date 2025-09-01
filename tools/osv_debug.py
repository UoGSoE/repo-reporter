#!/usr/bin/env python3
"""
Quick OSV debug helper.

Usage:
  python tools/osv_debug.py --id GHSA-25mq-v84q-4j7r
  python tools/osv_debug.py --pkg guzzlehttp/guzzle --eco Packagist --ver 7.8.1
"""

import argparse
import json
import sys
import requests


def fetch_by_id(vuln_id: str):
    url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.json()


def fetch_by_pkg(pkg: str, eco: str, ver: str):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": pkg, "ecosystem": eco},
        "version": ver,
    }
    r = requests.post(url, json=payload, timeout=15)
    r.raise_for_status()
    return r.json()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", dest="osv_id")
    ap.add_argument("--pkg")
    ap.add_argument("--eco")
    ap.add_argument("--ver")
    args = ap.parse_args()

    try:
        if args.osv_id:
            data = fetch_by_id(args.osv_id)
            print(json.dumps({
                "id": data.get("id"),
                "aliases": data.get("aliases"),
                "database_specific": data.get("database_specific"),
                "severity": data.get("severity"),
                "affected_count": len(data.get("affected", []) or []),
            }, indent=2))
        elif args.pkg and args.eco and args.ver:
            data = fetch_by_pkg(args.pkg, args.eco, args.ver)
            # Print a compact list of vulns with severity details
            out = []
            for v in data.get("vulns", []) or []:
                out.append({
                    "id": v.get("id"),
                    "database_specific.severity": (v.get("database_specific", {}) or {}).get("severity"),
                    "severity": v.get("severity"),
                    "summary": v.get("summary"),
                })
            print(json.dumps(out, indent=2))
        else:
            ap.print_help()
            return 2
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

