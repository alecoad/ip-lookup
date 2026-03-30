#!/usr/bin/env python3
"""
Shodan InternetDB bulk lookup — no API key required.
Usage:
    python idb.py ips.txt
    echo "1.1.1.1" | python idb.py -
    python idb.py ips.txt -o results.json
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.error

BASE_URL = "https://internetdb.shodan.io/{}"


def lookup(ip: str) -> dict:
    try:
        req = urllib.request.Request(
            BASE_URL.format(ip.strip()),
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ip": ip, "error": "no data"}
        return {"ip": ip, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def fmt(result: dict) -> str:
    if "error" in result:
        return f"  [!] {result['error']}"

    fields = [
        ("Ports",     ", ".join(str(p) for p in result.get("ports", []))),
        ("Hostnames", ", ".join(result.get("hostnames", []))),
        ("CPEs",      ", ".join(result.get("cpes", []))),
        ("Vulns",     ", ".join(result.get("vulns", []))),
        ("Tags",      ", ".join(result.get("tags", []))),
    ]
    active = [(k, v) for k, v in fields if v]
    if not active:
        return "  (no interesting data)"
    width = max(len(k) for k, _ in active)
    lines = [f"  {k:{width}} : {v}" for k, v in active]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Shodan InternetDB bulk lookup")
    parser.add_argument("input", help="file of IPs (one per line) or - for stdin")
    parser.add_argument("-o", "--output", help="save raw JSON results to file")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="seconds between requests (default: 0.5)")
    args = parser.parse_args()

    src = sys.stdin if args.input == "-" else open(args.input)
    ips = [line.strip() for line in src if line.strip() and not line.startswith("#")]
    if args.input != "-":
        src.close()

    results = []
    for ip in ips:
        print(f"\n[{ip}]")
        data = lookup(ip)
        print(fmt(data))
        results.append(data)
        if ip != ips[-1]:
            time.sleep(args.delay)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved {len(results)} results to {args.output}")


if __name__ == "__main__":
    main()
