#!/usr/bin/env python3
"""
Shodan InternetDB lookup — no API key required.
Usage:
    ipsho 1.1.1.1                 # single IP
    ipsho 1.1.1.1 8.8.8.8         # multiple IPs
    ipsho -l ips.txt              # list / scope file
    cat ips.txt | ipsho           # stdin
    ipsho -l ips.txt -o out.json  # save raw JSON
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.error

BASE_URL = "https://internetdb.shodan.io/{}"

# ANSI colors
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
GREY   = "\033[90m"
WHITE  = "\033[97m"

# Per-field colors
FIELD_COLORS = {
    "Ports":     GREEN,
    "Hostnames": CYAN,
    "CPEs":      YELLOW,
    "Vulns":     RED,
    "Tags":      WHITE,
}


def c(color: str, text: str) -> str:
    """Wrap text in a color if stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return text


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
        return c(GREY, f"  [!] {result['error']}")

    fields = [
        ("Ports",     ", ".join(str(p) for p in result.get("ports", []))),
        ("Hostnames", ", ".join(result.get("hostnames", []))),
        ("CPEs",      ", ".join(result.get("cpes", []))),
        ("Vulns",     ", ".join(result.get("vulns", []))),
        ("Tags",      ", ".join(result.get("tags", []))),
    ]
    active = [(k, v) for k, v in fields if v]
    if not active:
        return c(GREY, "  (no interesting data)")
    width = max(len(k) for k, _ in active)
    lines = [
        f"  {c(BOLD, f'{k:{width}}')} {c(GREY, ':')} {c(FIELD_COLORS[k], v)}"
        for k, v in active
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Shodan InternetDB lookup")
    parser.add_argument("targets", nargs="*", help="one or more IPs to look up")
    parser.add_argument("-l", "--list",
                        help="file of IPs (one per line) or - for stdin")
    parser.add_argument("-o", "--output", help="save raw JSON results to file")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="seconds between requests (default: 0.5)")
    args = parser.parse_args()

    ips = list(args.targets)

    if args.list:
        src = sys.stdin if args.list == "-" else open(args.list)
        ips += [line.strip() for line in src
                if line.strip() and not line.startswith("#")]
        if args.list != "-":
            src.close()
    elif not ips and not sys.stdin.isatty():
        ips += [line.strip() for line in sys.stdin
                if line.strip() and not line.startswith("#")]

    if not ips:
        parser.error("provide an IP, -l FILE, or pipe IPs on stdin")

    results = []
    for ip in ips:
        print(f"\n{c(BOLD + CYAN, f'[ {ip} ]')}")
        data = lookup(ip)
        print(fmt(data))
        results.append(data)
        if ip != ips[-1]:
            time.sleep(args.delay)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n{c(GREEN, 'Saved')} {len(results)} results to {c(BOLD, args.output)}")


if __name__ == "__main__":
    main()
