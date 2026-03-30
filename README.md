# ip-lookup

Bulk IP lookup against the [Shodan InternetDB](https://internetdb.shodan.io/) API. No API key required.

Returns open ports, hostnames, CPEs, known CVEs, and tags for each IP.

## Usage

```bash
# From a file (one IP per line)
python idb.py ips.txt

# From stdin
echo -e "1.1.1.1\n8.8.8.8" | python idb.py -

# Save raw JSON output
python idb.py ips.txt -o results.json

# Adjust request delay (default 0.5s)
python idb.py ips.txt --delay 1.0
```

## Example output

```
[1.1.1.1]
  Ports     : 53, 80, 443, 2082, 2083, 2086, 2087, 8080, 8443, 8880
  Hostnames : one.one.one.one
  Tags      : cdn

[8.8.8.8]
  Ports     : 53, 443
  Hostnames : dns.google
```

## Requirements

Python 3.6+ — no third-party dependencies.

---

Built with [Claude Code](https://claude.ai/claude-code)
