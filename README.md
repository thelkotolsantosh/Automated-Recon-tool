# 🔍 Automated Recon Tool — Bug Bounty Style

A Python CLI tool that automates the early-stage recon process used in bug bounty hunting and penetration testing. It chains together subdomain discovery, port scanning, and directory fuzzing into one command — and saves everything to a JSON report.

> **Disclaimer:** Only run this against targets you own or have written permission to test. Unauthorized scanning is illegal.

---

## What It Does

During real attacks (like the MOVEit 2024 breach), attackers don't jump straight to exploitation. They start with recon — mapping out what's exposed before deciding where to strike. This tool automates that first phase:

| Module | What it does |
|--------|--------------|
| **Subdomain Enum** | Finds subdomains via crt.sh (SSL cert logs), Shodan API, and brute force |
| **Port Scan** | Checks ~30 common ports using raw sockets + banner grabbing |
| **Dir Fuzzer** | Hits paths from a wordlist to find hidden admin panels, backups, APIs |
| **Reporter** | Saves everything to a clean JSON report with a summary |

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/yourusername/recon-tool.git
cd recon-tool
pip install -r requirements.txt
```

### 2. Run a scan

```bash
# Run all modules
python main.py -t example.com --all

# Run only subdomain enumeration
python main.py -t example.com --subdomains

# Run only port scan
python main.py -t example.com --ports

# Run only directory fuzzing
python main.py -t example.com --dirs

# Full scan with a Shodan key and custom output file
python main.py -t example.com --all --shodan-key YOUR_KEY -o results.json
```

### 3. Read your report

```bash
cat report.json
```

---

## All Options

```
usage: main.py [-h] -t TARGET [-o OUTPUT] [--all] [--subdomains] [--ports]
               [--dirs] [--threads N] [--timeout N] [--wordlist FILE]
               [--shodan-key KEY] [--rate-limit SECONDS]

  -t TARGET          Target domain (e.g. example.com)
  -o OUTPUT          Output JSON file (default: report.json)
  --all              Run all three modules
  --subdomains       Subdomain enumeration only
  --ports            Port scan only
  --dirs             Directory fuzzing only
  --threads N        Parallel threads (default: 10)
  --timeout N        Per-request timeout in seconds (default: 3)
  --wordlist FILE    Path to dir fuzzing wordlist (default: wordlists/common_dirs.txt)
  --shodan-key KEY   Shodan API key for extra subdomain data
  --rate-limit SECS  Delay between requests (default: 0.1s) — helps avoid tripping IDS
```

---

## Example Output

Terminal:
```
[START] Subdomain enumeration
[FOUND] [crt.sh] api.example.com
[FOUND] [brute-force] staging.example.com
[DONE]  Found 5 subdomains

[START] Port scanning
[OPEN]  Port 22 (SSH) - SSH-2.0-OpenSSH_8.2p1
[OPEN]  Port 443 (HTTPS)
[DONE]  Found 2 open ports

[START] Directory fuzzing
[HIT]   [200] https://example.com/api/v1  (1243 bytes)
[HIT]   [403] https://example.com/phpmyadmin (forbidden - resource exists but blocked)
[DONE]  Found 6 directories

==================================================
  SCAN SUMMARY
==================================================
  Subdomains found   : 5
  Open ports         : 2
  Directories found  : 6
  Auth-protected     : 1
  Server errors (500): 0
==================================================
```

See [`examples/example_report.json`](examples/example_report.json) for a full JSON report sample.

---

## Project Structure

```
recon-tool/
├── main.py                  # Entry point (run this)
├── requirements.txt
├── wordlists/
│   └── common_dirs.txt      # Paths to fuzz (edit this freely)
├── examples/
│   └── example_report.json  # Sample report output
└── recon/
    ├── main.py              # Argument parsing + orchestration
    ├── subdomain.py         # crt.sh + Shodan + brute force
    ├── portscan.py          # Raw socket scanner + banner grabbing
    ├── dirfuzz.py           # HTTP fuzzer
    ├── report.py            # JSON report writer
    └── utils.py             # Shared helpers (logging, validation)
```

---

## How Each Module Works

### Subdomain Enumeration

Three sources, run in order:

**1. crt.sh** — Certificate transparency logs are public records of every SSL cert ever issued. Domains get listed when the cert is created, so even forgotten subdomains show up here. This is fully passive — we never touch the target.

**2. Shodan** — Shodan indexes internet-facing servers and stores what services they run. With an API key, it can return subdomains associated with a domain. Optional but adds good coverage.

**3. Brute force** — Tries ~50 common prefixes (www, api, dev, staging, admin...) by attempting a TCP connection. If port 80 or 443 responds, the subdomain exists.

---

### Port Scanner

Uses Python's raw `socket` library — no Nmap needed. For each port it:
1. Tries a TCP connect (3s timeout)
2. If open, sends a small probe to grab the banner (the first bytes the service sends back)
3. Banners often reveal software and version info, which you can cross-reference with CVE databases

Runs all ports in parallel threads. The `--rate-limit` flag adds a small delay between connections to avoid triggering IDS rate-limit rules.

**Ports it checks:** FTP, SSH, Telnet, SMTP, DNS, HTTP/S, SMB, MySQL, PostgreSQL, MSSQL, Redis, MongoDB, Elasticsearch, RDP, VNC, and more. See `portscan.py` for the full list.

---

### Directory Fuzzer

Sends HTTP GET requests to paths from `wordlists/common_dirs.txt`. Looks for anything that isn't a 404:

- **200** — Path exists and is accessible
- **301/302/307** — Redirect (something is there)
- **401** — Auth required (resource exists, just locked)
- **403** — Forbidden (exists but blocked — still worth noting)
- **500** — Server error (might indicate a vulnerable or misconfigured endpoint)

The User-Agent is set to a generic browser string. HTTPS is tried first, falls back to HTTP.

---

## Integrating APIs

### crt.sh (no key needed)

Already built in. Just run the tool and it queries automatically.

### Shodan

1. Sign up at [shodan.io](https://shodan.io)
2. Get your API key from your account page
3. Pass it in: `--shodan-key YOUR_KEY`

Free tier works for basic domain lookups.

---

## Detection: How Defenders Spot Scans Like This

Understanding how defenders detect recon is just as useful as knowing how to run it. Here's what to look for on the blue team side:

### IDS Patterns

Tools like Snort and Suricata have built-in rules that flag:
- **Port sweep patterns** — One source IP hitting many ports in quick succession
- **Unusual User-Agent strings** — Scanners often forget to set a realistic UA header
- **404 floods** — A fuzzer hitting hundreds of non-existent paths in seconds
- **Half-open TCP connections** — SYN scans that never complete the handshake

### Rate Limiting

Web servers and cloud WAFs (Cloudflare, AWS WAF) will block or throttle IPs that:
- Send more than N requests/second to the same host
- Return too many 404s from the same IP
- Hit known scanner paths like `/phpmyadmin`, `/.git/config`, etc.

### What Helps (for recon operators)

- Use `--rate-limit 0.5` or higher on real engagements
- Use `--threads 5` instead of 50
- Spread scans over time
- Rotate source IPs when possible (outside scope of this tool)

---

## Mitigation: How to Harden Against This Kind of Recon

If you're defending a system, here's what actually helps:

### Disable Unnecessary Ports

Close anything you don't need. Check what's open:
```bash
# On Linux
ss -tlnp

# Or with nmap from outside
nmap -sV your-server.com
```

Then use your firewall to block it:
```bash
# UFW (Ubuntu)
ufw deny 6379    # Redis shouldn't be public
ufw deny 27017   # MongoDB shouldn't be public
ufw deny 9200    # Elasticsearch shouldn't be public
ufw allow 443
ufw allow 22
ufw enable
```

### Use Firewall Rules

**UFW (Ubuntu)**
```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow https
ufw enable
```

**iptables**
```bash
# Drop everything by default
iptables -P INPUT DROP
iptables -P FORWARD DROP

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH and HTTPS
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

### Other Quick Wins

- **Remove server version headers** — Don't tell scanners what software you're running (`Server: nginx` vs `Server: nginx/1.18.0`)
- **Hide `.git` directories** — Block access to `/.git` in your web server config
- **Rate limit at the WAF level** — Flag IPs that hit 50+ 404s in under a minute
- **Turn off directory listing** — `Options -Indexes` in Apache, `autoindex off` in Nginx
- **Rotate and monitor logs** — Subdomain brute force shows up clearly in DNS query logs

---

## Real-World Context: MOVEit 2024

In the MOVEit Transfer breach (CVE-2024-5806), attackers gained access to file transfer systems used by hundreds of organizations. Before exploiting the vulnerability, they:

1. **Identified exposed MOVEit instances** via Shodan and certificate logs — the same techniques this tool uses
2. **Confirmed which ports were open** (specifically MOVEit's web interface on 443/8443)
3. **Found the login path** (`/human.aspx`) through directory enumeration
4. **Then exploited the auth bypass** — only after confirming the target was running a vulnerable version

The recon phase took minutes for each target. The lesson: if your instance is publicly discoverable, it's a target. Defense starts with reducing your visible attack surface — which is exactly what the mitigation section above covers.

---

## Extending the Tool

Want to add more? A few ideas:

- **Add more API sources** — VirusTotal, SecurityTrails, and HackerTarget all have free tiers
- **Screenshot found pages** — use `playwright` or `selenium` to auto-screenshot 200-response URLs
- **CVE matching** — cross-reference banner strings (e.g. `Apache/2.4.29`) against a CVE database
- **Email harvesting** — scrape discovered pages for email addresses (useful for social engineering scope)
- **HTML report** — render the JSON into a readable HTML report with `jinja2`

---

## Requirements

- Python 3.8+
- `requests` library (see `requirements.txt`)
- No Nmap, no external binaries needed

---

## License

MIT — do what you want, but don't be evil about it.
