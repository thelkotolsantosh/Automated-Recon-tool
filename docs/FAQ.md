# ❓ Frequently Asked Questions — Automated Recon Tool

> A comprehensive FAQ covering general questions, installation (Linux & Windows), usage, modules, output, troubleshooting, legal/ethics, and contribution.

---

## Table of Contents

1. [What is the Automated Recon Tool?](#1-what-is-the-automated-recon-tool)
2. [Who is this tool intended for?](#2-who-is-this-tool-intended-for)
3. [Is it legal to use this tool?](#3-is-it-legal-to-use-this-tool)
4. [Step-by-step installation on Linux](#4-step-by-step-installation-on-linux)
5. [Step-by-step installation on Windows](#5-step-by-step-installation-on-windows)
6. [What are the system requirements?](#6-what-are-the-system-requirements)
7. [Do I need Nmap or any external binary installed?](#7-do-i-need-nmap-or-any-external-binary-installed)
8. [How do I run a full scan against a target?](#8-how-do-i-run-a-full-scan-against-a-target)
9. [What does each scanning module do?](#9-what-does-each-scanning-module-do)
10. [How do I use only one module at a time?](#10-how-do-i-use-only-one-module-at-a-time)
11. [How do I integrate the Shodan API?](#11-how-do-i-integrate-the-shodan-api)
12. [Where is the scan report saved and what format is it in?](#12-where-is-the-scan-report-saved-and-what-format-is-it-in)
13. [How do I control scan speed and avoid detection?](#13-how-do-i-control-scan-speed-and-avoid-detection)
14. [What do the HTTP status codes in the directory fuzzer output mean?](#14-what-do-the-http-status-codes-in-the-directory-fuzzer-output-mean)
15. [Can I use a custom wordlist for directory fuzzing?](#15-can-i-use-a-custom-wordlist-for-directory-fuzzing)
16. [Why are no subdomains being found?](#16-why-are-no-subdomains-being-found)
17. [The tool is running slowly — how do I speed it up?](#17-the-tool-is-running-slowly--how-do-i-speed-it-up)
18. [I am getting a `ModuleNotFoundError` — how do I fix it?](#18-i-am-getting-a-modulenotfounderror--how-do-i-fix-it)
19. [How do I extend the tool with new features?](#19-how-do-i-extend-the-tool-with-new-features)
20. [How can I contribute to the project?](#20-how-can-i-contribute-to-the-project)

---

## 1. What is the Automated Recon Tool?

The Automated Recon Tool is a Python-based command-line interface (CLI) tool that automates the early-stage reconnaissance process used in bug bounty hunting and penetration testing. Instead of running separate tools for each recon task, it chains together three core modules — subdomain enumeration, port scanning, and directory fuzzing — into a single command and saves the complete results to a structured JSON report.

It was inspired by how real-world attackers (and security researchers) approach target mapping before any exploitation attempt, as seen in breaches like the MOVEit 2024 incident.

---

## 2. Who is this tool intended for?

This tool is intended for:

- **Bug bounty hunters** who need a fast, automated recon workflow during the early stage of an engagement.
- **Penetration testers** who want a lightweight alternative to heavy recon frameworks.
- **Security students and researchers** who want to understand how reconnaissance is conducted and how defenders can detect it.
- **Blue teamers** who want to understand the attacker's perspective and improve defensive controls.

> ⚠️ **You must only use this tool against targets you own or have explicit written permission to test.**

---

## 3. Is it legal to use this tool?

**It depends entirely on the target.**

Using this tool against systems you own, a personal lab, or within an authorized bug bounty program scope is legal. Running it against any system without written authorization is illegal under laws such as the Computer Fraud and Abuse Act (CFAA) in the United States and similar legislation worldwide.

The tool itself is neutral — it is how and where you use it that determines legality. Always verify that your target is in-scope before running any scan.

---

## 4. Step-by-step installation on Linux

Follow these steps on any Debian/Ubuntu-based distro (or adapt for Arch/Fedora equivalents).

### Step 1 — Ensure Python 3.8+ is installed
```bash
python3 --version
```
If Python is missing, install it:
```bash
sudo apt update && sudo apt install python3 python3-pip -y
```

### Step 2 — Install Git (if not already installed)
```bash
sudo apt install git -y
```

### Step 3 — Clone the repository
```bash
git clone https://github.com/thelkotolsantosh/Automated-Recon-tool.git
cd Automated-Recon-tool
```

### Step 4 — (Recommended) Create and activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 5 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 6 — Verify the tool is working
```bash
python3 main.py --help
```
You should see the full list of available flags and options printed to the terminal.

### Step 7 — Run your first scan
```bash
python3 main.py -t example.com --all
```

---

## 5. Step-by-step installation on Windows

Follow these steps on Windows 10 or Windows 11.

### Step 1 — Install Python 3.8+
1. Go to [https://www.python.org/downloads/](https://www.python.org/downloads/) and download the latest Python 3 installer.
2. Run the installer. **Check the box "Add Python to PATH"** before clicking Install.
3. Verify the installation by opening **Command Prompt** (`Win + R` → type `cmd` → Enter):
```cmd
python --version
```

### Step 2 — Install Git
1. Go to [https://git-scm.com/download/win](https://git-scm.com/download/win) and download the installer.
2. Run the installer with default settings.
3. Verify:
```cmd
git --version
```

### Step 3 — Clone the repository
Open **Command Prompt** or **Git Bash** and run:
```cmd
git clone https://github.com/thelkotolsantosh/Automated-Recon-tool.git
cd Automated-Recon-tool
```

### Step 4 — (Recommended) Create and activate a virtual environment
```cmd
python -m venv venv
venv\Scripts\activate
```
You should see `(venv)` appear at the start of your prompt.

### Step 5 — Install dependencies
```cmd
pip install -r requirements.txt
```

### Step 6 — Verify the tool is working
```cmd
python main.py --help
```

### Step 7 — Run your first scan
```cmd
python main.py -t example.com --all
```

> 💡 **Windows tip:** If you see a `permission denied` error on port scanning, try running Command Prompt **as Administrator** (right-click → Run as administrator).

---

## 6. What are the system requirements?

| Requirement | Minimum |
|---|---|
| Python | 3.8 or higher |
| OS | Linux, macOS, Windows 10/11 |
| RAM | 256 MB (512 MB recommended for large scans) |
| Network | Active internet connection |
| Python Libraries | `requests >= 2.28.0`, `urllib3 >= 1.26.0` |
| External Binaries | None — no Nmap or other tools required |

---

## 7. Do I need Nmap or any external binary installed?

**No.** The port scanner is built entirely with Python's standard `socket` library. It performs raw TCP connect scans and banner grabbing without requiring Nmap, masscan, or any other external binary. This makes the tool portable and easy to set up on any system with Python installed.

---

## 8. How do I run a full scan against a target?

To run all three modules (subdomain enumeration, port scan, and directory fuzzing) in a single command:

```bash
python3 main.py -t example.com --all
```

To also use Shodan for enhanced subdomain discovery and save the report to a custom file:
```bash
python3 main.py -t example.com --all --shodan-key YOUR_SHODAN_KEY -o my_report.json
```

The tool will run each module sequentially and print a summary to the terminal when finished. The full JSON report is saved to `report.json` (or whatever filename you specified with `-o`).

---

## 9. What does each scanning module do?

The tool has three core modules:

**Subdomain Enumeration (`--subdomains`)**
Discovers subdomains using three techniques: passive certificate transparency log lookups via crt.sh, optional Shodan API queries, and active brute-force probing of ~50 common prefixes (e.g., `www`, `api`, `dev`, `staging`, `admin`).

**Port Scanner (`--ports`)**
Checks approximately 30 common ports using raw TCP sockets. For each open port, it attempts to grab the service banner, which often reveals the software name and version number useful for CVE lookups. Ports include FTP, SSH, HTTP/S, SMB, MySQL, Redis, MongoDB, RDP, and more.

**Directory Fuzzer (`--dirs`)**
Sends HTTP GET requests to paths listed in `wordlists/common_dirs.txt`. It flags any response that is not a `404`, including `200` (accessible), `301/302` (redirects), `401` (auth required), `403` (forbidden but exists), and `500` (server error).

---

## 10. How do I use only one module at a time?

You can run each module independently using its dedicated flag:

```bash
# Subdomain enumeration only
python3 main.py -t example.com --subdomains

# Port scan only
python3 main.py -t example.com --ports

# Directory fuzzing only
python3 main.py -t example.com --dirs
```

This is useful when you only need specific information or want to re-run a single phase without repeating the full scan.

---

## 11. How do I integrate the Shodan API?

Shodan provides additional subdomain and host data beyond what crt.sh can return. To use it:

1. Sign up for a free account at [https://shodan.io](https://shodan.io).
2. Navigate to your account page and copy your API key.
3. Pass it to the tool using the `--shodan-key` flag:

```bash
python3 main.py -t example.com --subdomains --shodan-key YOUR_API_KEY
```

The free Shodan tier is sufficient for basic domain lookups. Shodan integration is entirely optional — the tool works without it.

---

## 12. Where is the scan report saved and what format is it in?

By default, the report is saved as `report.json` in the same directory where you run the tool. You can customize the filename and path using the `-o` flag:

```bash
python3 main.py -t example.com --all -o /home/user/scans/target_report.json
```

The report is saved in **JSON format** and includes all discovered subdomains, open ports with banner information, discovered directories with their HTTP status codes, and a summary section. See `examples/example_report.json` in the repository for a sample output.

---

## 13. How do I control scan speed and avoid detection?

Two flags give you control over scan aggressiveness:

**`--threads N`** — Controls how many requests run in parallel. The default is `10`. Lower this on sensitive engagements:
```bash
python3 main.py -t example.com --all --threads 5
```

**`--rate-limit SECONDS`** — Adds a delay (in seconds) between each request. The default is `0.1` seconds. Increasing this reduces the chance of triggering WAF or IDS rate-limiting rules:
```bash
python3 main.py -t example.com --all --rate-limit 0.5
```

For real-world engagements, a combination of `--threads 5` and `--rate-limit 0.5` is a reasonable starting point to avoid standing out in logs.

---

## 14. What do the HTTP status codes in the directory fuzzer output mean?

| Status Code | Meaning | Significance |
|---|---|---|
| `200 OK` | Path exists and is accessible | High — review the content immediately |
| `301 / 302 / 307` | Redirect | Medium — something exists at the path |
| `401 Unauthorized` | Auth required | Medium — resource exists but is protected |
| `403 Forbidden` | Exists but access is blocked | Medium — worth noting; may be bypassable |
| `500 Internal Server Error` | Server error | High — may indicate a misconfigured or vulnerable endpoint |
| `404 Not Found` | Path does not exist | Filtered out by default |

---

## 15. Can I use a custom wordlist for directory fuzzing?

Yes. The default wordlist is located at `wordlists/common_dirs.txt`. You can supply any plain-text wordlist (one path per line) using the `--wordlist` flag:

```bash
python3 main.py -t example.com --dirs --wordlist /path/to/my_wordlist.txt
```

Popular community wordlists such as those from [SecLists](https://github.com/danielmiessler/SecLists) (`raft-large-directories.txt`, `common.txt`) work well with this tool and can dramatically expand coverage.

---

## 16. Why are no subdomains being found?

There are a few common reasons:

- **crt.sh rate limit or timeout** — crt.sh is a free public service and can be slow or temporarily unavailable. Re-run the scan after a short wait.
- **The domain has few SSL certificates issued** — Newer or private domains may not appear in certificate transparency logs.
- **No Shodan key provided** — Without a Shodan key, you lose one of the three discovery methods. Add `--shodan-key YOUR_KEY` for better coverage.
- **Brute-force is timing out** — Try increasing `--timeout` slightly: `--timeout 5`.
- **The domain has no publicly reachable subdomains** — This is a valid result; not all domains have exposed subdomains.

---

## 17. The tool is running slowly — how do I speed it up?

Try the following adjustments:

- **Increase threads:** `--threads 20` (use carefully to avoid triggering rate limits)
- **Decrease timeout:** `--timeout 2` reduces how long the tool waits per connection
- **Run modules separately** instead of `--all` to isolate which phase is slow
- **Use a smaller wordlist** for directory fuzzing to reduce the total number of requests
- **Check your network speed** — scans are network-bound; a slow or throttled connection will limit performance

---

## 18. I am getting a `ModuleNotFoundError` — how do I fix it?

This error means a required Python library is not installed in the current environment. Fix it by running:

**Linux / macOS:**
```bash
pip3 install -r requirements.txt
```

**Windows:**
```cmd
pip install -r requirements.txt
```

If you are using a virtual environment, make sure it is **activated** before installing:

**Linux / macOS:**
```bash
source venv/bin/activate
pip install -r requirements.txt
```

**Windows:**
```cmd
venv\Scripts\activate
pip install -r requirements.txt
```

If the error persists for a specific library, install it manually:
```bash
pip install requests urllib3
```

---

## 19. How do I extend the tool with new features?

The project is structured to make adding new modules straightforward. The `recon/` directory contains individual module files:

```
recon/
├── subdomain.py    # Add new subdomain sources here (VirusTotal, SecurityTrails, etc.)
├── portscan.py     # Add new ports or scanning techniques here
├── dirfuzz.py      # Modify request behavior or add new HTTP methods here
├── report.py       # Extend the JSON report structure here
└── utils.py        # Add shared helpers here
```

Some ideas from the README for extending the tool:
- **Additional subdomain sources** — VirusTotal, SecurityTrails, and HackerTarget all have free API tiers.
- **Screenshot capture** — Use `playwright` or `selenium` to auto-screenshot `200`-response URLs.
- **CVE matching** — Cross-reference banner strings (e.g., `Apache/2.4.29`) against the NVD CVE database.
- **HTML report generation** — Render the JSON output into a readable HTML report using `jinja2`.
- **Email harvesting** — Scrape discovered pages for email addresses useful in social engineering scope testing.

---

## 20. How can I contribute to the project?

Contributions are welcome! Here is how to get started:

### Step 1 — Fork the repository
Click the **Fork** button on the GitHub repository page to create your own copy.

### Step 2 — Clone your fork locally
```bash
git clone https://github.com/YOUR_USERNAME/Automated-Recon-tool.git
cd Automated-Recon-tool
```

### Step 3 — Create a new feature branch
```bash
git checkout -b feature/your-feature-name
```

### Step 4 — Make your changes
Edit or add files in the `recon/` directory, update `wordlists/`, or improve documentation.

### Step 5 — Commit your changes
```bash
git add .
git commit -m "feat: add VirusTotal subdomain source"
```

### Step 6 — Push and open a Pull Request
```bash
git push origin feature/your-feature-name
```
Then navigate to the original repository on GitHub and click **New Pull Request**.

### Contribution guidelines
- Keep new modules self-contained and placed in the `recon/` directory.
- Add a short comment block at the top of each new file explaining what it does.
- Test your changes against a domain you own before submitting.
- Do not introduce dependencies beyond what is already in `requirements.txt` without discussion.

---

> 📄 **License:** This project is released under the MIT License. Use it freely, but responsibly.
>
> ⚠️ **Reminder:** Unauthorized scanning is illegal. Always obtain written permission before testing any system you do not own.
