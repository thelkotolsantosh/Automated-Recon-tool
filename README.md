# Automated-Recon-tool
This is a cli python tool that automates the early stage recon process, used in the bug bounty hunting and pentesting. It chains together subdomain discovery, port scanning, and directory fuzzing into one command and saves everything to a JSON report.
# What does this do?
During real attack scenarios like MoveIT 2024 breach, the attackers just do not jumps straight to exploitation. They started with recon, mapping out every known vuln, whats exposed to the internet before deciding where to strike. This tool automates that first phase of surface recon.
# MODULE            # What does it do?
Subdomain Enum      Finds subdomains via crt.sh, shodan API and bruteforce
Port scan           Checks ~30 mostcommon ports using rawsockets + banner grabbing
Dir Fuzzer          Hits paths from a wordlist to find hidden admin panels, backups and APIs
Reporter            Saves everything to a clean JSON report with a summary

# Quick start:
1.Clone & Install
git clone https://github.com/thelkotolsantosh/recon-tool.git
cd recon-tool
pip install -r requirements.txt

**2.Run Scan**
bash
# Run All modules
Python main.py -t example.com --all

# Run only subdomain enumeration
python main.py -t example.com --subdomains

# Run only port scan
python main.py -t example.com --ports

# Run onl directory fuzzing
python main.py -t example.com --dirs

# Full scan with a Shodan Key and custom output file
python main.py -t example.com --all --shodan-key YOUR_KEY -o results.json

**3.Read your report**
bash
cat report.json

# ALL REPORTS
usage: main.py [-h] -t Target[-o OUTPUT] [--all] [--subdomains] [ ---ports] [--dirs] [--threads N] [--timeout N] [ --wordlist FILE] [--shodan-key KEY] [ --rate-limit SECONDS] 
-t TARGET           Target domain ( e.g. example.com)
-o OUTPUT           Output JSON file (default:report.json)
--all              Run all three modules
--subdomains      Subdomain enumeration only
--ports            Port scan only
--dirs           Directory fuzzing only
--threads N        Parallel threads (default: 10)
--timeout N        Per-request timeout in seconds (default: 3)
--wordlist FILE   Path to dir fuzzing wordlist ( default: wordlists/common_dirs.txt)
--shodan-key KEY   Shodan API key for extra subdomain data
--rate-limit SECS  Delay between requests ( default: 0.1s ) -helps avoid tripping IDS

**Example Output**
Terminal
[START] Subdomain enmeration
[FOUND] [crt.sh] api.example.com
[FOUND] [brute-force] staging.example.com
[DONE] Found 5 subdomains

[START] Port Scanning
[FOUND] Port 22 (SSH) - SSH-2.0-OpenSSH_8.2p1
[FOUND] Port 443 (HTTPS)
[DONE] Found 2 open ports

[START] Directory fuzzing
[FOUND] [200] https://example.com/api/v1 (1243 bytes)
[FOUND] [
[DONE]

