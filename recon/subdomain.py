"""
subdomain.py - Subdomain enumeration
Sources used:
  1. crt.sh  - certificate transparency logs (no API key needed)
  2. Brute force - tries common subdomain names
  3. Shodan    - if you have an API key
"""

import requests
import threading
import time
from recon.utils import log, is_alive


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "dev", "staging", "api", "admin", "portal",
    "app", "test", "vpn", "remote", "cdn", "static", "blog", "shop",
    "support", "help", "login", "auth", "oauth", "dashboard", "beta",
    "m", "mobile", "status", "monitor", "docs", "wiki", "git", "jenkins",
    "jira", "confluence", "smtp", "pop", "imap", "ns1", "ns2", "mx",
    "webmail", "cpanel", "whm", "backup", "db", "database", "mysql",
    "postgres", "redis", "elastic", "kibana", "grafana", "prometheus"
]


class SubdomainScanner:
    def __init__(self, target, threads=10, timeout=3, shodan_key=None, rate_limit=0.1):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.shodan_key = shodan_key
        self.rate_limit = rate_limit
        self.found = []
        self._lock = threading.Lock()

    def run(self):
        # Step 1: Pull from crt.sh (certificate transparency)
        log("SUB", "Querying crt.sh for certificate data...")
        self._crtsh_lookup()

        # Step 2: Shodan lookup (if key provided)
        if self.shodan_key:
            log("SUB", "Querying Shodan...")
            self._shodan_lookup()

        # Step 3: Brute force common names
        log("SUB", f"Brute forcing {len(COMMON_SUBDOMAINS)} common subdomain names...")
        self._brute_force()

        # Deduplicate
        seen = set()
        unique = []
        for entry in self.found:
            if entry["subdomain"] not in seen:
                seen.add(entry["subdomain"])
                unique.append(entry)

        self.found = unique
        return self.found

    def _crtsh_lookup(self):
        """
        crt.sh stores SSL certificate data which often reveals subdomains.
        This is passive - we never touch the target server directly.
        """
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        try:
            resp = requests.get(url, timeout=self.timeout * 3)
            if resp.status_code != 200:
                log("WARN", "crt.sh returned non-200 response")
                return

            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                # crt.sh can return multi-line names
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(self.target) and sub != self.target:
                        self._add_result(sub, source="crt.sh")

        except requests.RequestException as e:
            log("WARN", f"crt.sh error: {e}")
        except Exception as e:
            log("WARN", f"crt.sh parse error: {e}")

    def _shodan_lookup(self):
        """
        Shodan indexes internet-facing systems and can reveal subdomains
        tied to a domain that have open ports or services.
        """
        url = f"https://api.shodan.io/dns/domain/{self.target}?key={self.shodan_key}"
        try:
            resp = requests.get(url, timeout=self.timeout * 3)
            if resp.status_code != 200:
                log("WARN", f"Shodan returned {resp.status_code}")
                return

            data = resp.json()
            for sub_entry in data.get("subdomains", []):
                full = f"{sub_entry}.{self.target}"
                self._add_result(full, source="shodan")

        except requests.RequestException as e:
            log("WARN", f"Shodan error: {e}")
        except Exception as e:
            log("WARN", f"Shodan parse error: {e}")

    def _brute_force(self):
        """
        Try common subdomain prefixes by doing a DNS/HTTP check.
        Runs in parallel using threads.
        """
        queue = list(COMMON_SUBDOMAINS)
        sem = threading.Semaphore(self.threads)
        threads = []

        def worker(prefix):
            with sem:
                hostname = f"{prefix}.{self.target}"
                if is_alive(hostname, timeout=self.timeout):
                    self._add_result(hostname, source="brute-force")
                time.sleep(self.rate_limit)

        for prefix in queue:
            t = threading.Thread(target=worker, args=(prefix,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def _add_result(self, subdomain, source="unknown"):
        with self._lock:
            self.found.append({
                "subdomain": subdomain,
                "source": source
            })
            log("FOUND", f"[{source}] {subdomain}")
