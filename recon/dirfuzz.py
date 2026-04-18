"""
dirfuzz.py - Directory and file fuzzer
Tries paths from a wordlist to find hidden endpoints, admin panels,
backup files, or misconfigured paths on the target web server.
"""

import requests
import threading
import time
from recon.utils import log


# Status codes we care about (not 404, not errors)
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 500}


class DirFuzzer:
    def __init__(self, target, wordlist, threads=10, timeout=3, rate_limit=0.1):
        self.target = target
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.found = []
        self._lock = threading.Lock()

        # Build base URL - try HTTPS first, fall back to HTTP
        self.base_url = self._pick_protocol()

    def _pick_protocol(self):
        for proto in ("https", "http"):
            try:
                r = requests.get(f"{proto}://{self.target}", timeout=self.timeout, verify=False)
                log("DIR", f"Target is reachable over {proto.upper()}")
                return f"{proto}://{self.target}"
            except requests.RequestException:
                continue
        log("WARN", "Target unreachable, defaulting to https")
        return f"https://{self.target}"

    def run(self):
        paths = self._load_wordlist()
        if not paths:
            log("WARN", "Wordlist is empty or not found. Skipping directory fuzzing.")
            return []

        log("DIR", f"Fuzzing {len(paths)} paths with {self.threads} threads")

        sem = threading.Semaphore(self.threads)
        threads = []

        for path in paths:
            t = threading.Thread(target=self._check_path, args=(path, sem))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Sort by status code then path
        self.found.sort(key=lambda x: (x["status"], x["path"]))
        return self.found

    def _check_path(self, path, sem):
        with sem:
            time.sleep(self.rate_limit)
            url = f"{self.base_url}/{path.lstrip('/')}"
            try:
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (recon-tool/1.0)"}
                )

                if resp.status_code in INTERESTING_CODES:
                    note = self._classify(resp.status_code)
                    with self._lock:
                        entry = {
                            "path": path,
                            "url": url,
                            "status": resp.status_code,
                            "size": len(resp.content),
                            "note": note
                        }
                        self.found.append(entry)
                        log("HIT", f"[{resp.status_code}] {url}  ({len(resp.content)} bytes) {note}")

            except requests.RequestException:
                pass  # Timeout or connection error - just skip

    def _classify(self, code):
        """Add a human-readable note to explain what the status means."""
        notes = {
            200: "",
            201: "(created)",
            204: "(no content)",
            301: "(permanent redirect)",
            302: "(temporary redirect)",
            307: "(redirect)",
            401: "(auth required - worth noting)",
            403: "(forbidden - resource exists but blocked)",
            500: "(server error - might be exploitable)"
        }
        return notes.get(code, "")

    def _load_wordlist(self):
        try:
            with open(self.wordlist, "r") as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return lines
        except FileNotFoundError:
            log("WARN", f"Wordlist not found: {self.wordlist}")
            return []
