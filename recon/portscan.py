"""
portscan.py - Port scanner
Checks common ports to see which ones are open on the target.
Uses raw sockets (no nmap dependency needed).
"""

import socket
import threading
import time
from recon.utils import log


# These are the ports most likely to be interesting during recon
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    3000: "Dev Server (Node/Rails)",
    3306: "MySQL",
    3389: "RDP",
    4443: "Alt HTTPS",
    4848: "GlassFish Admin",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    7001: "WebLogic",
    8000: "Alt HTTP",
    8080: "Alt HTTP Proxy",
    8443: "Alt HTTPS",
    8888: "Jupyter / Dev",
    9200: "Elasticsearch",
    9300: "Elasticsearch Cluster",
    27017:"MongoDB",
    27018:"MongoDB Alt",
}


class PortScanner:
    def __init__(self, target, threads=10, timeout=3, rate_limit=0.1):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.open_ports = []
        self._lock = threading.Lock()

    def run(self):
        log("PORT", f"Scanning {len(COMMON_PORTS)} common ports on {self.target}")

        sem = threading.Semaphore(self.threads)
        threads = []

        for port, service in COMMON_PORTS.items():
            t = threading.Thread(target=self._scan_port, args=(port, service, sem))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Sort results by port number
        self.open_ports.sort(key=lambda x: x["port"])
        return self.open_ports

    def _scan_port(self, port, service, sem):
        with sem:
            time.sleep(self.rate_limit)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))
                s.close()

                if result == 0:
                    banner = self._grab_banner(port)
                    with self._lock:
                        entry = {
                            "port": port,
                            "service": service,
                            "state": "open",
                            "banner": banner
                        }
                        self.open_ports.append(entry)
                        log("OPEN", f"Port {port} ({service}){' - ' + banner if banner else ''}")

            except socket.error as e:
                log("WARN", f"Socket error on port {port}: {e}")

    def _grab_banner(self, port):
        """
        Try to read the first bytes the service sends back.
        This can reveal software version info (useful for CVE matching).
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.target, port))

            # HTTP services need a nudge
            if port in (80, 8080, 8000):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                s.close()
                return None  # TLS banners need ssl wrap, skip for now

            raw = s.recv(1024)
            s.close()
            return raw.decode(errors="replace").strip()[:200]

        except Exception:
            return None
