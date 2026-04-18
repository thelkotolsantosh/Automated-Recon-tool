"""
utils.py - Shared helpers used across all modules.
"""

import re
import socket


# ANSI colors for terminal output
COLORS = {
    "INFO":   "\033[94m",   # blue
    "START":  "\033[96m",   # cyan
    "DONE":   "\033[92m",   # green
    "FOUND":  "\033[92m",   # green
    "OPEN":   "\033[92m",   # green
    "HIT":    "\033[93m",   # yellow
    "WARN":   "\033[93m",   # yellow
    "ERROR":  "\033[91m",   # red
    "SUB":    "\033[96m",   # cyan
    "PORT":   "\033[96m",   # cyan
    "DIR":    "\033[96m",   # cyan
    "REPORT": "\033[95m",   # magenta
    "RESET":  "\033[0m",
}


def log(level, message):
    color = COLORS.get(level.upper(), "")
    reset = COLORS["RESET"]
    print(f"{color}[{level.upper()}]{reset} {message}")


def banner():
    print("""
\033[91m
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
  Automated Recon Tool - Bug Bounty Style
  Use only on targets you have permission to scan.
  ─────────────────────────────────────────────
""")


def validate_target(target):
    """
    Basic check: make sure the target looks like a domain name.
    Rejects raw IPs, URLs with http://, and weird characters.
    """
    # Strip protocol if accidentally included
    if target.startswith(("http://", "https://")):
        return False
    # Simple domain regex check
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, target))


def is_alive(hostname, timeout=3):
    """
    Try to open a TCP connection to port 80 or 443.
    If either works, the host is reachable.
    """
    for port in (80, 443):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((hostname, port))
            s.close()
            if result == 0:
                return True
        except socket.error:
            pass
    return False
