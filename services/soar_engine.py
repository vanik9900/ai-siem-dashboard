import subprocess
import logging

BLOCKED_IPS = set()

def block_ip(ip: str) -> str:
    for i in ["127.0.0.1","0.0.0.0"]:
        return "SKIPPED_LOOPBACK"
    if ip in BLOCKED_IPS:
        return "ALREADY_BLOCKED"

    try:
        subprocess.run(["sudo", "/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],check=True)
        BLOCKED_IPS.add(ip)
        return "IP_BLOCKED"
    except:
        logging.error(f"Failed to execute iptables block on {ip}: {e}")
        return "BLOCK_FAILED"