#!/usr/bin/env python3
"""
netscan.py – single-file network scanner & vuln checker
"""
import argparse
import asyncio
import ipaddress
import json
import logging
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List

import scapy.all as scapy
from loguru import logger
from rich.console import Console
from rich.table import Table
from jinja2 import Template

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
logger.remove()
logger.add(
    sys.stderr,
    level="INFO",
    format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | <level>{message}</level>",
)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
TOP_TCP = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080
] + list(range(8000, 8010))
TOP_UDP = [53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520, 631, 1434, 1900, 4500, 49152, 49153, 49154]
BANNER_TIMEOUT = 2
CVE_DB: Dict[str, Dict[str, str]] = {
    "ssh": {"CVE-2024-1234": "OpenSSH ≤9.6 auth bypass"},
    "http": {"CVE-2024-4321": "Apache httpd 2.4.x RCE"},
    "ftp": {"CVE-2025-0001": "vsftpd 3.0.3 backdoor"},
}


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class Host:
    def __init__(self, ip: str, mac: str = "") -> None:
        self.ip = ip
        self.mac = mac
        self.tcp: Dict[int, Dict[str, str]] = {}
        self.udp: Dict[int, str] = {}
        self.vulns: List[str] = []

    def to_dict(self) -> Dict[str, any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "tcp": self.tcp,
            "udp": self.udp,
            "vulns": self.vulns,
        }


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
async def arp_ping(cidr: str) -> List[str]:
    ans, _ = scapy.arping(cidr, verbose=False, timeout=2)
    return [rcv.psrc for _, rcv in ans]


async def icmp_ping(cidr: str) -> List[str]:
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c1", "-W1", "-b", str(ipaddress.ip_network(cidr).network_address),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    await proc.wait()
    # naive fallback
    net = ipaddress.ip_network(cidr)
    tasks = [asyncio.create_task(_icmp_single(str(ip))) for ip in net.hosts()]
    results = await asyncio.gather(*tasks)
    return [ip for ip, alive in results if alive]


async def _icmp_single(ip: str) -> tuple[str, bool]:
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c1", "-W1", ip, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return ip, (await proc.wait()) == 0


# --------------------------------------------------------------------------- #
# Port Scan
# --------------------------------------------------------------------------- #
async def tcp_scan(hosts: List[str], ports: List[int]) -> Dict[str, Host]:
    hosts_dict = {ip: Host(ip) for ip in hosts}
    tasks = [asyncio.create_task(_tcp_connect(ip, p, hosts_dict)) for ip in hosts for p in ports]
    await asyncio.gather(*tasks)
    return hosts_dict


async def udp_scan(hosts: List[str], ports: List[int], hosts_dict: Dict[str, Host]) -> None:
    tasks = [asyncio.create_task(_udp_probe(ip, p, hosts_dict)) for ip in hosts for p in ports]
    await asyncio.gather(*tasks)


async def _tcp_connect(ip: str, port: int, hosts_dict: Dict[str, Host]) -> None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=BANNER_TIMEOUT)
        banner = await _grab_banner(reader)
        writer.close()
        await writer.wait_closed()
        hosts_dict[ip].tcp[port] = {"state": "open", "banner": banner}
        if banner:
            hosts_dict[ip].vulns.extend(_match_cve(banner))
    except Exception:
        pass


async def _udp_probe(ip: str, port: int, hosts_dict: Dict[str, Host]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(BANNER_TIMEOUT)
    try:
        sock.sendto(b"", (ip, port))
        _, addr = sock.recvfrom(1024)
        hosts_dict[ip].udp[port] = "open"
    except socket.timeout:
        pass
    except Exception:
        pass
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Banner & CVE matching
# --------------------------------------------------------------------------- #
async def _grab_banner(reader: asyncio.StreamReader) -> str:
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def _match_cve(banner: str) -> List[str]:
    vulns = []
    for service, cves in CVE_DB.items():
        if service in banner.lower():
            vulns.extend(cves.keys())
    return vulns


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def console_report(results: Dict[str, Host]) -> None:
    table = Table(title="NetScan Results")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Open TCP", style="green")
    table.add_column("Open UDP", style="yellow")
    table.add_column("CVEs", style="red")
    for h in results.values():
        tcp = ", ".join(str(p) for p in h.tcp) or ""
        udp = ", ".join(str(p) for p in h.udp) or ""
        cve = ", ".join(h.vulns) or ""
        table.add_row(h.ip, h.mac, tcp, udp, cve)
    Console().print(table)


def save_json(results: Dict[str, Host], path: Path) -> None:
    with path.open("w") as fp:
        json.dump({ip: h.to_dict() for ip, h in results.items()}, fp, indent=2)


def save_html(results: Dict[str, Host], path: Path) -> None:
    template = Template(
        """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>NetScan Report</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="container py-4">
<h1 class="mb-4">NetScan Report</h1>
<table class="table table-sm table-bordered">
<thead><tr><th>IP</th><th>MAC</th><th>Open TCP</th><th>Open UDP</th><th>CVEs</th></tr></thead>
<tbody>
{% for ip, host in results.items() %}
<tr>
  <td>{{ host.ip }}</td>
  <td>{{ host.mac }}</td>
  <td>{{ host.tcp.keys()|list|join(', ') }}</td>
  <td>{{ host.udp.keys()|list|join(', ') }}</td>
  <td>{{ host.vulns|join(', ') }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</body>
</html>
    """
    )
    with path.open("w") as fp:
        fp.write(template.render(results=results))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
async def main() -> None:
    parser = argparse.ArgumentParser(description="NetScan CLI")
    parser.add_argument("-t", "--target", required=True, help="CIDR or IP")
    parser.add_argument("-p", "--ports", default="", help="comma list of tcp ports")
    parser.add_argument("-o", "--output", choices=["json", "html"], help="save report")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logs")
    parser.add_argument("-s", "--scan-type", choices=["arp", "icmp", "both"], default="arp")
    args = parser.parse_args()

    if args.verbose:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG")

    tcp_ports = [int(p) for p in args.ports.split(",") if p] or TOP_TCP
    udp_ports = TOP_UDP

    logger.info("Starting discovery", target=args.target, scan_type=args.scan_type)
    if args.scan_type == "arp":
        hosts = await arp_ping(args.target)
    elif args.scan_type == "icmp":
        hosts = await icmp_ping(args.target)
    else:
        hosts = list(set(await arp_ping(args.target) + await icmp_ping(args.target)))

    logger.info("Discovered hosts", count=len(hosts))

    results = await tcp_scan(hosts, tcp_ports)
    await udp_scan(hosts, udp_ports, results)

    console_report(results)

    if args.output == "json":
        save_json(results, Path("report.json"))
    elif args.output == "html":
        save_html(results, Path("report.html"))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Aborted by user")