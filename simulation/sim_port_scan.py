"""Protocol-aware localhost port-scan simulation for the honeypot lab."""

from __future__ import annotations

import argparse
import ftplib
import ipaddress
import socket
import time
import urllib.error
import urllib.request


def _require_loopback(host: str) -> None:
    if host.lower() == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise ValueError("port-scan simulation is restricted to localhost")


def _probe_ssh(host: str, port: int) -> int:
    with socket.create_connection((host, port), timeout=4) as sock:
        sock.recv(256)
        sock.sendall(b"scanner\n")
        sock.recv(256)
        sock.sendall(b"controlled-test\n")
        sock.recv(256)
    return 1


def _probe_ftp(host: str, port: int) -> int:
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=4)
    try:
        ftp.quit()
    except (EOFError, OSError, ftplib.Error):
        ftp.close()
    return 1


def _probe_http(host: str, port: int) -> int:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/", timeout=4) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def simulate_port_scan(
    host: str = "127.0.0.1",
    ssh_port: int = 2222,
    ftp_port: int = 2121,
    http_port: int = 8080,
    delay: float = 0.25,
) -> None:
    """Touch each local honeypot using enough protocol to create valid logs."""

    _require_loopback(host)
    probes = (
        ("SSH", ssh_port, _probe_ssh),
        ("FTP", ftp_port, _probe_ftp),
        ("HTTP", http_port, _probe_http),
    )

    print(f"\n[PORT-SCAN-SIM] Controlled localhost scan → {host}")
    for service, port, probe in probes:
        try:
            result = probe(host, port)
            print(f"  ✓ {service:<4} port {port} observed (result={result})")
        except (ConnectionRefusedError, OSError, urllib.error.URLError) as exc:
            print(f"  ✗ {service:<4} port {port} failed: {exc}")
        time.sleep(delay)
    print("[PORT-SCAN-SIM] Done. Expected attack_type: port_scanning\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local honeypot port-scan simulation")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--ftp-port", type=int, default=2121)
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--delay", type=float, default=0.25)
    arguments = parser.parse_args()
    simulate_port_scan(
        host=arguments.host,
        ssh_port=arguments.ssh_port,
        ftp_port=arguments.ftp_port,
        http_port=arguments.http_port,
        delay=arguments.delay,
    )
