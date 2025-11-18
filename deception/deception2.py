#!/usr/bin/env python3
"""
Minimal deception proxy (Module 1 skeleton)

Server1 (this box): 192.168.100.5
Decoy:              192.168.100.6
Server2 (backup):   192.168.100.7

- Listens on TCP/80 on Server1.
- Detects SYN scans to Server1 IP using Scapy.
- Any IP that scans many ports in a short time -> suspicious.
- suspicious IPs -> forwarded to Decoy.
- After first attacker, all *other* clients -> forwarded to Server2.
"""

import logging
import socket
import threading
import time

from scapy.all import sniff, IP, TCP

# -------------------- CONFIG --------------------

SERVER1_IP = "192.168.100.5"     # This machine
HONEYPOT_IP = "192.168.100.6"    # Decoy web server
HONEYPOT_PORT = 80

SERVER1_BACKEND = ("127.0.0.1", 8080)   # Local Apache moved to 8080
SERVER2_BACKEND = ("192.168.100.7", 80) # Backup web server

LISTEN_PORT = 80                # Public port on Server1

# SYN scan detection parameters
PORT_THRESHOLD = 5              # number of distinct ports
TIME_WINDOW = 10                # seconds

# -------------------- STATE ---------------------

suspicious_ips = set()
failover_triggered = False

scan_stats = {}                 # src_ip -> {"ports": set(), "first_seen": t}
scan_lock = threading.Lock()

# -------------------- SYN SCAN DETECTOR --------------------


def process_packet(pkt):
    """Callback for Scapy sniff: detect SYN scans to SERVER1_IP."""
    global failover_triggered

    if IP not in pkt or TCP not in pkt:
        return

    ip = pkt[IP]
    tcp = pkt[TCP]

    # Only care about packets to this server
    if ip.dst != SERVER1_IP:
        return

    # Check for SYN (no ACK) – typical for Nmap -sS probes
    # TCP flags: 0x02 is SYN, 0x10 is ACK
    flags = int(tcp.flags)
    if not (flags & 0x02) or (flags & 0x10):
        return

    src_ip = ip.src
    dport = int(tcp.dport)
    now = time.time()

    with scan_lock:
        entry = scan_stats.get(src_ip)
        if not entry:
            entry = {"ports": set(), "first_seen": now}
            scan_stats[src_ip] = entry

        # Reset window if too old
        if now - entry["first_seen"] > TIME_WINDOW:
            entry["ports"] = set()
            entry["first_seen"] = now

        entry["ports"].add(dport)
        port_count = len(entry["ports"])

        if (
            port_count >= PORT_THRESHOLD
            and src_ip not in suspicious_ips
        ):
            suspicious_ips.add(src_ip)
            failover_triggered = True
            logging.warning(
                "[!] SYN scan detected from %s on %d distinct ports -> marked suspicious, failover ON",
                src_ip,
                port_count,
            )


def detect_syn_scans():
    """
    Background thread: sniff TCP packets destined for SERVER1_IP
    and run process_packet on each.
    Must run with root privileges.
    """
    logging.info("[*] Starting SYN-scan detector for %s", SERVER1_IP)
    # BPF filter keeps sniffing lightweight
    bpf = f"tcp and dst host {SERVER1_IP}"
    sniff(filter=bpf, prn=process_packet, store=False)


# -------------------- BACKEND SELECTION --------------------


def choose_backend(client_ip: str):
    """
    Decide where to send this client:
      - suspicious IPs  -> decoy
      - after failover  -> server2
      - otherwise       -> server1 backend
    """
    if client_ip in suspicious_ips:
        logging.info("[*] %s classified as attacker -> routing to decoy", client_ip)
        return (HONEYPOT_IP, HONEYPOT_PORT)

    if failover_triggered:
        logging.info("[*] Failover active, %s treated as legit -> routing to Server2", client_ip)
        return SERVER2_BACKEND

    # Normal pre-attack traffic
    logging.info("[*] Normal client %s -> routing to Server1 backend", client_ip)
    return SERVER1_BACKEND


# -------------------- TCP PROXY ----------------------------


def pipe(src, dst):
    """Copy bytes from src socket to dst socket."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass  # keep skeleton clean; add debug logs if needed
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_conn(client_sock, client_addr):
    client_ip, client_port = client_addr
    backend_host, backend_port = choose_backend(client_ip)

    logging.info(
        "[+] New connection from %s:%d -> %s:%d",
        client_ip,
        client_port,
        backend_host,
        backend_port,
    )

    try:
        server_sock = socket.create_connection((backend_host, backend_port), timeout=5)
    except Exception as e:
        logging.error(
            "[!] Failed to connect to backend %s:%d: %s",
            backend_host,
            backend_port,
            e,
        )
        client_sock.close()
        return

    # Start bi-directional forwarding
    t1 = threading.Thread(target=pipe, args=(client_sock, server_sock), daemon=True)
    t2 = threading.Thread(target=pipe, args=(server_sock, client_sock), daemon=True)
    t1.start()
    t2.start()

    # Wait for both directions to finish
    t1.join()
    t2.join()

    client_sock.close()
    server_sock.close()
    logging.info("[-] Connection from %s:%d closed", client_ip, client_port)


def start_listener():
    """Listen on LISTEN_PORT and forward connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)
    logging.info("[*] Deception proxy listening on 0.0.0.0:%d", LISTEN_PORT)

    while True:
        client_sock, client_addr = server.accept()
        threading.Thread(
            target=handle_conn,
            args=(client_sock, client_addr),
            daemon=True,
        ).start()


# -------------------- MAIN ---------------------------------


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    logging.info("[*] Deception proxy starting (Module 1 skeleton)")

    # Start SYN-scan detector thread
    t_sniff = threading.Thread(target=detect_syn_scans, daemon=True)
    t_sniff.start()

    # Start TCP proxy listener
    start_listener()


if __name__ == "__main__":
    main()
