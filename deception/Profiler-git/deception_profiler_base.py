#!/usr/bin/env python3
"""
Deception proxy with Profiler integration

Server1 (this box): 192.168.100.5
Decoy:              192.168.100.6
Server2 (backup):   192.168.100.7

- Listens on TCP/80 on Server1.
- Detects SYN scans to Server1 IP using Scapy.
- Any IP that scans many ports in a short time -> suspicious.
- suspicious IPs -> forwarded to Decoy.
- After failover, all *other* clients -> forwarded to Server2.
- Sends events to Profiler and polls actions from Profiler.
"""

import logging
import socket
import threading
import time
import json

import requests
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

# Profiler config (CHANGE THIS IP TO YOUR PROFILER VM)
PROFILER_BASE = "http://192.168.100.12:5000"
PROFILER_EVENT_URL = f"{PROFILER_BASE}/api/events"
PROFILER_ACTION_URL = f"{PROFILER_BASE}/api/actions"

# -------------------- STATE ---------------------

suspicious_ips = set()
failover_triggered = False

scan_stats = {}                 # src_ip -> {"ports": set(), "first_seen": t}
scan_lock = threading.Lock()


# -------------------- PROFILER CLIENT --------------------

def send_event(src_ip, event_type, severity=1, details=None, origin="server1"):
    """
    Send an event to the Profiler.
    This should NEVER break the proxy if Profiler is down.
    """
    payload = {
        "src_ip": src_ip,
        "event_type": event_type,
        "severity": severity,
        "details": details or {},
        "origin": origin,
    }
    try:
        requests.post(PROFILER_EVENT_URL, json=payload, timeout=1.0)
    except Exception as e:
        logging.warning("[Profiler] Failed to send event: %s", e)


def permanently_redirect_ip_to_decoy(ip: str):
    """
    Action from Profiler: ensure this IP is always treated as attacker.
    """
    global suspicious_ips
    if ip:
        suspicious_ips.add(ip)
        logging.info("[Profiler] Permanently marking %s as attacker -> decoy", ip)


def trigger_web_failover_to_server2():
    """
    Action from Profiler: trigger failover to Server2.
    """
    global failover_triggered
    if not failover_triggered:
        failover_triggered = True
        logging.warning("[Profiler] FAILOVER_SERVICE_WEB action -> failover ON")


def handle_action(action: dict):
    """
    Apply a single action from Profiler.
    """
    action_id = action.get("id")
    action_type = action.get("action_type")
    src_ip = action.get("src_ip")
    params_raw = action.get("params") or "{}"

    try:
        params = json.loads(params_raw)
    except Exception:
        params = {}

    logging.info("[Profiler] Handling action %s (%s) for src_ip=%s",
                 action_id, action_type, src_ip)

    # Map action types to behavior
    try:
        if action_type == "REDIRECT_TO_DECOY_PERMANENT":
            permanently_redirect_ip_to_decoy(src_ip)

        elif action_type == "FAILOVER_SERVICE_WEB":
            trigger_web_failover_to_server2()

        # Notify profiler we completed the action
        try:
            requests.post(
                f"{PROFILER_ACTION_URL}/{action_id}/update",
                json={"status": "completed"},
                timeout=1.0
            )
        except Exception as e:
            logging.warning("[Profiler] Failed to update action status: %s", e)

    except Exception as e:
        logging.error("[Profiler] Error handling action %s: %s", action_id, e)
        try:
            requests.post(
                f"{PROFILER_ACTION_URL}/{action_id}/update",
                json={"status": "failed"},
                timeout=1.0
            )
        except Exception:
            pass


def poll_profiler_for_actions():
    """
    Background thread: periodically ask Profiler:
      GET /api/actions?target=server1&status=pending
    and apply them.
    """
    logging.info("[Profiler] Action polling thread started")
    while True:
        try:
            r = requests.get(
                PROFILER_ACTION_URL,
                params={"target": "server1", "status": "pending"},
                timeout=1.0
            )
            if r.status_code == 200:
                actions = r.json()
                if actions:
                    logging.info("[Profiler] Received %d actions", len(actions))
                for action in actions:
                    handle_action(action)
        except Exception as e:
            logging.warning("[Profiler] Failed to fetch actions: %s", e)

        time.sleep(3)  # poll every 3 seconds


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
                "[!] SYN scan detected from %s on %d distinct ports "
                "-> marked suspicious, failover ON",
                src_ip,
                port_count,
            )

            # ---- NEW: notify Profiler ----
            send_event(
                src_ip=src_ip,
                event_type="SYN_SCAN_DETECTED",
                severity=2,
                details={"ports": list(entry["ports"])},
                origin="server1",
            )
            send_event(
                src_ip=src_ip,
                event_type="FAILOVER_TRIGGERED",
                severity=5,
                details={"reason": "syn_scan_threshold_reached"},
                origin="server1",
            )


def detect_syn_scans():
    """
    Background thread: sniff TCP packets destined for SERVER1_IP
    and run process_packet on each.
    Must run with root privileges.
    """
    logging.info("[*] Starting SYN-scan detector for %s", SERVER1_IP)
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

        # NEW: notify Profiler attacker is being sent to decoy
        send_event(
            src_ip=client_ip,
            event_type="REDIRECT_TO_DECOY",
            severity=3,
            details={"reason": "suspicious_ip"},
            origin="server1",
        )
        return (HONEYPOT_IP, HONEYPOT_PORT)

    if failover_triggered:
        logging.info("[*] Failover active, %s treated as legit -> routing to Server2", client_ip)
        # Optional: tell Profiler legit traffic is going to Server2
        send_event(
            src_ip=client_ip,
            event_type="LEGIT_TO_SERVER2",
            severity=1,
            details={"reason": "failover_active"},
            origin="server1",
        )
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
        pass
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

    t1 = threading.Thread(target=pipe, args=(client_sock, server_sock), daemon=True)
    t2 = threading.Thread(target=pipe, args=(server_sock, client_sock), daemon=True)
    t1.start()
    t2.start()

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
    logging.info("[*] Deception proxy starting with Profiler integration")

    # Start SYN-scan detector thread
    t_sniff = threading.Thread(target=detect_syn_scans, daemon=True)
    t_sniff.start()

    # Start Profiler action polling thread
    t_actions = threading.Thread(target=poll_profiler_for_actions, daemon=True)
    t_actions.start()

    # Start TCP proxy listener
    start_listener()


if __name__ == "__main__":
    main()
