import socket
import threading
import time
import logging
import subprocess
import os
from scapy.all import sniff, IP, TCP
from collections import defaultdict
# ------------------ CONFIG ------------------
HONEYPOT_IP = "192.168.56.106" # Decoy system
REAL_HOST_IP = "127.0.0.1" # Web service on Server 1
REAL_HOST_PORT = 8080
SERVER2_IP = "192.168.56.105" # Server 2 (Hot standby)
SERVER2_USER = "koku"
SERVER2_PORT = 80
FAILOVER_SCRIPT = "/home/koku/failover.sh"
MONITORED_PORTS = [21, 22, 80]
SYN_THRESHOLD = 5
TIME_WINDOW = 5
SUSPICION_TIMEOUT = 60
CHECK_INTERVAL = 5
WHITELIST = {"192.168.0.100"} # Optional trusted IPs
LOG_FILE = "deception_proxy.log"
scan_tracker = defaultdict(list)
unique_ports_tracker = defaultdict(set)
suspicious_ips = set()
suspicion_timestamp = defaultdict(float)
failover_triggered = False
logging.basicConfig(
    filename=LOG_FILE,
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
# ------------------ SYN SCAN DETECTION ------------------
def detect_syn_scans():
    def callback(pkt):
        if IP in pkt and TCP in pkt and pkt[TCP].flags == 'S':
            src_ip = pkt[IP].src
            dst_port = pkt[TCP].dport
            now = time.time()
            if src_ip in WHITELIST:
                return
            scan_tracker[src_ip] = [t for t in scan_tracker[src_ip] if now - t < TIME_WINDOW]
            scan_tracker[src_ip].append(now)
            unique_ports_tracker[src_ip].add(dst_port)
            if len(unique_ports_tracker[src_ip]) >= SYN_THRESHOLD:
                if src_ip not in suspicious_ips:
                    suspicious_ips.add(src_ip)
                    suspicion_timestamp[src_ip] = now
                    logging.warning(f"[!] SYN scan detected from {src_ip} → redirecting to decoy")
    sniff(filter="tcp", prn=callback, store=False)

# ------------------ FAILOVER TRIGGER ------------------
def trigger_failover():
    global failover_triggered
    if failover_triggered:
        return
    failover_triggered = True
    logging.critical("[!] Failover triggered. Redirecting legit users to Server 2...")
    try:
        result = subprocess.run([
            "ssh", f"{SERVER2_USER}@{SERVER2_IP}", FAILOVER_SCRIPT
        ], capture_output=True, text=True)
        if result.returncode == 0:
            logging.info("[+] Server 2 Apache started via failover.sh.")
        else:
            logging.error(f"[!] SSH failover script error:\n{result.stderr}")
    except Exception as e:
        logging.error(f"[!] SSH connection failed: {e}")

# ------------------ EXPLOIT MONITOR ------------------
def monitor_attacks():
    while True:
        if suspicious_ips and not failover_triggered:
            trigger_failover()
        time.sleep(CHECK_INTERVAL)

# ------------------ TRAFFIC REDIRECTION ------------------
def forward(src, dst, direction, ip):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            logging.info("Forwarding (%s) [%s]: %d bytes", direction, ip, len(data))
            dst.sendall(data)
    except Exception as e:
        logging.warning("Pipe error (%s) [%s]: %s", direction, ip, e)
    finally:
        src.close()
        dst.close()

def get_target(ip, port):
    now = time.time()
    if ip in suspicious_ips:
        if now - suspicion_timestamp[ip] < SUSPICION_TIMEOUT:
            return (HONEYPOT_IP, port)
        else:
            suspicious_ips.discard(ip)
            scan_tracker[ip].clear()
            unique_ports_tracker[ip].clear()
            logging.info(f"[+] Cleared suspicion for {ip}")
    if failover_triggered and port == 80:
        return (SERVER2_IP, SERVER2_PORT)
    return (REAL_HOST_IP, REAL_HOST_PORT if port == 80 else port)

def handle_conn(client_sock, client_ip, port):
    target_ip, target_port = get_target(client_ip, port)
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((target_ip, target_port))
        threading.Thread(target=forward, args=(client_sock, server_sock, "Attacker → Target",
                         client_ip), daemon=True).start()
        threading.Thread(target=forward, args=(server_sock, client_sock, "Target → Attacker",
                         client_ip), daemon=True).start()
    except Exception as e:
        logging.error("[!] Connection error for %s: %s", client_ip, e)
        client_sock.close()

# ------------------ TCP PROXY LISTENERS ------------------
def start_listener(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(100)
    logging.info("[*] Listening on port %s", port)
    while True:
        try:
            client_sock, addr = sock.accept()
            logging.info("[+] Incoming from %s:%s on port %d", addr[0], addr[1], port)
            threading.Thread(target=handle_conn, args=(client_sock, addr[0], port),
                             daemon=True).start()
        except OSError as e:
            logging.error(f"[!] Socket accept failed: {e}")
        time.sleep(1)

# ------------------ RESTORE APACHE IF NEEDED ------------------
def restore_real_service():
    logging.info("[*] Restoring Apache on Server 1...")
    os.system("sudo systemctl start apache2")

import atexit
atexit.register(restore_real_service)

# ------------------ MAIN ------------------
print("[*] Deception Proxy Active with Decoy + SYN Detection + Failover")
logging.info("[*] Deception system running on monitored ports: %s", MONITORED_PORTS)
for p in MONITORED_PORTS:
    threading.Thread(target=start_listener, args=(p,), daemon=True).start()
threading.Thread(target=detect_syn_scans, daemon=True).start()
threading.Thread(target=monitor_attacks, daemon=True).start()
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[!] Shutting down.")
    logging.info("[*] Deception proxy stopped.")
