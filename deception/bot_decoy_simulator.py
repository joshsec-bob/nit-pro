import threading
import time
import random
import requests
import socket
# -------------------------
# CONFIGURATION
# -------------------------
DECOY_HTTP = "http://192.168.56.106"
DECOY_IP = "192.168.56.106"
BOTS = 5
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}
PORTS = {
    "http": 80,
    "ftp": 21
}
# -------------------------
# BOT ACTIONS
# -------------------------
def access_http(bot_name):
    try:
        response = requests.get(DECOY_HTTP, headers=HEADERS, timeout=3)
        print(f"[{bot_name}] HTTP {response.status_code}")
    except Exception as e:
        print(f"[{bot_name}] HTTP error: {e}")

def access_ftp(bot_name):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((DECOY_IP, PORTS["ftp"]))
        print(f"[{bot_name}] Connected to FTP port")
        s.close()
    except Exception as e:
        print(f"[{bot_name}] FTP error: {e}")

# -------------------------
# BOT BEHAVIOR
# -------------------------
def bot_loop(bot_id):
    bot_name = f"Bot-{bot_id}"
    while True:
        choice = random.choice(["http", "ftp"])
        if choice == "http":
            access_http(bot_name)
        else:
            access_ftp(bot_name)
        time.sleep(random.randint(5, 15)) # Human-like delay

# -------------------------
# START BOTS
# -------------------------
if __name__ == "__main__":
    for i in range(1, BOTS + 1):
        t = threading.Thread(target=bot_loop, args=(i,), daemon=True)
        t.start()
    while True:
        time.sleep(10)
