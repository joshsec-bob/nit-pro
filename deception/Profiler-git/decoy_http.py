#!/usr/bin/env python3
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests

# CHANGE this to your Profiler IP
PROFILER_EVENT_URL = "http://192.168.100.12:5000/api/events"

def send_event(src_ip, event_type, severity=1, details=None, origin="decoy"):
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
        logging.warning("[Decoy] Failed to send event to profiler: %s", e)


class DecoyHandler(BaseHTTPRequestHandler):
    def _log_and_respond(self):
        client_ip = self.client_address[0]
        logging.info("[Decoy] Hit from %s %s %s", client_ip, self.command, self.path)

        # Send event to profiler
        send_event(
            src_ip=client_ip,
            event_type="DECOY_HTTP_REQUEST",
            severity=2,
            details={"method": self.command, "path": self.path},
            origin="decoy",
        )

        body = b"<html><body><h1>Decoy Server</h1><p>You found a fake service.</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._log_and_respond()

    def do_POST(self):
        self._log_and_respond()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    server = HTTPServer(("0.0.0.0", 80), DecoyHandler)
    logging.info("[Decoy] HTTP decoy listening on 0.0.0.0:8080")
    server.serve_forever()


if __name__ == "__main__":
    main()
