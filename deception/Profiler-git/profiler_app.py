#!/usr/bin/env python3
"""
Profiler: Deception Tracking & Profiling Engine
- Receives events from Server1 and Decoy
- Stores in SQLite
- Maintains scores per src_ip
- Creates actions for Server1
- Provides simple web UI
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import json
from datetime import datetime
import os

DB_PATH = "profiler.db"

app = Flask(__name__)
CORS(app)


# -----------------------------
# DB helpers
# -----------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity INTEGER NOT NULL,
            origin TEXT NOT NULL,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_events_src_ip
            ON events(src_ip);

        CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp);


        CREATE TABLE IF NOT EXISTS scores (
            src_ip TEXT PRIMARY KEY,
            score INTEGER NOT NULL,
            status TEXT NOT NULL,
            last_update DATETIME DEFAULT CURRENT_TIMESTAMP
        );


        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT,
            action_type TEXT NOT NULL,
            params TEXT,
            target TEXT DEFAULT 'server1',
            status TEXT DEFAULT 'pending',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_update DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_actions_status_target
            ON actions(status, target);
        """
    )

    conn.commit()
    conn.close()


# -----------------------------
# Scoring logic
# -----------------------------

def classify_status(score: int) -> str:
    if score < 20:
        return "benign"
    elif score < 50:
        return "suspicious"
    elif score < 80:
        return "hostile"
    else:
        return "critical"


def get_event_weight(event_type: str) -> int:
    mapping = {
        "SYN_SCAN_DETECTED": 10,
        "REDIRECT_TO_DECOY": 5,
        "DECOY_CONNECTION": 5,
        "DECOY_LOGIN_ATTEMPT": 10,
        "DECOY_EXPLOIT_ATTEMPT": 40,
        "FAILOVER_TRIGGERED": 50,
    }
    return mapping.get(event_type, 1)


def maybe_create_actions(conn, src_ip: str, new_status: str):
    """Create actions based on new status, if not already pending."""
    cur = conn.cursor()

    # If IP is hostile: ensure redirect-permanent action
    if new_status == "hostile":
        cur.execute(
            """
            SELECT id FROM actions
            WHERE src_ip = ?
              AND action_type = 'REDIRECT_TO_DECOY_PERMANENT'
              AND status IN ('pending','in_progress')
            """,
            (src_ip,),
        )
        if not cur.fetchone():
            cur.execute(
                """
                INSERT INTO actions (src_ip, action_type, params, target)
                VALUES (?, 'REDIRECT_TO_DECOY_PERMANENT', '{}', 'server1')
                """,
                (src_ip,),
            )

    # If critical: ensure failover action exists
    if new_status == "critical":
        cur.execute(
            """
            SELECT id FROM actions
            WHERE action_type = 'FAILOVER_SERVICE_WEB'
              AND status IN ('pending','in_progress')
            """
        )
        if not cur.fetchone():
            cur.execute(
                """
                INSERT INTO actions (src_ip, action_type, params, target)
                VALUES (
                    ?, 'FAILOVER_SERVICE_WEB',
                    '{"service": "web"}', 'server1'
                )
                """,
                (src_ip,),
            )

    conn.commit()


def update_score(conn, src_ip: str, event_type: str, severity: int):
    cur = conn.cursor()
    cur.execute("SELECT score FROM scores WHERE src_ip = ?", (src_ip,))
    row = cur.fetchone()
    current_score = row["score"] if row else 0

    base = get_event_weight(event_type)
    delta = base * max(1, severity)
    new_score = current_score + delta
    status = classify_status(new_score)

    if row:
        cur.execute(
            """
            UPDATE scores
            SET score = ?, status = ?, last_update = CURRENT_TIMESTAMP
            WHERE src_ip = ?
            """,
            (new_score, status, src_ip),
        )
    else:
        cur.execute(
            """
            INSERT INTO scores (src_ip, score, status)
            VALUES (?, ?, ?)
            """,
            (src_ip, new_score, status),
        )

    conn.commit()
    maybe_create_actions(conn, src_ip, status)


# -----------------------------
# API routes
# -----------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/api/events", methods=["POST"])
def ingest_event():
    """Ingest event from Server1 or Decoy."""
    data = request.get_json(force=True) or {}

    src_ip = data.get("src_ip")
    event_type = data.get("event_type")
    severity = int(data.get("severity", 1))
    origin = data.get("origin", "unknown")
    details = json.dumps(data.get("details", {}))
    timestamp = data.get("timestamp") or datetime.utcnow().isoformat()

    if not src_ip or not event_type:
        return jsonify({"error": "src_ip and event_type are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events (src_ip, event_type, severity, origin, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (src_ip, event_type, severity, origin, details, timestamp),
    )
    conn.commit()

    update_score(conn, src_ip, event_type, severity)
    conn.close()

    return jsonify({"status": "ok"}), 201


@app.route("/api/scores/<src_ip>", methods=["GET"])
def get_score(src_ip):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT src_ip, score, status, last_update FROM scores WHERE src_ip = ?",
        (src_ip,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"src_ip": src_ip, "score": 0, "status": "benign"}), 200
    return jsonify(dict(row)), 200


@app.route("/api/actions", methods=["GET"])
def get_actions():
    """
    Server1 polls this endpoint:
    GET /api/actions?target=server1&status=pending
    """
    target = request.args.get("target", "server1")
    status = request.args.get("status", "pending")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, src_ip, action_type, params, target, status, timestamp
        FROM actions
        WHERE target = ? AND status = ?
        ORDER BY timestamp ASC
        LIMIT 50
        """,
        (target, status),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows), 200


@app.route("/api/actions/<int:action_id>/update", methods=["POST"])
def update_action_status(action_id):
    """
    Server1 calls this after executing an action:
    POST /api/actions/<id>/update
    { "status": "completed" }
    """
    data = request.get_json(force=True) or {}
    new_status = data.get("status", "completed")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE actions
        SET status = ?, last_update = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (new_status, action_id),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"}), 200


# -----------------------------
# UI routes (simple dashboard)
# -----------------------------

@app.route("/")
def dashboard():
    """Landing dashboard: top IPs by score + latest events."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT src_ip, score, status, last_update
        FROM scores
        ORDER BY score DESC
        LIMIT 10
        """
    )
    top_scores = cur.fetchall()

    cur.execute(
        """
        SELECT id, src_ip, event_type, severity, origin, timestamp
        FROM events
        ORDER BY timestamp DESC
        LIMIT 20
        """
    )
    latest_events = cur.fetchall()

    conn.close()
    return render_template(
        "dashboard.html",
        top_scores=top_scores,
        latest_events=latest_events,
    )


@app.route("/scores")
def scores_view():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT src_ip, score, status, last_update
        FROM scores
        ORDER BY score DESC
        LIMIT 100
        """
    )
    rows = cur.fetchall()
    conn.close()
    return render_template("scores.html", scores=rows)


@app.route("/events")
def events_view():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, src_ip, event_type, severity, origin, timestamp
        FROM events
        ORDER BY timestamp DESC
        LIMIT 100
        """
    )
    rows = cur.fetchall()
    conn.close()
    return render_template("events.html", events=rows)


# -----------------------------
# Main
# -----------------------------

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("[*] Initializing database...")
        init_db()
    else:
        # you can also run init_db() every time safely, it's idempotent
        init_db()

    app.run(host="0.0.0.0", port=5000, debug=True)
