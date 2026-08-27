from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import os
import re
import sqlite3
import socket
import time
import logging
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR)).expanduser()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE = DATA_DIR / "security_dashboard.db"
app = Flask(__name__)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 31_536_000 if IS_PRODUCTION else 0
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "local-lab-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "SESSION_COOKIE_SECURE", "0") == "1"
if IS_PRODUCTION and app.config["SECRET_KEY"] == "local-lab-secret-change-me":
    raise RuntimeError("SECRET_KEY must be set in production")
if IS_PRODUCTION and not all(os.environ.get(name) for name in ("ADMIN_PASSWORD", "ANALYST_PASSWORD", "VIEWER_PASSWORD")):
    raise RuntimeError(
        "ADMIN_PASSWORD, ANALYST_PASSWORD, and VIEWER_PASSWORD must be set in production")

DEMO_USER = "analyst"
DEMO_PASSWORD_HASH = generate_password_hash(
    os.environ.get("DASHBOARD_PASSWORD", "analyst123"))
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("m-and-m-lab")


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                user TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open'
            );
            CREATE TABLE IF NOT EXISTS detection_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                mitre_attack TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                rule_id TEXT,
                evidence TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                FOREIGN KEY(event_id) REFERENCES events(id),
                FOREIGN KEY(rule_id) REFERENCES detection_rules(rule_id)
            );
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'CRITICAL',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER,
                title TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'OPEN',
                updated_at TEXT NOT NULL,
                FOREIGN KEY(event_id) REFERENCES events(id)
            );
            CREATE TABLE IF NOT EXISTS file_baselines (
                path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip_address TEXT NOT NULL UNIQUE,
                asset_type TEXT NOT NULL DEFAULT 'Host',
                owner TEXT NOT NULL DEFAULT '',
                criticality TEXT NOT NULL DEFAULT 'MEDIUM',
                operating_system TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incident_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            );
            CREATE TABLE IF NOT EXISTS log_collectors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                source_type TEXT NOT NULL DEFAULT 'file',
                enabled INTEGER NOT NULL DEFAULT 1,
                cursor INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS threat_intel_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                source_type TEXT NOT NULL DEFAULT 'manual',
                confidence INTEGER NOT NULL DEFAULT 50,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_sync TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',
                kind TEXT NOT NULL DEFAULT 'system',
                link TEXT NOT NULL DEFAULT '/#alerts',
                created_at TEXT NOT NULL,
                read_at TEXT
            );
            CREATE TABLE IF NOT EXISTS notification_preferences (
                username TEXT PRIMARY KEY,
                minimum_severity TEXT NOT NULL DEFAULT 'INFO',
                browser_enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(username) REFERENCES users(username)
            );
            CREATE TABLE IF NOT EXISTS platform_settings (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        columns = {row["name"]
                   for row in db.execute("PRAGMA table_info(alerts)")}
        for name, definition in {
            "priority": "TEXT NOT NULL DEFAULT 'MEDIUM'",
            "assignee": "TEXT NOT NULL DEFAULT ''",
            "acknowledged_at": "TEXT",
            "resolved_at": "TEXT",
        }.items():
            if name not in columns:
                db.execute(
                    f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
        incident_columns = {row["name"]
                            for row in db.execute("PRAGMA table_info(incidents)")}
        if "assignee" not in incident_columns:
            db.execute(
                "ALTER TABLE incidents ADD COLUMN assignee TEXT NOT NULL DEFAULT ''")
        indicator_columns = {row["name"]
                             for row in db.execute("PRAGMA table_info(indicators)")}
        for name, definition in {"source": "TEXT NOT NULL DEFAULT 'manual'", "confidence": "INTEGER NOT NULL DEFAULT 50", "expires_at": "TEXT", "status": "TEXT NOT NULL DEFAULT 'ACTIVE'"}.items():
            if name not in indicator_columns:
                db.execute(
                    f"ALTER TABLE indicators ADD COLUMN {name} {definition}")
        credentials = (("admin", os.environ.get("ADMIN_PASSWORD", "admin123"), "Admin"), ("analyst", os.environ.get(
            "ANALYST_PASSWORD", "analyst123"), "Security Analyst"), ("viewer", os.environ.get("VIEWER_PASSWORD", "viewer123"), "Viewer"))
        for username, password, role in credentials:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?) ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, role = excluded.role",
                (username, generate_password_hash(password), role),
            )
        rules = (
            ("AUTH-001", "Brute-force authentication",
             "Repeated failed authentication attempts", "HIGH", "T1110"),
            ("AUTH-002", "Successful login after failures",
             "Successful authentication following failed attempts", "HIGH", "T1078"),
            ("NET-001", "Network reconnaissance",
             "Port scanning or service discovery", "MEDIUM", "T1046"),
            ("FILE-001", "Sensitive file access",
             "Access to a monitored sensitive file", "HIGH", "T1083"),
            ("WEB-001", "Repeated HTTP errors",
             "Repeated server errors from one source", "MEDIUM", "T1190"),
            ("MAL-001", "Malware indicator",
             "Known malware or ransomware indicator", "CRITICAL", "T1486"),
        )
        db.executemany(
            "INSERT OR IGNORE INTO detection_rules (rule_id, name, description, severity, mitre_attack) VALUES (?, ?, ?, ?, ?)", rules)
        db.execute("INSERT OR IGNORE INTO indicators (indicator_type, value, description, severity, source, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   ("IP", "185.220.101.14", "Seeded lab example indicator", "CRITICAL", "seeded-lab", 90, datetime.now(timezone.utc).isoformat()))
        if db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0:
            now = datetime.now(timezone.utc)
            samples = [
                (now - timedelta(minutes=8), "Failed login", "185.220.101.14",
                 "root", "HIGH", "6 failed SSH attempts in 2 minutes", "Open"),
                (now - timedelta(minutes=21), "Port scan", "45.155.205.9", "-", "MEDIUM",
                 "Sequential probes detected across 12 ports", "Investigating"),
                (now - timedelta(minutes=37), "Successful login", "192.168.1.24",
                 "analyst", "INFO", "Local console authentication succeeded", "Resolved"),
                (now - timedelta(hours=1, minutes=12), "File change", "192.168.1.24",
                 "analyst", "LOW", "Watched configuration file modified", "Resolved"),
                (now - timedelta(hours=2), "Malware signature", "10.0.0.8", "scanner",
                 "CRITICAL", "Known test signature found in quarantine", "Open"),
                (now - timedelta(hours=3, minutes=14), "Failed login", "185.220.101.14",
                 "admin", "HIGH", "Repeated invalid credentials from known source", "Open"),
                (now - timedelta(hours=5), "Policy update", "127.0.0.1",
                 "analyst", "INFO", "Detection rules reloaded", "Resolved"),
            ]
            db.executemany(
                "INSERT INTO events (timestamp, event_type, source_ip, user, severity, message, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(item[0].isoformat(), *item[1:]) for item in samples],
            )
        if db.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0:
            now_text = datetime.now(timezone.utc).isoformat()
            db.execute("INSERT INTO assets (name, ip_address, asset_type, owner, criticality, operating_system, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       ("SOC workstation", "192.168.1.24", "Workstation", "Security", "HIGH", "macOS", "ACTIVE", "Primary analyst lab endpoint", now_text, now_text))


def log_activity(action: str, detail: str) -> None:
    with get_db() as db:
        db.execute(
            "INSERT INTO activity_log (timestamp, actor, action, detail) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), session.get(
                "username", "system"), action, detail),
        )


def create_notification(title: str, message: str, severity: str = "INFO", kind: str = "system", link: str = "/#alerts", username: str | None = None) -> None:
    with get_db() as db:
        db.execute("INSERT INTO notifications (username, title, message, severity, kind, link, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (username, title, message, severity, kind, link, datetime.now(timezone.utc).isoformat()))


def record_event(event_type: str, source_ip: str, severity: str, message: str, user: str = "scanner") -> None:
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO events (timestamp, event_type, source_ip, user, severity, message, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), event_type,
             source_ip, user, severity, message, "Open"),
        )
        rule_id = {"Live log alert": "AUTH-001", "Log detection": "AUTH-001", "Live malware alert": "MAL-001",
                   "Threat intel match": "MAL-001", "File modified": "FILE-001"}.get(event_type)
        if rule_id:
            db.execute("INSERT INTO alerts (event_id, rule_id, evidence, created_at) VALUES (?, ?, ?, ?)",
                       (cursor.lastrowid, rule_id, message, datetime.now(timezone.utc).isoformat()))
        logger.info("security_event type=%s severity=%s source=%s rule=%s",
                    event_type, severity, source_ip, rule_id or "none")
    if severity in {"HIGH", "CRITICAL"}:
        create_notification(f"{severity.title()} security event",
                            f"{event_type} from {source_ip}: {message[:120]}", severity, "event", "/#events")


def parse_ports(value: str, limit: int = 64) -> list[int]:
    ports: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError("Port ranges must start with the lower port.")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    if not ports or len(ports) > limit or any(port < 1 or port > 65535 for port in ports):
        raise ValueError(f"Enter up to {limit} ports between 1 and 65535.")
    return sorted(ports)


def local_target(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ValueError("Use a valid IPv4 or IPv6 address.") from error
    if not (address.is_private or address.is_loopback or address.is_link_local):
        raise ValueError(
            "Scanners are limited to private, loopback, or link-local lab addresses.")
    return address


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = hashlib.sha256(os.urandom(32)).hexdigest()
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_security_context():
    def asset_url(filename: str) -> str:
        asset_filename = "styles.min.css" if IS_PRODUCTION and filename == "styles.css" else filename
        asset_path = BASE_DIR / "static" / asset_filename
        if not asset_path.exists():
            asset_filename = filename
            asset_path = BASE_DIR / "static" / asset_filename
        version = f"{asset_path.stat().st_mtime_ns:x}-{asset_path.stat().st_size:x}"
        return url_for("static", filename=asset_filename, v=version)

    return {"asset_url": asset_url, "csrf_token": csrf_token()}


@app.before_request
def protect_mutations():
    if request.method in {"POST", "PATCH", "PUT", "DELETE"} and request.endpoint != "login":
        expected = session.get("csrf_token")
        supplied = request.headers.get(
            "X-CSRF-Token") or request.form.get("csrf_token")
        if expected and supplied != expected:
            return jsonify({"error": "CSRF validation failed."}), 403


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src https://fonts.gstatic.com; script-src 'self'"
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                return jsonify({"error": "This action requires an authorized analyst role."}), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.template_filter("pretty_time")
def pretty_time(value: str) -> str:
    timestamp = datetime.fromisoformat(value)
    return timestamp.astimezone().strftime("%b %d, %H:%M")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        now = time.monotonic()
        attempts = [stamp for stamp in LOGIN_ATTEMPTS.get(
            request.remote_addr or "unknown", []) if now - stamp < 300]
        if len(attempts) >= 5:
            return render_template("login.html", error="Too many attempts. Try again in five minutes."), 429
        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            LOGIN_ATTEMPTS.pop(request.remote_addr or "unknown", None)
            session["username"] = username
            session["role"] = user["role"]
            log_activity(
                "User login", "Authenticated to local security console")
            create_notification(
                "User signed in",
                f"{username} signed in from {request.remote_addr or 'unknown'}.",
                "INFO",
                "authentication",
                "/#overview",
            )
            return redirect(url_for("dashboard"))
        error = "Invalid local analyst credentials."
        attempts.append(now)
        LOGIN_ATTEMPTS[request.remote_addr or "unknown"] = attempts
        log_activity(
            "Failed login", f"Rejected credentials for {username or 'blank username'}")
        create_notification(
            "Failed login attempt",
            f"Rejected sign-in for {username or 'blank username'} from {request.remote_addr or 'unknown'}.",
            "HIGH",
            "authentication",
            "/#alerts",
        )
        logger.warning("Failed login for username=%s from %s",
                       username, request.remote_addr)
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    if "username" in session:
        log_activity("User logout", "Signed out of local security console")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("index.html", username=session["username"], role=session.get("role", "Viewer"))


@app.route("/api/summary")
@login_required
def summary():
    with get_db() as db:
        counts = {row["severity"]: row["total"] for row in db.execute(
            "SELECT severity, COUNT(*) total FROM events GROUP BY severity")}
        total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        today = datetime.now(timezone.utc).date().isoformat()
        today_count = db.execute(
            "SELECT COUNT(*) FROM events WHERE substr(timestamp, 1, 10) = ?", (today,)).fetchone()[0]
        open_count = db.execute(
            "SELECT COUNT(*) FROM events WHERE status = 'Open'").fetchone()[0]
        sources = db.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM events").fetchone()[0]
        recent = db.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT 8").fetchall()
        activity = db.execute(
            "SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 5").fetchall()
        critical = db.execute(
            "SELECT COUNT(*) FROM events WHERE severity = 'CRITICAL'").fetchone()[0]
        suspicious_ips = db.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM events WHERE severity IN ('HIGH', 'CRITICAL')").fetchone()[0]
        hourly = db.execute(
            "SELECT substr(timestamp, 1, 13) hour, COUNT(*) total FROM events GROUP BY hour ORDER BY hour DESC LIMIT 12").fetchall()
        top_sources = db.execute(
            "SELECT source_ip, COUNT(*) total FROM events GROUP BY source_ip ORDER BY total DESC LIMIT 5").fetchall()
        top_users = db.execute(
            "SELECT user, COUNT(*) total FROM events WHERE user != '-' GROUP BY user ORDER BY total DESC LIMIT 5").fetchall()
        rule_counts = db.execute(
            "SELECT rule_id, COUNT(*) total FROM alerts GROUP BY rule_id ORDER BY total DESC LIMIT 5").fetchall()
    return jsonify({"total": total, "today": today_count, "open": open_count, "sources": sources, "critical": critical, "suspicious_ips": suspicious_ips, "counts": counts, "hourly": [dict(row) for row in reversed(hourly)], "top_sources": [dict(row) for row in top_sources], "top_users": [dict(row) for row in top_users], "rule_counts": [dict(row) for row in rule_counts], "events": [dict(row) for row in recent], "activity": [dict(row) for row in activity]})


@app.route("/api/assistant", methods=["POST"])
@login_required
def assistant():
    question = ((request.get_json(silent=True) or {}).get(
        "message", "")).strip().lower()
    with get_db() as db:
        critical = db.execute(
            "SELECT COUNT(*) FROM events WHERE severity = 'CRITICAL'").fetchone()[0]
        open_incidents = db.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN', 'INVESTIGATING')").fetchone()[0]
        latest = db.execute(
            "SELECT event_type, source_ip, severity, message FROM events ORDER BY timestamp DESC LIMIT 1").fetchone()
    if not question:
        answer = "Ask me about events, alerts, investigations, rules, or safe lab tools."
    elif any(word in question for word in ("critical", "urgent", "danger")):
        answer = f"There are {critical} critical events. Start with the newest event in the event stream and open an investigation from its detail view."
    elif any(word in question for word in ("investigation", "incident", "case")):
        answer = f"There are {open_incidents} open or investigating cases. Use the Investigations section to change status or export a CSV report."
    elif any(word in question for word in ("latest", "recent", "last")) and latest:
        answer = f"Latest signal: {latest['event_type']} from {latest['source_ip']} at {latest['severity']} severity. Evidence: {latest['message']}"
    elif any(word in question for word in ("rule", "mitre", "detection")):
        answer = "Detection rules are listed in the Rules panel with rule IDs, severity, and MITRE ATT&CK techniques."
    elif any(word in question for word in ("scan", "port", "vulnerability")):
        answer = "Use scanners with loopback, private, or link-local targets only. They perform connectivity checks and do not exploit services."
    else:
        answer = "I can summarize critical events, open investigations, latest activity, detection rules, or safe lab scanning guidance."
    log_activity("Assistant consulted",
                 f"Answered SOC question: {question[:80]}")
    return jsonify({"answer": answer, "mode": "local SOC assistant"})


@app.route("/api/events")
@login_required
def events():
    severity = request.args.get("severity", "").upper()
    query = request.args.get("q", "").strip()
    clauses, values = [], []
    if severity in SEVERITIES:
        clauses.append("severity = ?")
        values.append(severity)
    if query:
        clauses.append(
            "(event_type LIKE ? OR source_ip LIKE ? OR user LIKE ? OR message LIKE ?)")
        values.extend([f"%{query}%"] * 4)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_db() as db:
        rows = db.execute(
            f"SELECT * FROM events {where} ORDER BY timestamp DESC", values).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/events/<int:event_id>")
@login_required
def event_detail(event_id: int):
    with get_db() as db:
        event = db.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if event is None:
        return jsonify({"error": "Event not found."}), 404
    return jsonify(dict(event))


@app.route("/api/password-check", methods=["POST"])
@login_required
def password_check():
    password = request.json.get(
        "password", "") if request.is_json else request.form.get("password", "")
    checks = {
        "length": len(password) >= 12,
        "upper": bool(re.search(r"[A-Z]", password)),
        "lower": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    score = sum(checks.values())
    label = ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"][score]
    return jsonify({"score": score, "label": label, "checks": checks})


@app.route("/api/ip-info", methods=["POST"])
@login_required
def ip_info():
    value = request.json.get("ip", "").strip(
    ) if request.is_json else request.form.get("ip", "").strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return jsonify({"error": "Enter a valid IPv4 or IPv6 address."}), 400
    private = address.is_private
    reserved = address.is_reserved or address.is_loopback or address.is_link_local
    with get_db() as db:
        event_count = db.execute(
            "SELECT COUNT(*) FROM events WHERE source_ip = ?", (value,)).fetchone()[0]
    return jsonify({"ip": value, "version": f"IPv{address.version}", "scope": "Private / lab" if private else "Public", "classification": "Reserved or local" if reserved else "Routable address", "observed_events": event_count})


@app.route("/api/ip-reputation", methods=["POST"])
@login_required
def ip_reputation():
    value = (request.get_json(silent=True) or {}).get("ip", "").strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return jsonify({"error": "Enter a valid IP address."}), 400
    with get_db() as db:
        indicator = db.execute(
            "SELECT * FROM indicators WHERE indicator_type = 'IP' AND value = ?", (value.lower(),)).fetchone()
        observations = db.execute(
            "SELECT COUNT(*) FROM events WHERE source_ip = ?", (value,)).fetchone()[0]
    return jsonify({"ip": value, "country": "Unavailable offline", "isp": "Unavailable offline", "asn": "Unavailable offline", "reputation": "Suspicious" if indicator else "Unknown", "source": "local threat-intelligence registry", "observations": observations})


@app.route("/api/log-analyzer", methods=["POST"])
@login_required
def log_analyzer():
    text = request.json.get(
        "text", "") if request.is_json else request.form.get("text", "")
    lines = text.splitlines()[:5000]
    failed: dict[str, int] = {}
    suspicious = []
    for line in lines:
        match = re.search(
            r"(?:failed|invalid) (?:password|user|login).*?(?:from|ip[=:])\s*([\da-fA-F:.]+)", line, re.I)
        if match:
            source = match.group(1)
            failed[source] = failed.get(source, 0) + 1
        if re.search(r"(permission denied|command injection|malware|ransomware|brute.?force)", line, re.I):
            suspicious.append(line[:180])
    repeated = [{"ip": source, "attempts": count, "severity": "HIGH"}
                for source, count in failed.items() if count >= 5]
    with get_db() as db:
        known = {row["value"]: row for row in db.execute(
            "SELECT * FROM indicators")}
    for source in failed:
        if source in known:
            repeated.append(
                {"ip": source, "attempts": failed[source], "severity": "CRITICAL", "threat_intel": known[source]["description"]})
            record_event("Threat intel match", source, "CRITICAL",
                         f"Known malicious indicator matched: {known[source]['description']}")
    if repeated:
        for item in repeated:
            record_event("Log detection", item["ip"], item["severity"],
                         f"{item['attempts']} repeated failed login entries found in submitted log")
    log_activity(
        "Log analyzed", f"Analyzed {len(lines)} log lines; {len(repeated)} repeated-login sources")
    return jsonify({"lines": len(lines), "failed_logins": sum(failed.values()), "repeated_sources": repeated, "suspicious_lines": suspicious[:10]})


@app.route("/api/ids-analyze", methods=["POST"])
@login_required
def ids_analyze():
    text = request.json.get(
        "text", "") if request.is_json else request.form.get("text", "")
    rules = [
        ("AUTH-001", "T1110", r"failed login|authentication failure|invalid password",
         "Repeated authentication failure", "MEDIUM"),
        ("NET-001", "T1046", r"nmap|port scan|syn flood|masscan",
         "Network reconnaissance pattern", "HIGH"),
        ("CMD-001", "T1059", r"powershell.*encoded|cmd\.exe|base64",
         "Suspicious command execution", "HIGH"),
        ("MAL-001", "T1486", r"ransomware|trojan|malware|known test signature",
         "Malware indicator", "CRITICAL"),
    ]
    matches = [{"rule_id": rule_id, "mitre": mitre, "rule": name, "severity": severity}
               for rule_id, mitre, pattern, name, severity in rules if re.search(pattern, text, re.I)]
    log_activity(
        "IDS analysis", f"Applied {len(rules)} offline detection rules; {len(matches)} matched")
    return jsonify({"matches": matches, "severity": max((item["severity"] for item in matches), key=SEVERITIES.index, default="INFO")})


@app.route("/api/network-scan", methods=["POST"])
@login_required
def network_scan():
    payload = request.get_json(silent=True) or {}
    try:
        target = local_target(payload.get("ip", ""))
        ports = parse_ports(payload.get("ports", "22,80,443"))
    except (ValueError, TypeError) as error:
        return jsonify({"error": str(error)}), 400
    results = []
    for port in ports:
        with socket.socket(socket.AF_INET6 if target.version == 6 else socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                is_open = sock.connect_ex((str(target), port)) == 0
            except OSError:
                is_open = False
        results.append(
            {"port": port, "state": "open" if is_open else "closed"})
    open_ports = [item["port"] for item in results if item["state"] == "open"]
    log_activity("Lab port scan",
                 f"Scanned {target} across {len(ports)} ports; {len(open_ports)} open")
    return jsonify({"target": str(target), "results": results, "open_ports": open_ports})


@app.route("/api/vulnerability-scan", methods=["POST"])
@login_required
def vulnerability_scan():
    payload = request.get_json(silent=True) or {}
    try:
        target = local_target(payload.get("ip", ""))
        ports = parse_ports(payload.get("ports", "21,22,23,80,443,3306,3389"))
    except (ValueError, TypeError) as error:
        return jsonify({"error": str(error)}), 400
    findings_by_port = {21: ("FTP service exposed", "HIGH"), 23: ("Telnet service exposed", "HIGH"), 3306: (
        "Database port reachable", "MEDIUM"), 3389: ("Remote desktop port reachable", "MEDIUM")}
    findings = []
    for port in ports:
        with socket.socket(socket.AF_INET6 if target.version == 6 else socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            is_open = sock.connect_ex((str(target), port)) == 0
        if is_open and port in findings_by_port:
            name, severity = findings_by_port[port]
            findings.append(
                {"port": port, "finding": name, "severity": severity})
    log_activity("Vulnerability scan",
                 f"Scanned lab target {target}; {len(findings)} findings")
    return jsonify({"target": str(target), "findings": findings, "scanned_ports": len(ports)})


@app.route("/api/phishing-check", methods=["POST"])
@login_required
def phishing_check():
    payload = request.get_json(silent=True) or {}
    value = payload.get("url", "").strip()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    hostname = (parsed.hostname or "").lower()
    indicators = []
    if parsed.scheme != "https":
        indicators.append("No HTTPS transport")
    if parsed.username or parsed.password:
        indicators.append("Username embedded in URL")
    if "xn--" in hostname:
        indicators.append("Punycode hostname")
    if hostname.count("-") >= 3:
        indicators.append("Unusually hyphenated hostname")
    if hostname.endswith((".zip", ".click", ".top", ".work", ".support")):
        indicators.append("Frequently abused top-level domain")
    try:
        if ipaddress.ip_address(hostname):
            indicators.append("Raw IP used instead of domain")
    except ValueError:
        pass
    score = min(100, len(indicators) * 22 + (15 if len(value) > 100 else 0))
    verdict = "High risk" if score >= 45 else "Review" if score else "No obvious indicators"
    log_activity("URL analyzed",
                 f"Checked {hostname or 'invalid URL'}; verdict {verdict}")
    return jsonify({"url": value, "hostname": hostname, "score": score, "verdict": verdict, "indicators": indicators})


@app.route("/api/file-integrity", methods=["POST"])
@login_required
def file_integrity():
    payload = request.get_json(silent=True) or {}
    requested = Path(payload.get("path", "")).expanduser()
    try:
        path = requested.resolve()
        path.relative_to(BASE_DIR)
    except (OSError, ValueError):
        return jsonify({"error": "For safety, choose a file inside the project folder."}), 400
    if not path.is_file():
        return jsonify({"error": "That path is not a readable file."}), 400
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    previous = None
    with get_db() as db:
        previous_row = db.execute(
            "SELECT sha256 FROM file_baselines WHERE path = ?", (str(path),)).fetchone()
        previous = previous_row["sha256"] if previous_row else None
        db.execute("INSERT INTO file_baselines (path, sha256, updated_at) VALUES (?, ?, ?) ON CONFLICT(path) DO UPDATE SET sha256 = excluded.sha256, updated_at = excluded.updated_at", (str(
            path), digest, datetime.now(timezone.utc).isoformat()))
    if previous and previous != digest:
        record_event("File modified", "127.0.0.1", "HIGH",
                     f"Integrity change detected for {path.name}; previous hash {previous[:12]}...")
    log_activity("File hashed", f"SHA-256 calculated for {path.name}")
    return jsonify({"path": str(path.relative_to(BASE_DIR)), "sha256": digest, "previous_sha256": previous, "changed": bool(previous and previous != digest), "size": path.stat().st_size})


@app.route("/api/monitor-log", methods=["POST"])
@login_required
def monitor_log():
    payload = request.get_json(silent=True) or {}
    requested = Path(payload.get("path", "")).expanduser()
    try:
        path = requested.resolve()
        path.relative_to(BASE_DIR)
    except (OSError, ValueError):
        return jsonify({"error": "The live monitor can only watch files inside the project folder."}), 400
    if not path.is_file():
        return jsonify({"error": "That log file does not exist."}), 400
    cursor = int(payload.get("cursor", 0))
    content = path.read_text(errors="replace")
    new_text = content[cursor:]
    alerts = []
    for line in new_text.splitlines():
        if re.search(r"failed login|failed password|authentication failure|login_failed", line, re.I):
            source_match = re.search(
                r"(?:from|source|ip)[=:\s]+([\da-fA-F:.]+)", line, re.I)
            source = source_match.group(1) if source_match else "unknown"
            alerts.append({"rule_id": "AUTH-001", "description": "Failed authentication observed",
                          "severity": "MEDIUM", "source_ip": source, "evidence": line[:180]})
        if re.search(r"ransomware|malware|trojan", line, re.I):
            alerts.append({"rule_id": "MAL-001", "description": "Malware indicator observed",
                          "severity": "CRITICAL", "source_ip": "unknown", "evidence": line[:180]})
    for alert in alerts:
        record_event(alert["description"], alert["source_ip"],
                     alert["severity"], alert["evidence"])
    log_activity("Live log poll",
                 f"Read {len(new_text.splitlines())} new lines from {path.name}; {len(alerts)} alerts")
    return jsonify({"cursor": len(content), "lines": new_text.splitlines(), "alerts": alerts})


@app.route("/api/threat-intel", methods=["GET", "POST"])
@login_required
def threat_intel():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        value = payload.get("value", "").strip().lower()
        indicator_type = payload.get("indicator_type", "IP").upper()
        if indicator_type not in {"IP", "DOMAIN", "URL", "HASH"} or not value:
            return jsonify({"error": "Provide an indicator value and type."}), 400
        with get_db() as db:
            db.execute("INSERT OR IGNORE INTO indicators (indicator_type, value, description, severity, source, confidence, expires_at, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (indicator_type,
                       value, payload.get("description", "Analyst-added indicator"), payload.get("severity", "HIGH"), payload.get("source", "manual"), max(0, min(100, int(payload.get("confidence", 50)))), payload.get("expires_at"), payload.get("status", "ACTIVE"), datetime.now(timezone.utc).isoformat()))
        log_activity("Indicator added",
                     f"Added {indicator_type} indicator {value}")
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM indicators ORDER BY created_at DESC").fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/threat-intel/<int:indicator_id>", methods=["PATCH", "DELETE"])
@login_required
@role_required("Admin", "Security Analyst")
def update_threat_indicator(indicator_id: int):
    payload = request.get_json(silent=True) or {}
    with get_db() as db:
        if request.method == "DELETE":
            db.execute("DELETE FROM indicators WHERE id = ?", (indicator_id,))
        else:
            fields = {key: payload[key] for key in (
                "description", "severity") if key in payload}
            if not fields:
                return jsonify({"error": "Provide a description or severity to update."}), 400
            if "severity" in fields and fields["severity"] not in SEVERITIES:
                return jsonify({"error": "Unsupported indicator severity."}), 400
            db.execute("UPDATE indicators SET description = COALESCE(?, description), severity = COALESCE(?, severity) WHERE id = ?",
                       (fields.get("description"), fields.get("severity"), indicator_id))
    log_activity("Indicator updated",
                 f"Indicator #{indicator_id} {request.method.lower()}d")
    return jsonify({"ok": True})


@app.route("/api/assets", methods=["GET", "POST"])
@login_required
def assets():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        name, ip_address = payload.get("name", "").strip(
        ), payload.get("ip_address", "").strip()
        if not name or not ip_address:
            return jsonify({"error": "Asset name and IP address are required."}), 400
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return jsonify({"error": "Asset IP address is invalid."}), 400
        now_text = datetime.now(timezone.utc).isoformat()
        try:
            with get_db() as db:
                cursor = db.execute("INSERT INTO assets (name, ip_address, asset_type, owner, criticality, operating_system, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    (name, ip_address, payload.get("asset_type", "Host"), payload.get("owner", ""), payload.get("criticality", "MEDIUM"), payload.get("operating_system", ""), payload.get("status", "ACTIVE"), payload.get("notes", ""), now_text, now_text))
                asset_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            return jsonify({"error": "An asset with that IP address already exists."}), 409
        log_activity("Asset added", f"Registered asset {name} ({ip_address})")
        return jsonify({"id": asset_id}), 201
    with get_db() as db:
        rows = db.execute("SELECT assets.*, COUNT(events.id) AS event_count FROM assets LEFT JOIN events ON events.source_ip = assets.ip_address GROUP BY assets.id ORDER BY assets.criticality DESC, assets.name").fetchall()
    weights = {"LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}
    result = []
    for row in rows:
        item = dict(row)
        item["risk_score"] = min(100, weights.get(
            item["criticality"], 50) + min(item["event_count"] * 3, 25))
        item["risk_level"] = "CRITICAL" if item["risk_score"] >= 90 else "HIGH" if item[
            "risk_score"] >= 70 else "MEDIUM" if item["risk_score"] >= 40 else "LOW"
        result.append(item)
    return jsonify(result)


@app.route("/api/assets/<int:asset_id>", methods=["PATCH", "DELETE"])
@login_required
@role_required("Admin", "Security Analyst")
def update_asset(asset_id: int):
    payload = request.get_json(silent=True) or {}
    with get_db() as db:
        if request.method == "DELETE":
            db.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        else:
            allowed = ("name", "asset_type", "owner", "criticality",
                       "operating_system", "status", "notes")
            changes = {key: payload[key] for key in allowed if key in payload}
            if not changes:
                return jsonify({"error": "No asset fields supplied."}), 400
            assignments = ", ".join(f"{key} = ?" for key in changes)
            db.execute(f"UPDATE assets SET {assignments}, updated_at = ? WHERE id = ?", (
                *changes.values(), datetime.now(timezone.utc).isoformat(), asset_id))
    log_activity("Asset updated",
                 f"Asset #{asset_id} {request.method.lower()}d")
    return jsonify({"ok": True})


@app.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
@login_required
def triage_alert(alert_id: int):
    payload = request.get_json(silent=True) or {}
    status = payload.get("status", "NEW").upper()
    if status not in {"NEW", "ACKNOWLEDGED", "IN PROGRESS", "RESOLVED", "FALSE POSITIVE"}:
        return jsonify({"error": "Unsupported alert status."}), 400
    now_text = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute("UPDATE alerts SET status = ?, priority = COALESCE(?, priority), assignee = COALESCE(?, assignee), acknowledged_at = CASE WHEN ? != 'NEW' THEN COALESCE(acknowledged_at, ?) ELSE acknowledged_at END, resolved_at = CASE WHEN ? IN ('RESOLVED', 'FALSE POSITIVE') THEN ? ELSE resolved_at END WHERE id = ?",
                   (status, payload.get("priority"), payload.get("assignee"), status, now_text, status, now_text, alert_id))
    log_activity("Alert triaged", f"Alert #{alert_id} marked {status.lower()}")
    return jsonify({"ok": True})


@app.route("/api/metrics")
@login_required
def metrics():
    with get_db() as db:
        alert_count = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        acknowledged = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE status != 'NEW'").fetchone()[0]
        resolved = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE status IN ('RESOLVED', 'FALSE POSITIVE')").fetchone()[0]
        incidents = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        resolved_incidents = db.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('RESOLVED', 'FALSE POSITIVE')").fetchone()[0]
    return jsonify({"alerts": alert_count, "acknowledged_alerts": acknowledged, "resolved_alerts": resolved, "incidents": incidents, "resolved_incidents": resolved_incidents, "alert_acknowledgement_rate": round(acknowledged / alert_count * 100, 1) if alert_count else 0, "incident_resolution_rate": round(resolved_incidents / incidents * 100, 1) if incidents else 0})


@app.route("/api/health")
def health():
    try:
        with get_db() as db:
            db.execute("SELECT 1").fetchone()
        return jsonify({"status": "healthy", "database": "ok"})
    except sqlite3.Error:
        return jsonify({"status": "degraded", "database": "unavailable"}), 503


@app.route("/api/notifications")
@login_required
def notifications():
    with get_db() as db:
        preference = db.execute(
            "SELECT minimum_severity, browser_enabled FROM notification_preferences WHERE username = ?", (session["username"],)).fetchone()
        minimum = preference["minimum_severity"] if preference else "INFO"
        enabled = bool(preference["browser_enabled"]) if preference else True
        rows = db.execute(
            "SELECT * FROM notifications WHERE username IS NULL OR username = ? ORDER BY created_at DESC LIMIT 50", (session["username"],)).fetchall()
    items = [dict(row) for row in rows if enabled and SEVERITIES.index(
        row["severity"]) >= SEVERITIES.index(minimum)]
    return jsonify({"unread": sum(item["read_at"] is None for item in items), "items": items})


@app.route("/api/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
def mark_notification_read(notification_id: int):
    with get_db() as db:
        db.execute("UPDATE notifications SET read_at = ? WHERE id = ? AND (username IS NULL OR username = ?)",
                   (datetime.now(timezone.utc).isoformat(), notification_id, session["username"]))
    return jsonify({"ok": True})


@app.route("/api/notifications/read-all", methods=["POST"])
@login_required
def mark_notifications_read():
    with get_db() as db:
        db.execute("UPDATE notifications SET read_at = ? WHERE read_at IS NULL AND (username IS NULL OR username = ?)",
                   (datetime.now(timezone.utc).isoformat(), session["username"]))
    log_activity("Notifications cleared",
                 "Marked all visible notifications as read")
    return jsonify({"ok": True})


@app.route("/api/notification-preferences", methods=["GET", "PATCH"])
@login_required
def notification_preferences():
    if request.method == "PATCH":
        payload = request.get_json(silent=True) or {}
        minimum = payload.get("minimum_severity", "HIGH").upper()
        if minimum not in SEVERITIES:
            return jsonify({"error": "Unsupported minimum severity."}), 400
        with get_db() as db:
            db.execute("INSERT INTO notification_preferences (username, minimum_severity, browser_enabled, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET minimum_severity = excluded.minimum_severity, browser_enabled = excluded.browser_enabled, updated_at = excluded.updated_at",
                       (session["username"], minimum, int(bool(payload.get("browser_enabled", True))), datetime.now(timezone.utc).isoformat()))
        log_activity("Notification preferences updated",
                     f"Minimum severity set to {minimum}")
    with get_db() as db:
        row = db.execute("SELECT * FROM notification_preferences WHERE username = ?",
                         (session["username"],)).fetchone()
    return jsonify(dict(row) if row else {"username": session["username"], "minimum_severity": "INFO", "browser_enabled": 1})


@app.route("/api/activity")
@login_required
def activity_feed():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 30").fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/reports/summary")
@login_required
def report_summary():
    with get_db() as db:
        daily = db.execute("SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS events, SUM(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) AS high_risk FROM events GROUP BY day ORDER BY day DESC LIMIT 14").fetchall()
        techniques = db.execute(
            "SELECT detection_rules.mitre_attack AS technique, detection_rules.name, COUNT(alerts.id) AS alerts FROM alerts JOIN detection_rules ON detection_rules.rule_id = alerts.rule_id GROUP BY detection_rules.rule_id ORDER BY alerts DESC").fetchall()
    return jsonify({"daily": [dict(row) for row in daily], "techniques": [dict(row) for row in techniques]})


@app.route("/api/settings", methods=["GET", "PATCH"])
@login_required
@role_required("Admin")
def platform_settings():
    if request.method == "PATCH":
        payload = request.get_json(silent=True) or {}
        allowed = {"refresh_seconds",
                   "default_alert_priority", "retention_days"}
        values = {key: str(payload[key]) for key in allowed if key in payload}
        if not values:
            return jsonify({"error": "No supported settings supplied."}), 400
        with get_db() as db:
            for name, value in values.items():
                db.execute("INSERT INTO platform_settings (name, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                           (name, value, datetime.now(timezone.utc).isoformat()))
        log_activity("Platform settings updated",
                     f"Updated {len(values)} settings")
    with get_db() as db:
        rows = db.execute(
            "SELECT name, value, updated_at FROM platform_settings ORDER BY name").fetchall()
    return jsonify({row["name"]: row["value"] for row in rows})


@app.route("/api/alerts")
@login_required
def alerts():
    with get_db() as db:
        rows = db.execute("SELECT alerts.*, detection_rules.name, detection_rules.mitre_attack, events.source_ip, events.user, events.severity FROM alerts LEFT JOIN detection_rules ON detection_rules.rule_id = alerts.rule_id JOIN events ON events.id = alerts.event_id ORDER BY alerts.created_at DESC LIMIT 100").fetchall()
    log_activity("Alerts viewed", f"Viewed {len(rows)} alert records")
    return jsonify([dict(row) for row in rows])


@app.route("/api/rules", methods=["GET", "PATCH"])
@login_required
def rules():
    if request.method == "PATCH":
        if session.get("role") != "Admin":
            return jsonify({"error": "Only Admin users can change detection rules."}), 403
        payload = request.get_json(silent=True) or {}
        if payload.get("rule_id") is None:
            return jsonify({"error": "Rule ID is required."}), 400
        with get_db() as db:
            db.execute("UPDATE detection_rules SET enabled = ? WHERE rule_id = ?", (int(
                bool(payload.get("enabled"))), payload.get("rule_id")))
        log_activity(
            "Rule changed", f"Rule {payload.get('rule_id')} enabled={bool(payload.get('enabled'))}")
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM detection_rules ORDER BY rule_id").fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/collectors", methods=["GET", "POST"])
@login_required
def collectors():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        name, path = payload.get("name", "").strip(
        ), payload.get("path", "").strip()
        if not name or not path:
            return jsonify({"error": "Collector name and path are required."}), 400
        try:
            resolved = Path(path).expanduser().resolve()
            resolved.relative_to(BASE_DIR)
        except (OSError, ValueError):
            return jsonify({"error": "Collectors can only read files inside the project folder."}), 400
        try:
            with get_db() as db:
                cursor = db.execute("INSERT INTO log_collectors (name, path, source_type, enabled, created_at) VALUES (?, ?, ?, ?, ?)",
                                    (name, str(resolved), payload.get("source_type", "file"), int(bool(payload.get("enabled", True))), datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError:
            return jsonify({"error": "A collector already watches that path."}), 409
        log_activity("Collector added", f"Registered {name}")
        return jsonify({"id": cursor.lastrowid}), 201
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM log_collectors ORDER BY name").fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/collectors/<int:collector_id>/poll", methods=["POST"])
@login_required
def poll_collector(collector_id: int):
    with get_db() as db:
        collector = db.execute(
            "SELECT * FROM log_collectors WHERE id = ?", (collector_id,)).fetchone()
    if not collector or not collector["enabled"]:
        return jsonify({"error": "Collector is missing or disabled."}), 404
    path = Path(collector["path"])
    if not path.is_file():
        return jsonify({"error": "Collector file does not exist."}), 400
    content = path.read_text(errors="replace")
    new_text = content[collector["cursor"]:]
    alerts = []
    for line in new_text.splitlines():
        if re.search(r"failed login|failed password|authentication failure|login_failed", line, re.I):
            source_match = re.search(
                r"(?:from|source|ip)[=:\s]+([\da-fA-F:.]+)", line, re.I)
            source = source_match.group(1) if source_match else "unknown"
            alerts.append(
                {"source_ip": source, "severity": "MEDIUM", "evidence": line[:180]})
        if re.search(r"ransomware|malware|trojan", line, re.I):
            alerts.append(
                {"source_ip": "unknown", "severity": "CRITICAL", "evidence": line[:180]})
    for item in alerts:
        record_event("Collector detection",
                     item["source_ip"], item["severity"], item["evidence"])
    with get_db() as db:
        db.execute("UPDATE log_collectors SET cursor = ?, last_seen = ? WHERE id = ?", (len(
            content), datetime.now(timezone.utc).isoformat(), collector_id))
    log_activity("Collector polled",
                 f"Read {len(new_text.splitlines())} new lines from {collector['name']}")
    return jsonify({"cursor": len(content), "lines": new_text.splitlines(), "alerts": alerts})


@app.route("/api/audit")
@login_required
def audit():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 200").fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/incidents/<int:incident_id>/timeline", methods=["GET", "POST"])
@login_required
def incident_timeline(incident_id: int):
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        action, detail = payload.get(
            "action", "Analyst note").strip(), payload.get("detail", "").strip()
        if not action:
            return jsonify({"error": "Timeline action is required."}), 400
        with get_db() as db:
            db.execute("INSERT INTO incident_timeline (incident_id, actor, action, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                       (incident_id, session["username"], action, detail, datetime.now(timezone.utc).isoformat()))
        log_activity("Incident timeline updated",
                     f"Incident #{incident_id}: {action}")
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM incident_timeline WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,)).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/incidents", methods=["GET", "POST", "PATCH"])
@login_required
def incidents():
    payload = request.get_json(silent=True) or {}
    if request.method == "POST":
        with get_db() as db:
            now_text = datetime.now(timezone.utc).isoformat()
            cursor = db.execute("INSERT INTO incidents (event_id, title, notes, status, assignee, updated_at) VALUES (?, ?, ?, ?, ?, ?)", (payload.get(
                "event_id"), payload.get("title", "Investigation"), payload.get("notes", ""), "OPEN", payload.get("assignee", session["username"]), now_text))
            incident_id = cursor.lastrowid
            db.execute("INSERT INTO incident_timeline (incident_id, actor, action, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                       (incident_id, session["username"], "Investigation opened", payload.get("notes", ""), now_text))
        log_activity("Incident opened", f"Incident #{incident_id} created")
    elif request.method == "PATCH":
        status = payload.get("status", "OPEN").upper()
        if status not in {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE POSITIVE"}:
            return jsonify({"error": "Unsupported incident status."}), 400
        with get_db() as db:
            now_text = datetime.now(timezone.utc).isoformat()
            db.execute("UPDATE incidents SET status = ?, assignee = COALESCE(?, assignee), notes = COALESCE(?, notes), updated_at = ? WHERE id = ?",
                       (status, payload.get("assignee"), payload.get("notes"), now_text, payload.get("id")))
            db.execute("INSERT INTO incident_timeline (incident_id, actor, action, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                       (payload.get("id"), session["username"], f"Status changed to {status}", payload.get("notes") or "", now_text))
        log_activity("Incident updated",
                     f"Incident #{payload.get('id')} marked {status.lower()}")
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM incidents ORDER BY updated_at DESC").fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/users")
@login_required
@role_required("Admin")
def users():
    with get_db() as db:
        rows = db.execute(
            "SELECT username, role FROM users ORDER BY username").fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/users", methods=["POST", "PATCH", "DELETE"])
@login_required
@role_required("Admin")
def create_user():
    payload = request.get_json(silent=True) or {}
    if request.method == "PATCH":
        username = payload.get("username", "").strip()
        role = payload.get("role")
        if not username or role not in {"Admin", "Security Analyst", "Viewer"}:
            return jsonify({"error": "Username and a valid role are required."}), 400
        with get_db() as db:
            db.execute("UPDATE users SET role = ?, password_hash = COALESCE(?, password_hash) WHERE username = ?",
                       (role, generate_password_hash(payload["password"]) if payload.get("password") else None, username))
        log_activity("User updated", f"Admin updated account {username}")
        return jsonify({"ok": True})
    if request.method == "DELETE":
        username = payload.get("username", "").strip()
        if not username or username == session.get("username"):
            return jsonify({"error": "A different account must be selected."}), 400
        with get_db() as db:
            db.execute("DELETE FROM users WHERE username = ?", (username,))
        log_activity("User removed", f"Admin removed account {username}")
        return jsonify({"ok": True})
    username, password, role = payload.get("username", "").strip(
    ), payload.get("password", ""), payload.get("role", "Viewer")
    if not username or len(password) < 8 or role not in {"Admin", "Security Analyst", "Viewer"}:
        return jsonify({"error": "Username, an 8-character password, and a valid role are required."}), 400
    with get_db() as db:
        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   (username, generate_password_hash(password), role))
    log_activity("User created", f"Admin created {role} account {username}")
    return jsonify({"ok": True}), 201


@app.route("/export/incidents.csv")
@login_required
def export_incidents():
    with get_db() as db:
        rows = db.execute(
            "SELECT id, event_id, title, status, notes, updated_at FROM incidents ORDER BY updated_at DESC").fetchall()
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["incident", "event_id", "title",
                    "status", "notes", "updated_at"])
    writer.writerows([tuple(row) for row in rows])
    log_activity("Incident report exported",
                 f"Exported {len(rows)} incident records")
    return send_file(io.BytesIO(stream.getvalue().encode()), mimetype="text/csv", as_attachment=True, download_name="incident-report.csv")


@app.route("/api/events/<int:event_id>/status", methods=["POST"])
@login_required
def update_status(event_id: int):
    status = request.json.get("status", "Open")
    if status not in {"Open", "Investigating", "Resolved"}:
        return jsonify({"error": "Unsupported status"}), 400
    with get_db() as db:
        db.execute("UPDATE events SET status = ? WHERE id = ?",
                   (status, event_id))
    log_activity("Event updated", f"Event #{event_id} marked {status.lower()}")
    return jsonify({"ok": True})


@app.route("/export/events.csv")
@login_required
def export_events():
    with get_db() as db:
        rows = db.execute(
            "SELECT timestamp, event_type, source_ip, user, severity, message, status FROM events ORDER BY timestamp DESC").fetchall()
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["timestamp", "event_type", "source_ip",
                    "user", "severity", "message", "status"])
    writer.writerows([tuple(row) for row in rows])
    log_activity("Report exported",
                 f"Exported {len(rows)} security events as CSV")
    return send_file(io.BytesIO(stream.getvalue().encode()), mimetype="text/csv", as_attachment=True, download_name="security-events.csv")


initialize_database()

if __name__ == "__main__":
    app.run(debug=not IS_PRODUCTION, host=os.environ.get(
        "HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))
