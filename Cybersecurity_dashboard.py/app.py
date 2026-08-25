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
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR)).expanduser()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE = DATA_DIR / "security_dashboard.db"
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "local-lab-secret-change-me")
if os.environ.get("FLASK_ENV") == "production" and app.config["SECRET_KEY"] == "local-lab-secret-change-me":
    raise RuntimeError("SECRET_KEY must be set in production")

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
                address TEXT NOT NULL UNIQUE,
                asset_type TEXT NOT NULL DEFAULT 'lab-host',
                owner TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incident_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES incidents(id)
            );
            """
        )
        for username, password, role in (("admin", "admin123", "Admin"), ("analyst", "analyst123", "Security Analyst"), ("viewer", "viewer123", "Viewer")):
            db.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       (username, generate_password_hash(password), role))
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
        db.execute("INSERT OR IGNORE INTO assets (name, address, asset_type, owner, last_seen) VALUES (?, ?, ?, ?, ?)",
                   ("Localhost", "127.0.0.1", "loopback", "lab", datetime.now(timezone.utc).isoformat()))
        db.execute("INSERT OR IGNORE INTO indicators (indicator_type, value, description, severity, created_at) VALUES (?, ?, ?, ?, ?)",
                   ("IP", "185.220.101.14", "Seeded lab example indicator", "CRITICAL", datetime.now(timezone.utc).isoformat()))
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


def log_activity(action: str, detail: str) -> None:
    with get_db() as db:
        db.execute(
            "INSERT INTO activity_log (timestamp, actor, action, detail) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), session.get(
                "username", "system"), action, detail),
        )


def record_event(event_type: str, source_ip: str, severity: str, message: str, user: str = "scanner") -> None:
    with get_db() as db:
        cursor = db.execute(
            "INSERT INTO events (timestamp, event_type, source_ip, user, severity, message, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), event_type,
             source_ip, user, severity, message, "Open"),
        )
        rule_id = {"Live log alert": "AUTH-001", "Log detection": "AUTH-001", "Failed authentication observed": "AUTH-001", "Live malware alert": "MAL-001",
                   "Malware indicator observed": "MAL-001", "Threat intel match": "MAL-001", "File modified": "FILE-001"}.get(event_type)
        if rule_id:
            db.execute("INSERT INTO alerts (event_id, rule_id, evidence, created_at) VALUES (?, ?, ?, ?)",
                       (cursor.lastrowid, rule_id, message, datetime.now(timezone.utc).isoformat()))
        logger.info("security_event type=%s severity=%s source=%s rule=%s",
                    event_type, severity, source_ip, rule_id or "none")


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
    return {"csrf_token": csrf_token()}


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
            return redirect(url_for("dashboard"))
        error = "Invalid local analyst credentials."
        attempts.append(now)
        LOGIN_ATTEMPTS[request.remote_addr or "unknown"] = attempts
        log_activity(
            "Failed login", f"Rejected credentials for {username or 'blank username'}")
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
    return jsonify({"total": total, "open": open_count, "sources": sources, "critical": critical, "suspicious_ips": suspicious_ips, "counts": counts, "hourly": [dict(row) for row in reversed(hourly)], "top_sources": [dict(row) for row in top_sources], "top_users": [dict(row) for row in top_users], "rule_counts": [dict(row) for row in rule_counts], "events": [dict(row) for row in recent], "activity": [dict(row) for row in activity]})


@app.route("/healthz")
def healthz():
    try:
        with get_db() as db:
            db.execute("SELECT 1").fetchone()
        return jsonify({"status": "ok", "service": "m-and-m-lab"})
    except sqlite3.Error:
        return jsonify({"status": "error", "service": "m-and-m-lab"}), 503


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
            db.execute("INSERT OR IGNORE INTO indicators (indicator_type, value, description, severity, created_at) VALUES (?, ?, ?, ?, ?)", (indicator_type,
                       value, payload.get("description", "Analyst-added indicator"), payload.get("severity", "HIGH"), datetime.now(timezone.utc).isoformat()))
        log_activity("Indicator added",
                     f"Added {indicator_type} indicator {value}")
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM indicators ORDER BY created_at DESC").fetchall()
    return jsonify([dict(row) for row in rows])


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
        with get_db() as db:
            db.execute("UPDATE detection_rules SET enabled = ? WHERE rule_id = ?", (int(
                bool(payload.get("enabled"))), payload.get("rule_id")))
        log_activity(
            "Rule changed", f"Rule {payload.get('rule_id')} enabled={bool(payload.get('enabled'))}")
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM detection_rules ORDER BY rule_id").fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/audit")
@login_required
def audit():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 200").fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/incidents", methods=["GET", "POST", "PATCH"])
@login_required
def incidents():
    payload = request.get_json(silent=True) or {}
    if request.method == "POST":
        with get_db() as db:
            cursor = db.execute("INSERT INTO incidents (event_id, title, notes, status, updated_at) VALUES (?, ?, ?, ?, ?)", (payload.get(
                "event_id"), payload.get("title", "Investigation"), payload.get("notes", ""), "OPEN", datetime.now(timezone.utc).isoformat()))
            incident_id = cursor.lastrowid
        log_activity("Incident opened", f"Incident #{incident_id} created")
    elif request.method == "PATCH":
        status = payload.get("status", "OPEN").upper()
        if status not in {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE POSITIVE"}:
            return jsonify({"error": "Unsupported incident status."}), 400
        with get_db() as db:
            db.execute("UPDATE incidents SET status = ?, notes = COALESCE(?, notes), updated_at = ? WHERE id = ?",
                       (status, payload.get("notes"), datetime.now(timezone.utc).isoformat(), payload.get("id")))
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


@app.route("/api/users", methods=["POST"])
@login_required
@role_required("Admin")
def create_user():
    payload = request.get_json(silent=True) or {}
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
    app.run(debug=True, port=5000)
