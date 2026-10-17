"""
Detection rules Mini SOC.

Setiap rule adalah fungsi murni: menerima koneksi database dan satu
event, lalu mengembalikan daftar deteksi (dict). Fungsi tidak menulis
apa pun ke database; pembuatan alert dilakukan oleh detection engine.

RULES adalah registry tunggal: dipakai untuk seed tabel detection_rules,
halaman Detections, dan dokumentasi (termasuk pemetaan MITRE ATT&CK).
"""

import ntpath
import re
from datetime import datetime, timedelta
from urllib.parse import unquote_plus


TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# ---------------------------------------------------------
# Parameter deteksi
# ---------------------------------------------------------

FAILED_LOGIN_WINDOW = timedelta(minutes=5)
FAILED_LOGIN_THRESHOLD = 3
BRUTE_FORCE_THRESHOLD = 5

SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555, 6666}

SQLI_PATTERNS = [
    (
        "tautology",
        re.compile(
            r"['\"]\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+",
            re.IGNORECASE,
        ),
    ),
    (
        "numeric tautology",
        re.compile(r"\b(or|and)\s+\d+\s*=\s*\d+", re.IGNORECASE),
    ),
    (
        "UNION SELECT",
        re.compile(r"\bunion\b\s+(all\s+)?select\b", re.IGNORECASE),
    ),
    (
        "stacked query",
        re.compile(
            r";\s*(drop|delete|insert|update|exec|shutdown)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "time-based",
        re.compile(
            r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\b\s*[\(']",
            re.IGNORECASE,
        ),
    ),
    (
        "schema enumeration",
        re.compile(
            r"\b(information_schema|sqlite_master|xp_cmdshell)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "comment after quote",
        re.compile(r"['\"]\s*(--|#|/\*)"),
    ),
]


# ---------------------------------------------------------
# Helper
# ---------------------------------------------------------

def _parse_time(value):
    try:
        return datetime.fromisoformat(value).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _detection(event, alert_type, severity, description, dedup_match=None):
    return {
        "event_id": event["id"],
        "alert_type": alert_type,
        "severity": severity,
        "source_ip": event["source_ip"],
        "description": description,
        "dedup_match": dedup_match,
    }


def _failed_login_stats(conn, event):
    """Jumlah login gagal dan akun unik dari IP yang sama (5 menit)."""

    timestamp = _parse_time(event["created_at"])
    source_ip = event["source_ip"]

    if timestamp is None or not source_ip:
        return 0, 0

    start = (timestamp - FAILED_LOGIN_WINDOW).strftime(TIME_FORMAT)
    end = timestamp.strftime(TIME_FORMAT)

    row = conn.execute(
        """
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT username) AS accounts
        FROM security_events
        WHERE event_type = 'LOGIN_FAILED'
          AND source_ip = ?
          AND created_at >= ?
          AND created_at <= ?
          AND id <= ?
        """,
        (source_ip, start, end, event["id"]),
    ).fetchone()

    return row["total"], row["accounts"]


# ---------------------------------------------------------
# Rules
# ---------------------------------------------------------

def detect_failed_login(conn, event):
    """AUTH-001: login gagal berulang dari IP yang sama."""

    if event["event_type"] != "LOGIN_FAILED":
        return []

    count, _ = _failed_login_stats(conn, event)

    if count < FAILED_LOGIN_THRESHOLD:
        return []

    ip = event["source_ip"]

    return [_detection(
        event,
        "FAILED_LOGIN",
        "MEDIUM",
        f"Repeated failed logins from {ip}: {count} attempts "
        f"within 5 minutes.",
    )]


def detect_brute_force(conn, event):
    """AUTH-002: banyak login gagal dari IP yang sama dalam 5 menit."""

    if event["event_type"] != "LOGIN_FAILED":
        return []

    count, accounts = _failed_login_stats(conn, event)

    if count < BRUTE_FORCE_THRESHOLD:
        return []

    ip = event["source_ip"]

    return [_detection(
        event,
        "BRUTE_FORCE",
        "HIGH",
        f"Possible brute force from {ip}: {count} failed login "
        f"attempts against {accounts} account(s) within 5 minutes.",
    )]


def detect_network_scan(conn, event):
    """NET-001: event network scan."""

    if event["event_type"] != "NETWORK_SCAN" or not event["source_ip"]:
        return []

    return [_detection(
        event,
        "NETWORK_SCAN",
        "MEDIUM",
        f"Network scan activity detected from {event['source_ip']}.",
    )]


def detect_suspicious_process(conn, event):
    """PROC-001: proses command/script execution yang mencurigakan."""

    if event["event_type"] != "PROCESS_START":
        return []

    name = ntpath.basename((event["process_name"] or "").strip()).lower()

    if name not in SUSPICIOUS_PROCESSES:
        return []

    return [_detection(
        event,
        "SUSPICIOUS_PROCESS",
        "HIGH",
        f"Suspicious process detected: {name}",
        dedup_match=name,
    )]


def detect_suspicious_network(conn, event):
    """NET-002: koneksi ke port yang sering dipakai backdoor."""

    if event["event_type"] != "NETWORK_CONNECTION":
        return []

    port = event["destination_port"]

    if port is None:
        details = event["details"] or ""
        match = re.search(r":(\d{1,5})\b|\bport\s+(\d{1,5})\b",
                          details, re.IGNORECASE)

        if match:
            port = int(match.group(1) or match.group(2))

    if port not in SUSPICIOUS_PORTS:
        return []

    destination = event["destination_ip"] or "unknown"

    return [_detection(
        event,
        "SUSPICIOUS_NETWORK",
        "MEDIUM",
        f"Suspicious network connection to {destination}:{port}",
        dedup_match=f"{destination}:{port}",
    )]


def detect_sql_injection(conn, event):
    """WEB-001: pola SQL injection pada request web (heuristik)."""

    if event["event_type"] != "WEB_REQUEST":
        return []

    payload = unquote_plus(event["details"] or "")

    for label, pattern in SQLI_PATTERNS:
        if pattern.search(payload):
            snippet = payload[:120]

            return [_detection(
                event,
                "SQL_INJECTION",
                "HIGH",
                f"Possible SQL injection ({label}) from "
                f"{event['source_ip']}: {snippet}",
            )]

    return []


def detect_high_severity(conn, event):
    """SEV-001: event yang sudah berseverity HIGH/CRITICAL."""

    severity = (event["severity"] or "").upper()

    if severity not in ("HIGH", "CRITICAL"):
        return []

    return [_detection(
        event,
        "HIGH_SEVERITY_EVENT",
        severity,
        f"High severity security event detected: {event['event_type']}",
    )]


# ---------------------------------------------------------
# Registry
# ---------------------------------------------------------

RULES = [
    {
        "code": "AUTH-001",
        "name": "Repeated Failed Login",
        "title": "Failed Login Detection",
        "icon": "⚠",
        "description": "Detect repeated failed logins from the same IP.",
        "summary": (
            "Mendeteksi percobaan login yang gagal berulang "
            "dari sumber yang sama."
        ),
        "event_type": "LOGIN_FAILED",
        "condition": "≥ 3 attempts / 5 minutes",
        "severity": "MEDIUM",
        "mitre": "T1110",
        "function": detect_failed_login,
    },
    {
        "code": "AUTH-002",
        "name": "Brute Force Login",
        "title": "Brute Force Detection",
        "icon": "🚨",
        "description": (
            "Detect repeated failed login attempts from the same IP "
            "within five minutes."
        ),
        "summary": (
            "Mendeteksi pola percobaan login gagal dalam jumlah "
            "tinggi pada periode waktu tertentu."
        ),
        "event_type": "LOGIN_FAILED",
        "condition": "≥ 5 attempts / 5 minutes",
        "severity": "HIGH",
        "mitre": "T1110",
        "function": detect_brute_force,
    },
    {
        "code": "NET-001",
        "name": "Network Scan",
        "title": "Network Scan Detection",
        "icon": "🔍",
        "description": "Detect network scanning activity.",
        "summary": (
            "Mendeteksi event yang menunjukkan aktivitas network "
            "scanning terhadap target lab."
        ),
        "event_type": "NETWORK_SCAN",
        "condition": "Scan activity detected",
        "severity": "MEDIUM",
        "mitre": "T1046",
        "function": detect_network_scan,
    },
    {
        "code": "PROC-001",
        "name": "Suspicious Process",
        "title": "Suspicious Process Detection",
        "icon": "⚙",
        "description": (
            "Detect suspicious command execution such as PowerShell, "
            "CMD and scripting engines."
        ),
        "summary": (
            "Mendeteksi proses yang dianggap mencurigakan "
            "berdasarkan nama proses."
        ),
        "event_type": "PROCESS_START",
        "condition": "Process name in watchlist",
        "severity": "HIGH",
        "mitre": "T1059 / T1218",
        "function": detect_suspicious_process,
    },
    {
        "code": "NET-002",
        "name": "Suspicious Network Connection",
        "title": "Suspicious Network Connection",
        "icon": "🌐",
        "description": (
            "Detect connections to ports commonly used by backdoors."
        ),
        "summary": (
            "Mendeteksi koneksi jaringan ke port yang umum dipakai "
            "backdoor atau reverse shell."
        ),
        "event_type": "NETWORK_CONNECTION",
        "condition": "Port in 4444, 1337, 31337, 5555, 6666",
        "severity": "MEDIUM",
        "mitre": "T1571",
        "function": detect_suspicious_network,
    },
    {
        "code": "SEV-001",
        "name": "High Severity Event",
        "title": "High Severity Event",
        "icon": "🛡",
        "description": (
            "Detect security events with HIGH severity that require "
            "investigation."
        ),
        "summary": (
            "Menandai event yang secara langsung memiliki tingkat "
            "severity HIGH atau CRITICAL dan membutuhkan investigasi."
        ),
        "event_type": "Any event",
        "condition": "Severity = HIGH / CRITICAL",
        "severity": "HIGH",
        "mitre": "-",
        "function": detect_high_severity,
    },
    {
        "code": "WEB-001",
        "name": "SQL Injection Pattern",
        "title": "SQL Injection Detection",
        "icon": "💉",
        "description": (
            "Detect SQL injection patterns in web request events."
        ),
        "summary": (
            "Mendeteksi pola SQL injection pada event WEB_REQUEST "
            "(heuristik berbasis pola, bukan WAF)."
        ),
        "event_type": "WEB_REQUEST",
        "condition": "SQLi pattern in request",
        "severity": "HIGH",
        "mitre": "T1190",
        "function": detect_sql_injection,
    },
]
