"""
Lapisan database Mini SOC: koneksi, skema, event, dan alert.
"""

import ipaddress
import os
import secrets
import sqlite3
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

import config
from detector.rules import RULES, TIME_FORMAT


# Alert yang masih OPEN/INVESTIGATING dengan tipe dan sumber yang sama
# tidak dibuat ulang selama jendela ini; alert lama hanya di-update.
ALERT_DEDUP_WINDOW = timedelta(minutes=15)


def now():
    return datetime.now().strftime(TIME_FORMAT)


def get_db():
    conn = sqlite3.connect(config.DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def normalize_ip(value):
    """Samakan ::1 dan ::ffff:a.b.c.d dengan bentuk IPv4-nya."""

    if not value:
        return None

    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return str(value).strip()

    if address.version == 6:
        if address.is_loopback:
            return "127.0.0.1"

        if address.ipv4_mapped:
            return str(address.ipv4_mapped)

    return str(address)


# =========================================================
# SKEMA
# =========================================================

def _seed_user(cursor, username, role, password):
    """Buat user jika belum ada. Mengembalikan password acak bila dibuat."""

    cursor.execute(
        "SELECT 1 FROM users WHERE username = ?", (username,)
    )

    if cursor.fetchone():
        return None

    generated = None

    if not password:
        password = generated = secrets.token_urlsafe(9)

    cursor.execute(
        """
        INSERT INTO users (username, password_hash, role, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (username, generate_password_hash(password), role, now()),
    )

    return generated


def init_db():
    """
    Membuat tabel, indeks, rule bawaan, dan akun awal.

    Mengembalikan dict {username: password} untuk akun yang passwordnya
    dibuat acak, supaya bisa ditampilkan satu kali di console.
    """

    os.makedirs(os.path.dirname(config.DATABASE), exist_ok=True)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            destination_port INTEGER,
            process_name TEXT,
            details TEXT,
            severity TEXT DEFAULT 'INFO',
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            source_ip TEXT,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detection_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_code TEXT UNIQUE NOT NULL,
            rule_name TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    # Indeks untuk query deteksi dan halaman dashboard
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_ip_time
        ON security_events (source_ip, created_at)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_type
        ON security_events (event_type)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_status
        ON security_alerts (status)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_dedup
        ON security_alerts (alert_type, source_ip, status)
    """)

    for rule in RULES:
        cursor.execute(
            """
            INSERT OR IGNORE INTO detection_rules
            (rule_code, rule_name, description, severity, enabled, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (
                rule["code"],
                rule["name"],
                rule["description"],
                rule["severity"],
                now(),
            ),
        )

    created = {}

    for username, role, password in (
        ("admin", "admin", config.ADMIN_PASSWORD),
        ("analyst", "analyst", config.ANALYST_PASSWORD),
    ):
        generated = _seed_user(cursor, username, role, password)

        if generated:
            created[username] = generated

    conn.commit()
    conn.close()

    return created


# =========================================================
# EVENT
# =========================================================

def create_event(
    event_type,
    username=None,
    source_ip=None,
    destination_ip=None,
    destination_port=None,
    process_name=None,
    details=None,
    severity="INFO",
    created_at=None,
):
    username = username[:64] if username else username
    details = details[:500] if details else details

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO security_events
        (
            event_type, username, source_ip, destination_ip,
            destination_port, process_name, details, severity,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_type,
            username,
            normalize_ip(source_ip),
            normalize_ip(destination_ip),
            destination_port,
            process_name,
            details,
            severity,
            created_at or now(),
        ),
    )

    event_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return event_id


# =========================================================
# ALERT
# =========================================================

def create_alert(
    event_id,
    alert_type,
    severity,
    source_ip,
    description,
    dedup_match=None,
):
    """
    Membuat alert baru kecuali sudah ada alert yang setara.

    Mengembalikan (alert_id, created). created = False jika alert
    ditolak karena duplikat; alert lama hanya di-update waktunya.
    """

    conn = get_db()
    cursor = conn.cursor()

    # 1. Event yang sama tidak membuat alert bertipe sama dua kali
    cursor.execute(
        """
        SELECT id FROM security_alerts
        WHERE event_id = ? AND alert_type = ?
        """,
        (event_id, alert_type),
    )

    existing = cursor.fetchone()

    # 2. Alert aktif dengan tipe dan sumber sama dalam jendela dedup
    if not existing:
        cutoff = (
            datetime.now() - ALERT_DEDUP_WINDOW
        ).strftime(TIME_FORMAT)

        query = """
            SELECT id FROM security_alerts
            WHERE alert_type = ?
              AND source_ip IS ?
              AND status IN ('OPEN', 'INVESTIGATING')
              AND created_at >= ?
        """
        params = [alert_type, source_ip, cutoff]

        if dedup_match:
            query += " AND description LIKE ?"
            params.append(f"%{dedup_match}%")

        cursor.execute(query + " ORDER BY id DESC LIMIT 1", params)
        existing = cursor.fetchone()

        if existing:
            cursor.execute(
                "UPDATE security_alerts SET updated_at = ? WHERE id = ?",
                (now(), existing["id"]),
            )
            conn.commit()

    if existing:
        conn.close()
        return existing["id"], False

    timestamp = now()

    cursor.execute(
        """
        INSERT INTO security_alerts
        (
            event_id, alert_type, severity, status, source_ip,
            description, created_at, updated_at
        )
        VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?)
        """,
        (
            event_id, alert_type, severity, source_ip,
            description, timestamp, timestamp,
        ),
    )

    alert_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return alert_id, True
