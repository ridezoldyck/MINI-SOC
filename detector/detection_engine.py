"""
Mini SIEM - Detection Engine.

Mengevaluasi event terhadap rule yang aktif (lihat detector/rules.py)
lalu membuat alert melalui db.create_alert (dengan deduplikasi).
"""

from db import create_alert, get_db
from detector.rules import RULES


def get_enabled_rules(conn):
    rows = conn.execute(
        "SELECT rule_code FROM detection_rules WHERE enabled = 1"
    ).fetchall()

    return {row["rule_code"] for row in rows}


def run_all_detections(event_id=None, limit=100):
    """
    Menjalankan semua rule aktif.

    - event_id diberikan : hanya event itu yang dievaluasi (dipakai
      saat ingest event baru).
    - event_id None      : mengevaluasi ulang `limit` event terakhir
      dari yang terlama ke terbaru (rescan).

    Mengembalikan ringkasan; `alerts` hanya berisi alert yang benar-benar
    BARU dibuat (duplikat tidak dihitung).
    """

    conn = get_db()

    enabled = get_enabled_rules(conn)

    if event_id is not None:
        events = conn.execute(
            "SELECT * FROM security_events WHERE id = ?", (event_id,)
        ).fetchall()
    else:
        events = conn.execute(
            """
            SELECT * FROM (
                SELECT * FROM security_events ORDER BY id DESC LIMIT ?
            ) ORDER BY id ASC
            """,
            (limit,),
        ).fetchall()

    detections = []

    for event in events:
        for rule in RULES:
            if rule["code"] in enabled:
                detections.extend(rule["function"](conn, event))

    conn.close()

    alerts = []

    for detection in detections:
        alert_id, created = create_alert(
            event_id=detection["event_id"],
            alert_type=detection["alert_type"],
            severity=detection["severity"],
            source_ip=detection["source_ip"],
            description=detection["description"],
            dedup_match=detection.get("dedup_match"),
        )

        if created:
            alerts.append({
                "alert_id": alert_id,
                "event_id": detection["event_id"],
                "alert_type": detection["alert_type"],
                "severity": detection["severity"],
                "source_ip": detection["source_ip"],
                "description": detection["description"],
            })

    return {
        "events_analyzed": len(events),
        "detections_found": len(detections),
        "alerts_created": len(alerts),
        "alerts": alerts,
    }
