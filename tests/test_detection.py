import os
import unittest
from datetime import datetime, timedelta

import config
from db import create_event, get_db, init_db, normalize_ip
from detector.detection_engine import run_all_detections


def reset_db():
    if os.path.exists(config.DATABASE):
        os.remove(config.DATABASE)

    init_db()


def ts(offset_seconds=0):
    moment = datetime.now() + timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def ingest(event_type, **fields):
    """Buat event lalu jalankan engine, seperti alur /api/events."""

    event_id = create_event(event_type, **fields)

    return run_all_detections(event_id)


def alert_types():
    conn = get_db()
    rows = conn.execute(
        "SELECT alert_type FROM security_alerts ORDER BY id"
    ).fetchall()
    conn.close()

    return [row["alert_type"] for row in rows]


def failed_login(ip="203.0.113.50", offset=0, user="admin"):
    return ingest(
        "LOGIN_FAILED",
        username=user,
        source_ip=ip,
        created_at=ts(offset),
    )


class FailedLoginAndBruteForceTests(unittest.TestCase):

    def setUp(self):
        reset_db()

    def test_two_failures_raise_no_alert(self):
        failed_login()
        failed_login()

        self.assertEqual(alert_types(), [])

    def test_third_failure_raises_failed_login_only(self):
        for _ in range(3):
            failed_login()

        self.assertEqual(alert_types(), ["FAILED_LOGIN"])

    def test_fifth_failure_raises_brute_force(self):
        for _ in range(5):
            failed_login()

        self.assertEqual(
            alert_types(), ["FAILED_LOGIN", "BRUTE_FORCE"]
        )

    def test_four_failures_are_not_brute_force(self):
        for _ in range(4):
            failed_login()

        self.assertNotIn("BRUTE_FORCE", alert_types())

    def test_slow_attempts_outside_window_are_not_brute_force(self):
        # 5 percobaan, selang 2 menit: maksimal 3 dalam jendela 5 menit
        for i in range(5):
            failed_login(offset=-(4 - i) * 120)

        self.assertNotIn("BRUTE_FORCE", alert_types())

    def test_repeated_attack_is_deduplicated(self):
        for _ in range(8):
            failed_login()

        types = alert_types()

        self.assertEqual(types.count("BRUTE_FORCE"), 1)
        self.assertEqual(types.count("FAILED_LOGIN"), 1)

    def test_each_source_ip_is_tracked_separately(self):
        for _ in range(5):
            failed_login(ip="203.0.113.10")

        for _ in range(5):
            failed_login(ip="203.0.113.20")

        self.assertEqual(alert_types().count("BRUTE_FORCE"), 2)

    def test_closed_alert_allows_new_alert(self):
        for _ in range(5):
            failed_login()

        conn = get_db()
        conn.execute("UPDATE security_alerts SET status = 'CLOSED'")
        conn.commit()
        conn.close()

        failed_login()

        self.assertEqual(alert_types().count("BRUTE_FORCE"), 2)

    def test_disabled_rule_does_not_alert(self):
        conn = get_db()
        conn.execute(
            "UPDATE detection_rules SET enabled = 0 "
            "WHERE rule_code = 'AUTH-002'"
        )
        conn.commit()
        conn.close()

        for _ in range(6):
            failed_login()

        self.assertNotIn("BRUTE_FORCE", alert_types())


class EventRuleTests(unittest.TestCase):

    def setUp(self):
        reset_db()

    def test_network_scan(self):
        result = ingest("NETWORK_SCAN", source_ip="203.0.113.50")

        self.assertEqual(result["alerts"][0]["alert_type"], "NETWORK_SCAN")

    def test_suspicious_process_matches_full_windows_path(self):
        result = ingest(
            "PROCESS_START",
            source_ip="203.0.113.50",
            process_name=(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\POWERSHELL.EXE"
            ),
        )

        self.assertEqual(
            result["alerts"][0]["alert_type"], "SUSPICIOUS_PROCESS"
        )

    def test_benign_process_is_ignored(self):
        result = ingest(
            "PROCESS_START",
            source_ip="203.0.113.50",
            process_name="notepad.exe",
        )

        self.assertEqual(result["alerts_created"], 0)

    def test_different_processes_alert_separately(self):
        ingest("PROCESS_START", source_ip="203.0.113.50",
               process_name="powershell.exe")
        ingest("PROCESS_START", source_ip="203.0.113.50",
               process_name="mshta.exe")
        ingest("PROCESS_START", source_ip="203.0.113.50",
               process_name="powershell.exe")

        self.assertEqual(alert_types().count("SUSPICIOUS_PROCESS"), 2)

    def test_suspicious_port_from_field(self):
        result = ingest(
            "NETWORK_CONNECTION",
            source_ip="203.0.113.50",
            destination_ip="203.0.113.200",
            destination_port=4444,
        )

        self.assertEqual(
            result["alerts"][0]["alert_type"], "SUSPICIOUS_NETWORK"
        )

    def test_suspicious_port_from_details(self):
        result = ingest(
            "NETWORK_CONNECTION",
            source_ip="203.0.113.50",
            destination_ip="203.0.113.200",
            details="Outbound connection to 203.0.113.200:4444",
        )

        self.assertEqual(result["alerts_created"], 1)

    def test_common_port_is_ignored(self):
        result = ingest(
            "NETWORK_CONNECTION",
            source_ip="203.0.113.50",
            destination_ip="203.0.113.200",
            destination_port=443,
        )

        self.assertEqual(result["alerts_created"], 0)

    def test_high_severity_event(self):
        result = ingest(
            "MALWARE_DETECTED",
            source_ip="203.0.113.50",
            severity="HIGH",
        )

        self.assertEqual(
            result["alerts"][0]["alert_type"], "HIGH_SEVERITY_EVENT"
        )


class SqlInjectionTests(unittest.TestCase):

    PAYLOADS = [
        "GET /detail.php?id=1' OR '1'='1' -- -",
        "GET /item.php?id=1 OR 1=1",
        "GET /item.php?id=1 UNION SELECT username,password FROM users",
        "GET /item.php?id=1%27%20OR%20%271%27%3D%271",
        "GET /item.php?id=1; DROP TABLE users",
        "GET /item.php?id=1 AND SLEEP(5)",
        "GET /item.php?id=1 UNION ALL SELECT name FROM sqlite_master",
    ]

    BENIGN = [
        "GET /index.php?page=2&sort=name",
        "GET /search?q=select+a+good+book",
        "GET /products?category=or&page=1",
        "POST /login",
    ]

    def setUp(self):
        reset_db()

    def test_payloads_are_detected(self):
        for index, payload in enumerate(self.PAYLOADS):
            with self.subTest(payload=payload):
                result = ingest(
                    "WEB_REQUEST",
                    source_ip=f"203.0.113.{index + 1}",
                    details=payload,
                )

                self.assertEqual(
                    [a["alert_type"] for a in result["alerts"]],
                    ["SQL_INJECTION"],
                )

    def test_benign_requests_are_ignored(self):
        for payload in self.BENIGN:
            with self.subTest(payload=payload):
                result = ingest(
                    "WEB_REQUEST",
                    source_ip="203.0.113.50",
                    details=payload,
                )

                self.assertEqual(result["alerts_created"], 0)

    def test_only_web_requests_are_inspected(self):
        result = ingest(
            "PROCESS_START",
            source_ip="203.0.113.50",
            details="1' OR '1'='1",
        )

        self.assertEqual(result["alerts_created"], 0)


class HelperTests(unittest.TestCase):

    def test_normalize_ip(self):
        self.assertEqual(normalize_ip("::1"), "127.0.0.1")
        self.assertEqual(normalize_ip("::ffff:192.168.1.8"), "192.168.1.8")
        self.assertEqual(normalize_ip("203.0.113.50"), "203.0.113.50")
        self.assertIsNone(normalize_ip(None))


if __name__ == "__main__":
    unittest.main()
