import os
import unittest

import config
from app import app
from db import get_db, init_db


API_HEADERS = {"X-API-Key": "test-api-key"}


def reset_db():
    if os.path.exists(config.DATABASE):
        os.remove(config.DATABASE)

    init_db()


def count(table, where="1=1"):
    conn = get_db()
    total = conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE {where}"
    ).fetchone()[0]
    conn.close()

    return total


class ApiTests(unittest.TestCase):

    def setUp(self):
        reset_db()
        self.client = app.test_client()

    def post(self, payload, headers=API_HEADERS):
        return self.client.post(
            "/api/events", json=payload, headers=headers
        )

    def test_missing_or_wrong_key_is_rejected(self):
        payload = {"event_type": "NETWORK_SCAN"}

        self.assertEqual(self.post(payload, headers={}).status_code, 401)
        self.assertEqual(
            self.post(payload, headers={"X-API-Key": "wrong"}).status_code,
            401,
        )
        self.assertEqual(count("security_events"), 0)

    def test_valid_event_creates_event_and_alert(self):
        response = self.post({
            "event_type": "NETWORK_SCAN",
            "source_ip": "203.0.113.50",
        })

        body = response.get_json()

        self.assertEqual(response.status_code, 201)
        self.assertEqual(body["detections"]["alerts_created"], 1)
        self.assertEqual(count("security_alerts"), 1)

    def test_invalid_payloads_are_rejected(self):
        bad_payloads = [
            {},
            {"event_type": "bad type!"},
            {"event_type": "NETWORK_SCAN", "severity": "SUPER"},
            {"event_type": "NETWORK_SCAN", "source_ip": "999.1.1.1"},
            {"event_type": "NETWORK_SCAN", "destination_port": 70000},
            {"event_type": "NETWORK_SCAN", "destination_port": "abc"},
        ]

        for payload in bad_payloads:
            with self.subTest(payload=payload):
                self.assertEqual(self.post(payload).status_code, 400)

        self.assertEqual(count("security_events"), 0)

    def test_event_type_is_normalized_to_uppercase(self):
        self.post({"event_type": "network_scan", "source_ip": "203.0.113.5"})

        self.assertEqual(
            count("security_events", "event_type = 'NETWORK_SCAN'"), 1
        )

    def test_health_is_public(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)


class WebSecurityTests(unittest.TestCase):

    def setUp(self):
        reset_db()
        self.client = app.test_client()

    def login(self, username, password, csrf="token-123"):
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = csrf

        return self.client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": csrf,
            },
        )

    def post_with_csrf(self, url, csrf="token-123"):
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = csrf

        return self.client.post(url, data={"csrf_token": csrf})

    def test_pages_require_login(self):
        for path in ["/dashboard", "/events", "/alerts", "/detections"]:
            with self.subTest(path=path):
                response = self.client.get(path)

                self.assertEqual(response.status_code, 302)
                self.assertIn("/login", response.headers["Location"])

    def test_login_without_csrf_token_is_rejected(self):
        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "admin-test-password"},
        )

        self.assertEqual(response.status_code, 403)

    def test_successful_login(self):
        response = self.login("admin", "admin-test-password")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/dashboard", response.headers["Location"])
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_failed_login_is_logged_as_event(self):
        self.login("admin", "wrong-password")

        self.assertEqual(
            count("security_events", "event_type = 'LOGIN_FAILED'"), 1
        )

    def test_login_page_does_not_leak_credentials(self):
        html = self.client.get("/login").get_data(as_text=True)

        self.assertNotIn("admin123", html)
        self.assertNotIn("analyst123", html)

    def test_post_without_csrf_token_is_rejected(self):
        self.login("admin", "admin-test-password")

        response = self.client.post("/detections/AUTH-001/toggle")

        self.assertEqual(response.status_code, 403)

    def test_analyst_cannot_toggle_rules(self):
        self.login("analyst", "analyst-test-password")

        self.post_with_csrf("/detections/AUTH-001/toggle")

        self.assertEqual(
            count("detection_rules",
                  "rule_code = 'AUTH-001' AND enabled = 1"),
            1,
        )

    def test_admin_can_toggle_rules(self):
        self.login("admin", "admin-test-password")

        self.post_with_csrf("/detections/AUTH-001/toggle")

        self.assertEqual(
            count("detection_rules",
                  "rule_code = 'AUTH-001' AND enabled = 0"),
            1,
        )

    def test_detections_page_lists_every_rule(self):
        self.login("admin", "admin-test-password")

        html = self.client.get("/detections").get_data(as_text=True)

        for code in ["AUTH-001", "AUTH-002", "NET-001", "PROC-001",
                     "NET-002", "SEV-001", "WEB-001"]:
            self.assertIn(code, html)

    def test_alert_workflow(self):
        API = {"X-API-Key": "test-api-key"}
        self.client.post(
            "/api/events",
            json={"event_type": "NETWORK_SCAN", "source_ip": "203.0.113.5"},
            headers=API,
        )
        self.login("analyst", "analyst-test-password")

        self.post_with_csrf("/alerts/1/investigate")
        self.assertEqual(
            count("security_alerts", "id = 1 AND status = 'INVESTIGATING'"),
            1,
        )

        self.post_with_csrf("/alerts/1/close")
        self.assertEqual(
            count("security_alerts", "id = 1 AND status = 'CLOSED'"), 1
        )

        self.assertEqual(self.client.get("/incident/1").status_code, 200)
        self.assertEqual(
            self.client.get("/incident/1/report").status_code, 200
        )


if __name__ == "__main__":
    unittest.main()
