"""
Simulator event untuk Mini SOC Dashboard.

Mengirim event buatan ke SIEM API (POST /api/events) supaya setiap
detection rule bisa diuji dari terminal tanpa target eksternal.

Hanya menggunakan library bawaan Python (tanpa dependensi tambahan).
API key dibaca dari file .env (SIEM_API_KEY) atau opsi --api-key.
Semua trafik ditujukan ke Mini SOC lokal (127.0.0.1) dan memakai IP
dokumentasi (203.0.113.0/24, RFC 5737) sebagai sumber event, sehingga
tidak ada sistem nyata yang disentuh.

Contoh:
    python scripts/simulate_events.py brute-force
    python scripts/simulate_events.py network-scan --ip 203.0.113.77
    python scripts/simulate_events.py all
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402  (memuat .env di root project)


DEFAULT_URL = f"http://{config.HOST}:{config.PORT}"
DEFAULT_IP = "203.0.113.50"


# =========================================================
# SKENARIO
# Setiap skenario mengembalikan daftar event (dict) yang
# cocok dengan field yang diterima POST /api/events.
# =========================================================

def scenario_failed_login(ip, count):
    """AUTH-001: satu login gagal."""
    return [{
        "event_type": "LOGIN_FAILED",
        "username": "admin",
        "source_ip": ip,
        "details": "Invalid username or password",
        "severity": "WARNING",
    }]


def scenario_brute_force(ip, count):
    """AUTH-002: >= 5 login gagal dari IP yang sama dalam 5 menit."""
    return [{
        "event_type": "LOGIN_FAILED",
        "username": "admin",
        "source_ip": ip,
        "details": f"Invalid username or password (attempt {i})",
        "severity": "WARNING",
    } for i in range(1, count + 1)]


def scenario_network_scan(ip, count):
    """NET-001: aktivitas network scan."""
    return [{
        "event_type": "NETWORK_SCAN",
        "source_ip": ip,
        "details": "Port scan detected against local laboratory service",
        "severity": "WARNING",
    }]


def scenario_suspicious_process(ip, count):
    """PROC-001: proses command execution yang mencurigakan."""
    return [{
        "event_type": "PROCESS_START",
        "username": "analyst",
        "source_ip": ip,
        "process_name": "powershell.exe",
        "details": "PowerShell process started",
        "severity": "INFO",
    }]


def scenario_suspicious_network(ip, count):
    """NET-002: koneksi keluar ke port yang mencurigakan (4444)."""
    return [{
        "event_type": "NETWORK_CONNECTION",
        "source_ip": ip,
        "destination_ip": "203.0.113.200",
        "destination_port": 4444,
        "details": "Outbound connection to 203.0.113.200:4444",
        "severity": "INFO",
    }]


def scenario_high_severity(ip, count):
    """SEV-001: event berseverity HIGH."""
    return [{
        "event_type": "MALWARE_DETECTED",
        "source_ip": ip,
        "details": "Simulated malware signature match",
        "severity": "HIGH",
    }]


def scenario_sql_injection(ip, count):
    """WEB-001: request web dengan pola SQL injection."""
    return [{
        "event_type": "WEB_REQUEST",
        "source_ip": ip,
        "details": "GET /detail.php?id=1' OR '1'='1' -- -",
        "severity": "INFO",
    }]


SCENARIOS = {
    "failed-login": scenario_failed_login,
    "brute-force": scenario_brute_force,
    "network-scan": scenario_network_scan,
    "suspicious-process": scenario_suspicious_process,
    "suspicious-network": scenario_suspicious_network,
    "sql-injection": scenario_sql_injection,
    "high-severity": scenario_high_severity,
}


# =========================================================
# PENGIRIMAN
# =========================================================

def send_event(url, api_key, event):
    request = urllib.request.Request(
        url.rstrip("/") + "/api/events",
        data=json.dumps(event).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def run_scenario(name, args):
    events = SCENARIOS[name](args.ip, args.count)

    print(f"\n[*] Skenario: {name} ({len(events)} event, sumber {args.ip})")

    for event in events:
        result = send_event(args.url, args.api_key, event)

        event_id = result["event_id"]

        # Response memuat semua alert hasil deteksi; tampilkan
        # hanya yang dipicu oleh event yang baru saja dikirim.
        triggered = [
            alert
            for alert in result["detections"]["alerts"]
            if alert["event_id"] == event_id
        ]

        label = ", ".join(
            f"{a['alert_type']}/{a['severity']}" for a in triggered
        ) or "tanpa alert baru"

        print(f"    event #{event_id} {event['event_type']:<18} -> {label}")

        time.sleep(args.delay)


def main():
    parser = argparse.ArgumentParser(
        description="Kirim event simulasi ke Mini SOC Dashboard."
    )

    parser.add_argument(
        "scenario",
        choices=[*SCENARIOS, "all"],
        help="skenario yang dijalankan ('all' = semua skenario)",
    )
    parser.add_argument(
        "--ip", default=DEFAULT_IP,
        help=f"source IP event (default: {DEFAULT_IP})",
    )
    parser.add_argument(
        "--count", type=int, default=6,
        help="jumlah percobaan untuk brute-force (default: 6, minimal 5)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.2,
        help="jeda antar event dalam detik (default: 0.2)",
    )
    parser.add_argument(
        "--url", default=DEFAULT_URL,
        help=f"alamat Mini SOC (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "--api-key", default=config.SIEM_API_KEY,
        help="API key SIEM (default: SIEM_API_KEY dari .env)",
    )

    args = parser.parse_args()

    if not args.api_key:
        print("[!] SIEM_API_KEY belum diset. Isi file .env atau gunakan")
        print("    --api-key. Lihat .env.example.")
        return 1

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]

    try:
        for name in names:
            run_scenario(name, args)

    except urllib.error.HTTPError as error:
        if error.code == 401:
            print("[!] API key ditolak (401). Periksa --api-key.")
        else:
            print(f"[!] Server menjawab HTTP {error.code}.")
        return 1

    except urllib.error.URLError:
        print(f"[!] Tidak bisa terhubung ke {args.url}.")
        print("    Pastikan Mini SOC sudah berjalan: python app.py")
        return 1

    print("\n[+] Selesai. Cek hasilnya di dashboard -> Alerts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
