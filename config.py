"""
Konfigurasi Mini SOC Dashboard.

Nilai dibaca dari environment variable. Jika ada file `.env` di root
project, isinya dimuat otomatis (tanpa library tambahan). Environment
variable yang sudah diset di shell selalu diutamakan.
"""

import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_dotenv(path):
    if not os.path.isfile(path):
        return

    with open(path, encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")

            os.environ.setdefault(key.strip(), value)


_load_dotenv(os.path.join(BASE_DIR, ".env"))


DATABASE = (
    os.environ.get("MINI_SOC_DB")
    or os.path.join(BASE_DIR, "database", "soc.db")
)

# Jika SECRET_KEY tidak diset, dibuat acak setiap aplikasi dijalankan
# (session lama otomatis tidak berlaku setelah restart).
SECRET_KEY_FROM_ENV = bool(os.environ.get("SECRET_KEY"))
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Jika kosong, endpoint /api/events menolak semua request.
SIEM_API_KEY = os.environ.get("SIEM_API_KEY", "")

# Jika kosong, password dibuat acak dan ditampilkan SATU KALI di console
# saat akun dibuat pertama kali.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
ANALYST_PASSWORD = os.environ.get("ANALYST_PASSWORD", "")

DEBUG = os.environ.get("FLASK_DEBUG") == "1"
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE") == "1"
