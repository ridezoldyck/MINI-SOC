"""
Setup environment untuk test.

Dijalankan sebelum modul aplikasi di-import, sehingga test memakai
database sementara dan tidak menyentuh database/soc.db.
"""

import os
import tempfile

_TMP_DIR = tempfile.mkdtemp(prefix="mini-soc-test-")

os.environ["MINI_SOC_DB"] = os.path.join(_TMP_DIR, "test.db")
os.environ["SIEM_API_KEY"] = "test-api-key"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["ADMIN_PASSWORD"] = "admin-test-password"
os.environ["ANALYST_PASSWORD"] = "analyst-test-password"
