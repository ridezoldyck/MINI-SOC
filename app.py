import hmac
import ipaddress
import re
import secrets
from datetime import timedelta
from functools import wraps

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    session,
    url_for,
    flash,
    jsonify
)

from werkzeug.security import check_password_hash

import config
from db import get_db, init_db, now, create_event
from detector.detection_engine import run_all_detections
from detector.rules import RULES


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app = Flask(__name__)

app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    MAX_CONTENT_LENGTH=64 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)


# =========================================================
# SECURITY: CSRF, AUTHENTICATION, AUTHORIZATION
# =========================================================

PUBLIC_ENDPOINTS = {
    "index",
    "login",
    "static",
    "ingest_event",
    "health",
}


def csrf_token():

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_requests():

    endpoint = request.endpoint

    if endpoint is None:
        return None

    # CSRF: semua POST dari browser harus membawa token session.
    # /api/events dikecualikan karena memakai X-API-Key.
    if request.method == "POST" and endpoint != "ingest_event":

        sent_token = request.form.get("csrf_token", "")
        expected_token = session.get("csrf_token", "")

        if not expected_token or not hmac.compare_digest(
            sent_token.encode("utf-8"),
            expected_token.encode("utf-8")
        ):
            return (
                "Invalid or missing CSRF token. "
                "Reload the page and try again.",
                403
            )

    # Semua halaman selain endpoint publik wajib login.
    if endpoint not in PUBLIC_ENDPOINTS and "user_id" not in session:
        return redirect(url_for("login"))

    return None


def admin_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if session.get("role") != "admin":

            flash(
                "Hanya admin yang dapat melakukan aksi ini.",
                "warning"
            )

            return redirect(url_for("detections"))

        return view(*args, **kwargs)

    return wrapped


# =========================================================
# DETECTION ENGINE
# =========================================================

def run_detection_engine(event_id=None):

    return run_all_detections(event_id)


# =========================================================
# CONTEXT
# =========================================================

@app.context_processor
def inject_globals():

    return {
        "current_user": session.get("username"),
        "current_role": session.get("role"),
        "current_year": now()[:4]
    }


# =========================================================
# LOGIN
# =========================================================

@app.route("/", methods=["GET"])
def index():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    message = None


    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )


        conn = get_db()

        cursor = conn.cursor()


        cursor.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (
            username,
        ))


        user = cursor.fetchone()

        conn.close()


        # =================================================
        # LOGIN SUCCESS
        # =================================================

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session.clear()

            session.permanent = True

            session["user_id"] = user["id"]

            session["username"] = user["username"]

            session["role"] = user["role"]


            create_event(
                event_type="LOGIN_SUCCESS",
                username=username,
                source_ip=request.remote_addr,
                details="Successful login",
                severity="INFO"
            )


            return redirect(
                url_for("dashboard")
            )


        # =================================================
        # LOGIN FAILED
        # =================================================

        message = "Username atau password salah."


        failed_event_id = create_event(
            event_type="LOGIN_FAILED",
            username=username,
            source_ip=request.remote_addr,
            details="Failed login attempt",
            severity="WARNING"
        )


        run_detection_engine(failed_event_id)


    return render_template(
        "login.html",
        message=message
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    username = session.get("username")


    if username:

        create_event(
            event_type="LOGOUT",
            username=username,
            source_ip=request.remote_addr,
            details="User logged out",
            severity="INFO"
        )


    session.clear()


    return redirect(
        url_for("login")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    conn = get_db()

    cursor = conn.cursor()


    # TOTAL EVENTS

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM security_events
    """)

    total_events = cursor.fetchone()["total"]


    # SUCCESSFUL LOGIN

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM security_events
        WHERE event_type = 'LOGIN_SUCCESS'
    """)

    successful_logins = cursor.fetchone()["total"]


    # FAILED LOGIN

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM security_events
        WHERE event_type = 'LOGIN_FAILED'
    """)

    failed_logins = cursor.fetchone()["total"]


    # OPEN ALERTS

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM security_alerts
        WHERE status = 'OPEN'
    """)

    open_alerts = cursor.fetchone()["total"]


    # RECENT EVENTS

    cursor.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT 10
    """)

    recent_events = cursor.fetchall()


    # RECENT ALERTS

    cursor.execute("""
        SELECT *
        FROM security_alerts
        ORDER BY id DESC
        LIMIT 5
    """)

    recent_alerts = cursor.fetchall()


    conn.close()


    return render_template(
        "dashboard.html",
        total_events=total_events,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        open_alerts=open_alerts,
        recent_events=recent_events,
        recent_alerts=recent_alerts
    )


# =========================================================
# SECURITY EVENTS
# =========================================================

@app.route("/events")
def events():

    search = request.args.get(
        "search",
        ""
    ).strip()


    event_type = request.args.get(
        "event_type",
        ""
    ).strip()


    severity = request.args.get(
        "severity",
        ""
    ).strip()


    source_ip = request.args.get(
        "source_ip",
        ""
    ).strip()


    conn = get_db()

    cursor = conn.cursor()


    # =====================================================
    # EVENT TYPES
    # =====================================================

    cursor.execute("""
        SELECT DISTINCT event_type
        FROM security_events
        WHERE event_type IS NOT NULL
        AND event_type != ''
        ORDER BY event_type ASC
    """)


    event_types = [
        row["event_type"]
        for row in cursor.fetchall()
    ]


    # =====================================================
    # QUERY
    # =====================================================

    query = """
        SELECT *
        FROM security_events
        WHERE 1 = 1
    """


    params = []


    if search:

        query += """
            AND (
                event_type LIKE ?
                OR username LIKE ?
                OR source_ip LIKE ?
                OR destination_ip LIKE ?
                OR process_name LIKE ?
                OR details LIKE ?
            )
        """

        keyword = f"%{search}%"

        params.extend([
            keyword,
            keyword,
            keyword,
            keyword,
            keyword,
            keyword
        ])


    if event_type:

        query += """
            AND event_type = ?
        """

        params.append(
            event_type
        )


    if severity:

        query += """
            AND severity = ?
        """

        params.append(
            severity
        )


    if source_ip:

        query += """
            AND source_ip LIKE ?
        """

        params.append(
            f"%{source_ip}%"
        )


    query += """
        ORDER BY id DESC
        LIMIT 500
    """


    cursor.execute(
        query,
        params
    )


    event_list = cursor.fetchall()

    conn.close()


    return render_template(
        "events.html",
        events=event_list,
        event_types=event_types,
        search=search,
        event_type=event_type,
        severity=severity,
        source_ip=source_ip
    )


# =========================================================
# EVENT DETAIL
# =========================================================

@app.route("/events/<int:event_id>")
def event_detail(event_id):

    conn = get_db()

    cursor = conn.cursor()


    # =====================================================
    # EVENT
    # =====================================================

    cursor.execute("""
        SELECT *
        FROM security_events
        WHERE id = ?
    """, (
        event_id,
    ))


    event = cursor.fetchone()


    if not event:

        conn.close()

        flash(
            "Security event tidak ditemukan.",
            "warning"
        )

        return redirect(
            url_for("events")
        )


    # =====================================================
    # RELATED ALERTS
    # =====================================================

    cursor.execute("""
        SELECT *
        FROM security_alerts
        WHERE event_id = ?
        ORDER BY id DESC
    """, (
        event_id,
    ))


    related_alerts = cursor.fetchall()


    conn.close()


    return render_template(
        "event_detail.html",
        event=event,
        related_alerts=related_alerts
    )


# =========================================================
# SECURITY ALERTS
# =========================================================

@app.route("/alerts")
def alerts():

    status_filter = request.args.get(
        "status",
        "ALL"
    ).upper()


    conn = get_db()

    cursor = conn.cursor()


    if status_filter in [
        "OPEN",
        "INVESTIGATING",
        "CLOSED"
    ]:

        cursor.execute("""
            SELECT *
            FROM security_alerts
            WHERE status = ?
            ORDER BY id DESC
            LIMIT 500
        """, (
            status_filter,
        ))

    else:

        cursor.execute("""
            SELECT *
            FROM security_alerts
            ORDER BY id DESC
            LIMIT 500
        """)


    alert_list = cursor.fetchall()

    conn.close()


    return render_template(
        "alerts.html",
        alerts=alert_list,
        status_filter=status_filter
    )

# =========================================================
# START INVESTIGATION
# =========================================================

@app.route("/alerts/<int:alert_id>/investigate", methods=["POST"])
def start_investigation(alert_id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE security_alerts
        SET
            status = 'INVESTIGATING',
            updated_at = ?
        WHERE id = ?
        AND status = 'OPEN'
    """, (
        now(),
        alert_id
    ))

    conn.commit()

    affected_rows = cursor.rowcount

    conn.close()

    if affected_rows:
        flash(
            "Alert masuk ke tahap investigation.",
            "success"
        )
    else:
        flash(
            "Alert tidak ditemukan atau bukan OPEN.",
            "warning"
        )

    return redirect(
        url_for(
            "incident",
            alert_id=alert_id
        )
    )

# =========================================================
# CLOSE ALERT
# =========================================================

@app.route(
    "/alerts/<int:alert_id>/close",
    methods=["POST"]
)
def close_alert(alert_id):

    conn = get_db()

    cursor = conn.cursor()


    cursor.execute("""
        UPDATE security_alerts

        SET
            status = 'CLOSED',
            updated_at = ?

        WHERE id = ?

        AND status IN (
            'OPEN',
            'INVESTIGATING'
        )
    """, (
        now(),
        alert_id
    ))


    conn.commit()

    affected_rows = cursor.rowcount

    conn.close()


    if affected_rows:

        flash(
            "Alert berhasil ditutup.",
            "success"
        )

    else:

        flash(
            "Alert tidak ditemukan atau sudah ditutup.",
            "warning"
        )


    return redirect(
        url_for("alerts")
    )

# =========================================================
# INCIDENT INVESTIGATION
# =========================================================

@app.route("/incident/<int:alert_id>")
def incident(alert_id):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM security_alerts
        WHERE id = ?
    """, (alert_id,))

    alert = cursor.fetchone()

    if not alert:
        conn.close()

        flash(
            "Alert tidak ditemukan.",
            "warning"
        )

        return redirect(url_for("alerts"))

    triggering_event = None

    if alert["event_id"]:

        cursor.execute("""
            SELECT *
            FROM security_events
            WHERE id = ?
        """, (alert["event_id"],))

        triggering_event = cursor.fetchone()

    cursor.execute("""
        SELECT *
        FROM security_events
        WHERE source_ip = ?
        ORDER BY created_at DESC
        LIMIT 200
    """, (alert["source_ip"],))

    related_events = cursor.fetchall()

    conn.close()

    return render_template(
        "incident.html",
        alert=alert,
        triggering_event=triggering_event,
        related_events=related_events
    )


# =========================================================
# INCIDENT REPORT
# =========================================================

@app.route("/incident/<int:alert_id>/report")
def incident_report(alert_id):

    conn = get_db()
    cursor = conn.cursor()

    # Ambil alert
    cursor.execute("""
        SELECT *
        FROM security_alerts
        WHERE id = ?
    """, (alert_id,))

    alert = cursor.fetchone()

    if not alert:
        conn.close()

        flash(
            "Alert tidak ditemukan.",
            "warning"
        )

        return redirect(url_for("alerts"))

    # Ambil triggering event
    triggering_event = None

    if alert["event_id"]:

        cursor.execute("""
            SELECT *
            FROM security_events
            WHERE id = ?
        """, (alert["event_id"],))

        triggering_event = cursor.fetchone()

    # Ambil event terkait
    cursor.execute("""
        SELECT *
        FROM security_events
        WHERE source_ip = ?
        ORDER BY created_at ASC
        LIMIT 500
    """, (alert["source_ip"],))

    related_events = cursor.fetchall()

    conn.close()

    return render_template(
        "incident_report.html",
        alert=alert,
        triggering_event=triggering_event,
        related_events=related_events
    )


# =========================================================
# DETECTION RULES
# =========================================================

@app.route("/detections")
def detections():

    conn = get_db()

    rows = conn.execute(
        "SELECT rule_code, enabled FROM detection_rules"
    ).fetchall()

    conn.close()

    states = {
        row["rule_code"]: row["enabled"]
        for row in rows
    }

    rules = [
        dict(rule, enabled=bool(states.get(rule["code"], 1)))
        for rule in RULES
    ]

    return render_template(
        "detections.html",
        rules=rules
    )


@app.route(
    "/detections/<rule_code>/toggle",
    methods=["POST"]
)
@admin_required
def toggle_detection_rule(rule_code):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, rule_name, enabled
        FROM detection_rules
        WHERE rule_code = ?
    """, (rule_code,))

    rule = cursor.fetchone()

    if not rule:

        conn.close()

        flash(
            "Detection rule tidak ditemukan.",
            "warning"
        )

        return redirect(url_for("detections"))

    new_status = 0 if rule["enabled"] else 1

    cursor.execute("""
        UPDATE detection_rules
        SET enabled = ?
        WHERE id = ?
    """, (new_status, rule["id"]))

    conn.commit()
    conn.close()

    if new_status:

        flash(
            f"{rule['rule_name']} berhasil diaktifkan.",
            "success"
        )

    else:

        flash(
            f"{rule['rule_name']} berhasil dinonaktifkan.",
            "warning"
        )

    return redirect(url_for("detections"))


# =========================================================
# PROFILE
# =========================================================

@app.route("/profile")
def profile():

    return render_template("profile.html")


# =========================================================
# SIEM INGESTION API
# =========================================================

EVENT_TYPE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,39}$")

ALLOWED_SEVERITIES = {
    "INFO",
    "LOW",
    "WARNING",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
}


def _clean_text(value, limit):

    if value is None:
        return None

    return str(value).strip()[:limit] or None


def _clean_ip(value, field):

    if value in (None, ""):
        return None, None

    try:
        ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None, f"{field} is not a valid IP address"

    return str(value).strip(), None


def clean_event_payload(data):
    """Validasi dan bersihkan payload. Mengembalikan (event, error)."""

    if not isinstance(data, dict):
        return None, "JSON object required"

    event_type = str(data.get("event_type") or "").strip().upper()

    if not EVENT_TYPE_PATTERN.match(event_type):
        return None, (
            "event_type is required (A-Z, 0-9, underscore; "
            "3-40 characters)"
        )

    severity = str(data.get("severity") or "INFO").strip().upper()

    if severity not in ALLOWED_SEVERITIES:
        return None, (
            "severity must be one of: "
            + ", ".join(sorted(ALLOWED_SEVERITIES))
        )

    source_ip, error = _clean_ip(data.get("source_ip"), "source_ip")

    if error:
        return None, error

    destination_ip, error = _clean_ip(
        data.get("destination_ip"),
        "destination_ip"
    )

    if error:
        return None, error

    port = data.get("destination_port")

    if port in (None, ""):
        port = None
    else:
        if isinstance(port, bool):
            return None, "destination_port must be 0-65535"

        try:
            port = int(port)
        except (TypeError, ValueError):
            return None, "destination_port must be 0-65535"

        if not 0 <= port <= 65535:
            return None, "destination_port must be 0-65535"

    return {
        "event_type": event_type,
        "username": _clean_text(data.get("username"), 64),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": port,
        "process_name": _clean_text(data.get("process_name"), 128),
        "details": _clean_text(data.get("details"), 500),
        "severity": severity,
    }, None


@app.route(
    "/api/events",
    methods=["POST"]
)
def ingest_event():

    if not config.SIEM_API_KEY:

        return jsonify({
            "success": False,
            "message": "SIEM API key is not configured"
        }), 503

    api_key = request.headers.get("X-API-Key", "")

    if not hmac.compare_digest(
        api_key.encode("utf-8"),
        config.SIEM_API_KEY.encode("utf-8")
    ):

        return jsonify({
            "success": False,
            "message": "Invalid API key"
        }), 401

    data = request.get_json(silent=True)

    event, error = clean_event_payload(data)

    if error:

        return jsonify({
            "success": False,
            "message": error
        }), 400

    event_id = create_event(**event)

    detection_result = run_detection_engine(event_id)

    return jsonify({
        "success": True,
        "event_id": event_id,
        "detections": detection_result
    }), 201


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/api/health")
def health():

    return jsonify({
        "status": "online",
        "service": "Mini SOC SIEM",
        "time": now()
    })


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    new_accounts = init_db()

    print("")
    print("=" * 55)
    print(" MINI SOC / SIEM LAB")
    print("=" * 55)
    print(f" Dashboard : http://{config.HOST}:{config.PORT}")
    print(f" SIEM API  : http://{config.HOST}:{config.PORT}/api/events")

    if not config.SIEM_API_KEY:
        print(" [!] SIEM_API_KEY belum diset: API ingestion nonaktif.")

    if not config.SECRET_KEY_FROM_ENV:
        print(" [!] SECRET_KEY belum diset: memakai key acak sementara.")

    if new_accounts:
        print("")
        print(" Akun baru dibuat. Password hanya ditampilkan sekali:")

        for username, password in new_accounts.items():
            print(f"   {username:<8} : {password}")

    print("=" * 55)
    print("")

    app.run(
        debug=config.DEBUG,
        use_reloader=False,
        host=config.HOST,
        port=config.PORT
    )
