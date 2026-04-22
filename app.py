import os, secrets, sqlite3, traceback
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlencode
from flask import Flask, jsonify, request, g, redirect, send_from_directory, session
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
import requests
from werkzeug.security import generate_password_hash, check_password_hash

from notifications import notify

load_dotenv()

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "closeapp.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(__name__, static_folder=None)
app.secret_key = os.getenv("SECRET_KEY", "closetool2026secret")

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PATCH,DELETE,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db: db.close()

def q(sql, params=()):
    return get_db().execute(sql, params).fetchall()

def q1(sql, params=()):
    return get_db().execute(sql, params).fetchone()

def run(sql, params=()):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    return cur

def rows_to_list(rows):
    return [dict(r) for r in rows]

def err(msg, code=400):
    return jsonify({"error": msg}), code

def get_current_user():
    uid = session.get("user_id")
    return q1("SELECT * FROM users WHERE id=?", (uid,)) if uid else None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or user["role"] != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

def period_is_closed(period_id):
    row = q1("SELECT status FROM periods WHERE id=?", (period_id,))
    return bool(row and row["status"] == "closed")

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["GET", "POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "GET":
        return jsonify({"message": "login endpoint"})
    b = request.json or {}
    username = b.get("username", "").strip()
    password = b.get("password", "")
    if not username or not password:
        return err("Username and password required")
    user = q1("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (username,))
    if not user or not user["password_hash"]:
        return err("Invalid username or password")
    if not check_password_hash(user["password_hash"], password):
        return err("Invalid username or password")
    session["user_id"] = user["id"]
    session.permanent = True
    return jsonify({
        "id": user["id"],
        "name": user["name"],
        "initials": user["initials"],
        "role": user["role"],
        "color": user["color"]
    })

@app.route("/api/auth/logout", methods=["GET", "POST", "OPTIONS"])
def logout():
    if request.method == "OPTIONS":
        return "", 204
    session.clear()
    return jsonify({"status": "logged out"})

@app.route("/api/auth/me", methods=["GET", "OPTIONS"])
def me():
    if request.method == "OPTIONS":
        return "", 204
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False})
    return jsonify({
        "authenticated": True,
        "id": user["id"],
        "name": user["name"],
        "initials": user["initials"],
        "role": user["role"],
        "color": user["color"]
    })

# ── QuickBooks ────────────────────────────────────────────────────────────────

QB_CLIENT_ID     = os.getenv("QB_CLIENT_ID", "")
QB_CLIENT_SECRET = os.getenv("QB_CLIENT_SECRET", "")
QB_REDIRECT_URI  = os.getenv("QB_REDIRECT_URI", "http://127.0.0.1:5000/qb/callback")
QB_ENVIRONMENT   = os.getenv("QB_ENVIRONMENT", "sandbox")
QB_SCOPE         = os.getenv("QB_SCOPE", "com.intuit.quickbooks.accounting")
QB_AUTH_URL      = "https://appcenter.intuit.com/connect/oauth2"
QB_TOKEN_URL     = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
QB_API_BASE      = (
    "https://sandbox-quickbooks.api.intuit.com/v3/company"
    if QB_ENVIRONMENT == "sandbox"
    else "https://quickbooks.api.intuit.com/v3/company"
)

def get_tokens():
    row = q1("SELECT access_token, refresh_token, expires_at, realm_id FROM qb_tokens ORDER BY id DESC LIMIT 1")
    return dict(row) if row else {}

def save_tokens(at, rt, ei, realm=None):
    ea = datetime.now(timezone.utc).timestamp() + ei
    db = get_db()
    db.execute(
        "INSERT INTO qb_tokens (access_token, refresh_token, expires_at, realm_id) VALUES (?,?,?,?)",
        (at, rt, ea, realm))
    db.commit()

def refresh_access_token():
    tokens = get_tokens()
    if not tokens.get("refresh_token"):
        return None
    resp = requests.post(QB_TOKEN_URL,
        data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
        auth=(QB_CLIENT_ID, QB_CLIENT_SECRET))
    if resp.ok:
        d = resp.json()
        save_tokens(
            d["access_token"],
            d.get("refresh_token", tokens["refresh_token"]),
            d["expires_in"],
            tokens.get("realm_id"))
        return d["access_token"]
    return None

def qb_get(path):
    tokens = get_tokens()
    if not tokens:
        return None, "Not connected"
    realm = tokens.get("realm_id")
    if not realm:
        return None, "No realm on file"
    now = datetime.now(timezone.utc).timestamp()
    token = tokens["access_token"]
    if tokens.get("expires_at", 0) < now + 60:
        token = refresh_access_token()
    if not token:
        return None, "Token refresh failed"
    resp = requests.get(
        f"{QB_API_BASE}/{realm}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    return (resp.json(), None) if resp.ok else (None, f"QB error {resp.status_code}")

@app.route("/qb/connect")
@login_required
def qb_connect():
    if not QB_CLIENT_ID:
        return err("QB_CLIENT_ID not configured", 500)
    state = secrets.token_urlsafe(24)
    session["qb_oauth_state"] = state
    params = {
        "client_id":     QB_CLIENT_ID,
        "response_type": "code",
        "scope":         QB_SCOPE,
        "redirect_uri":  QB_REDIRECT_URI,
        "state":         state,
    }
    return redirect(f"{QB_AUTH_URL}?{urlencode(params)}")

@app.route("/qb/callback")
def qb_callback():
    code  = request.args.get("code")
    realm = request.args.get("realmId")
    state = request.args.get("state")
    expected = session.pop("qb_oauth_state", None)
    if not code:
        return err("Missing code")
    if not expected or state != expected:
        return err("Invalid OAuth state", 400)
    resp = requests.post(QB_TOKEN_URL,
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": QB_REDIRECT_URI},
        auth=(QB_CLIENT_ID, QB_CLIENT_SECRET))
    if not resp.ok:
        return err("Token exchange failed", 500)
    d = resp.json()
    save_tokens(d["access_token"], d["refresh_token"], d["expires_in"], realm)
    return redirect("/?qb=connected")

@app.route("/api/qb/disconnect", methods=["POST", "OPTIONS"])
@admin_required
def qb_disconnect():
    if request.method == "OPTIONS":
        return "", 204
    run("DELETE FROM qb_tokens")
    return jsonify({"status": "disconnected"})

@app.route("/api/qb/status", methods=["GET", "OPTIONS"])
@login_required
def qb_status():
    if request.method == "OPTIONS":
        return "", 204
    tokens = get_tokens()
    if not tokens:
        return jsonify({"connected": False})
    return jsonify({
        "connected": True,
        "realm_id": tokens.get("realm_id"),
        "environment": QB_ENVIRONMENT,
        "token_expires_in": max(0, int(tokens.get("expires_at", 0) - datetime.now(timezone.utc).timestamp()))
    })

def sync_qb_balances():
    with app.app_context():
        data, error = qb_get("/query?query=SELECT%20*%20FROM%20Account%20MAXRESULTS%201000")
        if error:
            return {"synced": 0, "error": error}
        bal_map = {
            a.get("AcctNum", "").strip(): float(a["CurrentBalance"])
            for a in data.get("QueryResponse", {}).get("Account", [])
            if a.get("AcctNum") and a.get("CurrentBalance") is not None
        }
        db = get_db()
        updated = 0
        period = q1("SELECT id FROM periods WHERE is_active=1")
        if not period:
            return {"synced": 0, "error": "No active period"}
        for r in q("SELECT id, account_number FROM reconciliations WHERE period_id=?", (period["id"],)):
            bal = bal_map.get(r["account_number"])
            if bal is not None:
                db.execute("UPDATE reconciliations SET qb_balance=?, last_synced_at=CURRENT_TIMESTAMP WHERE id=?", (bal, r["id"]))
                updated += 1
        db.commit()
        return {"synced": updated}

@app.route("/api/qb/sync", methods=["POST", "OPTIONS"])
@login_required
def manual_sync():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify(sync_qb_balances())

# ── Periods ───────────────────────────────────────────────────────────────────

@app.route("/api/periods", methods=["GET", "OPTIONS"])
@login_required
def get_periods():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify(rows_to_list(q("SELECT * FROM periods ORDER BY start_date DESC")))

@app.route("/api/periods/active", methods=["GET", "OPTIONS"])
@login_required
def get_active_period():
    if request.method == "OPTIONS":
        return "", 204
    row = q1("SELECT * FROM periods WHERE is_active=1")
    return jsonify(dict(row)) if row else err("No active period", 404)

@app.route("/api/periods/create", methods=["POST", "OPTIONS"])
@admin_required
def create_period():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    label = b.get("label", "").strip()
    start = b.get("start_date", "")
    end   = b.get("end_date", "")
    if not (label and start and end):
        return err("label, start_date, end_date required")
    cur = run("INSERT INTO periods (label,start_date,end_date,is_active) VALUES (?,?,?,0)", (label, start, end))
    return jsonify({"id": cur.lastrowid, "label": label}), 201

@app.route("/api/periods/<int:pid>/activate", methods=["POST", "OPTIONS"])
@admin_required
def activate_period(pid):
    if request.method == "OPTIONS":
        return "", 204
    run("UPDATE periods SET is_active=0")
    run("UPDATE periods SET is_active=1 WHERE id=?", (pid,))
    return jsonify({"activated": pid})

@app.route("/api/periods/<int:pid>/close", methods=["POST", "OPTIONS"])
@admin_required
def close_period(pid):
    if request.method == "OPTIONS":
        return "", 204
    user = get_current_user()
    run("UPDATE periods SET status='closed', closed_at=CURRENT_TIMESTAMP, closed_by=? WHERE id=?", (user["id"], pid))
    return jsonify({"closed": pid})

@app.route("/api/periods/<int:pid>/reopen", methods=["POST", "OPTIONS"])
@admin_required
def reopen_period(pid):
    if request.method == "OPTIONS":
        return "", 204
    run("UPDATE periods SET status='open', closed_at=NULL, closed_by=NULL WHERE id=?", (pid,))
    return jsonify({"reopened": pid})

def _calc_due(end_date_str, offset):
    if offset is None or end_date_str is None:
        return None
    try:
        return (date.fromisoformat(end_date_str) + timedelta(days=int(offset))).isoformat()
    except (ValueError, TypeError):
        return None

@app.route("/api/periods/rollover", methods=["POST", "OPTIONS"])
@admin_required
def rollover_period():
    """
    Clone tasks from `source_period_id` (defaults to most recent) into a newly
    created period. Recomputes each task's due_date from its `due_offset`
    relative to the new period's end_date. Also clones reconciliation shells
    (account number/name/assignee/threshold) minus balances.
    Body: { label, start_date, end_date, source_period_id?, activate? }
    """
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    label = b.get("label", "").strip()
    start = b.get("start_date", "")
    end   = b.get("end_date", "")
    if not (label and start and end):
        return err("label, start_date, end_date required")

    src = b.get("source_period_id")
    if src is None:
        row = q1("SELECT id FROM periods ORDER BY start_date DESC LIMIT 1")
        src = row["id"] if row else None

    db = get_db()
    cur = db.execute(
        "INSERT INTO periods (label,start_date,end_date,is_active,status) VALUES (?,?,?,0,'open')",
        (label, start, end))
    new_id = cur.lastrowid

    cloned_tasks = 0
    cloned_recons = 0
    if src:
        for t in q(
            "SELECT category_id,name,assignee_id,reviewer_id,frequency,due_offset,notes FROM tasks WHERE period_id=?",
            (src,)):
            due = _calc_due(end, t["due_offset"])
            db.execute(
                """INSERT INTO tasks
                   (period_id,category_id,name,assignee_id,reviewer_id,due_date,frequency,due_offset,notes,status,review_status)
                   VALUES (?,?,?,?,?,?,?,?,?, 'open','pending')""",
                (new_id, t["category_id"], t["name"], t["assignee_id"], t["reviewer_id"],
                 due, t["frequency"], t["due_offset"], t["notes"] or ""))
            cloned_tasks += 1
        for r in q(
            "SELECT account_number,account_name,assignee_id,expected_balance,variance_threshold FROM reconciliations WHERE period_id=?",
            (src,)):
            db.execute(
                """INSERT INTO reconciliations
                   (period_id,account_number,account_name,assignee_id,expected_balance,variance_threshold,status)
                   VALUES (?,?,?,?,?,?, 'open')""",
                (new_id, r["account_number"], r["account_name"], r["assignee_id"],
                 r["expected_balance"], r["variance_threshold"]))
            cloned_recons += 1

    if b.get("activate"):
        db.execute("UPDATE periods SET is_active=0")
        db.execute("UPDATE periods SET is_active=1 WHERE id=?", (new_id,))

    db.commit()
    return jsonify({
        "id": new_id,
        "label": label,
        "cloned_tasks": cloned_tasks,
        "cloned_recons": cloned_recons,
        "source_period_id": src,
    }), 201

# ── Users ─────────────────────────────────────────────────────────────────────

@app.route("/api/users", methods=["GET", "OPTIONS"])
@login_required
def get_users():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify(rows_to_list(q("SELECT id,name,initials,username,email,role,color FROM users")))

@app.route("/api/users/create", methods=["POST", "OPTIONS"])
@admin_required
def create_user():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    if not all(k in b for k in ("name", "initials", "username", "role", "color")):
        return err("name, initials, username, role, color required")
    cur = run(
        "INSERT INTO users (name,initials,username,email,role,color,password_hash) VALUES (?,?,?,?,?,?,?)",
        (b["name"], b["initials"], b["username"], b.get("email", ""), b["role"], b["color"],
         generate_password_hash(b.get("password", "changeme123"))))
    return jsonify({"id": cur.lastrowid}), 201

@app.route("/api/users/<int:uid>", methods=["PATCH", "DELETE", "OPTIONS"])
@admin_required
def manage_user(uid):
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "DELETE":
        if uid == session.get("user_id"):
            return err("Cannot delete yourself")
        run("DELETE FROM users WHERE id=?", (uid,))
        return jsonify({"deleted": uid})
    b = request.json or {}
    allowed = {"name", "initials", "username", "email", "role", "color"}
    updates = {k: v for k, v in b.items() if k in allowed}
    if "password" in b:
        updates["password_hash"] = generate_password_hash(b["password"])
    if not updates:
        return err("No valid fields")
    set_clause = ", ".join(f"{k}=?" for k in updates)
    run(f"UPDATE users SET {set_clause} WHERE id=?", list(updates.values()) + [uid])
    return jsonify({"updated": uid})

# ── Categories ────────────────────────────────────────────────────────────────

@app.route("/api/categories", methods=["GET", "OPTIONS"])
@login_required
def get_categories():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify(rows_to_list(q("SELECT * FROM categories ORDER BY sort_order")))

@app.route("/api/categories/create", methods=["POST", "OPTIONS"])
@admin_required
def create_category():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    name = b.get("name", "").strip()
    if not name:
        return err("name required")
    cur = run("INSERT INTO categories (name,sort_order) VALUES (?,?)", (name, b.get("sort_order", 99)))
    return jsonify({"id": cur.lastrowid, "name": name}), 201

@app.route("/api/categories/<int:cid>", methods=["PATCH", "DELETE", "OPTIONS"])
@admin_required
def manage_category(cid):
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "DELETE":
        run("DELETE FROM categories WHERE id=?", (cid,))
        return jsonify({"deleted": cid})
    b = request.json or {}
    allowed = {"name", "sort_order"}
    updates = {k: v for k, v in b.items() if k in allowed}
    if not updates:
        return err("No valid fields")
    set_clause = ", ".join(f"{k}=?" for k in updates)
    run(f"UPDATE categories SET {set_clause} WHERE id=?", list(updates.values()) + [cid])
    return jsonify({"updated": cid})

# ── Tasks ─────────────────────────────────────────────────────────────────────

TASK_SELECT = """
    SELECT t.*, c.name AS category_name,
           u1.name AS assignee_name, u1.initials AS assignee_initials, u1.color AS assignee_color,
           u2.name AS reviewer_name, u2.initials AS reviewer_initials
    FROM tasks t
    JOIN categories c ON c.id = t.category_id
    JOIN users u1 ON u1.id = t.assignee_id
    JOIN users u2 ON u2.id = t.reviewer_id
"""

@app.route("/api/tasks", methods=["GET", "OPTIONS"])
@login_required
def get_tasks():
    if request.method == "OPTIONS":
        return "", 204
    period_id = request.args.get("period_id")
    if not period_id:
        active = q1("SELECT id FROM periods WHERE is_active=1")
        period_id = active["id"] if active else None
    if not period_id:
        return jsonify([])
    return jsonify(rows_to_list(q(TASK_SELECT + " WHERE t.period_id=? ORDER BY c.sort_order, t.id", (period_id,))))

@app.route("/api/tasks/create", methods=["POST", "OPTIONS"])
@admin_required
def create_task():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    if not all(k in b for k in ("period_id", "category_id", "name", "assignee_id", "reviewer_id")):
        return err("Missing required fields")
    cur = run(
        "INSERT INTO tasks (period_id,category_id,name,assignee_id,reviewer_id,due_date,notes) VALUES (?,?,?,?,?,?,?)",
        (b["period_id"], b["category_id"], b["name"], b["assignee_id"], b["reviewer_id"],
         b.get("due_date"), b.get("notes", "")))
    return jsonify({"id": cur.lastrowid}), 201

@app.route("/api/tasks/<int:tid>", methods=["GET", "PATCH", "DELETE", "OPTIONS"])
@login_required
def manage_task(tid):
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "GET":
        row = q1(TASK_SELECT + " WHERE t.id=?", (tid,))
        return jsonify(dict(row)) if row else err("Task not found", 404)
    if request.method == "DELETE":
        user = get_current_user()
        if user["role"] != "admin":
            return err("Admin required", 403)
        run("DELETE FROM task_activity WHERE task_id=?", (tid,))
        run("DELETE FROM tasks WHERE id=?", (tid,))
        return jsonify({"deleted": tid})
    # PATCH
    b = request.json or {}
    user = get_current_user()
    old = q1("SELECT * FROM tasks WHERE id=?", (tid,))
    if not old:
        return err("Task not found", 404)
    if period_is_closed(old["period_id"]):
        return err("Period is closed; reopen it to edit", 423)
    if user["role"] == "admin":
        allowed = {"status", "review_status", "notes", "assignee_id", "reviewer_id",
                   "due_date", "name", "category_id", "frequency", "due_offset"}
    else:
        if old["assignee_id"] != user["id"] and old["reviewer_id"] != user["id"]:
            return err("You can only update your own tasks", 403)
        allowed = {"status", "review_status", "notes"}
    updates = {k: v for k, v in b.items() if k in allowed}
    if not updates:
        return err("No valid fields")
    if updates.get("status") == "complete" and old["status"] != "complete":
        updates["completed_at"] = datetime.utcnow().isoformat()
    if updates.get("review_status") == "approved" and old["review_status"] != "approved":
        updates["approved_at"] = datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k}=?" for k in updates)
    run(f"UPDATE tasks SET {set_clause} WHERE id=?", list(updates.values()) + [tid])
    actor_id = user["id"]
    if "status" in updates:
        run("INSERT INTO task_activity (task_id,user_id,action,old_value,new_value) VALUES (?,?,?,?,?)",
            (tid, actor_id, "status_change", old["status"], updates["status"]))
    if "review_status" in updates:
        run("INSERT INTO task_activity (task_id,user_id,action,old_value,new_value) VALUES (?,?,?,?,?)",
            (tid, actor_id, "review_change", old["review_status"], updates["review_status"]))
    if "notes" in updates and updates["notes"] != (old["notes"] or ""):
        run("INSERT INTO task_activity (task_id,user_id,action,old_value,new_value) VALUES (?,?,?,?,?)",
            (tid, actor_id, "note", None, updates["notes"]))
    _notify_task_change(old, updates, user)
    return jsonify(dict(q1(TASK_SELECT + " WHERE t.id=?", (tid,))))

@app.route("/api/tasks/<int:tid>/activity", methods=["GET", "OPTIONS"])
@login_required
def get_task_activity(tid):
    if request.method == "OPTIONS":
        return "", 204
    rows = q("""
        SELECT a.id, a.action, a.old_value, a.new_value, a.created_at,
               u.name AS user_name, u.initials AS user_initials, u.color AS user_color
        FROM task_activity a
        JOIN users u ON u.id = a.user_id
        WHERE a.task_id=?
        ORDER BY a.created_at DESC, a.id DESC
    """, (tid,))
    return jsonify(rows_to_list(rows))

def _notify_task_change(old, updates, actor):
    """Fire notifications for meaningful status/review transitions."""
    if "status" in updates and updates["status"] == "complete" and old["status"] != "complete":
        reviewer = q1("SELECT name,email FROM users WHERE id=?", (old["reviewer_id"],))
        if reviewer:
            notify(reviewer["email"],
                f"[Close] Ready for review: {old['name']}",
                f"{actor['name']} marked '{old['name']}' complete. Please review.")
    if "review_status" in updates:
        new_rev = updates["review_status"]
        if new_rev == "needs_revision" and old["review_status"] != "needs_revision":
            assignee = q1("SELECT name,email FROM users WHERE id=?", (old["assignee_id"],))
            if assignee:
                notify(assignee["email"],
                    f"[Close] Needs revision: {old['name']}",
                    f"{actor['name']} sent '{old['name']}' back for revision.")
        elif new_rev == "approved" and old["review_status"] != "approved":
            assignee = q1("SELECT name,email FROM users WHERE id=?", (old["assignee_id"],))
            if assignee:
                notify(assignee["email"],
                    f"[Close] Approved: {old['name']}",
                    f"{actor['name']} approved '{old['name']}'.")

# ── Reconciliations ───────────────────────────────────────────────────────────

RECON_SELECT = """
    SELECT r.*, u.name AS assignee_name, u.initials AS assignee_initials, u.color AS assignee_color,
           CASE WHEN r.expected_balance IS NOT NULL
                THEN r.qb_balance - r.expected_balance
                ELSE NULL END AS variance
    FROM reconciliations r
    JOIN users u ON u.id = r.assignee_id
"""

@app.route("/api/reconciliations", methods=["GET", "OPTIONS"])
@login_required
def get_reconciliations():
    if request.method == "OPTIONS":
        return "", 204
    period_id = request.args.get("period_id")
    if not period_id:
        active = q1("SELECT id FROM periods WHERE is_active=1")
        period_id = active["id"] if active else None
    if not period_id:
        return jsonify([])
    return jsonify(rows_to_list(q(RECON_SELECT + " WHERE r.period_id=? ORDER BY r.account_number", (period_id,))))

@app.route("/api/reconciliations/create", methods=["POST", "OPTIONS"])
@admin_required
def create_reconciliation():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    if not all(k in b for k in ("period_id", "account_number", "account_name", "assignee_id")):
        return err("Missing required fields")
    cur = run(
        "INSERT INTO reconciliations (period_id,account_number,account_name,assignee_id,qb_balance,expected_balance,status) VALUES (?,?,?,?,?,?,?)",
        (b["period_id"], b["account_number"], b["account_name"], b["assignee_id"],
         b.get("qb_balance"), b.get("expected_balance"), "open"))
    return jsonify({"id": cur.lastrowid}), 201

@app.route("/api/reconciliations/<int:rid>", methods=["GET", "PATCH", "DELETE", "OPTIONS"])
@login_required
def manage_reconciliation(rid):
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "GET":
        row = q1(RECON_SELECT + " WHERE r.id=?", (rid,))
        return jsonify(dict(row)) if row else err("Reconciliation not found", 404)
    if request.method == "DELETE":
        user = get_current_user()
        if user["role"] != "admin":
            return err("Admin required", 403)
        run("DELETE FROM recon_activity WHERE recon_id=?", (rid,))
        run("DELETE FROM reconciliations WHERE id=?", (rid,))
        return jsonify({"deleted": rid})
    b = request.json or {}
    user = get_current_user()
    old = q1("SELECT * FROM reconciliations WHERE id=?", (rid,))
    if not old:
        return err("Reconciliation not found", 404)
    if period_is_closed(old["period_id"]):
        return err("Period is closed; reopen it to edit", 423)
    if user["role"] == "admin":
        allowed = {"expected_balance", "variance_threshold", "notes", "status",
                   "assignee_id", "account_number", "account_name"}
    else:
        allowed = {"expected_balance", "variance_threshold", "notes", "status"}
    updates = {k: v for k, v in b.items() if k in allowed}
    if not updates:
        return err("No valid fields")

    # Auto-flip status when variance exceeds threshold (only if caller didn't
    # explicitly set status in this request).
    if "status" not in updates:
        expected = updates.get("expected_balance", old["expected_balance"])
        threshold = updates.get("variance_threshold", old["variance_threshold"])
        qb_bal = old["qb_balance"]
        if expected is not None and qb_bal is not None and threshold is not None:
            variance = abs(qb_bal - expected)
            if variance > threshold and old["status"] != "needs_attention":
                updates["status"] = "needs_attention"
            elif variance <= threshold and old["status"] == "needs_attention":
                updates["status"] = "reconciled"

    updates["last_updated_at"] = datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k}=?" for k in updates)
    run(f"UPDATE reconciliations SET {set_clause} WHERE id=?", list(updates.values()) + [rid])

    for k in ("status", "expected_balance", "variance_threshold", "notes"):
        if k in updates and str(updates[k]) != str(old[k] or ""):
            run("INSERT INTO recon_activity (recon_id,user_id,action,old_value,new_value) VALUES (?,?,?,?,?)",
                (rid, user["id"], k, None if old[k] is None else str(old[k]), None if updates[k] is None else str(updates[k])))

    return jsonify(dict(q1(RECON_SELECT + " WHERE r.id=?", (rid,))))

@app.route("/api/reconciliations/<int:rid>/activity", methods=["GET", "OPTIONS"])
@login_required
def get_recon_activity(rid):
    if request.method == "OPTIONS":
        return "", 204
    rows = q("""
        SELECT a.id, a.action, a.old_value, a.new_value, a.created_at,
               u.name AS user_name, u.initials AS user_initials, u.color AS user_color
        FROM recon_activity a
        JOIN users u ON u.id = a.user_id
        WHERE a.recon_id=?
        ORDER BY a.created_at DESC, a.id DESC
    """, (rid,))
    return jsonify(rows_to_list(rows))

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/api/dashboard", methods=["GET", "OPTIONS"])
@login_required
def dashboard():
    if request.method == "OPTIONS":
        return "", 204
    period_id = request.args.get("period_id")
    if not period_id:
        active = q1("SELECT id FROM periods WHERE is_active=1")
        period_id = active["id"] if active else None
    if not period_id:
        return err("No active period", 404)
    tasks_all  = rows_to_list(q("SELECT status,review_status,assignee_id,category_id FROM tasks WHERE period_id=?", (period_id,)))
    recons_all = rows_to_list(q("SELECT status FROM reconciliations WHERE period_id=?", (period_id,)))
    total      = len(tasks_all)
    complete   = sum(1 for t in tasks_all if t["status"] == "complete")
    approved   = sum(1 for t in tasks_all if t["review_status"] == "approved")
    recon_done = sum(1 for r in recons_all if r["status"] == "reconciled")
    users = rows_to_list(q("SELECT id,name,initials,color FROM users"))
    for u in users:
        ut = [t for t in tasks_all if t["assignee_id"] == u["id"]]
        u["tasks_total"]    = len(ut)
        u["tasks_complete"] = sum(1 for t in ut if t["status"] == "complete")
    cats = rows_to_list(q("SELECT id,name FROM categories ORDER BY sort_order"))
    for c in cats:
        ct = [t for t in tasks_all if t["category_id"] == c["id"]]
        c["tasks_total"]    = len(ct)
        c["tasks_complete"] = sum(1 for t in ct if t["status"] == "complete")
    attention = rows_to_list(q("""
        SELECT t.id, t.name, t.status, t.review_status, t.due_date,
               u.name AS assignee_name, u.color AS assignee_color, c.name AS category_name
        FROM tasks t
        JOIN users u ON u.id = t.assignee_id
        JOIN categories c ON c.id = t.category_id
        WHERE t.period_id=? AND (t.review_status='needs_revision' OR t.status='open')
        ORDER BY t.due_date LIMIT 8""", (period_id,)))
    return jsonify({
        "period_id":      period_id,
        "tasks_total":    total,
        "tasks_complete": complete,
        "tasks_approved": approved,
        "close_pct":      round(complete / total * 100) if total else 0,
        "approval_pct":   round(approved / total * 100) if total else 0,
        "recon_total":    len(recons_all),
        "recon_done":     recon_done,
        "recon_pct":      round(recon_done / len(recons_all) * 100) if recons_all else 0,
        "by_user":        users,
        "by_category":    cats,
        "attention":      attention,
    })

# ── Frontend ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    filepath = os.path.join(STATIC_DIR, filename)
    if os.path.exists(filepath):
        return send_from_directory(STATIC_DIR, filename)
    return send_from_directory(STATIC_DIR, "index.html")

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    traceback.print_exc()
    return jsonify({"error": "Internal server error"}), 500

def _start_scheduler():
    sched = BackgroundScheduler()
    sched.add_job(sync_qb_balances, "interval", minutes=15, id="qb_sync")
    sched.start()
    return sched

if os.getenv("RUN_SCHEDULER") == "1":
    _start_scheduler()

if __name__ == "__main__":
    from init_db import init
    init()
    if os.getenv("RUN_SCHEDULER") != "1":
        _start_scheduler()
    app.run(debug=True, port=5000, use_reloader=False)