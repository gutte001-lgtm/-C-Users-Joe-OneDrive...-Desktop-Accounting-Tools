import os, sqlite3, traceback, io, csv, uuid, json
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
from functools import wraps
from flask import Flask, jsonify, request, g, send_from_directory, session, Response, redirect
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "closeapp.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__, static_folder=None)
app.secret_key = os.getenv("SECRET_KEY", "closetool2026secret")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB cap on uploads

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
QB_REALM_ID      = os.getenv("QB_REALM_ID", "")
QB_ENVIRONMENT   = os.getenv("QB_ENVIRONMENT", "sandbox")
QB_TOKEN_URL     = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
QB_API_BASE      = (
    "https://sandbox-quickbooks.api.intuit.com/v3/company"
    if QB_ENVIRONMENT == "sandbox"
    else "https://quickbooks.api.intuit.com/v3/company"
)

def get_tokens():
    try:
        row = q1("SELECT access_token, refresh_token, expires_at FROM qb_tokens ORDER BY id DESC LIMIT 1")
    except sqlite3.OperationalError:
        return {}
    return dict(row) if row else {}

def save_tokens(at, rt, ei):
    ea = datetime.now(timezone.utc).timestamp() + ei
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS qb_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, access_token TEXT, refresh_token TEXT, expires_at REAL)")
    db.execute("INSERT INTO qb_tokens (access_token, refresh_token, expires_at) VALUES (?,?,?)", (at, rt, ea))
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
        save_tokens(d["access_token"], d.get("refresh_token", tokens["refresh_token"]), d["expires_in"])
        return d["access_token"]
    return None

def _qb_token_or_error():
    tokens = get_tokens()
    if not tokens:
        return None, "QuickBooks is not connected"
    now = datetime.now(timezone.utc).timestamp()
    token = tokens["access_token"]
    if tokens.get("expires_at", 0) < now + 60:
        token = refresh_access_token()
    if not token:
        return None, "QuickBooks token refresh failed — reconnect required"
    return token, None

def qb_get(path):
    token, error = _qb_token_or_error()
    if error:
        return None, error
    resp = requests.get(
        f"{QB_API_BASE}/{QB_REALM_ID}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    return (resp.json(), None) if resp.ok else (None, f"QB error {resp.status_code}")

def qb_post(path, body):
    token, error = _qb_token_or_error()
    if error:
        return None, error
    if not QB_REALM_ID:
        return None, "QB_REALM_ID not configured — reconnect QuickBooks"
    resp = requests.post(
        f"{QB_API_BASE}/{QB_REALM_ID}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=body)
    if resp.ok:
        return resp.json(), None
    try:
        detail = resp.json()
    except Exception:
        detail = {"text": resp.text[:500]}
    fault = (detail.get("Fault", {}) or {}).get("Error", [{}])[0] if isinstance(detail, dict) else {}
    msg = fault.get("Message") or fault.get("Detail") or str(detail)[:300]
    return None, f"QB {resp.status_code}: {msg}"

@app.route("/qb/connect")
@login_required
def qb_connect():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return err("Admin required", 403)
    if not QB_CLIENT_ID:
        return err("QB_CLIENT_ID not configured in environment", 500)
    state = uuid.uuid4().hex
    session["qb_oauth_state"] = state
    params = urlencode({
        "client_id": QB_CLIENT_ID,
        "scope": "com.intuit.quickbooks.accounting openid profile email",
        "redirect_uri": QB_REDIRECT_URI,
        "response_type": "code",
        "state": state,
    })
    return redirect(f"https://appcenter.intuit.com/connect/oauth2?{params}")

@app.route("/qb/callback")
def qb_callback():
    code = request.args.get("code")
    realm = request.args.get("realmId")
    state = request.args.get("state")
    expected_state = session.pop("qb_oauth_state", None)
    if expected_state and state != expected_state:
        return err("OAuth state mismatch", 400)
    if not code:
        return err("Missing code")
    resp = requests.post(QB_TOKEN_URL,
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": QB_REDIRECT_URI},
        auth=(QB_CLIENT_ID, QB_CLIENT_SECRET))
    if not resp.ok:
        return err("Token exchange failed", 500)
    d = resp.json()
    save_tokens(d["access_token"], d["refresh_token"], d["expires_in"])
    if realm:
        os.environ["QB_REALM_ID"] = realm
        global QB_REALM_ID
        QB_REALM_ID = realm
    return redirect("/?qb=connected")

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

scheduler = BackgroundScheduler()
scheduler.add_job(sync_qb_balances, "interval", minutes=15, id="qb_balance_sync")
scheduler.add_job(lambda: scheduled_qb_sync(), "interval", minutes=15, id="qb_data_sync", max_instances=1, coalesce=True)
scheduler.start()

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
    if user["role"] == "admin":
        allowed = {"status", "review_status", "notes", "assignee_id", "reviewer_id", "due_date", "name", "category_id"}
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
    if "notes" in updates:
        run("INSERT INTO task_activity (task_id,user_id,action,old_value,new_value) VALUES (?,?,?,?,?)",
            (tid, actor_id, "note", None, updates["notes"]))
    return jsonify(dict(q1("SELECT * FROM tasks WHERE id=?", (tid,))))

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

@app.route("/api/reconciliations/<int:rid>", methods=["PATCH", "DELETE", "OPTIONS"])
@login_required
def manage_reconciliation(rid):
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "DELETE":
        user = get_current_user()
        if user["role"] != "admin":
            return err("Admin required", 403)
        run("DELETE FROM reconciliations WHERE id=?", (rid,))
        return jsonify({"deleted": rid})
    b = request.json or {}
    user = get_current_user()
    allowed = {"expected_balance", "status", "assignee_id", "account_number", "account_name"} if user["role"] == "admin" else {"expected_balance", "status"}
    updates = {k: v for k, v in b.items() if k in allowed}
    if not updates:
        return err("No valid fields")
    updates["last_updated_at"] = datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k}=?" for k in updates)
    run(f"UPDATE reconciliations SET {set_clause} WHERE id=?", list(updates.values()) + [rid])
    return jsonify(dict(q1(RECON_SELECT + " WHERE r.id=?", (rid,))))

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

# ── Activity (Audit Trail) ────────────────────────────────────────────────────

ACTIVITY_SELECT = """
    SELECT a.id, a.task_id, a.action, a.old_value, a.new_value, a.created_at,
           u.id AS user_id, u.name AS user_name, u.initials AS user_initials, u.color AS user_color,
           t.name AS task_name, t.period_id AS period_id,
           c.name AS category_name
    FROM task_activity a
    JOIN users u ON u.id = a.user_id
    JOIN tasks t ON t.id = a.task_id
    JOIN categories c ON c.id = t.category_id
"""

@app.route("/api/tasks/<int:tid>/activity", methods=["GET", "OPTIONS"])
@login_required
def task_activity_feed(tid):
    if request.method == "OPTIONS":
        return "", 204
    rows = q(ACTIVITY_SELECT + " WHERE a.task_id=? ORDER BY a.created_at DESC", (tid,))
    return jsonify(rows_to_list(rows))

@app.route("/api/activity", methods=["GET", "OPTIONS"])
@login_required
def activity_feed():
    if request.method == "OPTIONS":
        return "", 204
    period_id = request.args.get("period_id")
    limit = int(request.args.get("limit", 500))
    if period_id:
        rows = q(ACTIVITY_SELECT + " WHERE t.period_id=? ORDER BY a.created_at DESC LIMIT ?", (period_id, limit))
    else:
        rows = q(ACTIVITY_SELECT + " ORDER BY a.created_at DESC LIMIT ?", (limit,))
    return jsonify(rows_to_list(rows))

@app.route("/api/activity/export.csv", methods=["GET", "OPTIONS"])
@login_required
def activity_export():
    if request.method == "OPTIONS":
        return "", 204
    period_id = request.args.get("period_id")
    if period_id:
        rows = q(ACTIVITY_SELECT + " WHERE t.period_id=? ORDER BY a.created_at DESC", (period_id,))
    else:
        rows = q(ACTIVITY_SELECT + " ORDER BY a.created_at DESC")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Timestamp", "User", "Category", "Task", "Action", "Old Value", "New Value"])
    for r in rows:
        w.writerow([r["created_at"], r["user_name"], r["category_name"], r["task_name"],
                    r["action"], r["old_value"] or "", r["new_value"] or ""])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=close_activity.csv"})

# ── Bulk Task Actions + Roll-Forward ──────────────────────────────────────────

@app.route("/api/tasks/bulk", methods=["POST", "OPTIONS"])
@login_required
def bulk_tasks():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    ids = b.get("ids") or []
    patch = b.get("patch") or {}
    if not ids or not isinstance(ids, list) or not patch:
        return err("ids (list) and patch required")
    user = get_current_user()
    if user["role"] == "admin":
        allowed = {"status", "review_status", "assignee_id", "reviewer_id", "due_date", "category_id"}
    else:
        allowed = {"status", "review_status"}
    updates = {k: v for k, v in patch.items() if k in allowed}
    if not updates:
        return err("No valid fields in patch")
    set_clause = ", ".join(f"{k}=?" for k in updates)
    affected = 0
    for tid in ids:
        t = q1("SELECT * FROM tasks WHERE id=?", (tid,))
        if not t:
            continue
        if user["role"] != "admin" and t["assignee_id"] != user["id"] and t["reviewer_id"] != user["id"]:
            continue
        run(f"UPDATE tasks SET {set_clause} WHERE id=?", list(updates.values()) + [tid])
        for k, v in updates.items():
            run("INSERT INTO task_activity (task_id,user_id,action,old_value,new_value) VALUES (?,?,?,?,?)",
                (tid, user["id"], "bulk_" + k, str(t[k]) if t[k] is not None else None, str(v)))
        affected += 1
    return jsonify({"updated": affected})

@app.route("/api/periods/rollforward", methods=["POST", "OPTIONS"])
@admin_required
def roll_forward():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    src = b.get("source_period_id")
    dst = b.get("target_period_id")
    shift_days = int(b.get("shift_days", 30))
    if not src or not dst:
        return err("source_period_id and target_period_id required")
    if not q1("SELECT 1 FROM periods WHERE id=?", (dst,)):
        return err("Target period not found", 404)
    src_tasks = q("SELECT * FROM tasks WHERE period_id=?", (src,))
    created = 0
    for t in src_tasks:
        new_due = None
        if t["due_date"]:
            try:
                new_due = (datetime.fromisoformat(t["due_date"]) + timedelta(days=shift_days)).date().isoformat()
            except Exception:
                new_due = t["due_date"]
        run("INSERT INTO tasks (period_id,category_id,name,assignee_id,reviewer_id,due_date) VALUES (?,?,?,?,?,?)",
            (dst, t["category_id"], t["name"], t["assignee_id"], t["reviewer_id"], new_due))
        created += 1
    return jsonify({"created": created})

# ── Reconciliation Attachments ────────────────────────────────────────────────

@app.route("/api/reconciliations/<int:rid>/attachments", methods=["GET", "POST", "OPTIONS"])
@login_required
def recon_attachments(rid):
    if request.method == "OPTIONS":
        return "", 204
    if not q1("SELECT 1 FROM reconciliations WHERE id=?", (rid,)):
        return err("Reconciliation not found", 404)
    if request.method == "GET":
        rows = q("""SELECT a.id, a.recon_id, a.filename, a.size_bytes, a.created_at, a.uploader_id,
                           u.name AS uploader_name, u.initials AS uploader_initials, u.color AS uploader_color
                    FROM recon_attachments a
                    LEFT JOIN users u ON u.id = a.uploader_id
                    WHERE a.recon_id=? ORDER BY a.created_at DESC""", (rid,))
        return jsonify(rows_to_list(rows))
    f = request.files.get("file")
    if not f or not f.filename:
        return err("No file uploaded")
    safe = secure_filename(f.filename) or "upload"
    stored = f"{uuid.uuid4().hex}_{safe}"
    path = os.path.join(UPLOAD_DIR, stored)
    f.save(path)
    size = os.path.getsize(path)
    user = get_current_user()
    cur = run("INSERT INTO recon_attachments (recon_id,filename,stored_name,size_bytes,uploader_id) VALUES (?,?,?,?,?)",
              (rid, safe, stored, size, user["id"]))
    return jsonify({"id": cur.lastrowid, "filename": safe, "size_bytes": size}), 201

@app.route("/api/reconciliations/<int:rid>/attachments/<int:aid>", methods=["GET", "DELETE", "OPTIONS"])
@login_required
def recon_attachment(rid, aid):
    if request.method == "OPTIONS":
        return "", 204
    row = q1("SELECT * FROM recon_attachments WHERE id=? AND recon_id=?", (aid, rid))
    if not row:
        return err("Attachment not found", 404)
    if request.method == "DELETE":
        user = get_current_user()
        if user["role"] != "admin" and row["uploader_id"] != user["id"]:
            return err("Only uploader or admin can delete", 403)
        path = os.path.join(UPLOAD_DIR, row["stored_name"])
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
        run("DELETE FROM recon_attachments WHERE id=?", (aid,))
        return jsonify({"deleted": aid})
    return send_from_directory(UPLOAD_DIR, row["stored_name"], as_attachment=True, download_name=row["filename"])

# ── Checklist Templates ───────────────────────────────────────────────────────

@app.route("/api/templates", methods=["GET", "POST", "OPTIONS"])
@login_required
def templates_list():
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "GET":
        rows = q("""SELECT t.*, (SELECT COUNT(*) FROM template_items WHERE template_id=t.id) AS item_count
                    FROM templates t ORDER BY t.name""")
        return jsonify(rows_to_list(rows))
    user = get_current_user()
    if user["role"] != "admin":
        return err("Admin required", 403)
    b = request.json or {}
    name = (b.get("name") or "").strip()
    if not name:
        return err("name required")
    try:
        cur = run("INSERT INTO templates (name, description) VALUES (?,?)", (name, b.get("description", "")))
    except sqlite3.IntegrityError:
        return err("Template name already exists")
    return jsonify({"id": cur.lastrowid, "name": name}), 201

@app.route("/api/templates/<int:tid>", methods=["GET", "DELETE", "OPTIONS"])
@login_required
def template_detail(tid):
    if request.method == "OPTIONS":
        return "", 204
    t = q1("SELECT * FROM templates WHERE id=?", (tid,))
    if not t:
        return err("Template not found", 404)
    if request.method == "DELETE":
        user = get_current_user()
        if user["role"] != "admin":
            return err("Admin required", 403)
        run("DELETE FROM template_items WHERE template_id=?", (tid,))
        run("DELETE FROM templates WHERE id=?", (tid,))
        return jsonify({"deleted": tid})
    items = q("""SELECT ti.*, c.name AS category_name,
                        u1.name AS assignee_name, u1.initials AS assignee_initials, u1.color AS assignee_color,
                        u2.name AS reviewer_name, u2.initials AS reviewer_initials
                 FROM template_items ti
                 LEFT JOIN categories c ON c.id = ti.category_id
                 LEFT JOIN users u1 ON u1.id = ti.default_assignee_id
                 LEFT JOIN users u2 ON u2.id = ti.default_reviewer_id
                 WHERE ti.template_id=? ORDER BY ti.sort_order, ti.id""", (tid,))
    return jsonify({**dict(t), "items": rows_to_list(items)})

@app.route("/api/templates/<int:tid>/items", methods=["POST", "OPTIONS"])
@admin_required
def add_template_item(tid):
    if request.method == "OPTIONS":
        return "", 204
    if not q1("SELECT 1 FROM templates WHERE id=?", (tid,)):
        return err("Template not found", 404)
    b = request.json or {}
    name = (b.get("name") or "").strip()
    if not name:
        return err("name required")
    cur = run("""INSERT INTO template_items
                 (template_id,category_id,name,default_assignee_id,default_reviewer_id,days_offset,sort_order)
                 VALUES (?,?,?,?,?,?,?)""",
              (tid, b.get("category_id"), name, b.get("default_assignee_id"), b.get("default_reviewer_id"),
               int(b.get("days_offset", 0)), int(b.get("sort_order", 0))))
    return jsonify({"id": cur.lastrowid}), 201

@app.route("/api/templates/<int:tid>/items/<int:iid>", methods=["DELETE", "OPTIONS"])
@admin_required
def delete_template_item(tid, iid):
    if request.method == "OPTIONS":
        return "", 204
    run("DELETE FROM template_items WHERE id=? AND template_id=?", (iid, tid))
    return jsonify({"deleted": iid})

@app.route("/api/templates/<int:tid>/instantiate", methods=["POST", "OPTIONS"])
@admin_required
def instantiate_template(tid):
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    period_id = b.get("period_id")
    if not period_id:
        return err("period_id required")
    period = q1("SELECT * FROM periods WHERE id=?", (period_id,))
    if not period:
        return err("Period not found", 404)
    items = q("SELECT * FROM template_items WHERE template_id=? ORDER BY sort_order, id", (tid,))
    if not items:
        return err("Template has no items")
    try:
        start = datetime.fromisoformat(period["start_date"])
    except Exception:
        return err("Invalid period start_date")
    fallback_assignee = b.get("default_assignee_id")
    fallback_reviewer = b.get("default_reviewer_id")
    created, skipped = 0, 0
    for it in items:
        assignee_id = it["default_assignee_id"] or fallback_assignee
        reviewer_id = it["default_reviewer_id"] or fallback_reviewer
        if not assignee_id or not reviewer_id or not it["category_id"]:
            skipped += 1
            continue
        due = (start + timedelta(days=int(it["days_offset"] or 0))).date().isoformat()
        run("""INSERT INTO tasks (period_id,category_id,name,assignee_id,reviewer_id,due_date)
               VALUES (?,?,?,?,?,?)""",
            (period_id, it["category_id"], it["name"], assignee_id, reviewer_id, due))
        created += 1
    return jsonify({"created": created, "skipped": skipped})

@app.route("/api/templates/from_period", methods=["POST", "OPTIONS"])
@admin_required
def template_from_period():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    pid = b.get("period_id")
    name = (b.get("name") or "").strip()
    if not pid or not name:
        return err("period_id and name required")
    period = q1("SELECT * FROM periods WHERE id=?", (pid,))
    if not period:
        return err("Period not found", 404)
    try:
        cur = run("INSERT INTO templates (name, description) VALUES (?,?)",
                  (name, b.get("description") or f"Created from {period['label']}"))
    except sqlite3.IntegrityError:
        return err("Template name already exists")
    tid = cur.lastrowid
    try:
        start = datetime.fromisoformat(period["start_date"])
    except Exception:
        start = None
    tasks_in_period = q("SELECT * FROM tasks WHERE period_id=? ORDER BY category_id, id", (pid,))
    for i, t in enumerate(tasks_in_period):
        offset = 0
        if t["due_date"] and start:
            try:
                offset = (datetime.fromisoformat(t["due_date"]) - start).days
            except Exception:
                offset = 0
        run("""INSERT INTO template_items
               (template_id,category_id,name,default_assignee_id,default_reviewer_id,days_offset,sort_order)
               VALUES (?,?,?,?,?,?,?)""",
            (tid, t["category_id"], t["name"], t["assignee_id"], t["reviewer_id"], offset, i))
    return jsonify({"id": tid, "items": len(tasks_in_period)}), 201

# ── Trial Balance Snapshots ───────────────────────────────────────────────────

def fetch_qb_accounts():
    data, error = qb_get("/query?query=SELECT%20*%20FROM%20Account%20MAXRESULTS%201000")
    if error:
        return None, error
    return data.get("QueryResponse", {}).get("Account", []), None

@app.route("/api/periods/<int:pid>/tb_snapshots", methods=["GET", "POST", "OPTIONS"])
@login_required
def period_tb_snapshots(pid):
    if request.method == "OPTIONS":
        return "", 204
    if not q1("SELECT 1 FROM periods WHERE id=?", (pid,)):
        return err("Period not found", 404)
    if request.method == "GET":
        rows = q("""SELECT s.*, u.name AS user_name, u.initials AS user_initials,
                           (SELECT COUNT(*) FROM tb_snapshot_rows WHERE snapshot_id=s.id) AS row_count,
                           (SELECT ROUND(SUM(CASE WHEN classification='Asset' THEN balance ELSE 0 END),2)
                              FROM tb_snapshot_rows WHERE snapshot_id=s.id) AS total_assets
                    FROM tb_snapshots s LEFT JOIN users u ON u.id=s.snapshotted_by
                    WHERE s.period_id=? ORDER BY s.snapshotted_at DESC""", (pid,))
        return jsonify(rows_to_list(rows))
    user = get_current_user()
    if user["role"] != "admin":
        return err("Admin required", 403)
    b = request.json or {}
    accounts, error = fetch_qb_accounts()
    if error:
        return err(f"QB fetch failed: {error}", 502)
    period = q1("SELECT * FROM periods WHERE id=?", (pid,))
    default_label = f"{period['label']} close snapshot"
    label = (b.get("label") or "").strip() or default_label
    cur = run("INSERT INTO tb_snapshots (period_id,label,notes,snapshotted_by) VALUES (?,?,?,?)",
              (pid, label, b.get("notes", ""), user["id"]))
    sid = cur.lastrowid
    inserted = 0
    for a in accounts:
        if not a.get("Active", True):
            continue
        run("""INSERT INTO tb_snapshot_rows
               (snapshot_id,account_number,account_name,account_type,account_subtype,classification,balance)
               VALUES (?,?,?,?,?,?,?)""",
            (sid, (a.get("AcctNum") or "").strip(), a.get("Name", ""),
             a.get("AccountType"), a.get("AccountSubType"), a.get("Classification"),
             float(a.get("CurrentBalance") or 0)))
        inserted += 1
    return jsonify({"id": sid, "label": label, "rows": inserted}), 201

@app.route("/api/tb_snapshots/<int:sid>", methods=["GET", "DELETE", "OPTIONS"])
@login_required
def tb_snapshot_detail(sid):
    if request.method == "OPTIONS":
        return "", 204
    s = q1("""SELECT s.*, u.name AS user_name, u.initials AS user_initials, p.label AS period_label
              FROM tb_snapshots s LEFT JOIN users u ON u.id=s.snapshotted_by
              JOIN periods p ON p.id=s.period_id WHERE s.id=?""", (sid,))
    if not s:
        return err("Snapshot not found", 404)
    if request.method == "DELETE":
        user = get_current_user()
        if user["role"] != "admin":
            return err("Admin required", 403)
        run("DELETE FROM tb_snapshot_rows WHERE snapshot_id=?", (sid,))
        run("DELETE FROM tb_snapshots WHERE id=?", (sid,))
        return jsonify({"deleted": sid})
    rows = q("""SELECT * FROM tb_snapshot_rows WHERE snapshot_id=?
                ORDER BY classification, account_number, account_name""", (sid,))
    rows_list = rows_to_list(rows)
    totals = {}
    for r in rows_list:
        c = r.get("classification") or "Other"
        totals[c] = totals.get(c, 0) + (r.get("balance") or 0)
    return jsonify({**dict(s), "rows": rows_list, "totals_by_classification": totals})

@app.route("/api/tb_snapshots/<int:sid>/export.csv", methods=["GET", "OPTIONS"])
@login_required
def tb_snapshot_csv(sid):
    if request.method == "OPTIONS":
        return "", 204
    s = q1("SELECT s.*, p.label AS period_label FROM tb_snapshots s JOIN periods p ON p.id=s.period_id WHERE s.id=?", (sid,))
    if not s:
        return err("Snapshot not found", 404)
    rows = q("SELECT * FROM tb_snapshot_rows WHERE snapshot_id=? ORDER BY classification, account_number", (sid,))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([f"Trial Balance — {s['period_label']}", s['label']])
    w.writerow(["Snapshotted", s['snapshotted_at']])
    w.writerow([])
    w.writerow(["Account #", "Account Name", "Type", "Sub-type", "Classification", "Balance"])
    for r in rows:
        w.writerow([r["account_number"], r["account_name"], r["account_type"],
                    r["account_subtype"], r["classification"], f"{r['balance']:.2f}"])
    fname = f"tb_snapshot_{sid}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})

# ── Close Report PDF ──────────────────────────────────────────────────────────

def build_close_report_pdf(period_id):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.enums import TA_LEFT

    period = q1("SELECT * FROM periods WHERE id=?", (period_id,))
    if not period:
        return None, "Period not found"

    tasks_all = q("""SELECT t.*, c.name AS category_name,
                            u1.name AS assignee_name, u1.initials AS assignee_initials,
                            u2.name AS reviewer_name, u2.initials AS reviewer_initials
                     FROM tasks t
                     JOIN categories c ON c.id=t.category_id
                     JOIN users u1 ON u1.id=t.assignee_id
                     JOIN users u2 ON u2.id=t.reviewer_id
                     WHERE t.period_id=? ORDER BY c.sort_order, t.id""", (period_id,))
    recons_all = q("""SELECT r.*, u.name AS assignee_name, u.initials AS assignee_initials,
                             CASE WHEN r.expected_balance IS NOT NULL
                                  THEN r.qb_balance - r.expected_balance ELSE NULL END AS variance
                      FROM reconciliations r JOIN users u ON u.id=r.assignee_id
                      WHERE r.period_id=? ORDER BY r.account_number""", (period_id,))
    cats = q("SELECT * FROM categories ORDER BY sort_order")
    users = q("SELECT * FROM users")

    total = len(tasks_all)
    complete = sum(1 for t in tasks_all if t["status"] == "complete")
    approved = sum(1 for t in tasks_all if t["review_status"] == "approved")
    recon_done = sum(1 for r in recons_all if r["status"] == "reconciled")
    close_pct = round(complete / total * 100) if total else 0
    apv_pct = round(approved / total * 100) if total else 0
    recon_pct = round(recon_done / len(recons_all) * 100) if recons_all else 0

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=48, leftMargin=48, topMargin=54, bottomMargin=54)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=20, textColor=colors.HexColor("#0f172a"), spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#334155"), spaceBefore=14, spaceAfter=6)
    meta = ParagraphStyle("meta", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#64748b"))
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9.5, alignment=TA_LEFT)

    story = []
    story.append(Paragraph("Month-End Close Report", h1))
    story.append(Paragraph(period["label"], ParagraphStyle("sub", parent=styles["Normal"], fontSize=12, textColor=colors.HexColor("#475569"), spaceAfter=4)))
    story.append(Paragraph(f"Generated {datetime.utcnow().strftime('%b %d, %Y %H:%M UTC')}", meta))
    story.append(Spacer(1, 12))

    kpi_data = [
        ["Close Progress", f"{close_pct}%", f"{complete} / {total} tasks"],
        ["Reviewer Approval", f"{apv_pct}%", f"{approved} / {total} approved"],
        ["Reconciliations", f"{recon_pct}%", f"{recon_done} / {len(recons_all)} complete"],
    ]
    kpi = Table(kpi_data, colWidths=[1.9*inch, 1.2*inch, 2.4*inch])
    kpi.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#2563eb")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#64748b")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(kpi)

    story.append(Paragraph("Progress by Category", h2))
    cat_rows = [["Category", "Complete", "Total", "%"]]
    for c in cats:
        ct = [t for t in tasks_all if t["category_id"] == c["id"]]
        if not ct:
            continue
        cdone = sum(1 for t in ct if t["status"] == "complete")
        cat_rows.append([c["name"], str(cdone), str(len(ct)), f"{round(cdone/len(ct)*100)}%"])
    tbl = Table(cat_rows, colWidths=[3.2*inch, 1*inch, 1*inch, 1*inch])
    tbl.setStyle(_basic_table_style())
    story.append(tbl)

    story.append(Paragraph("Progress by Team Member", h2))
    u_rows = [["Team Member", "Complete", "Total", "%"]]
    for u in users:
        ut = [t for t in tasks_all if t["assignee_id"] == u["id"]]
        if not ut:
            continue
        udone = sum(1 for t in ut if t["status"] == "complete")
        u_rows.append([u["name"], str(udone), str(len(ut)), f"{round(udone/len(ut)*100)}%"])
    tbl = Table(u_rows, colWidths=[3.2*inch, 1*inch, 1*inch, 1*inch])
    tbl.setStyle(_basic_table_style())
    story.append(tbl)

    open_items = [t for t in tasks_all if t["status"] != "complete" or t["review_status"] == "needs_revision"]
    if open_items:
        story.append(Paragraph(f"Open / Needs Attention ({len(open_items)})", h2))
        rows = [["Task", "Category", "Assignee", "Due", "Status", "Review"]]
        for t in open_items[:50]:
            rows.append([
                Paragraph(t["name"], body),
                t["category_name"],
                t["assignee_initials"] or "",
                t["due_date"] or "",
                t["status"].replace("_", " "),
                t["review_status"].replace("_", " "),
            ])
        tbl = Table(rows, colWidths=[2.4*inch, 1.1*inch, 0.7*inch, 0.8*inch, 0.9*inch, 1.0*inch])
        tbl.setStyle(_basic_table_style())
        story.append(tbl)
        if len(open_items) > 50:
            story.append(Paragraph(f"…and {len(open_items) - 50} more.", meta))

    story.append(PageBreak())
    story.append(Paragraph("Account Reconciliations", h2))
    rrows = [["Account", "QB Balance", "Expected", "Variance", "Status"]]
    for r in recons_all:
        var = r["variance"]
        var_str = "—" if var is None else (f"${var:,.2f}" if abs(var) > 0.005 else "—")
        rrows.append([
            f"{r['account_number']} {r['account_name']}",
            f"${r['qb_balance']:,.2f}" if r["qb_balance"] is not None else "—",
            f"${r['expected_balance']:,.2f}" if r["expected_balance"] is not None else "—",
            var_str,
            r["status"].replace("_", " "),
        ])
    tbl = Table(rrows, colWidths=[2.4*inch, 1.2*inch, 1.2*inch, 1.0*inch, 1.1*inch])
    tbl.setStyle(_basic_table_style())
    story.append(tbl)

    variance_items = [r for r in recons_all if r["variance"] is not None and abs(r["variance"]) > 0.005]
    if variance_items:
        story.append(Paragraph("Variances Requiring Attention", h2))
        vrows = [["Account", "Variance", "Assignee", "Status"]]
        for r in variance_items:
            vrows.append([
                f"{r['account_number']} {r['account_name']}",
                f"${r['variance']:,.2f}",
                r["assignee_initials"] or "",
                r["status"].replace("_", " "),
            ])
        tbl = Table(vrows, colWidths=[2.8*inch, 1.2*inch, 1*inch, 1.4*inch])
        tbl.setStyle(_basic_table_style())
        story.append(tbl)

    story.append(Spacer(1, 24))
    story.append(Paragraph("Signoff", h2))
    signoff = [["Role", "Name", "Signature / Date"],
               ["Controller", "", ""],
               ["CFO", "", ""]]
    tbl = Table(signoff, colWidths=[1.2*inch, 2.4*inch, 2.6*inch], rowHeights=[0.3*inch, 0.55*inch, 0.55*inch])
    tbl.setStyle(_basic_table_style())
    story.append(tbl)

    doc.build(story)
    return buf.getvalue(), None

def _basic_table_style():
    from reportlab.lib import colors
    from reportlab.platypus import TableStyle
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])

@app.route("/api/periods/<int:pid>/report.pdf", methods=["GET", "OPTIONS"])
@login_required
def close_report_pdf(pid):
    if request.method == "OPTIONS":
        return "", 204
    pdf, error = build_close_report_pdf(pid)
    if error:
        return err(error, 404)
    period = q1("SELECT * FROM periods WHERE id=?", (pid,))
    fname = f"close_report_{period['label'].replace(' ', '_')}.pdf"
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})

# ── QuickBooks Data Sync (read-only) ──────────────────────────────────────────

QB_BACKFILL_YEARS = 3
QB_PAGE_SIZE = 1000

def _qb_custom_field(obj, *names):
    """Return the value of a CustomField matching any of the given names (case-insensitive)."""
    wanted = {n.lower().replace(" ", "").replace("_", "") for n in names}
    for cf in (obj or {}).get("CustomField", []) or []:
        n = (cf.get("Name") or "").lower().replace(" ", "").replace("_", "")
        if n in wanted:
            return cf.get("StringValue") or cf.get("Value") or cf.get("NumberValue") or cf.get("DateValue")
    return None

def _jira_epic(obj):
    return _qb_custom_field(obj, "Jira Epic ID", "Jira Epic", "JiraEpic", "Epic", "Epic ID", "Epic_ID")

def _qb_ref(obj, field):
    v = (obj or {}).get(field) or {}
    return v.get("value"), v.get("name")

def _to_date(s):
    if not s:
        return None
    return s[:10]

# Registry of synced entities. Each entry describes how to pull and shred one QB entity.
# kind: "reference" (no date filter) | "transaction" (uses TxnDate horizon on first pull)
QB_ENTITIES = {}

def _register_entity(key, qb_name, kind, header_table, map_header, line_table=None, map_lines=None):
    QB_ENTITIES[key] = {
        "qb_name": qb_name, "kind": kind,
        "header_table": header_table, "map_header": map_header,
        "line_table": line_table, "map_lines": map_lines,
    }

# ── Entity mappers ──

def _map_account(a):
    return {
        "id": a["Id"], "name": a.get("Name"), "acct_num": (a.get("AcctNum") or "").strip(),
        "account_type": a.get("AccountType"), "account_subtype": a.get("AccountSubType"),
        "classification": a.get("Classification"),
        "current_balance": a.get("CurrentBalance"),
        "active": 1 if a.get("Active", True) else 0,
        "parent_id": (a.get("ParentRef") or {}).get("value"),
        "sync_token": a.get("SyncToken"),
        "last_updated_at": (a.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(a),
    }

def _map_customer(c):
    email = (c.get("PrimaryEmailAddr") or {}).get("Address")
    phone = (c.get("PrimaryPhone") or {}).get("FreeFormNumber")
    return {
        "id": c["Id"], "display_name": c.get("DisplayName"), "company_name": c.get("CompanyName"),
        "email": email, "phone": phone, "balance": c.get("Balance"),
        "active": 1 if c.get("Active", True) else 0,
        "parent_id": (c.get("ParentRef") or {}).get("value"),
        "sync_token": c.get("SyncToken"),
        "last_updated_at": (c.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(c),
    }

def _map_vendor(v):
    email = (v.get("PrimaryEmailAddr") or {}).get("Address")
    phone = (v.get("PrimaryPhone") or {}).get("FreeFormNumber")
    return {
        "id": v["Id"], "display_name": v.get("DisplayName"), "company_name": v.get("CompanyName"),
        "email": email, "phone": phone, "balance": v.get("Balance"),
        "active": 1 if v.get("Active", True) else 0,
        "sync_token": v.get("SyncToken"),
        "last_updated_at": (v.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(v),
    }

def _map_item(i):
    return {
        "id": i["Id"], "name": i.get("Name"), "sku": i.get("Sku"),
        "type": i.get("Type"), "description": i.get("Description"),
        "unit_price": i.get("UnitPrice"),
        "income_account_id": (i.get("IncomeAccountRef") or {}).get("value"),
        "expense_account_id": (i.get("ExpenseAccountRef") or {}).get("value"),
        "asset_account_id": (i.get("AssetAccountRef") or {}).get("value"),
        "active": 1 if i.get("Active", True) else 0,
        "sync_token": i.get("SyncToken"),
        "last_updated_at": (i.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(i),
    }

def _map_invoice(x):
    cust_id, cust_name = _qb_ref(x, "CustomerRef")
    cls_id, _ = _qb_ref(x, "ClassRef")
    dept_id, _ = _qb_ref(x, "DepartmentRef")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")), "due_date": _to_date(x.get("DueDate")),
        "customer_id": cust_id, "customer_name": cust_name,
        "total_amt": x.get("TotalAmt"), "balance": x.get("Balance"),
        "deposit": x.get("Deposit"), "currency": (x.get("CurrencyRef") or {}).get("value"),
        "email_status": x.get("EmailStatus"), "print_status": x.get("PrintStatus"),
        "private_note": x.get("PrivateNote"), "memo": x.get("CustomerMemo", {}).get("value") if isinstance(x.get("CustomerMemo"), dict) else None,
        "jira_epic_id": _jira_epic(x),
        "class_id": cls_id, "department_id": dept_id,
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_invoice_lines(inv):
    out = []
    for ln in inv.get("Line", []) or []:
        if ln.get("DetailType") not in ("SalesItemLineDetail", "DescriptionOnly"):
            continue
        d = ln.get("SalesItemLineDetail") or {}
        item_id, item_name = _qb_ref(d, "ItemRef")
        acct_id, _ = _qb_ref(d, "AccountRef")
        cls_id, _ = _qb_ref(d, "ClassRef")
        out.append({
            "id": f"{inv['Id']}:{ln.get('Id') or len(out)}",
            "invoice_id": inv["Id"], "line_num": ln.get("LineNum"),
            "description": ln.get("Description"), "amount": ln.get("Amount"),
            "item_id": item_id, "item_name": item_name,
            "qty": d.get("Qty"), "unit_price": d.get("UnitPrice"),
            "account_id": acct_id, "tax_code": (d.get("TaxCodeRef") or {}).get("value"),
            "class_id": cls_id, "jira_epic_id": _jira_epic(ln),
            "raw_json": json.dumps(ln),
        })
    return out

def _map_bill(x):
    vid, vname = _qb_ref(x, "VendorRef")
    cls_id, _ = _qb_ref(x, "ClassRef")
    dept_id, _ = _qb_ref(x, "DepartmentRef")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")), "due_date": _to_date(x.get("DueDate")),
        "vendor_id": vid, "vendor_name": vname,
        "total_amt": x.get("TotalAmt"), "balance": x.get("Balance"),
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"), "memo": x.get("Memo"),
        "jira_epic_id": _jira_epic(x),
        "class_id": cls_id, "department_id": dept_id,
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_bill_lines(bill):
    out = []
    for ln in bill.get("Line", []) or []:
        dt = ln.get("DetailType")
        d = ln.get("AccountBasedExpenseLineDetail") or ln.get("ItemBasedExpenseLineDetail") or {}
        acct_id, _ = _qb_ref(d, "AccountRef")
        item_id, _ = _qb_ref(d, "ItemRef")
        cls_id, _ = _qb_ref(d, "ClassRef")
        out.append({
            "id": f"{bill['Id']}:{ln.get('Id') or len(out)}",
            "bill_id": bill["Id"], "line_num": ln.get("LineNum"),
            "description": ln.get("Description"), "amount": ln.get("Amount"),
            "account_id": acct_id, "item_id": item_id,
            "qty": d.get("Qty"), "unit_price": d.get("UnitPrice"),
            "class_id": cls_id, "jira_epic_id": _jira_epic(ln),
            "raw_json": json.dumps(ln),
        })
    return out

def _map_payment(x):
    cid, cname = _qb_ref(x, "CustomerRef")
    dep_id, _ = _qb_ref(x, "DepositToAccountRef")
    return {
        "id": x["Id"], "txn_date": _to_date(x.get("TxnDate")),
        "customer_id": cid, "customer_name": cname,
        "total_amt": x.get("TotalAmt"), "unapplied_amt": x.get("UnappliedAmt"),
        "payment_method": (x.get("PaymentMethodRef") or {}).get("name"),
        "deposit_to_id": dep_id,
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "jira_epic_id": _jira_epic(x),
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_payment_lines(pay):
    out = []
    for ln in pay.get("Line", []) or []:
        linked = ln.get("LinkedTxn") or []
        if linked:
            for lt in linked:
                out.append({
                    "id": f"{pay['Id']}:{ln.get('Id') or len(out)}:{lt.get('TxnId')}",
                    "payment_id": pay["Id"], "amount": ln.get("Amount"),
                    "applied_txn_type": lt.get("TxnType"), "applied_txn_id": lt.get("TxnId"),
                    "raw_json": json.dumps(ln),
                })
        else:
            out.append({
                "id": f"{pay['Id']}:{ln.get('Id') or len(out)}",
                "payment_id": pay["Id"], "amount": ln.get("Amount"),
                "applied_txn_type": None, "applied_txn_id": None,
                "raw_json": json.dumps(ln),
            })
    return out

def _map_bill_payment(x):
    vid, vname = _qb_ref(x, "VendorRef")
    ptype = x.get("PayType")
    bank_id, cc_id, check_num = None, None, None
    if ptype == "Check":
        bank_id = ((x.get("CheckPayment") or {}).get("BankAccountRef") or {}).get("value")
        check_num = x.get("DocNumber")
    elif ptype == "CreditCard":
        cc_id = ((x.get("CreditCardPayment") or {}).get("CCAccountRef") or {}).get("value")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")),
        "vendor_id": vid, "vendor_name": vname,
        "total_amt": x.get("TotalAmt"), "payment_type": ptype,
        "bank_account_id": bank_id, "cc_account_id": cc_id, "check_number": check_num,
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_bill_payment_lines(bp):
    out = []
    for ln in bp.get("Line", []) or []:
        for lt in (ln.get("LinkedTxn") or []):
            out.append({
                "id": f"{bp['Id']}:{ln.get('Id') or len(out)}:{lt.get('TxnId')}",
                "bill_payment_id": bp["Id"], "amount": ln.get("Amount"),
                "applied_txn_type": lt.get("TxnType"), "applied_txn_id": lt.get("TxnId"),
                "raw_json": json.dumps(ln),
            })
    return out

def _map_sales_receipt(x):
    cid, cname = _qb_ref(x, "CustomerRef")
    dep_id, _ = _qb_ref(x, "DepositToAccountRef")
    cls_id, _ = _qb_ref(x, "ClassRef")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")),
        "customer_id": cid, "customer_name": cname,
        "total_amt": x.get("TotalAmt"),
        "payment_method": (x.get("PaymentMethodRef") or {}).get("name"),
        "deposit_to_id": dep_id,
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "memo": x.get("CustomerMemo", {}).get("value") if isinstance(x.get("CustomerMemo"), dict) else None,
        "jira_epic_id": _jira_epic(x),
        "class_id": cls_id,
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_sales_receipt_lines(sr):
    out = []
    for ln in sr.get("Line", []) or []:
        if ln.get("DetailType") != "SalesItemLineDetail":
            continue
        d = ln.get("SalesItemLineDetail") or {}
        item_id, item_name = _qb_ref(d, "ItemRef")
        acct_id, _ = _qb_ref(d, "AccountRef")
        cls_id, _ = _qb_ref(d, "ClassRef")
        out.append({
            "id": f"{sr['Id']}:{ln.get('Id') or len(out)}",
            "sales_receipt_id": sr["Id"], "line_num": ln.get("LineNum"),
            "description": ln.get("Description"), "amount": ln.get("Amount"),
            "item_id": item_id, "item_name": item_name,
            "qty": d.get("Qty"), "unit_price": d.get("UnitPrice"),
            "account_id": acct_id, "tax_code": (d.get("TaxCodeRef") or {}).get("value"),
            "class_id": cls_id, "jira_epic_id": _jira_epic(ln),
            "raw_json": json.dumps(ln),
        })
    return out

def _map_journal_entry(x):
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")),
        "total_amt": x.get("TotalAmt"),
        "adjustment": 1 if x.get("Adjustment") else 0,
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "memo": x.get("Memo"),
        "jira_epic_id": _jira_epic(x),
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_journal_entry_lines(je):
    out = []
    for ln in je.get("Line", []) or []:
        if ln.get("DetailType") != "JournalEntryLineDetail":
            continue
        d = ln.get("JournalEntryLineDetail") or {}
        acct_id, acct_name = _qb_ref(d, "AccountRef")
        entity = d.get("Entity") or {}
        ent_id, _ = _qb_ref(entity, "EntityRef")
        cls_id, _ = _qb_ref(d, "ClassRef")
        dept_id, _ = _qb_ref(d, "DepartmentRef")
        out.append({
            "id": f"{je['Id']}:{ln.get('Id') or len(out)}",
            "journal_entry_id": je["Id"], "line_num": ln.get("LineNum"),
            "posting_type": d.get("PostingType"), "amount": ln.get("Amount"),
            "account_id": acct_id, "account_name": acct_name,
            "entity_type": entity.get("Type"), "entity_id": ent_id,
            "class_id": cls_id, "department_id": dept_id,
            "description": ln.get("Description"),
            "jira_epic_id": _jira_epic(ln),
            "raw_json": json.dumps(ln),
        })
    return out

# ── Phase 2 mappers ──

def _map_employee(e):
    email = (e.get("PrimaryEmailAddr") or {}).get("Address")
    phone = (e.get("PrimaryPhone") or {}).get("FreeFormNumber")
    return {
        "id": e["Id"], "display_name": e.get("DisplayName"), "email": email, "phone": phone,
        "active": 1 if e.get("Active", True) else 0,
        "sync_token": e.get("SyncToken"),
        "last_updated_at": (e.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(e),
    }

def _map_class(c):
    return {
        "id": c["Id"], "name": c.get("Name"),
        "fully_qualified_name": c.get("FullyQualifiedName"),
        "parent_id": (c.get("ParentRef") or {}).get("value"),
        "active": 1 if c.get("Active", True) else 0,
        "sync_token": c.get("SyncToken"),
        "last_updated_at": (c.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(c),
    }

def _map_department(d):
    return {
        "id": d["Id"], "name": d.get("Name"),
        "fully_qualified_name": d.get("FullyQualifiedName"),
        "parent_id": (d.get("ParentRef") or {}).get("value"),
        "active": 1 if d.get("Active", True) else 0,
        "sync_token": d.get("SyncToken"),
        "last_updated_at": (d.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(d),
    }

def _map_tax_code(t):
    return {
        "id": t["Id"], "name": t.get("Name"), "description": t.get("Description"),
        "taxable": 1 if t.get("Taxable") else 0,
        "active": 1 if t.get("Active", True) else 0,
        "sync_token": t.get("SyncToken"),
        "last_updated_at": (t.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(t),
    }

def _map_term(t):
    return {
        "id": t["Id"], "name": t.get("Name"), "type": t.get("Type"),
        "due_days": t.get("DueDays"), "discount_days": t.get("DiscountDays"),
        "discount_percent": t.get("DiscountPercent"),
        "active": 1 if t.get("Active", True) else 0,
        "sync_token": t.get("SyncToken"),
        "last_updated_at": (t.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(t),
    }

def _map_payment_method(pm):
    return {
        "id": pm["Id"], "name": pm.get("Name"), "type": pm.get("Type"),
        "active": 1 if pm.get("Active", True) else 0,
        "sync_token": pm.get("SyncToken"),
        "last_updated_at": (pm.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(pm),
    }

def _map_credit_memo(x):
    cid, cname = _qb_ref(x, "CustomerRef")
    cls_id, _ = _qb_ref(x, "ClassRef")
    dept_id, _ = _qb_ref(x, "DepartmentRef")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")),
        "customer_id": cid, "customer_name": cname,
        "total_amt": x.get("TotalAmt"), "remaining_credit": x.get("RemainingCredit"),
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "memo": x.get("CustomerMemo", {}).get("value") if isinstance(x.get("CustomerMemo"), dict) else None,
        "jira_epic_id": _jira_epic(x), "class_id": cls_id, "department_id": dept_id,
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_credit_memo_lines(cm):
    out = []
    for ln in cm.get("Line", []) or []:
        if ln.get("DetailType") != "SalesItemLineDetail":
            continue
        d = ln.get("SalesItemLineDetail") or {}
        item_id, item_name = _qb_ref(d, "ItemRef")
        acct_id, _ = _qb_ref(d, "AccountRef")
        cls_id, _ = _qb_ref(d, "ClassRef")
        out.append({
            "id": f"{cm['Id']}:{ln.get('Id') or len(out)}",
            "credit_memo_id": cm["Id"], "line_num": ln.get("LineNum"),
            "description": ln.get("Description"), "amount": ln.get("Amount"),
            "item_id": item_id, "item_name": item_name,
            "qty": d.get("Qty"), "unit_price": d.get("UnitPrice"),
            "account_id": acct_id, "tax_code": (d.get("TaxCodeRef") or {}).get("value"),
            "class_id": cls_id, "jira_epic_id": _jira_epic(ln),
            "raw_json": json.dumps(ln),
        })
    return out

def _map_vendor_credit(x):
    vid, vname = _qb_ref(x, "VendorRef")
    cls_id, _ = _qb_ref(x, "ClassRef")
    dept_id, _ = _qb_ref(x, "DepartmentRef")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")),
        "vendor_id": vid, "vendor_name": vname,
        "total_amt": x.get("TotalAmt"),
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"), "memo": x.get("Memo"),
        "jira_epic_id": _jira_epic(x), "class_id": cls_id, "department_id": dept_id,
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_vendor_credit_lines(vc):
    out = []
    for ln in vc.get("Line", []) or []:
        d = ln.get("AccountBasedExpenseLineDetail") or ln.get("ItemBasedExpenseLineDetail") or {}
        acct_id, _ = _qb_ref(d, "AccountRef")
        item_id, _ = _qb_ref(d, "ItemRef")
        cls_id, _ = _qb_ref(d, "ClassRef")
        out.append({
            "id": f"{vc['Id']}:{ln.get('Id') or len(out)}",
            "vendor_credit_id": vc["Id"], "line_num": ln.get("LineNum"),
            "description": ln.get("Description"), "amount": ln.get("Amount"),
            "account_id": acct_id, "item_id": item_id,
            "qty": d.get("Qty"), "unit_price": d.get("UnitPrice"),
            "class_id": cls_id, "jira_epic_id": _jira_epic(ln),
            "raw_json": json.dumps(ln),
        })
    return out

def _map_refund_receipt(x):
    cid, cname = _qb_ref(x, "CustomerRef")
    dep_id, _ = _qb_ref(x, "DepositToAccountRef")
    cls_id, _ = _qb_ref(x, "ClassRef")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")),
        "customer_id": cid, "customer_name": cname,
        "total_amt": x.get("TotalAmt"),
        "payment_method": (x.get("PaymentMethodRef") or {}).get("name"),
        "deposit_account_id": dep_id,
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "memo": x.get("CustomerMemo", {}).get("value") if isinstance(x.get("CustomerMemo"), dict) else None,
        "jira_epic_id": _jira_epic(x), "class_id": cls_id,
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_refund_receipt_lines(rr):
    out = []
    for ln in rr.get("Line", []) or []:
        if ln.get("DetailType") != "SalesItemLineDetail":
            continue
        d = ln.get("SalesItemLineDetail") or {}
        item_id, item_name = _qb_ref(d, "ItemRef")
        acct_id, _ = _qb_ref(d, "AccountRef")
        cls_id, _ = _qb_ref(d, "ClassRef")
        out.append({
            "id": f"{rr['Id']}:{ln.get('Id') or len(out)}",
            "refund_receipt_id": rr["Id"], "line_num": ln.get("LineNum"),
            "description": ln.get("Description"), "amount": ln.get("Amount"),
            "item_id": item_id, "item_name": item_name,
            "qty": d.get("Qty"), "unit_price": d.get("UnitPrice"),
            "account_id": acct_id, "tax_code": (d.get("TaxCodeRef") or {}).get("value"),
            "class_id": cls_id, "jira_epic_id": _jira_epic(ln),
            "raw_json": json.dumps(ln),
        })
    return out

def _map_deposit(x):
    dep_id, _ = _qb_ref(x, "DepositToAccountRef")
    cls_id, _ = _qb_ref(x, "ClassRef")
    dept_id, _ = _qb_ref(x, "DepartmentRef")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")),
        "deposit_account_id": dep_id,
        "total_amt": x.get("TotalAmt"),
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "memo": x.get("CustomerMemo", {}).get("value") if isinstance(x.get("CustomerMemo"), dict) else None,
        "jira_epic_id": _jira_epic(x), "class_id": cls_id, "department_id": dept_id,
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_deposit_lines(dep):
    out = []
    for ln in dep.get("Line", []) or []:
        d = ln.get("DepositLineDetail") or {}
        acct_id, _ = _qb_ref(d, "AccountRef")
        entity = d.get("Entity") or {}
        ent_id = entity.get("value")
        cls_id, _ = _qb_ref(d, "ClassRef")
        applied_type = applied_id = None
        for lt in (ln.get("LinkedTxn") or []):
            applied_type = lt.get("TxnType"); applied_id = lt.get("TxnId"); break
        out.append({
            "id": f"{dep['Id']}:{ln.get('Id') or len(out)}",
            "deposit_id": dep["Id"], "line_num": ln.get("LineNum"),
            "description": ln.get("Description"), "amount": ln.get("Amount"),
            "account_id": acct_id, "entity_type": entity.get("type"),
            "entity_id": ent_id,
            "applied_txn_type": applied_type, "applied_txn_id": applied_id,
            "class_id": cls_id, "raw_json": json.dumps(ln),
        })
    return out

def _map_purchase(x):
    acct_id, acct_name = _qb_ref(x, "AccountRef")
    entity = x.get("EntityRef") or {}
    cls_id, _ = _qb_ref(x, "ClassRef")
    dept_id, _ = _qb_ref(x, "DepartmentRef")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")),
        "payment_type": x.get("PaymentType"),
        "account_id": acct_id, "account_name": acct_name,
        "entity_type": entity.get("type"), "entity_id": entity.get("value"), "entity_name": entity.get("name"),
        "total_amt": x.get("TotalAmt"),
        "credit": 1 if x.get("Credit") else 0,
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "memo": x.get("Memo"),
        "jira_epic_id": _jira_epic(x), "class_id": cls_id, "department_id": dept_id,
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_purchase_lines(pur):
    out = []
    for ln in pur.get("Line", []) or []:
        d = ln.get("AccountBasedExpenseLineDetail") or ln.get("ItemBasedExpenseLineDetail") or {}
        acct_id, _ = _qb_ref(d, "AccountRef")
        item_id, _ = _qb_ref(d, "ItemRef")
        cls_id, _ = _qb_ref(d, "ClassRef")
        out.append({
            "id": f"{pur['Id']}:{ln.get('Id') or len(out)}",
            "purchase_id": pur["Id"], "line_num": ln.get("LineNum"),
            "description": ln.get("Description"), "amount": ln.get("Amount"),
            "account_id": acct_id, "item_id": item_id,
            "qty": d.get("Qty"), "unit_price": d.get("UnitPrice"),
            "class_id": cls_id, "jira_epic_id": _jira_epic(ln),
            "raw_json": json.dumps(ln),
        })
    return out

def _map_transfer(x):
    from_id, _ = _qb_ref(x, "FromAccountRef")
    to_id, _ = _qb_ref(x, "ToAccountRef")
    return {
        "id": x["Id"], "txn_date": _to_date(x.get("TxnDate")),
        "from_account_id": from_id, "to_account_id": to_id,
        "amount": x.get("Amount"),
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_estimate(x):
    cid, cname = _qb_ref(x, "CustomerRef")
    cls_id, _ = _qb_ref(x, "ClassRef")
    dept_id, _ = _qb_ref(x, "DepartmentRef")
    return {
        "id": x["Id"], "doc_number": x.get("DocNumber"),
        "txn_date": _to_date(x.get("TxnDate")),
        "expiration_date": _to_date(x.get("ExpirationDate")),
        "customer_id": cid, "customer_name": cname,
        "total_amt": x.get("TotalAmt"), "status": x.get("TxnStatus"),
        "currency": (x.get("CurrencyRef") or {}).get("value"),
        "private_note": x.get("PrivateNote"),
        "memo": x.get("CustomerMemo", {}).get("value") if isinstance(x.get("CustomerMemo"), dict) else None,
        "jira_epic_id": _jira_epic(x), "class_id": cls_id, "department_id": dept_id,
        "sync_token": x.get("SyncToken"),
        "last_updated_at": (x.get("MetaData") or {}).get("LastUpdatedTime"),
        "raw_json": json.dumps(x),
    }

def _map_estimate_lines(est):
    out = []
    for ln in est.get("Line", []) or []:
        if ln.get("DetailType") != "SalesItemLineDetail":
            continue
        d = ln.get("SalesItemLineDetail") or {}
        item_id, item_name = _qb_ref(d, "ItemRef")
        acct_id, _ = _qb_ref(d, "AccountRef")
        cls_id, _ = _qb_ref(d, "ClassRef")
        out.append({
            "id": f"{est['Id']}:{ln.get('Id') or len(out)}",
            "estimate_id": est["Id"], "line_num": ln.get("LineNum"),
            "description": ln.get("Description"), "amount": ln.get("Amount"),
            "item_id": item_id, "item_name": item_name,
            "qty": d.get("Qty"), "unit_price": d.get("UnitPrice"),
            "account_id": acct_id, "tax_code": (d.get("TaxCodeRef") or {}).get("value"),
            "class_id": cls_id, "jira_epic_id": _jira_epic(ln),
            "raw_json": json.dumps(ln),
        })
    return out

# Register Phase 1 entities
_register_entity("accounts",        "Account",        "reference",   "qb_accounts",        _map_account)
_register_entity("customers",       "Customer",       "reference",   "qb_customers",       _map_customer)
_register_entity("vendors",         "Vendor",         "reference",   "qb_vendors",         _map_vendor)
_register_entity("items",           "Item",           "reference",   "qb_items",           _map_item)
_register_entity("invoices",        "Invoice",        "transaction", "qb_invoices",        _map_invoice,        "qb_invoice_lines",        _map_invoice_lines)
_register_entity("bills",           "Bill",           "transaction", "qb_bills",           _map_bill,           "qb_bill_lines",           _map_bill_lines)
_register_entity("payments",        "Payment",        "transaction", "qb_payments",        _map_payment,        "qb_payment_lines",        _map_payment_lines)
_register_entity("bill_payments",   "BillPayment",    "transaction", "qb_bill_payments",   _map_bill_payment,   "qb_bill_payment_lines",   _map_bill_payment_lines)
_register_entity("sales_receipts",  "SalesReceipt",   "transaction", "qb_sales_receipts",  _map_sales_receipt,  "qb_sales_receipt_lines",  _map_sales_receipt_lines)
_register_entity("journal_entries", "JournalEntry",   "transaction", "qb_journal_entries", _map_journal_entry,  "qb_journal_entry_lines",  _map_journal_entry_lines)

# Register Phase 2 entities
_register_entity("employees",       "Employee",       "reference",   "qb_employees",       _map_employee)
_register_entity("classes",         "Class",          "reference",   "qb_classes",         _map_class)
_register_entity("departments",     "Department",     "reference",   "qb_departments",     _map_department)
_register_entity("tax_codes",       "TaxCode",        "reference",   "qb_tax_codes",       _map_tax_code)
_register_entity("terms",           "Term",           "reference",   "qb_terms",           _map_term)
_register_entity("payment_methods", "PaymentMethod",  "reference",   "qb_payment_methods", _map_payment_method)
_register_entity("credit_memos",    "CreditMemo",     "transaction", "qb_credit_memos",    _map_credit_memo,    "qb_credit_memo_lines",    _map_credit_memo_lines)
_register_entity("vendor_credits",  "VendorCredit",   "transaction", "qb_vendor_credits",  _map_vendor_credit,  "qb_vendor_credit_lines",  _map_vendor_credit_lines)
_register_entity("refund_receipts", "RefundReceipt",  "transaction", "qb_refund_receipts", _map_refund_receipt, "qb_refund_receipt_lines", _map_refund_receipt_lines)
_register_entity("deposits",        "Deposit",        "transaction", "qb_deposits",        _map_deposit,        "qb_deposit_lines",        _map_deposit_lines)
_register_entity("purchases",       "Purchase",       "transaction", "qb_purchases",       _map_purchase,       "qb_purchase_lines",       _map_purchase_lines)
_register_entity("transfers",       "Transfer",       "transaction", "qb_transfers",       _map_transfer)
_register_entity("estimates",       "Estimate",       "transaction", "qb_estimates",       _map_estimate,       "qb_estimate_lines",       _map_estimate_lines)

def _upsert(db, table, row, touch_synced=True):
    cols = list(row.keys())
    placeholders = ",".join("?" * len(cols))
    col_list = ",".join(cols)
    updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
    if touch_synced:
        updates = (updates + ",last_synced_at=CURRENT_TIMESTAMP") if updates else "last_synced_at=CURRENT_TIMESTAMP"
    conflict = f" ON CONFLICT(id) DO UPDATE SET {updates}" if updates else ""
    db.execute(f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}){conflict}",
               [row[c] for c in cols])

def _insert_line(db, table, row):
    cols = list(row.keys())
    placeholders = ",".join("?" * len(cols))
    col_list = ",".join(cols)
    db.execute(f"INSERT OR REPLACE INTO {table} ({col_list}) VALUES ({placeholders})",
               [row[c] for c in cols])

def _line_fk_column(line_table):
    # qb_invoice_lines -> invoice_id ; qb_sales_receipt_lines -> sales_receipt_id ; etc.
    base = line_table.replace("qb_", "").rsplit("_lines", 1)[0]
    return f"{base}_id"

def _get_sync_state(db, key):
    row = db.execute("SELECT * FROM qb_sync_state WHERE entity=?", (key,)).fetchone()
    return dict(row) if row else None

def _set_sync_state(db, key, **fields):
    existing = _get_sync_state(db, key)
    if existing:
        set_clause = ", ".join(f"{k}=?" for k in fields)
        db.execute(f"UPDATE qb_sync_state SET {set_clause} WHERE entity=?", list(fields.values()) + [key])
    else:
        cols = ["entity"] + list(fields.keys())
        vals = [key] + list(fields.values())
        db.execute(f"INSERT INTO qb_sync_state ({','.join(cols)}) VALUES ({','.join('?'*len(cols))})", vals)

def sync_entity(entity_key, *, force_full=False, horizon_years=QB_BACKFILL_YEARS):
    """Sync one entity from QB into local tables. Returns dict with counts/error."""
    if entity_key not in QB_ENTITIES:
        return {"error": f"Unknown entity: {entity_key}"}
    cfg = QB_ENTITIES[entity_key]
    with app.app_context():
        db = get_db()
        _set_sync_state(db, entity_key, last_status="syncing", last_run_at=datetime.utcnow().isoformat(), last_error=None)
        db.commit()
        state = _get_sync_state(db, entity_key) or {}
        clauses = []
        last_sync = state.get("last_sync_time") if not force_full else None
        if last_sync:
            clauses.append(f"Metadata.LastUpdatedTime > '{last_sync}'")
        elif cfg["kind"] == "transaction":
            horizon = (datetime.utcnow() - timedelta(days=365 * horizon_years)).date().isoformat()
            clauses.append(f"TxnDate >= '{horizon}'")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        total = 0
        max_updated = last_sync
        start = 1
        while True:
            sql = f"SELECT * FROM {cfg['qb_name']}{where} STARTPOSITION {start} MAXRESULTS {QB_PAGE_SIZE}"
            from urllib.parse import quote
            data, error = qb_get(f"/query?query={quote(sql)}")
            if error:
                _set_sync_state(db, entity_key, last_status="error", last_error=error, last_run_at=datetime.utcnow().isoformat())
                db.commit()
                return {"entity": entity_key, "error": error, "synced": total}
            batch = (data.get("QueryResponse", {}) or {}).get(cfg["qb_name"], []) or []
            for obj in batch:
                header = cfg["map_header"](obj)
                _upsert(db, cfg["header_table"], header)
                if cfg["line_table"] and cfg["map_lines"]:
                    fk = _line_fk_column(cfg["line_table"])
                    db.execute(f"DELETE FROM {cfg['line_table']} WHERE {fk}=?", (obj["Id"],))
                    for ln in cfg["map_lines"](obj):
                        _insert_line(db, cfg["line_table"], ln)
                lu = (obj.get("MetaData") or {}).get("LastUpdatedTime")
                if lu and (not max_updated or lu > max_updated):
                    max_updated = lu
                total += 1
            if len(batch) < QB_PAGE_SIZE:
                break
            start += QB_PAGE_SIZE
        count_row = db.execute(f"SELECT COUNT(*) AS c FROM {cfg['header_table']}").fetchone()
        _set_sync_state(db, entity_key,
                        last_status="idle", last_error=None,
                        last_sync_time=max_updated or state.get("last_sync_time"),
                        last_run_at=datetime.utcnow().isoformat(),
                        record_count=count_row["c"],
                        last_backfill_at=(datetime.utcnow().isoformat() if force_full else state.get("last_backfill_at")))
        db.commit()
        return {"entity": entity_key, "synced": total, "total_in_db": count_row["c"]}

def sync_all_qb(force_full=False):
    results = {}
    # Always sync reference data first so transactions can resolve FKs
    for k, cfg in QB_ENTITIES.items():
        if cfg["kind"] == "reference":
            results[k] = sync_entity(k, force_full=force_full)
    for k, cfg in QB_ENTITIES.items():
        if cfg["kind"] == "transaction":
            results[k] = sync_entity(k, force_full=force_full)
    return results

@app.route("/api/qb/sync_state", methods=["GET", "OPTIONS"])
@login_required
def qb_sync_state_api():
    if request.method == "OPTIONS":
        return "", 204
    rows = q("SELECT * FROM qb_sync_state")
    state_map = {r["entity"]: dict(r) for r in rows}
    out = []
    for key, cfg in QB_ENTITIES.items():
        s = state_map.get(key, {})
        out.append({
            "entity": key, "qb_name": cfg["qb_name"], "kind": cfg["kind"],
            "record_count": s.get("record_count", 0),
            "last_sync_time": s.get("last_sync_time"),
            "last_run_at": s.get("last_run_at"),
            "last_backfill_at": s.get("last_backfill_at"),
            "last_status": s.get("last_status", "never"),
            "last_error": s.get("last_error"),
        })
    return jsonify(out)

@app.route("/api/qb/sync/<entity>", methods=["POST", "OPTIONS"])
@admin_required
def qb_sync_entity_api(entity):
    if request.method == "OPTIONS":
        return "", 204
    if entity not in QB_ENTITIES:
        return err(f"Unknown entity. Known: {', '.join(QB_ENTITIES)}", 404)
    force = (request.json or {}).get("force_full", False) if request.is_json else False
    result = sync_entity(entity, force_full=bool(force))
    if result.get("error"):
        return jsonify(result), 502
    return jsonify(result)

@app.route("/api/qb/sync_all", methods=["POST", "OPTIONS"])
@admin_required
def qb_sync_all_api():
    if request.method == "OPTIONS":
        return "", 204
    force = (request.json or {}).get("force_full", False) if request.is_json else False
    return jsonify(sync_all_qb(force_full=bool(force)))

def scheduled_qb_sync():
    """Called by APScheduler every 15 min. Skips quietly if not connected."""
    if not get_tokens():
        return
    try:
        sync_all_qb(force_full=False)
    except Exception:
        traceback.print_exc()

# ── Flux Analysis ─────────────────────────────────────────────────────────────

@app.route("/api/flux", methods=["GET", "OPTIONS"])
@login_required
def flux_analysis():
    if request.method == "OPTIONS":
        return "", 204
    current_id = request.args.get("current_snapshot_id", type=int)
    prior_id = request.args.get("prior_snapshot_id", type=int)
    pct_threshold = float(request.args.get("pct_threshold", 10))
    dollar_threshold = float(request.args.get("dollar_threshold", 1000))
    if not current_id:
        return err("current_snapshot_id required")
    cur = q1("SELECT s.*, p.label AS period_label FROM tb_snapshots s JOIN periods p ON p.id=s.period_id WHERE s.id=?", (current_id,))
    if not cur:
        return err("Current snapshot not found", 404)
    if not prior_id:
        prior = q1("""SELECT s.*, p.label AS period_label FROM tb_snapshots s JOIN periods p ON p.id=s.period_id
                      WHERE s.snapshotted_at < ? ORDER BY s.snapshotted_at DESC LIMIT 1""", (cur["snapshotted_at"],))
        if not prior:
            return err("No prior snapshot available to compare against")
    else:
        prior = q1("SELECT s.*, p.label AS period_label FROM tb_snapshots s JOIN periods p ON p.id=s.period_id WHERE s.id=?", (prior_id,))
        if not prior:
            return err("Prior snapshot not found", 404)
    cur_rows = q("SELECT * FROM tb_snapshot_rows WHERE snapshot_id=?", (cur["id"],))
    prior_rows = q("SELECT * FROM tb_snapshot_rows WHERE snapshot_id=?", (prior["id"],))
    def key(r):
        return (r["account_number"] or "") + "|" + r["account_name"]
    prior_map = {key(r): r for r in prior_rows}
    cur_map = {key(r): r for r in cur_rows}
    all_keys = sorted(set(cur_map) | set(prior_map))
    results = []
    for k in all_keys:
        c = cur_map.get(k)
        p = prior_map.get(k)
        current_balance = c["balance"] if c else 0.0
        prior_balance = p["balance"] if p else 0.0
        delta = current_balance - prior_balance
        pct = None
        if prior_balance != 0:
            pct = round(delta / abs(prior_balance) * 100, 2)
        elif current_balance != 0:
            pct = None  # new account
        dollar_flagged = abs(delta) >= dollar_threshold
        pct_flagged = pct is not None and abs(pct) >= pct_threshold
        flagged = dollar_flagged or pct_flagged or (c is None) or (p is None)
        base = c or p
        results.append({
            "account_number": base["account_number"],
            "account_name": base["account_name"],
            "account_type": base["account_type"],
            "classification": base["classification"],
            "prior_balance": prior_balance,
            "current_balance": current_balance,
            "delta": round(delta, 2),
            "pct_change": pct,
            "flagged": flagged,
            "new_account": p is None,
            "removed_account": c is None,
        })
    results.sort(key=lambda r: (not r["flagged"], -abs(r["delta"])))
    return jsonify({
        "current": {"id": cur["id"], "label": cur["label"], "period_label": cur["period_label"], "snapshotted_at": cur["snapshotted_at"]},
        "prior": {"id": prior["id"], "label": prior["label"], "period_label": prior["period_label"], "snapshotted_at": prior["snapshotted_at"]},
        "pct_threshold": pct_threshold,
        "dollar_threshold": dollar_threshold,
        "rows": results,
        "flagged_count": sum(1 for r in results if r["flagged"]),
    })

@app.route("/api/tb_snapshots", methods=["GET", "OPTIONS"])
@login_required
def tb_snapshots_all():
    if request.method == "OPTIONS":
        return "", 204
    rows = q("""SELECT s.id, s.label, s.snapshotted_at, s.period_id, p.label AS period_label,
                       (SELECT COUNT(*) FROM tb_snapshot_rows WHERE snapshot_id=s.id) AS row_count
                FROM tb_snapshots s JOIN periods p ON p.id=s.period_id
                ORDER BY s.snapshotted_at DESC""")
    return jsonify(rows_to_list(rows))

# ── Review Queue (unified QB post queue) ──────────────────────────────────────

TARGET_PATHS = {
    "invoice": "/invoice",
    "sales_receipt": "/salesreceipt",
    "bill": "/bill",
    "payment": "/payment",
    "credit_memo": "/creditmemo",
    "bill_payment": "/billpayment",
    "vendor_credit": "/vendorcredit",
}

@app.route("/api/pending_posts", methods=["GET", "POST", "OPTIONS"])
@login_required
def pending_posts_list():
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "GET":
        status = request.args.get("status")
        source = request.args.get("source")
        clauses, params = [], []
        if status:
            clauses.append("status=?"); params.append(status)
        if source:
            clauses.append("source=?"); params.append(source)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = q(f"""SELECT p.*, u.name AS posted_by_name, u.initials AS posted_by_initials
                     FROM pending_posts p LEFT JOIN users u ON u.id=p.posted_by
                     {where} ORDER BY p.created_at DESC LIMIT 500""", params)
        return jsonify(rows_to_list(rows))
    user = get_current_user()
    if user["role"] != "admin":
        return err("Admin required", 403)
    b = request.json or {}
    required = ("source", "target_type", "payload")
    if not all(k in b for k in required):
        return err("source, target_type, payload required")
    if b["target_type"] not in TARGET_PATHS:
        return err(f"target_type must be one of: {', '.join(TARGET_PATHS)}")
    payload_str = json.dumps(b["payload"]) if isinstance(b["payload"], (dict, list)) else str(b["payload"])
    try:
        cur = run("""INSERT INTO pending_posts
                     (source,external_id,target_type,customer_vendor,amount,reference,payload,notes)
                     VALUES (?,?,?,?,?,?,?,?)""",
                  (b["source"], b.get("external_id"), b["target_type"],
                   b.get("customer_vendor"), b.get("amount"), b.get("reference"),
                   payload_str, b.get("notes", "")))
    except sqlite3.IntegrityError:
        return err("Duplicate: a pending post with this source + external_id already exists", 409)
    return jsonify({"id": cur.lastrowid}), 201

@app.route("/api/pending_posts/<int:pid>", methods=["GET", "PATCH", "DELETE", "OPTIONS"])
@login_required
def pending_post_detail(pid):
    if request.method == "OPTIONS":
        return "", 204
    row = q1("""SELECT p.*, u.name AS posted_by_name, u.initials AS posted_by_initials
                FROM pending_posts p LEFT JOIN users u ON u.id=p.posted_by WHERE p.id=?""", (pid,))
    if not row:
        return err("Pending post not found", 404)
    if request.method == "GET":
        d = dict(row)
        try:
            d["payload_obj"] = json.loads(d["payload"])
        except Exception:
            d["payload_obj"] = None
        return jsonify(d)
    user = get_current_user()
    if user["role"] != "admin":
        return err("Admin required", 403)
    if request.method == "DELETE":
        run("DELETE FROM pending_posts WHERE id=?", (pid,))
        return jsonify({"deleted": pid})
    b = request.json or {}
    allowed = {"status", "notes", "customer_vendor", "amount", "reference", "payload"}
    updates = {k: v for k, v in b.items() if k in allowed}
    if "payload" in updates and isinstance(updates["payload"], (dict, list)):
        updates["payload"] = json.dumps(updates["payload"])
    if not updates:
        return err("No valid fields")
    updates["updated_at"] = datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k}=?" for k in updates)
    run(f"UPDATE pending_posts SET {set_clause} WHERE id=?", list(updates.values()) + [pid])
    return jsonify({"updated": pid})

@app.route("/api/pending_posts/<int:pid>/post", methods=["POST", "OPTIONS"])
@admin_required
def pending_post_execute(pid):
    if request.method == "OPTIONS":
        return "", 204
    row = q1("SELECT * FROM pending_posts WHERE id=?", (pid,))
    if not row:
        return err("Pending post not found", 404)
    if row["status"] == "posted":
        return err("Already posted", 409)
    path = TARGET_PATHS.get(row["target_type"])
    if not path:
        return err(f"Unknown target_type: {row['target_type']}")
    try:
        body = json.loads(row["payload"])
    except Exception:
        return err("Stored payload is not valid JSON")
    result, error = qb_post(path, body)
    user = get_current_user()
    if error:
        run("""UPDATE pending_posts SET status='error', error_message=?, updated_at=? WHERE id=?""",
            (error, datetime.utcnow().isoformat(), pid))
        return err(error, 502)
    # Extract the new QB id — first top-level key after the primary wrapper
    qb_id = None
    if isinstance(result, dict):
        for v in result.values():
            if isinstance(v, dict) and "Id" in v:
                qb_id = v["Id"]
                break
    run("""UPDATE pending_posts SET status='posted', qb_id=?, posted_by=?, posted_at=?,
           error_message=NULL, updated_at=? WHERE id=?""",
        (qb_id, user["id"], datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), pid))
    return jsonify({"posted": pid, "qb_id": qb_id, "response": result})

@app.route("/api/pending_posts/<int:pid>/link", methods=["POST", "OPTIONS"])
@admin_required
def pending_post_link(pid):
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    qb_id = (b.get("qb_id") or "").strip()
    if not qb_id:
        return err("qb_id required")
    row = q1("SELECT 1 FROM pending_posts WHERE id=?", (pid,))
    if not row:
        return err("Pending post not found", 404)
    user = get_current_user()
    run("""UPDATE pending_posts SET status='posted', qb_id=?, posted_by=?, posted_at=?,
           error_message=NULL, updated_at=?, notes=COALESCE(notes,'')||?
           WHERE id=?""",
        (qb_id, user["id"], datetime.utcnow().isoformat(), datetime.utcnow().isoformat(),
         f"\n[linked manually to QB #{qb_id}]", pid))
    return jsonify({"linked": pid, "qb_id": qb_id})

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

if __name__ == "__main__":
    from init_db import init
    init()
    app.run(debug=True, port=5000, use_reloader=False)