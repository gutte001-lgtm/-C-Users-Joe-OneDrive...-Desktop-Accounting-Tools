import os, sqlite3, traceback, io, csv, uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, jsonify, request, g, send_from_directory, session, Response
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
    row = q1("SELECT access_token, refresh_token, expires_at FROM qb_tokens ORDER BY id DESC LIMIT 1")
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

def qb_get(path):
    tokens = get_tokens()
    if not tokens:
        return None, "Not connected"
    now = datetime.now(timezone.utc).timestamp()
    token = tokens["access_token"]
    if tokens.get("expires_at", 0) < now + 60:
        token = refresh_access_token()
    if not token:
        return None, "Token refresh failed"
    resp = requests.get(
        f"{QB_API_BASE}/{QB_REALM_ID}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    return (resp.json(), None) if resp.ok else (None, f"QB error {resp.status_code}")

@app.route("/qb/callback")
def qb_callback():
    code = request.args.get("code")
    realm = request.args.get("realmId")
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
    return jsonify({"status": "connected", "realm_id": realm})

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
scheduler.add_job(sync_qb_balances, "interval", minutes=15, id="qb_sync")
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