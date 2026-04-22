import os, sqlite3, traceback, secrets, urllib.parse
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, jsonify, request, g, send_from_directory, session, redirect
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
import requests
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

# Patch Werkzeug Response.set_cookie to drop 'partitioned' kwarg if this build doesn't support it.
# Needed when Flask>=3.1 is paired with an older Werkzeug that lacks the partitioned parameter.
import inspect as _inspect
from werkzeug.wrappers import Response as _WResponse
if 'partitioned' not in _inspect.signature(_WResponse.set_cookie).parameters:
    _orig_set_cookie = _WResponse.set_cookie
    def _patched_set_cookie(self, *args, **kwargs):
        kwargs.pop('partitioned', None)
        return _orig_set_cookie(self, *args, **kwargs)
    _WResponse.set_cookie = _patched_set_cookie

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
QB_AUTH_URL      = "https://appcenter.intuit.com/connect/oauth2"
QB_API_BASE      = (
    "https://sandbox-quickbooks.api.intuit.com/v3/company"
    if QB_ENVIRONMENT == "sandbox"
    else "https://quickbooks.api.intuit.com/v3/company"
)

def _ensure_qb_tokens_table():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS qb_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, access_token TEXT, refresh_token TEXT, expires_at REAL, realm_id TEXT)")
    cols = {r[1] for r in db.execute("PRAGMA table_info(qb_tokens)").fetchall()}
    if "realm_id" not in cols:
        db.execute("ALTER TABLE qb_tokens ADD COLUMN realm_id TEXT")
    db.commit()

def get_tokens():
    _ensure_qb_tokens_table()
    row = q1("SELECT access_token, refresh_token, expires_at, realm_id FROM qb_tokens ORDER BY id DESC LIMIT 1")
    return dict(row) if row else {}

def save_tokens(at, rt, ei, realm_id=None):
    _ensure_qb_tokens_table()
    ea = datetime.now(timezone.utc).timestamp() + ei
    db = get_db()
    if realm_id is None:
        prev = q1("SELECT realm_id FROM qb_tokens ORDER BY id DESC LIMIT 1")
        realm_id = prev["realm_id"] if prev else None
    db.execute("INSERT INTO qb_tokens (access_token, refresh_token, expires_at, realm_id) VALUES (?,?,?,?)", (at, rt, ea, realm_id))
    db.commit()

def get_realm_id():
    tokens = get_tokens()
    return tokens.get("realm_id") or os.getenv("QB_REALM_ID", "")

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
    realm = get_realm_id()
    if not realm:
        return None, "No realm_id — reconnect to QuickBooks"
    now = datetime.now(timezone.utc).timestamp()
    token = tokens["access_token"]
    if tokens.get("expires_at", 0) < now + 60:
        token = refresh_access_token()
    if not token:
        return None, "Token refresh failed"
    resp = requests.get(
        f"{QB_API_BASE}/{realm}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    return (resp.json(), None) if resp.ok else (None, f"QB error {resp.status_code}: {resp.text[:200]}")

@app.route("/api/qb/connect")
@login_required
def qb_connect():
    state = secrets.token_urlsafe(16)
    session["qb_state"] = state
    params = {
        "client_id": QB_CLIENT_ID,
        "scope": "com.intuit.quickbooks.accounting",
        "redirect_uri": QB_REDIRECT_URI,
        "response_type": "code",
        "state": state,
    }
    return redirect(QB_AUTH_URL + "?" + urllib.parse.urlencode(params))

@app.route("/qb/callback")
def qb_callback():
    code = request.args.get("code")
    realm = request.args.get("realmId")
    state = request.args.get("state")
    if not code:
        return redirect("/?qb=error")
    if state and state != session.get("qb_state"):
        return redirect("/?qb=error")
    resp = requests.post(QB_TOKEN_URL,
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": QB_REDIRECT_URI},
        auth=(QB_CLIENT_ID, QB_CLIENT_SECRET))
    if not resp.ok:
        return redirect("/?qb=error")
    d = resp.json()
    save_tokens(d["access_token"], d["refresh_token"], d["expires_in"], realm_id=realm)
    session.pop("qb_state", None)
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

# ── QuickBooks Report Sync (P&L, Balance Sheet) ───────────────────────────────

def _ensure_report_tables():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS qb_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        period_id INTEGER NOT NULL REFERENCES periods(id),
        report_type TEXT NOT NULL,
        start_date TEXT NOT NULL,
        end_date TEXT NOT NULL,
        raw_json TEXT NOT NULL,
        pulled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(period_id, report_type)
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS qb_report_lines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        period_id INTEGER NOT NULL REFERENCES periods(id),
        report_type TEXT NOT NULL,
        section TEXT,
        account_name TEXT NOT NULL,
        amount REAL NOT NULL DEFAULT 0,
        is_subtotal INTEGER DEFAULT 0,
        depth INTEGER DEFAULT 0,
        sort_order INTEGER DEFAULT 0
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_rl_period_type ON qb_report_lines(period_id, report_type)")
    db.commit()

def _flatten_qb_rows(rows, report_type, out, section=None, depth=0):
    """Recursively walk a QB Report Rows tree and emit flat line records."""
    if not rows or not isinstance(rows, dict):
        return
    for row in rows.get("Row", []):
        rtype = row.get("type", "Data")
        if rtype == "Section":
            header = row.get("Header", {}).get("ColData", [])
            header_name = header[0].get("value", "") if header else ""
            new_section = section or header_name or None
            _flatten_qb_rows(row.get("Rows", {}), report_type, out, new_section, depth+1)
            summary = row.get("Summary", {}).get("ColData", [])
            if summary:
                name = summary[0].get("value", "")
                try:
                    amt = float(summary[-1].get("value", 0) or 0)
                except (TypeError, ValueError):
                    amt = 0.0
                out.append({
                    "section": new_section, "account_name": name, "amount": amt,
                    "is_subtotal": 1, "depth": depth, "sort_order": len(out),
                })
        else:
            cd = row.get("ColData", [])
            if not cd:
                continue
            name = cd[0].get("value", "")
            try:
                amt = float(cd[-1].get("value", 0) or 0)
            except (TypeError, ValueError):
                amt = 0.0
            out.append({
                "section": section, "account_name": name, "amount": amt,
                "is_subtotal": 0, "depth": depth, "sort_order": len(out),
            })

def sync_qb_report(period_id, report_type):
    """report_type: 'pl' | 'bs'. Pulls from QB and caches into qb_reports + qb_report_lines."""
    _ensure_report_tables()
    period = q1("SELECT id, start_date, end_date FROM periods WHERE id=?", (period_id,))
    if not period:
        return {"ok": False, "error": "Period not found"}

    if report_type == "pl":
        path = f"/reports/ProfitAndLoss?start_date={period['start_date']}&end_date={period['end_date']}&accounting_method=Accrual&minorversion=65"
    elif report_type == "bs":
        path = f"/reports/BalanceSheet?start_date={period['start_date']}&end_date={period['end_date']}&accounting_method=Accrual&minorversion=65"
    else:
        return {"ok": False, "error": "Unknown report_type"}

    data, error = qb_get(path)
    if error:
        return {"ok": False, "error": error}

    import json
    db = get_db()
    db.execute("DELETE FROM qb_report_lines WHERE period_id=? AND report_type=?", (period_id, report_type))
    db.execute("""INSERT INTO qb_reports (period_id, report_type, start_date, end_date, raw_json, pulled_at)
                  VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)
                  ON CONFLICT(period_id, report_type) DO UPDATE SET
                    start_date=excluded.start_date, end_date=excluded.end_date,
                    raw_json=excluded.raw_json, pulled_at=CURRENT_TIMESTAMP""",
               (period_id, report_type, period["start_date"], period["end_date"], json.dumps(data)))

    lines = []
    _flatten_qb_rows(data.get("Rows", {}), report_type, lines)
    for ln in lines:
        db.execute("""INSERT INTO qb_report_lines
                      (period_id, report_type, section, account_name, amount, is_subtotal, depth, sort_order)
                      VALUES (?,?,?,?,?,?,?,?)""",
                   (period_id, report_type, ln["section"], ln["account_name"], ln["amount"],
                    ln["is_subtotal"], ln["depth"], ln["sort_order"]))
    db.commit()
    return {"ok": True, "lines": len(lines)}

@app.route("/api/qb/sync_reports", methods=["POST", "OPTIONS"])
@login_required
def sync_reports_endpoint():
    if request.method == "OPTIONS":
        return "", 204
    body = request.get_json(silent=True) or {}
    period_id = body.get("period_id")
    if not period_id:
        active = q1("SELECT id FROM periods WHERE is_active=1")
        period_id = active["id"] if active else None
    if not period_id:
        return jsonify({"ok": False, "error": "No period selected and no active period"}), 400
    types = body.get("types") or ["pl", "bs"]
    results = {t: sync_qb_report(period_id, t) for t in types}
    return jsonify({"ok": all(r.get("ok") for r in results.values()), "results": results})

def _load_report_lines(period_id, report_type):
    rows = q("""SELECT section, account_name, amount, is_subtotal, depth, sort_order
                FROM qb_report_lines WHERE period_id=? AND report_type=?
                ORDER BY sort_order""", (period_id, report_type))
    return [dict(r) for r in rows]

def _prior_period_id(period_id):
    cur = q1("SELECT start_date FROM periods WHERE id=?", (period_id,))
    if not cur:
        return None
    prior = q1("SELECT id FROM periods WHERE start_date < ? ORDER BY start_date DESC LIMIT 1",
               (cur["start_date"],))
    return prior["id"] if prior else None

@app.route("/api/reports/<rtype>", methods=["GET", "OPTIONS"])
@login_required
def get_report(rtype):
    if request.method == "OPTIONS":
        return "", 204
    if rtype not in ("pl", "bs"):
        return jsonify({"error": "Unknown report type"}), 400
    _ensure_report_tables()
    period_id = request.args.get("period_id", type=int)
    if not period_id:
        active = q1("SELECT id FROM periods WHERE is_active=1")
        period_id = active["id"] if active else None
    if not period_id:
        return jsonify({"error": "No period"}), 400

    compare_id = request.args.get("compare_to", type=int)
    if compare_id is None and request.args.get("auto_compare", "1") == "1":
        compare_id = _prior_period_id(period_id)

    cur_lines = _load_report_lines(period_id, rtype)
    cmp_lines = _load_report_lines(compare_id, rtype) if compare_id else []
    cmp_by_name = {(l["section"], l["account_name"]): l["amount"] for l in cmp_lines}

    merged = []
    for l in cur_lines:
        prior_amt = cmp_by_name.get((l["section"], l["account_name"]))
        var = None if prior_amt is None else (l["amount"] - prior_amt)
        var_pct = None
        if prior_amt not in (None, 0):
            var_pct = round((l["amount"] - prior_amt) / abs(prior_amt) * 100, 2)
        merged.append({**l, "prior_amount": prior_amt, "variance": var, "variance_pct": var_pct})

    period_meta = q1("SELECT id, label, start_date, end_date FROM periods WHERE id=?", (period_id,))
    compare_meta = q1("SELECT id, label, start_date, end_date FROM periods WHERE id=?", (compare_id,)) if compare_id else None
    pulled = q1("SELECT pulled_at FROM qb_reports WHERE period_id=? AND report_type=?", (period_id, rtype))

    return jsonify({
        "report_type": rtype,
        "period": dict(period_meta) if period_meta else None,
        "compare": dict(compare_meta) if compare_meta else None,
        "pulled_at": pulled["pulled_at"] if pulled else None,
        "lines": merged,
    })

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