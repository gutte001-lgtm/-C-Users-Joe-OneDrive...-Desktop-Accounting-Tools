import os, sqlite3, traceback, secrets, urllib.parse, json
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, jsonify, request, g, send_from_directory, session, redirect
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
import requests
from cryptography.fernet import Fernet, InvalidToken

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

_ENV_PATH = os.path.join(BASE_DIR, ".env")

def _persist_env(key, value):
    """Append KEY=VALUE to .env so subsequent runs reuse the same secret.
    Silent no-op on filesystem errors — the generated value still works
    for this process; next run will just generate a new one."""
    try:
        with open(_ENV_PATH, "a", encoding="utf-8") as f:
            f.write(f"\n{key}={value}\n")
        print(f"[security] generated {key} and saved to {_ENV_PATH}", flush=True)
    except OSError as e:
        print(f"[security] generated {key} in-memory (could not write {_ENV_PATH}: {e})", flush=True)

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    _persist_env("SECRET_KEY", SECRET_KEY)

# Fernet-encrypts QB access/refresh tokens at rest. Auto-generates a key on
# first run and writes it to .env. Legacy plaintext token rows are read back
# transparently by decrypt_token(), so rolling this out does not break an
# existing qb_tokens table.
_TOKEN_KEY = os.getenv("TOKEN_ENCRYPTION_KEY", "").strip()
if not _TOKEN_KEY:
    _TOKEN_KEY = Fernet.generate_key().decode()
    _persist_env("TOKEN_ENCRYPTION_KEY", _TOKEN_KEY)
_FERNET = Fernet(_TOKEN_KEY.encode())

# Cross-origin requests are denied unless the Origin matches this whitelist.
# Defaults cover the local Flask server; add more via ALLOWED_ORIGINS=a,b,c.
_DEFAULT_ORIGINS = {"http://127.0.0.1:5000", "http://localhost:5000"}
ALLOWED_ORIGINS = _DEFAULT_ORIGINS | {
    o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()
}

app = Flask(__name__, static_folder=None)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
)

@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin")
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,PATCH,DELETE,OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,X-CSRF-Token"
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

def safe_update(table, pk_col, allowed_cols, updates, pk_value):
    """UPDATE <table> SET k=? ... WHERE <pk_col>=? with every column name
    validated against a whitelist. Prevents f-string SQL injection if an
    upstream filter is ever loosened."""
    if not table.isidentifier() or not pk_col.isidentifier():
        raise ValueError("Invalid table/column identifier")
    if not updates:
        raise ValueError("No updates provided")
    invalid = set(updates) - set(allowed_cols)
    if invalid:
        raise ValueError(f"Disallowed column(s): {sorted(invalid)}")
    for k in updates:
        if not k.isidentifier():
            raise ValueError(f"Invalid column identifier: {k}")
    set_clause = ", ".join(f"{k}=?" for k in updates)
    return run(
        f"UPDATE {table} SET {set_clause} WHERE {pk_col}=?",
        list(updates.values()) + [pk_value],
    )

def encrypt_token(plain):
    if plain is None or not _FERNET:
        return plain
    return _FERNET.encrypt(plain.encode()).decode()

def decrypt_token(stored):
    if stored is None or not _FERNET:
        return stored
    try:
        return _FERNET.decrypt(stored.encode()).decode()
    except InvalidToken:
        return stored  # legacy plaintext row — leave alone

def csrf_protect(f):
    """Reject POST/PATCH/PUT/DELETE without a valid X-CSRF-Token header.
    The token is seeded by /api/auth/me and lives in the session cookie."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PATCH", "PUT", "DELETE"):
            sent = request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf_token", "")
            if not expected or not sent or not secrets.compare_digest(sent, expected):
                return jsonify({"error": "Invalid CSRF token"}), 403
        return f(*args, **kwargs)
    return decorated

# ── Auth disabled ─────────────────────────────────────────────────────────────
# Login screen intentionally removed. The app runs as the seeded admin
# (user id 1 — "Joe G.") for every request. See AGENTS.md §1 before touching.

DEFAULT_USER_ID = 1

def get_current_user():
    user = q1("SELECT * FROM users WHERE id=?", (DEFAULT_USER_ID,))
    if not user:
        user = q1("SELECT * FROM users ORDER BY id LIMIT 1")
    return user

def login_required(f):
    return f

def admin_required(f):
    return f

@app.route("/api/auth/me", methods=["GET", "OPTIONS"])
def me():
    if request.method == "OPTIONS":
        return "", 204
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
    csrf_token = session["csrf_token"]
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": True, "id": 0, "name": "Guest", "initials": "?", "role": "admin", "color": "#4f8ef7", "csrf_token": csrf_token})
    return jsonify({
        "authenticated": True,
        "id": user["id"],
        "name": user["name"],
        "initials": user["initials"],
        "role": user["role"],
        "color": user["color"],
        "csrf_token": csrf_token,
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

# OAuth state is also persisted here so the callback can validate even if the
# session cookie didn't survive the Intuit round-trip (e.g. user hit the app
# on localhost but the redirect_uri is 127.0.0.1, or Edge stripped SameSite=Lax
# on some flows). Rows expire after _QB_STATE_TTL seconds.
_QB_STATE_TTL = 900  # 15 minutes

def _ensure_qb_oauth_states_table():
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS qb_oauth_states (state TEXT PRIMARY KEY, created_at REAL)")
    db.commit()

def _save_oauth_state(state):
    _ensure_qb_oauth_states_table()
    db = get_db()
    now = datetime.now(timezone.utc).timestamp()
    db.execute("DELETE FROM qb_oauth_states WHERE created_at < ?", (now - _QB_STATE_TTL,))
    db.execute("INSERT OR REPLACE INTO qb_oauth_states (state, created_at) VALUES (?, ?)", (state, now))
    db.commit()

def _consume_oauth_state(state):
    _ensure_qb_oauth_states_table()
    db = get_db()
    now = datetime.now(timezone.utc).timestamp()
    row = db.execute("SELECT created_at FROM qb_oauth_states WHERE state=?", (state,)).fetchone()
    db.execute("DELETE FROM qb_oauth_states WHERE state=?", (state,))
    db.commit()
    if not row:
        return False
    return (now - row["created_at"]) <= _QB_STATE_TTL

def get_tokens():
    _ensure_qb_tokens_table()
    row = q1("SELECT access_token, refresh_token, expires_at, realm_id FROM qb_tokens ORDER BY id DESC LIMIT 1")
    if not row:
        return {}
    return {
        "access_token": decrypt_token(row["access_token"]),
        "refresh_token": decrypt_token(row["refresh_token"]),
        "expires_at": row["expires_at"],
        "realm_id": row["realm_id"],
    }

def save_tokens(at, rt, ei, realm_id=None):
    _ensure_qb_tokens_table()
    ea = datetime.now(timezone.utc).timestamp() + ei
    db = get_db()
    if realm_id is None:
        prev = q1("SELECT realm_id FROM qb_tokens ORDER BY id DESC LIMIT 1")
        realm_id = prev["realm_id"] if prev else None
    db.execute(
        "INSERT INTO qb_tokens (access_token, refresh_token, expires_at, realm_id) VALUES (?,?,?,?)",
        (encrypt_token(at), encrypt_token(rt), ea, realm_id),
    )
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

def _qb_error(reason):
    print(f"[qb] connect failed: {reason}", flush=True)
    return redirect("/?qb=error&reason=" + urllib.parse.quote(reason, safe=""))

@app.route("/api/qb/connect")
@login_required
def qb_connect():
    if not QB_CLIENT_ID or not QB_CLIENT_SECRET:
        return _qb_error("missing_credentials")
    state = secrets.token_urlsafe(16)
    session["qb_state"] = state
    _save_oauth_state(state)
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
    qb_err = request.args.get("error")
    if qb_err:
        return _qb_error(f"intuit_{qb_err}")
    if not code:
        return _qb_error("missing_code")
    if not state:
        return _qb_error("missing_state")
    session_state = session.get("qb_state")
    state_ok = (state == session_state) or _consume_oauth_state(state)
    if not state_ok:
        return _qb_error("state_mismatch")
    if not QB_CLIENT_ID or not QB_CLIENT_SECRET:
        return _qb_error("missing_credentials")
    try:
        resp = requests.post(QB_TOKEN_URL,
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": QB_REDIRECT_URI},
            auth=(QB_CLIENT_ID, QB_CLIENT_SECRET),
            headers={"Accept": "application/json"},
            timeout=15)
    except requests.RequestException as e:
        return _qb_error(f"network:{type(e).__name__}")
    if not resp.ok:
        print(f"[qb] token exchange {resp.status_code}: {resp.text[:300]}", flush=True)
        return _qb_error(f"token_exchange_{resp.status_code}")
    try:
        d = resp.json()
    except ValueError:
        return _qb_error("token_response_not_json")
    if not d.get("access_token") or not d.get("refresh_token"):
        return _qb_error("token_response_incomplete")
    save_tokens(d["access_token"], d["refresh_token"], d.get("expires_in", 3600), realm_id=realm)
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

@app.route("/api/qb/diagnose", methods=["GET", "OPTIONS"])
@login_required
def qb_diagnose():
    """Fetches a report straight from QuickBooks and returns the raw shape so
    we can see *why* a sync produces zero lines. Usage:
    /api/qb/diagnose?period_id=123&rtype=pl   (rtype: pl | bs | cf; default pl)
    Returns: {connected, realm_id, environment, period, url, qb_error, rows,
              row_count_top_level, row_count_flattened, sample_rows, header}.
    No side effects — does not touch qb_reports / qb_report_lines."""
    if request.method == "OPTIONS":
        return "", 204
    tokens = get_tokens()
    realm = get_realm_id()
    out = {
        "connected": bool(tokens),
        "realm_id": realm or None,
        "environment": QB_ENVIRONMENT,
    }
    if not tokens:
        out["qb_error"] = "Not connected — click Settings → Connect QuickBooks"
        return jsonify(out)
    period_id = request.args.get("period_id", type=int)
    if not period_id:
        active = q1("SELECT id FROM periods WHERE is_active=1")
        period_id = active["id"] if active else None
    if not period_id:
        out["qb_error"] = "No period_id supplied and no active period"
        return jsonify(out)
    period = q1("SELECT id, label, start_date, end_date FROM periods WHERE id=?", (period_id,))
    if not period:
        out["qb_error"] = "Period not found"
        return jsonify(out)
    out["period"] = dict(period)
    rtype = (request.args.get("rtype") or "pl").lower()
    endpoints = {"pl": "ProfitAndLoss", "bs": "BalanceSheet", "cf": "CashFlow"}
    if rtype not in endpoints:
        out["qb_error"] = f"Unknown rtype '{rtype}' (expected pl/bs/cf)"
        return jsonify(out)
    path = f"/reports/{endpoints[rtype]}?start_date={period['start_date']}&end_date={period['end_date']}&accounting_method=Accrual&minorversion=65"
    out["url"] = f"{QB_API_BASE}/{realm}{path}"
    data, err_str = qb_get(path)
    if err_str:
        out["qb_error"] = err_str
        return jsonify(out)
    out["qb_error"] = None
    out["header"] = data.get("Header")
    rows = data.get("Rows", {}) or {}
    top_rows = rows.get("Row", []) if isinstance(rows, dict) else []
    out["row_count_top_level"] = len(top_rows)
    flat = []
    _flatten_qb_rows(rows, rtype, flat)
    out["row_count_flattened"] = len(flat)
    out["sample_rows"] = [
        {"name": r.get("account_name"), "amount": r.get("amount"),
         "section": r.get("section"), "is_subtotal": r.get("is_subtotal")}
        for r in flat[:12]
    ]
    return jsonify(out)

def sync_qb_accounts(period_id):
    """Pull QB's chart of accounts, cache it, and make sure there's a
    reconciliation row for every Asset/Liability/Equity account in the given
    period. Updates qb_balance on existing rows too. Idempotent: matches
    existing rows by AcctNum → Name → falls back to creating with QB Id as
    account_number."""
    _ensure_report_tables()
    data, error = qb_get("/query?query=SELECT%20*%20FROM%20Account%20MAXRESULTS%201000")
    if error:
        return {"ok": False, "error": error}
    accounts = data.get("QueryResponse", {}).get("Account", []) or []
    db = get_db()
    for a in accounts:
        db.execute("""INSERT INTO qb_accounts (id, name, acct_num, account_type, classification, synced_at)
                      VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)
                      ON CONFLICT(id) DO UPDATE SET
                        name=excluded.name, acct_num=excluded.acct_num,
                        account_type=excluded.account_type, classification=excluded.classification,
                        synced_at=CURRENT_TIMESTAMP""",
                   (str(a.get("Id", "")), a.get("Name", ""), (a.get("AcctNum") or "").strip(),
                    a.get("AccountType", ""), a.get("Classification", "")))

    bs_accounts = [a for a in accounts if a.get("Classification") in ("Asset", "Liability", "Equity")]
    existing = q("SELECT id, account_number, account_name FROM reconciliations WHERE period_id=?", (period_id,))
    by_num  = {r["account_number"]: r["id"] for r in existing if (r["account_number"] or "").strip()}
    by_name = {r["account_name"].strip().lower(): r["id"] for r in existing if r["account_name"]}

    admin = q1("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1") \
            or q1("SELECT id FROM users ORDER BY id LIMIT 1")
    assignee_id = admin["id"] if admin else DEFAULT_USER_ID

    created = updated = 0
    for a in bs_accounts:
        acct_num = (a.get("AcctNum") or "").strip()
        name = (a.get("Name") or "").strip()
        if not name:
            continue
        try:
            bal = float(a.get("CurrentBalance") or 0)
        except (TypeError, ValueError):
            bal = 0.0
        rid = None
        if acct_num and acct_num in by_num:
            rid = by_num[acct_num]
        elif name.lower() in by_name:
            rid = by_name[name.lower()]
        if rid:
            db.execute("UPDATE reconciliations SET qb_balance=?, last_synced_at=CURRENT_TIMESTAMP WHERE id=?", (bal, rid))
            updated += 1
        else:
            db.execute("""INSERT INTO reconciliations
                          (period_id, account_number, account_name, assignee_id,
                           qb_balance, expected_balance, status, last_synced_at)
                          VALUES (?,?,?,?,?,NULL,'open',CURRENT_TIMESTAMP)""",
                       (period_id, acct_num or f"QB{a.get('Id','')}", name, assignee_id, bal))
            created += 1
    db.commit()
    return {"ok": True, "created": created, "updated": updated, "total": len(bs_accounts)}

def _ensure_period_close_columns():
    """Idempotent: add is_closed / closed_at / closed_by columns to `periods`
    if they're missing. Safe to call repeatedly."""
    db = get_db()
    cols = {r[1] for r in db.execute("PRAGMA table_info(periods)").fetchall()}
    for col, ddl in [
        ("is_closed", "ALTER TABLE periods ADD COLUMN is_closed INTEGER NOT NULL DEFAULT 0"),
        ("closed_at", "ALTER TABLE periods ADD COLUMN closed_at DATETIME"),
        ("closed_by", "ALTER TABLE periods ADD COLUMN closed_by INTEGER REFERENCES users(id)"),
    ]:
        if col not in cols:
            db.execute(ddl)
    db.commit()

def _backfill_closed_once():
    """On first-ever run (no period has been marked closed yet), mark every
    month period that ENDED BEFORE the most-recently-ended month as closed.
    Result: the earliest unclosed month is the most recently completed month.
    Joe's expected starting point — 'April 2026 today → start on March 2026'."""
    _ensure_period_close_columns()
    if q1("SELECT 1 FROM periods WHERE is_closed=1 LIMIT 1"):
        return  # user has already closed something; don't touch history
    today_iso = date.today().isoformat()
    latest_ended = q1("""SELECT end_date FROM periods
                         WHERE period_type='month' AND end_date < ?
                         ORDER BY end_date DESC LIMIT 1""", (today_iso,))
    if not latest_ended:
        return
    run("""UPDATE periods SET is_closed=1, closed_at=CURRENT_TIMESTAMP
           WHERE period_type='month' AND end_date < ?""", (latest_ended["end_date"],))

def _next_open_month():
    """The earliest month period with is_closed=0, globally. That's the close
    period the app should default to: 'whichever period has not been closed'.
    Returns a full row or None."""
    return q1("""SELECT * FROM periods
                 WHERE period_type='month' AND is_closed=0
                 ORDER BY start_date ASC LIMIT 1""")

def _activate_current_close_period():
    """Make the 'next open month' the active close period. Safe to call
    repeatedly; no-op if the active period is already the next-open-month.
    Returns the active period id (or None if no months exist)."""
    _ensure_fiscal_calendar()
    _ensure_period_close_columns()
    _backfill_closed_once()
    target = _next_open_month()
    if not target:
        active = q1("SELECT id FROM periods WHERE is_active=1")
        return active["id"] if active else None
    current = q1("SELECT id FROM periods WHERE is_active=1")
    if current and current["id"] == target["id"]:
        return target["id"]
    run("UPDATE periods SET is_active=0")
    run("UPDATE periods SET is_active=1 WHERE id=?", (target["id"],))
    return target["id"]

# Back-compat alias — older call sites still reference the old name.
_activate_current_period_if_stale = _activate_current_close_period

def sync_qb_balances():
    with app.app_context():
        period = q1("SELECT id FROM periods WHERE is_active=1")
        if not period:
            return {"ok": False, "error": "No active period"}
        return sync_qb_accounts(period["id"])

@app.route("/api/qb/sync", methods=["POST", "OPTIONS"])
@login_required
@csrf_protect
def manual_sync():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify(sync_qb_balances())

@app.route("/api/qb/bootstrap", methods=["POST", "OPTIONS"])
@login_required
@csrf_protect
def qb_bootstrap():
    """One-click 'set this up from my real QuickBooks': activate the current
    4-4-5 month, seed reconciliations from QB's chart of accounts, pull
    P&L/BS/CF for current month/quarter/year, and then sweep every
    month/quarter/year from 2024-01-01 through today so historical reporting
    and prior-period reconciliations work. Body may pass
    {history_start: 'YYYY-MM-DD'} or {skip_history: true}."""
    if request.method == "OPTIONS":
        return "", 204
    if not get_tokens():
        return jsonify({"ok": False, "error": "Not connected to QuickBooks"}), 400
    period_id = _activate_current_period_if_stale()
    if not period_id:
        return jsonify({"ok": False, "error": "Could not activate a current period"}), 500
    accounts_result = sync_qb_accounts(period_id)
    active = q1("SELECT id, parent_id, fiscal_year FROM periods WHERE id=?", (period_id,))
    targets = [active["id"]]
    if active["parent_id"]:
        targets.append(active["parent_id"])
    year_row = q1("SELECT id FROM periods WHERE period_type='year' AND fiscal_year=?",
                  (active["fiscal_year"],))
    if year_row:
        targets.append(year_row["id"])
    report_results = {}
    for pid in targets:
        for rtype in ("pl", "bs", "cf"):
            report_results[f"{pid}:{rtype}"] = sync_qb_report(pid, rtype)

    body = request.get_json(silent=True) or {}
    history = None
    if not body.get("skip_history"):
        history = sync_history_range(
            start_iso=body.get("history_start") or "2024-01-01",
            end_iso=body.get("history_end") or date.today().isoformat(),
        )

    return jsonify({
        "ok": True,
        "period_id": period_id,
        "accounts": accounts_result,
        "reports": report_results,
        "history": history,
    })

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
        account_id TEXT,
        amount REAL NOT NULL DEFAULT 0,
        is_subtotal INTEGER DEFAULT 0,
        depth INTEGER DEFAULT 0,
        sort_order INTEGER DEFAULT 0
    )""")
    cols = {r[1] for r in db.execute("PRAGMA table_info(qb_report_lines)").fetchall()}
    if "account_id" not in cols:
        db.execute("ALTER TABLE qb_report_lines ADD COLUMN account_id TEXT")
    db.execute("CREATE INDEX IF NOT EXISTS idx_rl_period_type ON qb_report_lines(period_id, report_type)")

    db.execute("""CREATE TABLE IF NOT EXISTS flux_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        period_id INTEGER NOT NULL REFERENCES periods(id),
        report_type TEXT NOT NULL,
        account_name TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        author_id INTEGER REFERENCES users(id),
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(period_id, report_type, account_name)
    )""")

    db.execute("""CREATE TABLE IF NOT EXISTS report_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        report_type TEXT NOT NULL,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS report_group_map (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL REFERENCES report_groups(id) ON DELETE CASCADE,
        account_name TEXT NOT NULL,
        UNIQUE(group_id, account_name)
    )""")

    db.execute("""CREATE TABLE IF NOT EXISTS qb_accounts (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        acct_num TEXT,
        account_type TEXT,
        classification TEXT,
        synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
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
                    "section": new_section, "account_name": name, "account_id": None, "amount": amt,
                    "is_subtotal": 1, "depth": depth, "sort_order": len(out),
                })
        else:
            cd = row.get("ColData", [])
            if not cd:
                continue
            name = cd[0].get("value", "")
            acct_id = cd[0].get("id")
            try:
                amt = float(cd[-1].get("value", 0) or 0)
            except (TypeError, ValueError):
                amt = 0.0
            out.append({
                "section": section, "account_name": name, "account_id": acct_id, "amount": amt,
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
    elif report_type == "cf":
        path = f"/reports/CashFlow?start_date={period['start_date']}&end_date={period['end_date']}&accounting_method=Accrual&minorversion=65"
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
                      (period_id, report_type, section, account_name, account_id, amount, is_subtotal, depth, sort_order)
                      VALUES (?,?,?,?,?,?,?,?,?)""",
                   (period_id, report_type, ln["section"], ln["account_name"], ln.get("account_id"),
                    ln["amount"], ln["is_subtotal"], ln["depth"], ln["sort_order"]))
    db.commit()
    return {"ok": True, "lines": len(lines)}

def sync_qb_recons_from_bs(period_id):
    """Derive reconciliation rows for `period_id` from its cached Balance
    Sheet lines. Unlike sync_qb_accounts() — which stamps TODAY'S balance
    against a period — this uses the BS as-of the period end, so historical
    periods get their real ending balances. Call sync_qb_report(period_id,'bs')
    first. Idempotent: matches existing rows by name (case-insensitive)."""
    lines = q("""SELECT account_name, account_id, amount FROM qb_report_lines
                 WHERE period_id=? AND report_type='bs' AND is_subtotal=0
                   AND account_name != ''""", (period_id,))
    if not lines:
        return {"ok": False, "error": "No BS lines cached — run sync_qb_report(period_id,'bs') first"}

    db = get_db()
    existing = q("SELECT id, account_name FROM reconciliations WHERE period_id=?", (period_id,))
    by_name = {(r["account_name"] or "").strip().lower(): r["id"] for r in existing if r["account_name"]}

    qb_acct_by_id = {r["id"]: dict(r) for r in q("SELECT id, name, acct_num FROM qb_accounts")}

    admin = q1("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1") \
            or q1("SELECT id FROM users ORDER BY id LIMIT 1")
    assignee_id = admin["id"] if admin else DEFAULT_USER_ID

    created = updated = 0
    for ln in lines:
        name = (ln["account_name"] or "").strip()
        if not name:
            continue
        try:
            amt = float(ln["amount"] or 0)
        except (TypeError, ValueError):
            amt = 0.0
        acct_num = ""
        acct_id = ln["account_id"]
        if acct_id and str(acct_id) in qb_acct_by_id:
            acct_num = (qb_acct_by_id[str(acct_id)].get("acct_num") or "").strip()
        rid = by_name.get(name.lower())
        if rid:
            db.execute("UPDATE reconciliations SET qb_balance=?, last_synced_at=CURRENT_TIMESTAMP WHERE id=?",
                       (amt, rid))
            updated += 1
        else:
            db.execute("""INSERT INTO reconciliations
                          (period_id, account_number, account_name, assignee_id,
                           qb_balance, expected_balance, status, last_synced_at)
                          VALUES (?,?,?,?,?,NULL,'open',CURRENT_TIMESTAMP)""",
                       (period_id, acct_num or f"QB{acct_id or ''}", name, assignee_id, amt))
            created += 1
    db.commit()
    return {"ok": True, "created": created, "updated": updated, "total": len(lines)}

def sync_history_range(start_iso="2024-01-01", end_iso=None, types=("pl", "bs", "cf"), derive_recons=True):
    """Sweep every 4-4-5 month / quarter / year period whose window overlaps
    [start_iso, end_iso] and sync P&L / BS / CF into the cache. If derive_recons
    is on, also upsert per-period reconciliations from the cached BS lines.
    Returns a summary dict; non-fatal QB errors are collected in 'errors'."""
    _ensure_fiscal_calendar()
    _ensure_report_tables()
    if not end_iso:
        end_iso = date.today().isoformat()
    periods = q("""SELECT id, label, period_type, start_date, end_date FROM periods
                   WHERE end_date >= ? AND start_date <= ?
                   ORDER BY period_type, start_date""", (start_iso, end_iso))
    summary = {
        "ok": True, "start_date": start_iso, "end_date": end_iso,
        "periods": len(periods), "pl": 0, "bs": 0, "cf": 0,
        "recons_created": 0, "recons_updated": 0, "errors": [],
    }
    for p in periods:
        pid = p["id"]
        bs_ok = False
        for rtype in types:
            res = sync_qb_report(pid, rtype)
            if res.get("ok"):
                summary[rtype] = summary.get(rtype, 0) + 1
                if rtype == "bs":
                    bs_ok = True
            else:
                summary["errors"].append(f"{p['label']} {rtype}: {res.get('error')}")
        if derive_recons and bs_ok:
            rec = sync_qb_recons_from_bs(pid)
            if rec.get("ok"):
                summary["recons_created"] += rec.get("created", 0)
                summary["recons_updated"] += rec.get("updated", 0)
    return summary

@app.route("/api/qb/sync_history", methods=["POST", "OPTIONS"])
@login_required
@csrf_protect
def qb_sync_history():
    """One-click historical sweep. Body: {start_date?, end_date?, types?,
    derive_recons?}. Defaults to 2024-01-01 through today, all three reports,
    and deriving recons from each period's BS."""
    if request.method == "OPTIONS":
        return "", 204
    if not get_tokens():
        return jsonify({"ok": False, "error": "Not connected to QuickBooks"}), 400
    body = request.get_json(silent=True) or {}
    start = body.get("start_date") or "2024-01-01"
    end = body.get("end_date") or date.today().isoformat()
    types = body.get("types") or ("pl", "bs", "cf")
    derive = body.get("derive_recons", True)
    return jsonify(sync_history_range(start, end, types=tuple(types), derive_recons=bool(derive)))

@app.route("/api/qb/sync_reports", methods=["POST", "OPTIONS"])
@login_required
@csrf_protect
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
    types = body.get("types") or ["pl", "bs", "cf"]
    results = {t: sync_qb_report(period_id, t) for t in types}
    recons = None
    if "bs" in types and results.get("bs", {}).get("ok") and body.get("derive_recons", True):
        recons = sync_qb_recons_from_bs(period_id)
    return jsonify({
        "ok": all(r.get("ok") for r in results.values()),
        "results": results,
        "recons": recons,
    })

def _load_report_lines(period_id, report_type):
    rows = q("""SELECT section, account_name, account_id, amount, is_subtotal, depth, sort_order
                FROM qb_report_lines WHERE period_id=? AND report_type=?
                ORDER BY sort_order""", (period_id, report_type))
    return [dict(r) for r in rows]

def _prior_period_id(period_id, mode="prev"):
    """Resolve a compare-to period id from a mode string. Supported modes:
      prev    — immediately prior period of same type (MoM / QoQ / Y-1)
      prev2   — two periods ago (same type)
      prev3   — three periods ago (same type)
      yoy     — same type + same period_number in the previous fiscal year
      yoy2    — same period_number two fiscal years ago
      ytd     — the FY `year` period of the same fiscal year (this period vs YTD)
      ytd_ly  — the FY `year` period of the prior fiscal year
    Unknown modes fall back to 'prev'."""
    cur = q1("SELECT start_date, period_type, period_number, fiscal_year FROM periods WHERE id=?", (period_id,))
    if not cur:
        return None
    ptype = cur["period_type"] or "month"
    fy = cur["fiscal_year"]

    if mode in ("yoy", "yoy2") and fy:
        back = 1 if mode == "yoy" else 2
        pn_match = "period_number IS NULL" if cur["period_number"] is None else "period_number=?"
        params = [ptype, fy - back]
        if cur["period_number"] is not None:
            params.append(cur["period_number"])
        row = q1(f"""SELECT id FROM periods
                     WHERE period_type=? AND fiscal_year=? AND {pn_match}
                     LIMIT 1""", tuple(params))
        if row:
            return row["id"]

    if mode == "ytd" and fy:
        row = q1("SELECT id FROM periods WHERE period_type='year' AND fiscal_year=? LIMIT 1", (fy,))
        if row:
            return row["id"]
    if mode == "ytd_ly" and fy:
        row = q1("SELECT id FROM periods WHERE period_type='year' AND fiscal_year=? LIMIT 1", (fy - 1,))
        if row:
            return row["id"]

    offset_map = {"prev": 1, "prev2": 2, "prev3": 3}
    offset = offset_map.get(mode, 1)
    # LIMIT 1 OFFSET N-1 picks the Nth-prior period of this type
    row = q1(f"""SELECT id FROM periods WHERE period_type=? AND start_date < ?
                 ORDER BY start_date DESC LIMIT 1 OFFSET {offset - 1}""",
             (ptype, cur["start_date"]))
    return row["id"] if row else None

def _build_report_payload(period_id, rtype, compare_id=None, view="native"):
    cur_lines = _load_report_lines(period_id, rtype)
    cmp_lines = _load_report_lines(compare_id, rtype) if compare_id else []
    cmp_by_name = {(l["section"], l["account_name"]): l["amount"] for l in cmp_lines}

    notes = {r["account_name"]: {"note": r["note"], "updated_at": r["updated_at"], "author_id": r["author_id"]}
             for r in q("""SELECT account_name, note, updated_at, author_id FROM flux_notes
                           WHERE period_id=? AND report_type=?""", (period_id, rtype))}

    merged = []
    for l in cur_lines:
        prior_amt = cmp_by_name.get((l["section"], l["account_name"]))
        var = None if prior_amt is None else (l["amount"] - prior_amt)
        var_pct = None
        if prior_amt not in (None, 0):
            var_pct = round((l["amount"] - prior_amt) / abs(prior_amt) * 100, 2)
        n = notes.get(l["account_name"], {})
        merged.append({**l, "prior_amount": prior_amt, "variance": var, "variance_pct": var_pct,
                       "flux_note": n.get("note", ""), "flux_updated_at": n.get("updated_at"),
                       "flux_author_id": n.get("author_id")})

    if view == "custom":
        merged = _regroup_lines_custom(period_id, rtype, merged, compare_id)

    return merged

def _regroup_lines_custom(period_id, rtype, lines, compare_id=None):
    """Re-group non-subtotal lines under admin-defined groups; preserve uncategorized under 'Other'."""
    groups = q("SELECT id, name, sort_order FROM report_groups WHERE report_type=? ORDER BY sort_order, name", (rtype,))
    if not groups:
        return lines
    name_to_group = {}
    for g in groups:
        for m in q("SELECT account_name FROM report_group_map WHERE group_id=?", (g["id"],)):
            name_to_group[m["account_name"]] = g["name"]

    buckets = {g["name"]: [] for g in groups}
    buckets["Other"] = []
    for l in lines:
        if l.get("is_subtotal"):
            continue
        g_name = name_to_group.get(l["account_name"], "Other")
        buckets.setdefault(g_name, []).append(l)

    out = []
    sort_order = 0
    group_order = [g["name"] for g in groups] + ["Other"]
    for gname in group_order:
        rows = buckets.get(gname, [])
        if not rows:
            continue
        for r in rows:
            out.append({**r, "section": gname, "depth": 1, "sort_order": sort_order, "is_subtotal": 0})
            sort_order += 1
        subtotal = sum(r["amount"] for r in rows)
        prior_subtotal = sum((r.get("prior_amount") or 0) for r in rows if r.get("prior_amount") is not None)
        has_prior = any(r.get("prior_amount") is not None for r in rows)
        var = (subtotal - prior_subtotal) if has_prior else None
        var_pct = None
        if has_prior and prior_subtotal != 0:
            var_pct = round((subtotal - prior_subtotal) / abs(prior_subtotal) * 100, 2)
        out.append({
            "section": gname, "account_name": f"Total {gname}", "account_id": None,
            "amount": subtotal, "is_subtotal": 1, "depth": 0, "sort_order": sort_order,
            "prior_amount": prior_subtotal if has_prior else None,
            "variance": var, "variance_pct": var_pct,
            "flux_note": "", "flux_updated_at": None, "flux_author_id": None,
        })
        sort_order += 1
    return out

@app.route("/api/reports/<rtype>", methods=["GET", "OPTIONS"])
@login_required
def get_report(rtype):
    if request.method == "OPTIONS":
        return "", 204
    if rtype not in ("pl", "bs", "cf"):
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
        compare_id = _prior_period_id(period_id, request.args.get("compare_mode", "prev"))

    view = request.args.get("view", "native")
    merged = _build_report_payload(period_id, rtype, compare_id, view)

    period_meta = q1("SELECT id, label, start_date, end_date FROM periods WHERE id=?", (period_id,))
    compare_meta = q1("SELECT id, label, start_date, end_date FROM periods WHERE id=?", (compare_id,)) if compare_id else None
    pulled = q1("SELECT pulled_at FROM qb_reports WHERE period_id=? AND report_type=?", (period_id, rtype))

    return jsonify({
        "report_type": rtype,
        "view": view,
        "period": dict(period_meta) if period_meta else None,
        "compare": dict(compare_meta) if compare_meta else None,
        "pulled_at": pulled["pulled_at"] if pulled else None,
        "lines": merged,
    })

# ── Transaction drill-down ────────────────────────────────────────────────────

@app.route("/api/qb/transactions", methods=["GET", "OPTIONS"])
@login_required
def qb_transactions():
    if request.method == "OPTIONS":
        return "", 204
    account_id = request.args.get("account_id")
    account_name = request.args.get("account_name")
    period_id = request.args.get("period_id", type=int)
    if not period_id:
        return jsonify({"error": "period_id required"}), 400
    period = q1("SELECT start_date, end_date FROM periods WHERE id=?", (period_id,))
    if not period:
        return jsonify({"error": "Period not found"}), 404

    if not account_id and account_name:
        row = q1("""SELECT account_id FROM qb_report_lines
                    WHERE period_id=? AND account_name=? AND account_id IS NOT NULL
                    LIMIT 1""", (period_id, account_name))
        if row:
            account_id = row["account_id"]

    qs = [f"start_date={period['start_date']}", f"end_date={period['end_date']}",
          "accounting_method=Accrual", "minorversion=65"]
    if account_id:
        qs.append(f"account={account_id}")
    data, error = qb_get("/reports/TransactionList?" + "&".join(qs))
    if error:
        return jsonify({"error": error}), 502

    cols = data.get("Columns", {}).get("Column", [])
    col_titles = [c.get("ColTitle", "") for c in cols]
    flat = []
    def _walk(rows):
        if not isinstance(rows, dict):
            return
        for row in rows.get("Row", []):
            if row.get("type") == "Section":
                _walk(row.get("Rows", {}))
            else:
                cd = row.get("ColData", [])
                flat.append({col_titles[i] if i < len(col_titles) else f"col{i}": (cd[i].get("value") if i < len(cd) else "")
                             for i in range(max(len(cd), len(col_titles)))})
    _walk(data.get("Rows", {}))

    return jsonify({
        "account_id": account_id,
        "account_name": account_name,
        "period_id": period_id,
        "columns": col_titles,
        "transactions": flat,
    })

# ── Flux Notes ────────────────────────────────────────────────────────────────

@app.route("/api/flux_notes", methods=["GET", "POST", "OPTIONS"])
@login_required
@csrf_protect
def flux_notes():
    if request.method == "OPTIONS":
        return "", 204
    _ensure_report_tables()
    if request.method == "GET":
        period_id = request.args.get("period_id", type=int)
        rtype = request.args.get("report_type")
        if not period_id or not rtype:
            return jsonify({"error": "period_id and report_type required"}), 400
        rows = q("""SELECT id, account_name, note, author_id, updated_at FROM flux_notes
                    WHERE period_id=? AND report_type=?""", (period_id, rtype))
        return jsonify([dict(r) for r in rows])

    body = request.get_json(silent=True) or {}
    period_id = body.get("period_id")
    rtype = body.get("report_type")
    account_name = body.get("account_name")
    note = (body.get("note") or "").strip()
    if not (period_id and rtype and account_name):
        return jsonify({"error": "period_id, report_type, account_name required"}), 400
    user = get_current_user()
    uid = user["id"] if user else DEFAULT_USER_ID
    if not note:
        run("DELETE FROM flux_notes WHERE period_id=? AND report_type=? AND account_name=?",
            (period_id, rtype, account_name))
        return jsonify({"ok": True, "deleted": True})
    run("""INSERT INTO flux_notes (period_id, report_type, account_name, note, author_id, updated_at)
           VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)
           ON CONFLICT(period_id, report_type, account_name) DO UPDATE SET
             note=excluded.note, author_id=excluded.author_id, updated_at=CURRENT_TIMESTAMP""",
        (period_id, rtype, account_name, note, uid))
    return jsonify({"ok": True})

# ── Report Groups (custom P&L / BS grouping) ──────────────────────────────────

@app.route("/api/report_groups", methods=["GET", "POST", "OPTIONS"])
@login_required
@csrf_protect
def report_groups():
    if request.method == "OPTIONS":
        return "", 204
    _ensure_report_tables()
    if request.method == "GET":
        rtype = request.args.get("report_type")
        sql = "SELECT id, name, report_type, sort_order FROM report_groups"
        params = ()
        if rtype:
            sql += " WHERE report_type=?"
            params = (rtype,)
        sql += " ORDER BY report_type, sort_order, name"
        groups = [dict(r) for r in q(sql, params)]
        for g in groups:
            g["accounts"] = [r["account_name"] for r in q(
                "SELECT account_name FROM report_group_map WHERE group_id=? ORDER BY account_name", (g["id"],))]
        return jsonify(groups)

    u = get_current_user()
    if not u or u["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    rtype = body.get("report_type")
    if not name or rtype not in ("pl", "bs", "cf"):
        return jsonify({"error": "name and valid report_type required"}), 400
    cur = run("INSERT INTO report_groups (name, report_type, sort_order) VALUES (?,?,?)",
              (name, rtype, int(body.get("sort_order") or 0)))
    return jsonify({"id": cur.lastrowid, "name": name, "report_type": rtype})

@app.route("/api/report_groups/<int:gid>", methods=["PATCH", "DELETE", "OPTIONS"])
@login_required
@csrf_protect
def report_group_detail(gid):
    if request.method == "OPTIONS":
        return "", 204
    u = get_current_user()
    if not u or u["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403
    _ensure_report_tables()
    if request.method == "DELETE":
        run("DELETE FROM report_group_map WHERE group_id=?", (gid,))
        run("DELETE FROM report_groups WHERE id=?", (gid,))
        return jsonify({"ok": True})
    body = request.get_json(silent=True) or {}
    if "name" in body:
        run("UPDATE report_groups SET name=? WHERE id=?", (body["name"], gid))
    if "sort_order" in body:
        run("UPDATE report_groups SET sort_order=? WHERE id=?", (int(body["sort_order"]), gid))
    if "accounts" in body:
        run("DELETE FROM report_group_map WHERE group_id=?", (gid,))
        for acct in body["accounts"]:
            run("INSERT OR IGNORE INTO report_group_map (group_id, account_name) VALUES (?,?)", (gid, acct))
    return jsonify({"ok": True})

# ── KPI Dashboard ─────────────────────────────────────────────────────────────

def _find_line(lines, *needles):
    needles = [n.lower() for n in needles]
    for l in lines:
        nm = (l.get("account_name") or "").lower().strip()
        if any(n == nm or nm.endswith(n) or nm.startswith(n) for n in needles):
            return l["amount"]
    return None

@app.route("/api/reports/kpis", methods=["GET", "OPTIONS"])
@login_required
def report_kpis():
    if request.method == "OPTIONS":
        return "", 204
    _ensure_report_tables()
    period_id = request.args.get("period_id", type=int)
    if not period_id:
        active = q1("SELECT id FROM periods WHERE is_active=1")
        period_id = active["id"] if active else None
    if not period_id:
        return jsonify({"error": "No period"}), 400

    pl = _load_report_lines(period_id, "pl")
    bs = _load_report_lines(period_id, "bs")

    revenue = _find_line(pl, "total income", "total revenue")
    cogs = _find_line(pl, "total cost of goods sold", "total cogs")
    gross = _find_line(pl, "gross profit")
    opex = _find_line(pl, "total expenses", "total operating expenses")
    net_income = _find_line(pl, "net income")

    total_assets = _find_line(bs, "total assets")
    current_assets = _find_line(bs, "total current assets")
    current_liab = _find_line(bs, "total current liabilities")
    total_liab = _find_line(bs, "total liabilities")
    equity = _find_line(bs, "total equity", "total stockholders' equity")
    cash = _find_line(bs, "total bank accounts", "total cash and cash equivalents")
    inventory = _find_line(bs, "total other current assets", "total inventory")

    def div(a, b):
        return round(a / b, 4) if (a is not None and b not in (None, 0)) else None

    kpis = {
        "revenue": revenue,
        "cogs": cogs,
        "gross_profit": gross,
        "operating_expenses": opex,
        "net_income": net_income,
        "gross_margin_pct": round(div(gross, revenue) * 100, 2) if div(gross, revenue) is not None else None,
        "operating_margin_pct": round(div((gross or 0) - (opex or 0), revenue) * 100, 2) if revenue else None,
        "net_margin_pct": round(div(net_income, revenue) * 100, 2) if div(net_income, revenue) is not None else None,
        "total_assets": total_assets,
        "total_liabilities": total_liab,
        "total_equity": equity,
        "cash": cash,
        "current_ratio": div(current_assets, current_liab),
        "quick_ratio": div((current_assets or 0) - (inventory or 0), current_liab) if current_liab else None,
        "debt_to_equity": div(total_liab, equity),
        "working_capital": (current_assets - current_liab) if (current_assets is not None and current_liab is not None) else None,
    }
    return jsonify({"period_id": period_id, "kpis": kpis})

# ── Report Export ─────────────────────────────────────────────────────────────

@app.route("/api/reports/<rtype>/export", methods=["GET"])
@login_required
def export_report(rtype):
    if rtype not in ("pl", "bs", "cf"):
        return "Unknown report type", 400
    _ensure_report_tables()
    period_id = request.args.get("period_id", type=int)
    if not period_id:
        active = q1("SELECT id FROM periods WHERE is_active=1")
        period_id = active["id"] if active else None
    if not period_id:
        return "No period", 400
    compare_id = request.args.get("compare_to", type=int)
    if compare_id is None and request.args.get("auto_compare", "1") == "1":
        compare_id = _prior_period_id(period_id, request.args.get("compare_mode", "prev"))
    view = request.args.get("view", "native")
    fmt = (request.args.get("format") or "xlsx").lower()

    lines = _build_report_payload(period_id, rtype, compare_id, view)
    period = q1("SELECT label FROM periods WHERE id=?", (period_id,))
    compare = q1("SELECT label FROM periods WHERE id=?", (compare_id,)) if compare_id else None
    title = {"pl": "Profit & Loss", "bs": "Balance Sheet", "cf": "Cash Flow"}[rtype]
    headers = ["Account", f"{period['label'] if period else 'Current'}"]
    if compare:
        headers += [compare["label"], "Variance $", "Variance %"]
    headers.append("Flux Note")

    def row_for(l):
        r = [("  " * (l.get("depth") or 0)) + (l.get("account_name") or ""), l.get("amount")]
        if compare:
            r += [l.get("prior_amount"), l.get("variance"), l.get("variance_pct")]
        r.append(l.get("flux_note") or "")
        return r

    if fmt == "csv":
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([title, period["label"] if period else ""])
        w.writerow([])
        w.writerow(headers)
        for l in lines:
            w.writerow(row_for(l))
        from flask import Response
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{rtype}_{period_id}.csv"'})

    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    except ImportError:
        return "openpyxl not installed — run: pip install openpyxl  (or use ?format=csv)", 500

    wb = Workbook()
    ws = wb.active
    ws.title = title[:31]
    bold = Font(bold=True)
    hdr_fill = PatternFill("solid", fgColor="1E2D3D")
    hdr_font = Font(bold=True, color="E2E8F0")
    sub_fill = PatternFill("solid", fgColor="F1F5F9")
    right = Alignment(horizontal="right")
    thin = Side(border_style="thin", color="CBD5E1")

    ws.cell(1, 1, title).font = Font(bold=True, size=14)
    ws.cell(2, 1, f"Period: {period['label'] if period else ''}").font = Font(italic=True, color="64748B")
    if compare:
        ws.cell(2, 2, f"Compare: {compare['label']}").font = Font(italic=True, color="64748B")

    for i, h in enumerate(headers, 1):
        c = ws.cell(4, i, h)
        c.font = hdr_font
        c.fill = hdr_fill
        c.alignment = right if i > 1 else Alignment(horizontal="left")
        c.border = Border(bottom=thin)

    for ri, l in enumerate(lines, 5):
        row = row_for(l)
        for ci, val in enumerate(row, 1):
            c = ws.cell(ri, ci, val)
            if ci > 1 and ci < len(row):
                c.number_format = '#,##0.00;[Red](#,##0.00)' if ci != len(row)-1 or not compare else '0.00"%"'
                c.alignment = right
            if l.get("is_subtotal"):
                c.font = bold
                c.fill = sub_fill
        if compare and l.get("variance_pct") is not None:
            ws.cell(ri, len(headers)-1).number_format = '0.00"%"'

    ws.column_dimensions['A'].width = 42
    for col_letter in "BCDEF":
        ws.column_dimensions[col_letter].width = 18
    ws.column_dimensions['G' if compare else 'C'].width = 60

    import io
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    from flask import Response
    return Response(buf.read(),
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{rtype}_{period_id}.xlsx"'})

# ── Fiscal Calendar (4-4-5) ───────────────────────────────────────────────────

from datetime import date, timedelta

_MONTH_NAMES = ["January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"]

def _iso_week1_monday(year):
    """Monday of ISO week 1 for given year (the week containing Jan 4)."""
    jan4 = date(year, 1, 4)
    return jan4 - timedelta(days=jan4.weekday())

def _generate_445_year(year):
    """Yields (period_type, period_number, label, start, end) for one 4-4-5 fiscal year."""
    w1_mon = _iso_week1_monday(year)
    pattern = [4, 4, 5, 4, 4, 5, 4, 4, 5, 4, 4, 5]
    out, month_ranges, week_idx = [], [], 0
    for i, weeks in enumerate(pattern):
        start = w1_mon + timedelta(days=week_idx * 7)
        end = start + timedelta(days=weeks * 7 - 1)
        mnum = i + 1
        if year == 2023 and mnum == 1:
            start = date(2023, 1, 1)
        month_ranges.append((start, end))
        out.append(("month", mnum, f"{_MONTH_NAMES[i]} {year}", start, end))
        week_idx += weeks
    for q in range(4):
        qstart = month_ranges[q * 3][0]
        qend = month_ranges[q * 3 + 2][1]
        out.append(("quarter", q + 1, f"Q{q+1} {year}", qstart, qend))
    out.append(("year", None, f"FY {year}", month_ranges[0][0], month_ranges[11][1]))
    return out

def _generate_gregorian_year(year):
    """Yields standard-calendar periods for one year (used pre-2023)."""
    out, month_ranges = [], []
    for m in range(1, 13):
        start = date(year, m, 1)
        end = (date(year, m + 1, 1) - timedelta(days=1)) if m < 12 else date(year, 12, 31)
        month_ranges.append((start, end))
        out.append(("month", m, f"{_MONTH_NAMES[m-1]} {year}", start, end))
    for q in range(4):
        out.append(("quarter", q + 1, f"Q{q+1} {year}",
                    month_ranges[q * 3][0], month_ranges[q * 3 + 2][1]))
    out.append(("year", None, f"FY {year}", date(year, 1, 1), date(year, 12, 31)))
    return out

def _ensure_fiscal_calendar():
    """Idempotent: adds fiscal columns to periods, seeds 2022-2030 hierarchy."""
    db = get_db()
    cols = {r[1] for r in db.execute("PRAGMA table_info(periods)").fetchall()}
    for col, ddl in [
        ("period_type", "ALTER TABLE periods ADD COLUMN period_type TEXT DEFAULT 'month'"),
        ("fiscal_year", "ALTER TABLE periods ADD COLUMN fiscal_year INTEGER"),
        ("period_number", "ALTER TABLE periods ADD COLUMN period_number INTEGER"),
        ("parent_id", "ALTER TABLE periods ADD COLUMN parent_id INTEGER"),
        ("calendar_type", "ALTER TABLE periods ADD COLUMN calendar_type TEXT DEFAULT 'gregorian'"),
    ]:
        if col not in cols:
            db.execute(ddl)
    db.commit()

    have_q = q1("SELECT COUNT(*) c FROM periods WHERE period_type='quarter'")
    if have_q and have_q["c"] > 0:
        return  # already seeded

    for year in range(2022, 2031):
        cal_type = "gregorian" if year < 2023 else "4-4-5"
        gen = _generate_gregorian_year if year < 2023 else _generate_445_year
        periods_for_year = gen(year)

        year_p = next(p for p in periods_for_year if p[0] == "year")
        quarter_ps = [p for p in periods_for_year if p[0] == "quarter"]
        month_ps = [p for p in periods_for_year if p[0] == "month"]

        cur = db.execute("""INSERT INTO periods
            (label, start_date, end_date, is_active, period_type, fiscal_year,
             period_number, parent_id, calendar_type)
            VALUES (?,?,?,0,?,?,?,?,?)""",
            (year_p[2], year_p[3].isoformat(), year_p[4].isoformat(),
             "year", year, None, None, cal_type))
        year_id = cur.lastrowid

        quarter_ids = {}
        for qp in quarter_ps:
            cur = db.execute("""INSERT INTO periods
                (label, start_date, end_date, is_active, period_type, fiscal_year,
                 period_number, parent_id, calendar_type)
                VALUES (?,?,?,0,?,?,?,?,?)""",
                (qp[2], qp[3].isoformat(), qp[4].isoformat(),
                 "quarter", year, qp[1], year_id, cal_type))
            quarter_ids[qp[1]] = cur.lastrowid

        for mp in month_ps:
            mnum = mp[1]
            qnum = (mnum - 1) // 3 + 1
            parent_q_id = quarter_ids[qnum]
            existing = q1("SELECT id FROM periods WHERE label=? AND period_type='month'", (mp[2],))
            if existing:
                db.execute("""UPDATE periods SET start_date=?, end_date=?,
                              period_type='month', fiscal_year=?, period_number=?,
                              parent_id=?, calendar_type=? WHERE id=?""",
                           (mp[3].isoformat(), mp[4].isoformat(), year, mnum,
                            parent_q_id, cal_type, existing["id"]))
            else:
                db.execute("""INSERT INTO periods
                    (label, start_date, end_date, is_active, period_type, fiscal_year,
                     period_number, parent_id, calendar_type)
                    VALUES (?,?,?,0,?,?,?,?,?)""",
                    (mp[2], mp[3].isoformat(), mp[4].isoformat(),
                     "month", year, mnum, parent_q_id, cal_type))
    db.commit()

# ── Auto-sync all reports every 15 min ────────────────────────────────────────

def sync_qb_all_reports():
    """Background: refresh P&L / BS / CF for active month, its quarter, and its year."""
    with app.app_context():
        if not get_tokens():
            return
        _ensure_fiscal_calendar()
        active = q1("SELECT id, parent_id, fiscal_year FROM periods WHERE is_active=1 AND period_type='month'")
        if not active:
            return
        targets = [active["id"]]
        if active["parent_id"]:
            targets.append(active["parent_id"])
        year_row = q1("SELECT id FROM periods WHERE period_type='year' AND fiscal_year=?",
                      (active["fiscal_year"],))
        if year_row:
            targets.append(year_row["id"])
        for pid in targets:
            for rtype in ("pl", "bs", "cf"):
                try:
                    sync_qb_report(pid, rtype)
                except Exception:
                    pass

@app.route("/api/calendar/reseed", methods=["POST", "OPTIONS"])
@login_required
@csrf_protect
def reseed_calendar():
    if request.method == "OPTIONS":
        return "", 204
    u = get_current_user()
    if not u or u["role"] != "admin":
        return jsonify({"error": "Admin only"}), 403
    _ensure_fiscal_calendar()
    return jsonify({"ok": True})

# ── Jira ──────────────────────────────────────────────────────────────────────
# Jira Cloud auth: HTTP Basic with (email, API token). Token is Fernet-encrypted
# at rest via encrypt_token() / decrypt_token(). Config is a single row
# (id=1). Issues are cached into jira_issues so downstream features (e.g.
# tagging recons by Jira epic) can JOIN without a round-trip to Atlassian.
# Uses /rest/api/3/search/jql (POST) — the classic GET /search was removed
# by Atlassian in 2025.

JIRA_SEARCH_ENDPOINT = "/rest/api/3/search/jql"
JIRA_MYSELF_ENDPOINT = "/rest/api/3/myself"
JIRA_DEFAULT_FIELDS = [
    "summary", "status", "issuetype", "priority", "assignee", "reporter",
    "project", "parent", "labels", "created", "updated", "resolutiondate", "duedate",
]
JIRA_SYNC_MAX_PAGES = 50   # safety cap: 50 * 100 = 5000 issues per sync

def _ensure_jira_tables():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS jira_config (
        id          INTEGER PRIMARY KEY CHECK (id = 1),
        base_url    TEXT NOT NULL,
        email       TEXT NOT NULL,
        api_token   TEXT NOT NULL,
        default_jql TEXT DEFAULT '',
        updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS jira_issues (
        issue_key       TEXT PRIMARY KEY,
        summary         TEXT,
        status          TEXT,
        status_category TEXT,
        issue_type      TEXT,
        priority        TEXT,
        assignee        TEXT,
        reporter        TEXT,
        project_key     TEXT,
        project_name    TEXT,
        parent_key      TEXT,
        labels          TEXT,
        jira_created    TEXT,
        jira_updated    TEXT,
        resolved_at     TEXT,
        due_date        TEXT,
        synced_at       DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_jira_issues_status  ON jira_issues(status)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_jira_issues_project ON jira_issues(project_key)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_jira_issues_updated ON jira_issues(jira_updated)")
    db.commit()

def get_jira_config():
    _ensure_jira_tables()
    row = q1("SELECT base_url, email, api_token, default_jql FROM jira_config WHERE id=1")
    if not row:
        return None
    return {
        "base_url":    row["base_url"].rstrip("/"),
        "email":       row["email"],
        "api_token":   decrypt_token(row["api_token"]),
        "default_jql": row["default_jql"] or "",
    }

def save_jira_config(base_url, email, api_token, default_jql=""):
    _ensure_jira_tables()
    db = get_db()
    db.execute("""INSERT INTO jira_config (id, base_url, email, api_token, default_jql, updated_at)
                  VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                  ON CONFLICT(id) DO UPDATE SET
                      base_url=excluded.base_url, email=excluded.email,
                      api_token=excluded.api_token, default_jql=excluded.default_jql,
                      updated_at=CURRENT_TIMESTAMP""",
               (base_url.rstrip("/"), email, encrypt_token(api_token), default_jql or ""))
    db.commit()

def jira_request(method, path, cfg=None, **kwargs):
    """Call Jira REST with basic-auth. Returns (json_or_none, error_str_or_none)."""
    cfg = cfg or get_jira_config()
    if not cfg:
        return None, "Not connected"
    url = f"{cfg['base_url']}{path}"
    try:
        r = requests.request(
            method, url,
            auth=(cfg["email"], cfg["api_token"]),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=30, **kwargs,
        )
    except requests.RequestException as e:
        return None, f"Network error: {e}"
    if r.status_code in (401, 403):
        return None, f"Jira auth failed (HTTP {r.status_code}). Check email and API token."
    if r.status_code == 404:
        return None, f"Jira 404 — endpoint not found. Check base URL: {cfg['base_url']}"
    if not r.ok:
        return None, f"Jira HTTP {r.status_code}: {r.text[:300]}"
    try:
        return r.json(), None
    except ValueError:
        return None, "Jira returned non-JSON response"

def _flatten_jira_issue(issue):
    f = issue.get("fields") or {}
    def dn(v): return (v or {}).get("displayName") if isinstance(v, dict) else None
    return {
        "issue_key":       issue.get("key"),
        "summary":         f.get("summary"),
        "status":          (f.get("status") or {}).get("name"),
        "status_category": ((f.get("status") or {}).get("statusCategory") or {}).get("name"),
        "issue_type":      (f.get("issuetype") or {}).get("name"),
        "priority":        (f.get("priority") or {}).get("name"),
        "assignee":        dn(f.get("assignee")),
        "reporter":        dn(f.get("reporter")),
        "project_key":     (f.get("project") or {}).get("key"),
        "project_name":    (f.get("project") or {}).get("name"),
        "parent_key":      (f.get("parent") or {}).get("key"),
        "labels":          json.dumps(f.get("labels") or []),
        "jira_created":    f.get("created"),
        "jira_updated":    f.get("updated"),
        "resolved_at":     f.get("resolutiondate"),
        "due_date":        f.get("duedate"),
    }

def sync_jira_issues(jql=None):
    cfg = get_jira_config()
    if not cfg:
        return {"ok": False, "error": "Not connected"}
    _ensure_jira_tables()
    effective_jql = (jql or cfg.get("default_jql") or "").strip() or "updated >= -90d ORDER BY updated DESC"
    payload = {"jql": effective_jql, "fields": JIRA_DEFAULT_FIELDS, "maxResults": 100}
    pulled = 0
    pages = 0
    db = get_db()
    while pages < JIRA_SYNC_MAX_PAGES:
        data, error = jira_request("POST", JIRA_SEARCH_ENDPOINT, cfg=cfg, json=payload)
        if error:
            return {"ok": False, "error": error, "pulled": pulled, "jql": effective_jql}
        for raw in (data.get("issues") or []):
            it = _flatten_jira_issue(raw)
            db.execute("""INSERT INTO jira_issues
                (issue_key, summary, status, status_category, issue_type, priority,
                 assignee, reporter, project_key, project_name, parent_key, labels,
                 jira_created, jira_updated, resolved_at, due_date, synced_at)
                VALUES (:issue_key, :summary, :status, :status_category, :issue_type, :priority,
                        :assignee, :reporter, :project_key, :project_name, :parent_key, :labels,
                        :jira_created, :jira_updated, :resolved_at, :due_date, CURRENT_TIMESTAMP)
                ON CONFLICT(issue_key) DO UPDATE SET
                    summary=excluded.summary, status=excluded.status, status_category=excluded.status_category,
                    issue_type=excluded.issue_type, priority=excluded.priority,
                    assignee=excluded.assignee, reporter=excluded.reporter,
                    project_key=excluded.project_key, project_name=excluded.project_name,
                    parent_key=excluded.parent_key, labels=excluded.labels,
                    jira_created=excluded.jira_created, jira_updated=excluded.jira_updated,
                    resolved_at=excluded.resolved_at, due_date=excluded.due_date,
                    synced_at=CURRENT_TIMESTAMP""", it)
            pulled += 1
        db.commit()
        pages += 1
        if data.get("isLast") or not data.get("nextPageToken"):
            break
        payload["nextPageToken"] = data["nextPageToken"]
    return {"ok": True, "pulled": pulled, "pages": pages, "jql": effective_jql}

@app.route("/api/jira/status", methods=["GET", "OPTIONS"])
@login_required
def jira_status():
    if request.method == "OPTIONS":
        return "", 204
    cfg = get_jira_config()
    if not cfg:
        return jsonify({"connected": False})
    stats = q1("SELECT COUNT(*) AS n, MAX(synced_at) AS last FROM jira_issues")
    return jsonify({
        "connected":      True,
        "base_url":       cfg["base_url"],
        "email":          cfg["email"],
        "default_jql":    cfg["default_jql"],
        "issue_count":    stats["n"] if stats else 0,
        "last_synced_at": stats["last"] if stats else None,
    })

@app.route("/api/jira/connect", methods=["POST", "OPTIONS"])
@admin_required
@csrf_protect
def jira_connect():
    """Validate credentials against Jira /myself before persisting. Body:
    {base_url, email, api_token, default_jql?}."""
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    base_url    = (b.get("base_url") or "").strip()
    email       = (b.get("email") or "").strip()
    api_token   = (b.get("api_token") or "").strip()
    default_jql = (b.get("default_jql") or "").strip()
    if not (base_url and email and api_token):
        return err("base_url, email, api_token are required")
    if not base_url.startswith(("http://", "https://")):
        return err("base_url must start with http:// or https://")
    probe = {"base_url": base_url.rstrip("/"), "email": email, "api_token": api_token, "default_jql": default_jql}
    data, error = jira_request("GET", JIRA_MYSELF_ENDPOINT, cfg=probe)
    if error:
        return jsonify({"ok": False, "error": error}), 400
    save_jira_config(base_url, email, api_token, default_jql)
    return jsonify({
        "ok":           True,
        "account_id":   data.get("accountId"),
        "display_name": data.get("displayName"),
        "email":        data.get("emailAddress"),
    })

@app.route("/api/jira/disconnect", methods=["POST", "OPTIONS"])
@admin_required
@csrf_protect
def jira_disconnect():
    if request.method == "OPTIONS":
        return "", 204
    _ensure_jira_tables()
    run("DELETE FROM jira_config WHERE id=1")
    return jsonify({"ok": True})

@app.route("/api/jira/sync", methods=["POST", "OPTIONS"])
@login_required
@csrf_protect
def jira_sync():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    jql = (b.get("jql") or "").strip() or None
    res = sync_jira_issues(jql=jql)
    return jsonify(res), (200 if res.get("ok") else 400)

@app.route("/api/jira/issues", methods=["GET", "OPTIONS"])
@login_required
def jira_issues_list():
    if request.method == "OPTIONS":
        return "", 204
    _ensure_jira_tables()
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
    except ValueError:
        limit = 200
    project = request.args.get("project")
    status  = request.args.get("status")
    sql = "SELECT * FROM jira_issues"
    conds, params = [], []
    if project:
        conds.append("project_key = ?"); params.append(project)
    if status:
        conds.append("status = ?");      params.append(status)
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY jira_updated DESC LIMIT ?"
    params.append(limit)
    return jsonify(rows_to_list(q(sql, params)))

scheduler = BackgroundScheduler()
scheduler.add_job(sync_qb_balances, "interval", minutes=15, id="qb_sync")
scheduler.add_job(sync_qb_all_reports, "interval", minutes=15, id="qb_reports_sync")
scheduler.start()

# Ensure the base schema + seed data exist before the fiscal-calendar migration
# runs. init_db.init() is idempotent.
try:
    from init_db import init as _init_db
    _init_db()
    with app.app_context():
        _ensure_fiscal_calendar()
        _ensure_period_close_columns()
        _backfill_closed_once()
        _activate_current_close_period()
except Exception:
    traceback.print_exc()

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

@app.route("/api/periods", methods=["POST", "OPTIONS"])
@admin_required
@csrf_protect
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
@csrf_protect
def activate_period(pid):
    if request.method == "OPTIONS":
        return "", 204
    run("UPDATE periods SET is_active=0")
    run("UPDATE periods SET is_active=1 WHERE id=?", (pid,))
    return jsonify({"activated": pid})

@app.route("/api/periods/<int:pid>/close", methods=["POST", "OPTIONS"])
@admin_required
@csrf_protect
def close_period(pid):
    """Mark a period as closed and auto-advance `is_active` to the next
    unclosed month. Response includes the newly-active period so the
    frontend can jump to it without a second round-trip."""
    if request.method == "OPTIONS":
        return "", 204
    _ensure_period_close_columns()
    row = q1("SELECT id, label FROM periods WHERE id=?", (pid,))
    if not row:
        return err("Period not found", 404)
    u = get_current_user()
    uid = u["id"] if u else None
    run("UPDATE periods SET is_closed=1, closed_at=CURRENT_TIMESTAMP, closed_by=? WHERE id=?", (uid, pid))
    new_active_id = _activate_current_close_period()
    new_active = q1("SELECT * FROM periods WHERE id=?", (new_active_id,)) if new_active_id else None
    return jsonify({
        "closed": pid,
        "closed_label": row["label"],
        "active": dict(new_active) if new_active else None,
    })

@app.route("/api/periods/<int:pid>/reopen", methods=["POST", "OPTIONS"])
@admin_required
@csrf_protect
def reopen_period(pid):
    """Undo a close. If the reopened period is earlier than the currently
    active one, it becomes active again (it's now the earliest unclosed)."""
    if request.method == "OPTIONS":
        return "", 204
    _ensure_period_close_columns()
    row = q1("SELECT id, label FROM periods WHERE id=?", (pid,))
    if not row:
        return err("Period not found", 404)
    run("UPDATE periods SET is_closed=0, closed_at=NULL, closed_by=NULL WHERE id=?", (pid,))
    new_active_id = _activate_current_close_period()
    new_active = q1("SELECT * FROM periods WHERE id=?", (new_active_id,)) if new_active_id else None
    return jsonify({
        "reopened": pid,
        "reopened_label": row["label"],
        "active": dict(new_active) if new_active else None,
    })

# ── Users ─────────────────────────────────────────────────────────────────────

@app.route("/api/users", methods=["GET", "OPTIONS"])
@login_required
def get_users():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify(rows_to_list(q("SELECT id,name,initials,email,role,color FROM users")))

@app.route("/api/users", methods=["POST", "OPTIONS"])
@admin_required
@csrf_protect
def create_user():
    if request.method == "OPTIONS":
        return "", 204
    b = request.json or {}
    if not all(k in b for k in ("name", "initials", "role", "color")):
        return err("name, initials, role, color required")
    cur = run(
        "INSERT INTO users (name,initials,email,role,color) VALUES (?,?,?,?,?)",
        (b["name"], b["initials"], b.get("email", ""), b["role"], b["color"]))
    return jsonify({"id": cur.lastrowid}), 201

@app.route("/api/users/<int:uid>", methods=["PATCH", "DELETE", "OPTIONS"])
@admin_required
@csrf_protect
def manage_user(uid):
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "DELETE":
        if uid == DEFAULT_USER_ID:
            return err("Cannot delete the default admin user")
        tasks = q1("SELECT COUNT(*) AS n FROM tasks WHERE assignee_id=? OR reviewer_id=?", (uid, uid))["n"]
        recons = q1("SELECT COUNT(*) AS n FROM reconciliations WHERE assignee_id=?", (uid,))["n"]
        if tasks or recons:
            parts = []
            if tasks:  parts.append(f"{tasks} task(s)")
            if recons: parts.append(f"{recons} reconciliation(s)")
            return err(f"Cannot delete: user is still assigned to {' and '.join(parts)}. Reassign them first.", 409)
        run("DELETE FROM task_activity WHERE user_id=?", (uid,))
        run("DELETE FROM users WHERE id=?", (uid,))
        return jsonify({"deleted": uid})
    b = request.json or {}
    allowed = {"name", "initials", "email", "role", "color"}
    updates = {k: v for k, v in b.items() if k in allowed}
    if not updates:
        return err("No valid fields")
    safe_update("users", "id", allowed, updates, uid)
    return jsonify({"updated": uid})

# ── Categories ────────────────────────────────────────────────────────────────

@app.route("/api/categories", methods=["GET", "OPTIONS"])
@login_required
def get_categories():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify(rows_to_list(q("SELECT * FROM categories ORDER BY sort_order")))

@app.route("/api/categories", methods=["POST", "OPTIONS"])
@admin_required
@csrf_protect
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
@csrf_protect
def manage_category(cid):
    if request.method == "OPTIONS":
        return "", 204
    if request.method == "DELETE":
        in_use = q1("SELECT COUNT(*) AS n FROM tasks WHERE category_id=?", (cid,))["n"]
        if in_use:
            return err(f"Cannot delete: category still has {in_use} task(s). Reassign or delete them first.", 409)
        run("DELETE FROM categories WHERE id=?", (cid,))
        return jsonify({"deleted": cid})
    b = request.json or {}
    allowed = {"name", "sort_order"}
    updates = {k: v for k, v in b.items() if k in allowed}
    if not updates:
        return err("No valid fields")
    safe_update("categories", "id", allowed, updates, cid)
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

@app.route("/api/tasks", methods=["POST", "OPTIONS"])
@admin_required
@csrf_protect
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
@csrf_protect
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
        updates["completed_at"] = datetime.now(timezone.utc).isoformat()
    if updates.get("review_status") == "approved" and old["review_status"] != "approved":
        updates["approved_at"] = datetime.now(timezone.utc).isoformat()
    safe_update("tasks", "id", allowed | {"completed_at", "approved_at"}, updates, tid)
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

@app.route("/api/reconciliations", methods=["POST", "OPTIONS"])
@admin_required
@csrf_protect
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
@csrf_protect
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
    updates["last_updated_at"] = datetime.now(timezone.utc).isoformat()
    safe_update("reconciliations", "id", allowed | {"last_updated_at"}, updates, rid)
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