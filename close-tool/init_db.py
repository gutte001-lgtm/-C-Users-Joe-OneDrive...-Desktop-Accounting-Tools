"""
init_db.py  –  Run once to create / reset the CloseTool database.
Usage:  python init_db.py
"""
import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), "closeapp.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ─────────────────────────────────────────
--  Users
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    initials    TEXT    NOT NULL,
    email       TEXT    UNIQUE NOT NULL,
    role        TEXT    NOT NULL DEFAULT 'preparer',   -- admin | preparer | reviewer
    color       TEXT    NOT NULL DEFAULT '#4f8ef7',
    password_hash TEXT,          -- placeholder for future Flask-Login
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────
--  Close Periods
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS periods (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT    NOT NULL,   -- e.g. "March 2025"
    start_date  DATE    NOT NULL,
    end_date    DATE    NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────
--  Task Categories
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS categories (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT UNIQUE NOT NULL,
    sort_order INTEGER DEFAULT 0
);

-- ─────────────────────────────────────────
--  Tasks
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    period_id       INTEGER NOT NULL REFERENCES periods(id),
    category_id     INTEGER NOT NULL REFERENCES categories(id),
    name            TEXT    NOT NULL,
    assignee_id     INTEGER NOT NULL REFERENCES users(id),
    reviewer_id     INTEGER NOT NULL REFERENCES users(id),
    due_date        DATE,
    status          TEXT NOT NULL DEFAULT 'open',        -- open | in_progress | complete
    review_status   TEXT NOT NULL DEFAULT 'pending',     -- pending | approved | needs_revision
    notes           TEXT DEFAULT '',
    completed_at    DATETIME,
    approved_at     DATETIME,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────
--  Task Activity Log
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS task_activity (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     INTEGER NOT NULL REFERENCES tasks(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    action      TEXT NOT NULL,   -- status_change | review_change | note | created
    old_value   TEXT,
    new_value   TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────
--  Reconciliations
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reconciliations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    period_id        INTEGER NOT NULL REFERENCES periods(id),
    account_number   TEXT    NOT NULL,
    account_name     TEXT    NOT NULL,
    assignee_id      INTEGER NOT NULL REFERENCES users(id),
    qb_balance       REAL,
    expected_balance REAL,
    status           TEXT NOT NULL DEFAULT 'open',  -- open | reconciled | needs_attention
    last_synced_at   DATETIME,
    last_updated_at  DATETIME,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Trigger: auto-update tasks.updated_at
CREATE TRIGGER IF NOT EXISTS tasks_updated_at
AFTER UPDATE ON tasks
BEGIN
    UPDATE tasks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
"""

SEED_USERS = [
    (1, "Joe G.",    "JG", "joe@company.com",   "admin",    "#4f8ef7"),
    (2, "Sarah M.",  "SM", "sarah@company.com",  "preparer", "#f7894f"),
    (3, "Chris L.",  "CL", "chris@company.com",  "preparer", "#4fd9a0"),
    (4, "Dana R.",   "DR", "dana@company.com",   "preparer", "#c084fc"),
    (5, "Alex T.",   "AT", "alex@company.com",   "reviewer", "#f472b6"),
]

SEED_CATEGORIES = [
    (1, "Revenue",      1),
    (2, "AR",           2),
    (3, "AP",           3),
    (4, "Payroll",      4),
    (5, "Prepaids",     5),
    (6, "Fixed Assets", 6),
    (7, "Tax",          7),
    (8, "Bank",         8),
    (9, "Equity",       9),
    (10,"Reporting",   10),
]

SEED_PERIOD = (1, "March 2025", "2025-03-01", "2025-03-31", 1)

SEED_TASKS = [
    # (period, category, name, assignee, reviewer, due, status, review_status)
    (1,1,"Recognize revenue — SaaS subscriptions",2,5,"2025-04-03","complete","approved"),
    (1,1,"Deferred revenue schedule reconciliation",2,5,"2025-04-03","complete","approved"),
    (1,2,"AR aging review & bad debt estimate",3,1,"2025-04-04","in_progress","pending"),
    (1,2,"Unbilled AR accrual",3,1,"2025-04-04","open","pending"),
    (1,3,"Vendor invoice accruals",4,5,"2025-04-04","complete","needs_revision"),
    (1,3,"Credit card reconciliation",4,5,"2025-04-05","open","pending"),
    (1,4,"Payroll journal entry — March",2,1,"2025-04-03","complete","approved"),
    (1,4,"Payroll tax liability reconciliation",2,1,"2025-04-04","in_progress","pending"),
    (1,9,"Stock-based compensation expense",1,5,"2025-04-05","open","pending"),
    (1,6,"Depreciation run & tie-out",3,1,"2025-04-04","complete","approved"),
    (1,6,"Capitalized software review",1,5,"2025-04-05","open","pending"),
    (1,5,"Prepaid insurance amortization",4,5,"2025-04-04","complete","approved"),
    (1,5,"Prepaid software / SaaS amortization",4,5,"2025-04-04","in_progress","pending"),
    (1,7,"Sales tax accrual — multi-state",1,5,"2025-04-06","open","pending"),
    (1,8,"Bank reconciliation — operating account",3,1,"2025-04-03","complete","approved"),
    (1,8,"Bank reconciliation — payroll account",3,1,"2025-04-03","complete","approved"),
    (1,10,"Flux analysis — P&L vs prior month",1,5,"2025-04-07","open","pending"),
    (1,10,"Board package — financial statements",1,5,"2025-04-08","open","pending"),
]

SEED_RECONS = [
    # (period, acct_num, acct_name, assignee, qb_balance, expected, status)
    (1,"1010","Operating Checking",3,284750.22,284750.22,"reconciled"),
    (1,"1020","Payroll Checking",3,42100.00,42100.00,"reconciled"),
    (1,"1100","Accounts Receivable",3,198340.55,195000.00,"needs_attention"),
    (1,"1200","Prepaid Expenses",4,31200.00,31200.00,"reconciled"),
    (1,"1500","Fixed Assets, Net",3,412800.00,412800.00,"reconciled"),
    (1,"2000","Accounts Payable",4,87450.00,91200.00,"needs_attention"),
    (1,"2100","Accrued Liabilities",1,44000.00,None,"open"),
    (1,"2200","Deferred Revenue",2,225600.00,225600.00,"reconciled"),
    (1,"2300","Payroll Liabilities",2,18700.00,None,"open"),
    (1,"3000","Common Stock",1,1200000.00,1200000.00,"reconciled"),
]


def init():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT OR IGNORE INTO users (id,name,initials,email,role,color) VALUES (?,?,?,?,?,?)",
            SEED_USERS)

    cur.executemany(
        "INSERT OR IGNORE INTO categories (id,name,sort_order) VALUES (?,?,?)",
        SEED_CATEGORIES)

    cur.execute("INSERT OR IGNORE INTO periods (id,label,start_date,end_date,is_active) VALUES (?,?,?,?,?)",
                SEED_PERIOD)

    cur.execute("SELECT COUNT(*) FROM tasks")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            """INSERT INTO tasks
               (period_id,category_id,name,assignee_id,reviewer_id,due_date,status,review_status)
               VALUES (?,?,?,?,?,?,?,?)""",
            SEED_TASKS)

    cur.execute("SELECT COUNT(*) FROM reconciliations")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            """INSERT INTO reconciliations
               (period_id,account_number,account_name,assignee_id,qb_balance,expected_balance,status)
               VALUES (?,?,?,?,?,?,?)""",
            SEED_RECONS)

    conn.commit()
    conn.close()
    print(f"✓ Database initialised at {DB_PATH}")


if __name__ == "__main__":
    init()
