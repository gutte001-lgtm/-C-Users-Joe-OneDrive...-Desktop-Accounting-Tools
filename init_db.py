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
    username    TEXT    UNIQUE,
    role        TEXT    NOT NULL DEFAULT 'preparer',   -- admin | preparer | reviewer
    color       TEXT    NOT NULL DEFAULT '#4f8ef7',
    password_hash TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────
--  Close Periods
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS periods (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT    NOT NULL,   -- e.g. "April 2026"
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
    (1, "Joe G.",    "JG", "joe@company.com",   "joe",   "admin",    "#4f8ef7"),
    (2, "Sarah M.",  "SM", "sarah@company.com",  "sarah", "preparer", "#f7894f"),
    (3, "Chris L.",  "CL", "chris@company.com",  "chris", "preparer", "#4fd9a0"),
    (4, "Dana R.",   "DR", "dana@company.com",   "dana",  "preparer", "#c084fc"),
    (5, "Alex T.",   "AT", "alex@company.com",   "alex",  "reviewer", "#f472b6"),
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

# 2026 fiscal year — 4-4-5 calendar (53-week year; Q1 is 5-4-5)
# Weeks run Monday–Sunday
SEED_PERIODS = [
    (1,  "January 2026",   "2025-12-29", "2026-02-01", 0),  # 5 weeks
    (2,  "February 2026",  "2026-02-02", "2026-03-01", 0),  # 4 weeks
    (3,  "March 2026",     "2026-03-02", "2026-04-05", 0),  # 5 weeks
    (4,  "April 2026",     "2026-04-06", "2026-05-03", 1),  # 4 weeks — ACTIVE
    (5,  "May 2026",       "2026-05-04", "2026-05-31", 0),  # 4 weeks
    (6,  "June 2026",      "2026-06-01", "2026-07-05", 0),  # 5 weeks
    (7,  "July 2026",      "2026-07-06", "2026-08-02", 0),  # 4 weeks
    (8,  "August 2026",    "2026-08-03", "2026-08-30", 0),  # 4 weeks
    (9,  "September 2026", "2026-08-31", "2026-10-04", 0),  # 5 weeks
    (10, "October 2026",   "2026-10-05", "2026-11-01", 0),  # 4 weeks
    (11, "November 2026",  "2026-11-02", "2026-11-29", 0),  # 4 weeks
    (12, "December 2026",  "2026-11-30", "2027-01-03", 0),  # 5 weeks
]

# Seed tasks for the active period: April 2026 (period_id=4)
# Close tasks are due in the first week of May 2026
SEED_TASKS = [
    # (period, category, name, assignee, reviewer, due, status, review_status)
    (4,1,"Recognize revenue — SaaS subscriptions",2,5,"2026-05-04","complete","approved"),
    (4,1,"Deferred revenue schedule reconciliation",2,5,"2026-05-04","complete","approved"),
    (4,2,"AR aging review & bad debt estimate",3,1,"2026-05-05","in_progress","pending"),
    (4,2,"Unbilled AR accrual",3,1,"2026-05-05","open","pending"),
    (4,3,"Vendor invoice accruals",4,5,"2026-05-05","complete","needs_revision"),
    (4,3,"Credit card reconciliation",4,5,"2026-05-06","open","pending"),
    (4,4,"Payroll journal entry — April",2,1,"2026-05-04","complete","approved"),
    (4,4,"Payroll tax liability reconciliation",2,1,"2026-05-05","in_progress","pending"),
    (4,9,"Stock-based compensation expense",1,5,"2026-05-06","open","pending"),
    (4,6,"Depreciation run & tie-out",3,1,"2026-05-05","complete","approved"),
    (4,6,"Capitalized software review",1,5,"2026-05-06","open","pending"),
    (4,5,"Prepaid insurance amortization",4,5,"2026-05-05","complete","approved"),
    (4,5,"Prepaid software / SaaS amortization",4,5,"2026-05-05","in_progress","pending"),
    (4,7,"Sales tax accrual — multi-state",1,5,"2026-05-07","open","pending"),
    (4,8,"Bank reconciliation — operating account",3,1,"2026-05-04","complete","approved"),
    (4,8,"Bank reconciliation — payroll account",3,1,"2026-05-04","complete","approved"),
    (4,10,"Flux analysis — P&L vs prior month",1,5,"2026-05-08","open","pending"),
    (4,10,"Board package — financial statements",1,5,"2026-05-11","open","pending"),
]

SEED_RECONS = [
    # (period, acct_num, acct_name, assignee, qb_balance, expected, status)
    (4,"1010","Operating Checking",3,284750.22,284750.22,"reconciled"),
    (4,"1020","Payroll Checking",3,42100.00,42100.00,"reconciled"),
    (4,"1100","Accounts Receivable",3,198340.55,195000.00,"needs_attention"),
    (4,"1200","Prepaid Expenses",4,31200.00,31200.00,"reconciled"),
    (4,"1500","Fixed Assets, Net",3,412800.00,412800.00,"reconciled"),
    (4,"2000","Accounts Payable",4,87450.00,91200.00,"needs_attention"),
    (4,"2100","Accrued Liabilities",1,44000.00,None,"open"),
    (4,"2200","Deferred Revenue",2,225600.00,225600.00,"reconciled"),
    (4,"2300","Payroll Liabilities",2,18700.00,None,"open"),
    (4,"3000","Common Stock",1,1200000.00,1200000.00,"reconciled"),
]


def init():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT OR IGNORE INTO users (id,name,initials,email,username,role,color) VALUES (?,?,?,?,?,?,?)",
            SEED_USERS)

    cur.executemany(
        "INSERT OR IGNORE INTO categories (id,name,sort_order) VALUES (?,?,?)",
        SEED_CATEGORIES)

    cur.executemany(
        "INSERT OR IGNORE INTO periods (id,label,start_date,end_date,is_active) VALUES (?,?,?,?,?)",
        SEED_PERIODS)

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
