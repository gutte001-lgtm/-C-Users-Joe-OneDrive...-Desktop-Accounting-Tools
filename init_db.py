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

-- ─────────────────────────────────────────
--  Reconciliation Attachments
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS recon_attachments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    recon_id     INTEGER NOT NULL REFERENCES reconciliations(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    stored_name  TEXT NOT NULL,
    size_bytes   INTEGER,
    uploader_id  INTEGER REFERENCES users(id),
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────
--  Checklist Templates
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS template_items (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id         INTEGER NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    category_id         INTEGER REFERENCES categories(id),
    name                TEXT NOT NULL,
    default_assignee_id INTEGER REFERENCES users(id),
    default_reviewer_id INTEGER REFERENCES users(id),
    days_offset         INTEGER DEFAULT 0,
    sort_order          INTEGER DEFAULT 0
);

-- ─────────────────────────────────────────
--  Trial Balance Snapshots
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tb_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    period_id       INTEGER NOT NULL REFERENCES periods(id),
    label           TEXT NOT NULL,
    notes           TEXT DEFAULT '',
    snapshotted_by  INTEGER REFERENCES users(id),
    snapshotted_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tb_snapshot_rows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id     INTEGER NOT NULL REFERENCES tb_snapshots(id) ON DELETE CASCADE,
    account_number  TEXT,
    account_name    TEXT NOT NULL,
    account_type    TEXT,
    account_subtype TEXT,
    classification  TEXT,
    balance         REAL
);

CREATE INDEX IF NOT EXISTS idx_tb_rows_snapshot ON tb_snapshot_rows(snapshot_id);

-- ─────────────────────────────────────────
--  Pending Posts (unified review queue for QB writes)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pending_posts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT NOT NULL,              -- authnet | pandadoc | billcom | shopify | manual
    external_id     TEXT,                       -- source transaction/doc id (idempotency key)
    target_type     TEXT NOT NULL,              -- invoice | sales_receipt | bill | payment | credit_memo
    customer_vendor TEXT,                       -- display name
    amount          REAL,
    reference       TEXT,                       -- short description for the queue row
    payload         TEXT NOT NULL,              -- JSON body to send to QB
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending | posted | dismissed | error
    qb_id           TEXT,                       -- QB document ID after successful post
    error_message   TEXT,
    notes           TEXT DEFAULT '',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    posted_by       INTEGER REFERENCES users(id),
    posted_at       DATETIME
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_external
    ON pending_posts(source, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_posts(status);

-- ─────────────────────────────────────────
--  QuickBooks Sync State
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qb_sync_state (
    entity            TEXT PRIMARY KEY,
    last_sync_time    DATETIME,         -- most recent Metadata.LastUpdatedTime seen
    last_backfill_at  DATETIME,
    record_count      INTEGER DEFAULT 0,
    last_status       TEXT DEFAULT 'idle',   -- idle | syncing | error
    last_error        TEXT,
    last_run_at       DATETIME
);

-- ─────────────────────────────────────────
--  QuickBooks Reference Data
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qb_accounts (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    acct_num          TEXT,
    account_type      TEXT,
    account_subtype   TEXT,
    classification    TEXT,
    current_balance   REAL,
    active            INTEGER DEFAULT 1,
    parent_id         TEXT,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_accounts_acctnum ON qb_accounts(acct_num);
CREATE INDEX IF NOT EXISTS idx_qb_accounts_class ON qb_accounts(classification);

CREATE TABLE IF NOT EXISTS qb_customers (
    id                TEXT PRIMARY KEY,
    display_name      TEXT NOT NULL,
    company_name      TEXT,
    email             TEXT,
    phone             TEXT,
    balance           REAL,
    active            INTEGER DEFAULT 1,
    parent_id         TEXT,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_customers_name ON qb_customers(display_name);
CREATE INDEX IF NOT EXISTS idx_qb_customers_email ON qb_customers(email);

CREATE TABLE IF NOT EXISTS qb_vendors (
    id                TEXT PRIMARY KEY,
    display_name      TEXT NOT NULL,
    company_name      TEXT,
    email             TEXT,
    phone             TEXT,
    balance           REAL,
    active            INTEGER DEFAULT 1,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_vendors_name ON qb_vendors(display_name);

CREATE TABLE IF NOT EXISTS qb_items (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    sku               TEXT,
    type              TEXT,             -- Service | Inventory | NonInventory | Bundle
    description       TEXT,
    unit_price        REAL,
    income_account_id TEXT,
    expense_account_id TEXT,
    asset_account_id  TEXT,
    active            INTEGER DEFAULT 1,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_items_sku ON qb_items(sku);

-- ─────────────────────────────────────────
--  QuickBooks Transactions
-- ─────────────────────────────────────────
-- Common pattern: headers + lines, with jira_epic_id pulled out of the
-- CustomField array on both header and line where present.

CREATE TABLE IF NOT EXISTS qb_invoices (
    id                TEXT PRIMARY KEY,
    doc_number        TEXT,
    txn_date          DATE,
    due_date          DATE,
    customer_id       TEXT,
    customer_name     TEXT,
    total_amt         REAL,
    balance           REAL,
    deposit           REAL,
    currency          TEXT,
    email_status      TEXT,
    print_status      TEXT,
    private_note      TEXT,
    memo              TEXT,
    jira_epic_id      TEXT,
    class_id          TEXT,
    department_id     TEXT,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_invoices_date ON qb_invoices(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_invoices_customer ON qb_invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_qb_invoices_epic ON qb_invoices(jira_epic_id);
CREATE INDEX IF NOT EXISTS idx_qb_invoices_balance ON qb_invoices(balance);

CREATE TABLE IF NOT EXISTS qb_invoice_lines (
    id                TEXT PRIMARY KEY,   -- invoice_id + ":" + line_id
    invoice_id        TEXT NOT NULL REFERENCES qb_invoices(id) ON DELETE CASCADE,
    line_num          INTEGER,
    description       TEXT,
    amount            REAL,
    item_id           TEXT,
    item_name         TEXT,
    qty               REAL,
    unit_price        REAL,
    account_id        TEXT,
    tax_code          TEXT,
    class_id          TEXT,
    jira_epic_id      TEXT,
    raw_json          TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_invoice_lines_inv ON qb_invoice_lines(invoice_id);
CREATE INDEX IF NOT EXISTS idx_qb_invoice_lines_item ON qb_invoice_lines(item_id);
CREATE INDEX IF NOT EXISTS idx_qb_invoice_lines_epic ON qb_invoice_lines(jira_epic_id);

CREATE TABLE IF NOT EXISTS qb_bills (
    id                TEXT PRIMARY KEY,
    doc_number        TEXT,
    txn_date          DATE,
    due_date          DATE,
    vendor_id         TEXT,
    vendor_name       TEXT,
    total_amt         REAL,
    balance           REAL,
    currency          TEXT,
    private_note      TEXT,
    memo              TEXT,
    jira_epic_id      TEXT,
    class_id          TEXT,
    department_id     TEXT,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_bills_date ON qb_bills(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_bills_vendor ON qb_bills(vendor_id);
CREATE INDEX IF NOT EXISTS idx_qb_bills_epic ON qb_bills(jira_epic_id);

CREATE TABLE IF NOT EXISTS qb_bill_lines (
    id                TEXT PRIMARY KEY,
    bill_id           TEXT NOT NULL REFERENCES qb_bills(id) ON DELETE CASCADE,
    line_num          INTEGER,
    description       TEXT,
    amount            REAL,
    account_id        TEXT,
    item_id           TEXT,
    qty               REAL,
    unit_price        REAL,
    class_id          TEXT,
    jira_epic_id      TEXT,
    raw_json          TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_bill_lines_bill ON qb_bill_lines(bill_id);

CREATE TABLE IF NOT EXISTS qb_payments (
    id                TEXT PRIMARY KEY,
    txn_date          DATE,
    customer_id       TEXT,
    customer_name     TEXT,
    total_amt         REAL,
    unapplied_amt     REAL,
    payment_method    TEXT,
    deposit_to_id     TEXT,
    currency          TEXT,
    private_note      TEXT,
    jira_epic_id      TEXT,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_payments_date ON qb_payments(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_payments_customer ON qb_payments(customer_id);

CREATE TABLE IF NOT EXISTS qb_payment_lines (
    id                TEXT PRIMARY KEY,
    payment_id        TEXT NOT NULL REFERENCES qb_payments(id) ON DELETE CASCADE,
    amount            REAL,
    applied_txn_type  TEXT,   -- Invoice | CreditMemo | etc.
    applied_txn_id    TEXT,
    raw_json          TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_payment_lines_pay ON qb_payment_lines(payment_id);
CREATE INDEX IF NOT EXISTS idx_qb_payment_lines_applied ON qb_payment_lines(applied_txn_type, applied_txn_id);

CREATE TABLE IF NOT EXISTS qb_bill_payments (
    id                TEXT PRIMARY KEY,
    doc_number        TEXT,
    txn_date          DATE,
    vendor_id         TEXT,
    vendor_name       TEXT,
    total_amt         REAL,
    payment_type      TEXT,   -- Check | CreditCard
    bank_account_id   TEXT,
    cc_account_id     TEXT,
    check_number      TEXT,
    currency          TEXT,
    private_note      TEXT,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_bill_payments_date ON qb_bill_payments(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_bill_payments_vendor ON qb_bill_payments(vendor_id);

CREATE TABLE IF NOT EXISTS qb_bill_payment_lines (
    id                TEXT PRIMARY KEY,
    bill_payment_id   TEXT NOT NULL REFERENCES qb_bill_payments(id) ON DELETE CASCADE,
    amount            REAL,
    applied_txn_type  TEXT,
    applied_txn_id    TEXT,
    raw_json          TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_bp_lines_bp ON qb_bill_payment_lines(bill_payment_id);
CREATE INDEX IF NOT EXISTS idx_qb_bp_lines_applied ON qb_bill_payment_lines(applied_txn_type, applied_txn_id);

CREATE TABLE IF NOT EXISTS qb_sales_receipts (
    id                TEXT PRIMARY KEY,
    doc_number        TEXT,
    txn_date          DATE,
    customer_id       TEXT,
    customer_name     TEXT,
    total_amt         REAL,
    payment_method    TEXT,
    deposit_to_id     TEXT,
    currency          TEXT,
    private_note      TEXT,
    memo              TEXT,
    jira_epic_id      TEXT,
    class_id          TEXT,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_sr_date ON qb_sales_receipts(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_sr_customer ON qb_sales_receipts(customer_id);
CREATE INDEX IF NOT EXISTS idx_qb_sr_epic ON qb_sales_receipts(jira_epic_id);

CREATE TABLE IF NOT EXISTS qb_sales_receipt_lines (
    id                TEXT PRIMARY KEY,
    sales_receipt_id  TEXT NOT NULL REFERENCES qb_sales_receipts(id) ON DELETE CASCADE,
    line_num          INTEGER,
    description       TEXT,
    amount            REAL,
    item_id           TEXT,
    item_name         TEXT,
    qty               REAL,
    unit_price        REAL,
    account_id        TEXT,
    tax_code          TEXT,
    class_id          TEXT,
    jira_epic_id      TEXT,
    raw_json          TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_sr_lines_sr ON qb_sales_receipt_lines(sales_receipt_id);

CREATE TABLE IF NOT EXISTS qb_journal_entries (
    id                TEXT PRIMARY KEY,
    doc_number        TEXT,
    txn_date          DATE,
    total_amt         REAL,
    adjustment        INTEGER DEFAULT 0,
    currency          TEXT,
    private_note      TEXT,
    memo              TEXT,
    jira_epic_id      TEXT,
    sync_token        TEXT,
    last_updated_at   DATETIME,
    raw_json          TEXT,
    first_synced_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_synced_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_je_date ON qb_journal_entries(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_je_epic ON qb_journal_entries(jira_epic_id);

CREATE TABLE IF NOT EXISTS qb_journal_entry_lines (
    id                TEXT PRIMARY KEY,
    journal_entry_id  TEXT NOT NULL REFERENCES qb_journal_entries(id) ON DELETE CASCADE,
    line_num          INTEGER,
    posting_type      TEXT,            -- Debit | Credit
    amount            REAL,
    account_id        TEXT,
    account_name      TEXT,
    entity_type       TEXT,            -- Customer | Vendor | Employee
    entity_id         TEXT,
    class_id          TEXT,
    department_id     TEXT,
    description       TEXT,
    jira_epic_id      TEXT,
    raw_json          TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_je_lines_je ON qb_journal_entry_lines(journal_entry_id);
CREATE INDEX IF NOT EXISTS idx_qb_je_lines_acct ON qb_journal_entry_lines(account_id);
CREATE INDEX IF NOT EXISTS idx_qb_je_lines_epic ON qb_journal_entry_lines(jira_epic_id);

-- ── Phase 2 reference data ──

CREATE TABLE IF NOT EXISTS qb_employees (
    id TEXT PRIMARY KEY, display_name TEXT, email TEXT, phone TEXT,
    active INTEGER DEFAULT 1, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS qb_classes (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, fully_qualified_name TEXT, parent_id TEXT,
    active INTEGER DEFAULT 1, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS qb_departments (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, fully_qualified_name TEXT, parent_id TEXT,
    active INTEGER DEFAULT 1, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS qb_tax_codes (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, taxable INTEGER DEFAULT 0,
    active INTEGER DEFAULT 1, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS qb_terms (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT, due_days INTEGER,
    discount_days INTEGER, discount_percent REAL,
    active INTEGER DEFAULT 1, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS qb_payment_methods (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT,
    active INTEGER DEFAULT 1, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Phase 2 transactional entities ──

CREATE TABLE IF NOT EXISTS qb_credit_memos (
    id TEXT PRIMARY KEY, doc_number TEXT, txn_date DATE,
    customer_id TEXT, customer_name TEXT, total_amt REAL, remaining_credit REAL,
    currency TEXT, private_note TEXT, memo TEXT, jira_epic_id TEXT,
    class_id TEXT, department_id TEXT, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_cm_date ON qb_credit_memos(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_cm_customer ON qb_credit_memos(customer_id);

CREATE TABLE IF NOT EXISTS qb_credit_memo_lines (
    id TEXT PRIMARY KEY,
    credit_memo_id TEXT NOT NULL REFERENCES qb_credit_memos(id) ON DELETE CASCADE,
    line_num INTEGER, description TEXT, amount REAL,
    item_id TEXT, item_name TEXT, qty REAL, unit_price REAL,
    account_id TEXT, tax_code TEXT, class_id TEXT, jira_epic_id TEXT, raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_cm_lines_cm ON qb_credit_memo_lines(credit_memo_id);

CREATE TABLE IF NOT EXISTS qb_vendor_credits (
    id TEXT PRIMARY KEY, doc_number TEXT, txn_date DATE,
    vendor_id TEXT, vendor_name TEXT, total_amt REAL,
    currency TEXT, private_note TEXT, memo TEXT, jira_epic_id TEXT,
    class_id TEXT, department_id TEXT, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_vc_date ON qb_vendor_credits(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_vc_vendor ON qb_vendor_credits(vendor_id);

CREATE TABLE IF NOT EXISTS qb_vendor_credit_lines (
    id TEXT PRIMARY KEY,
    vendor_credit_id TEXT NOT NULL REFERENCES qb_vendor_credits(id) ON DELETE CASCADE,
    line_num INTEGER, description TEXT, amount REAL,
    account_id TEXT, item_id TEXT, qty REAL, unit_price REAL,
    class_id TEXT, jira_epic_id TEXT, raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_vc_lines_vc ON qb_vendor_credit_lines(vendor_credit_id);

CREATE TABLE IF NOT EXISTS qb_refund_receipts (
    id TEXT PRIMARY KEY, doc_number TEXT, txn_date DATE,
    customer_id TEXT, customer_name TEXT, total_amt REAL,
    payment_method TEXT, deposit_account_id TEXT, currency TEXT,
    private_note TEXT, memo TEXT, jira_epic_id TEXT,
    class_id TEXT, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_rr_date ON qb_refund_receipts(txn_date);

CREATE TABLE IF NOT EXISTS qb_refund_receipt_lines (
    id TEXT PRIMARY KEY,
    refund_receipt_id TEXT NOT NULL REFERENCES qb_refund_receipts(id) ON DELETE CASCADE,
    line_num INTEGER, description TEXT, amount REAL,
    item_id TEXT, item_name TEXT, qty REAL, unit_price REAL,
    account_id TEXT, tax_code TEXT, class_id TEXT, jira_epic_id TEXT, raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_rr_lines_rr ON qb_refund_receipt_lines(refund_receipt_id);

CREATE TABLE IF NOT EXISTS qb_deposits (
    id TEXT PRIMARY KEY, doc_number TEXT, txn_date DATE,
    deposit_account_id TEXT, total_amt REAL, currency TEXT,
    private_note TEXT, memo TEXT, jira_epic_id TEXT,
    class_id TEXT, department_id TEXT, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_dep_date ON qb_deposits(txn_date);

CREATE TABLE IF NOT EXISTS qb_deposit_lines (
    id TEXT PRIMARY KEY,
    deposit_id TEXT NOT NULL REFERENCES qb_deposits(id) ON DELETE CASCADE,
    line_num INTEGER, description TEXT, amount REAL,
    account_id TEXT, entity_type TEXT, entity_id TEXT,
    applied_txn_type TEXT, applied_txn_id TEXT,
    class_id TEXT, raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_dep_lines_dep ON qb_deposit_lines(deposit_id);

CREATE TABLE IF NOT EXISTS qb_purchases (
    id TEXT PRIMARY KEY, doc_number TEXT, txn_date DATE,
    payment_type TEXT, account_id TEXT, account_name TEXT,
    entity_type TEXT, entity_id TEXT, entity_name TEXT,
    total_amt REAL, credit INTEGER DEFAULT 0, currency TEXT,
    private_note TEXT, memo TEXT, jira_epic_id TEXT,
    class_id TEXT, department_id TEXT, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_pur_date ON qb_purchases(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_pur_account ON qb_purchases(account_id);

CREATE TABLE IF NOT EXISTS qb_purchase_lines (
    id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL REFERENCES qb_purchases(id) ON DELETE CASCADE,
    line_num INTEGER, description TEXT, amount REAL,
    account_id TEXT, item_id TEXT, qty REAL, unit_price REAL,
    class_id TEXT, jira_epic_id TEXT, raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_pur_lines_pur ON qb_purchase_lines(purchase_id);

CREATE TABLE IF NOT EXISTS qb_transfers (
    id TEXT PRIMARY KEY, txn_date DATE,
    from_account_id TEXT, to_account_id TEXT, amount REAL,
    currency TEXT, private_note TEXT,
    sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_xfer_date ON qb_transfers(txn_date);

CREATE TABLE IF NOT EXISTS qb_estimates (
    id TEXT PRIMARY KEY, doc_number TEXT, txn_date DATE, expiration_date DATE,
    customer_id TEXT, customer_name TEXT, total_amt REAL, status TEXT,
    currency TEXT, private_note TEXT, memo TEXT, jira_epic_id TEXT,
    class_id TEXT, department_id TEXT, sync_token TEXT, last_updated_at DATETIME, raw_json TEXT,
    first_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_qb_est_date ON qb_estimates(txn_date);
CREATE INDEX IF NOT EXISTS idx_qb_est_customer ON qb_estimates(customer_id);

CREATE TABLE IF NOT EXISTS qb_estimate_lines (
    id TEXT PRIMARY KEY,
    estimate_id TEXT NOT NULL REFERENCES qb_estimates(id) ON DELETE CASCADE,
    line_num INTEGER, description TEXT, amount REAL,
    item_id TEXT, item_name TEXT, qty REAL, unit_price REAL,
    account_id TEXT, tax_code TEXT, class_id TEXT, jira_epic_id TEXT, raw_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_qb_est_lines_est ON qb_estimate_lines(estimate_id);

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
