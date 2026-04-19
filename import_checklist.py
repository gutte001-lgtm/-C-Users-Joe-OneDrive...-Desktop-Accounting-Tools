"""
import_checklist.py  —  Run once to replace sample data with your real checklist.

Usage:
    python import_checklist.py

This script will:
1. Clear all sample tasks, users, and categories
2. Insert your real team members
3. Insert your real categories
4. Import all tasks from your checklist for the current period
5. Update the period to April 2026
"""

import sqlite3, os
from datetime import date, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "closeapp.db")

# ── Real team members from your checklist ────────────────────────────────────
USERS = [
    (1, "Joe Guttenplan",  "JG", "joe@hm.com",     "admin",    "#4f8ef7"),
    (2, "Shaun Groat",     "SG", "shaun@hm.com",    "preparer", "#f7894f"),
    (3, "Anita Savoj",     "AS", "anita@hm.com",    "preparer", "#4fd9a0"),
    (4, "Mandy Roberson",  "MR", "mandy@hm.com",    "preparer", "#c084fc"),
    (5, "Kat Cary",        "KC", "kat@hm.com",      "preparer", "#f472b6"),
    (6, "Ali Hilferty",    "AH", "ali@hm.com",      "preparer", "#f7c948"),
    (7, "Marilyn Carson",  "MC", "marilyn@hm.com",  "preparer", "#60a5fa"),
]

# ── Real categories from your checklist ──────────────────────────────────────
CATEGORIES = [
    (1,  "Payroll",                      1),
    (2,  "Sales",                        2),
    (3,  "COGS",                         3),
    (4,  "Benefits",                     4),
    (5,  "Accruals",                     5),
    (6,  "Prepaids",                     6),
    (7,  "Sales Tax",                    7),
    (8,  "Operating Expenses",           8),
    (9,  "Debt",                         9),
    (10, "Equity",                       10),
    (11, "Administrative",               11),
    (12, "Financial Reporting",          12),
    (13, "Financial Controls",           13),
    (14, "Balance Sheet Reconciliations",14),
]

# ── Period: April 2026 (4-4-5, Period 4) ─────────────────────────────────────
# April 2026 in your 4-4-5 calendar = 4 weeks = Apr 6 – May 3
PERIOD = {
    "id":         1,
    "label":      "April 2026 (Period 4)",
    "start_date": "2026-04-06",
    "end_date":   "2026-05-03",
    "is_active":  1,
}

# Helper: convert due day offset to actual date
# Positive = days after period end, negative = days before period end
# Special strings like "10th", "Wed", "TBD" handled separately
def calc_due(period_end: str, due_offset) -> str | None:
    if due_offset is None:
        return None
    try:
        offset = int(float(str(due_offset)))
        base = date.fromisoformat(period_end)
        return (base + timedelta(days=offset)).isoformat()
    except (ValueError, TypeError):
        return None

PE = PERIOD["end_date"]  # period end date for offset calculations

# ── Owner name → user ID mapping ─────────────────────────────────────────────
OWNER_MAP = {
    "Joe Guttenplan":  1,
    "Shaun Groat":     2,
    "Anita Savoj":     3,
    "Mandy Roberson":  4,
    "Kat Cary":        5,
    "Ali Hilferty":    6,
    "Marilyn Carson":  7,
}

def uid(name: str) -> int:
    return OWNER_MAP.get(name, 1)  # default to Joe if unknown

# ── Category name → ID mapping ───────────────────────────────────────────────
CAT_MAP = {c[1]: c[0] for c in CATEGORIES}
CAT_MAP["Operating Expenes"] = 8  # fix typo in source data

def cid(name: str) -> int:
    return CAT_MAP.get(name, 11)  # default to Administrative

# ── Your real tasks ───────────────────────────────────────────────────────────
# Format: (category, name, assignee, reviewer, due_offset, frequency)
# Reviewer defaults to Joe (1) for all tasks
TASKS = [
    # PAYROLL
    ("Payroll", "Payroll Accrual",           "Shaun Groat",    "Joe Guttenplan", 5,    "Monthly"),
    ("Payroll", "Payroll Expense",           "Shaun Groat",    "Joe Guttenplan", 5,    "Bi-Weekly"),
    ("Payroll", "Payroll Bill",              "Shaun Groat",    "Joe Guttenplan", 5,    "Bi-Weekly"),
    ("Payroll", "Payroll Bill (401K)",       "Shaun Groat",    "Joe Guttenplan", 5,    "Bi-Weekly"),
    ("Payroll", "Off-Cycle Payroll",         "Shaun Groat",    "Joe Guttenplan", 5,    "As Needed"),
    ("Payroll", "401(k) Contributions",      "Shaun Groat",    "Joe Guttenplan", 5,    "Monthly"),
    ("Payroll", "Stock Comp Entry",          "Shaun Groat",    "Joe Guttenplan", 5,    "Monthly"),

    # SALES
    ("Sales",   "Revenue Recognition",       "Joe Guttenplan", "Shaun Groat",    5,    "Monthly"),

    # ACCRUALS
    ("Accruals","Merchant Fee Expense Accrual",         "Anita Savoj",    "Joe Guttenplan", 4, "Monthly"),
    ("Accruals","Outbound Shipping Expense Accrual",    "Joe Guttenplan", "Joe Guttenplan", 5, "Monthly"),
    ("Accruals","Marketing Accrual",                    "Joe Guttenplan", "Joe Guttenplan", 3, "Monthly"),
    ("Accruals","Professional Fee Accruals",            "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Accruals","Audit and Tax Accrual",                "Joe Guttenplan", "Joe Guttenplan", 3, "Monthly"),
    ("Accruals","Operating Expense Accrual",            "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Accruals","Commission Expense Accrual",           "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Accruals","Training Expense Accrual",             "Joe Guttenplan", "Joe Guttenplan", 5, "Monthly"),
    ("Accruals","Other Expense Accrual",                "Joe Guttenplan", "Joe Guttenplan", 5, "As Needed"),

    # BENEFITS
    ("Benefits","Health Insurance Expense Accrual",     "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Benefits","Health Insurance Allocation",          "Shaun Groat",    "Joe Guttenplan", 4, "Monthly"),

    # COGS
    ("COGS",    "COGS / Inventory Adjustment",          "Joe Guttenplan", "Joe Guttenplan", 5, "Monthly"),
    ("COGS",    "Inventory Deposits",                   "Joe Guttenplan", "Joe Guttenplan", 5, "Monthly"),
    ("COGS",    "AP Review — undelivered payables",     "Kat Cary",       "Joe Guttenplan", 5, "Monthly"),
    ("COGS",    "Review prepaid inventory vs COGS",     "Kat Cary",       "Joe Guttenplan", 5, "Monthly"),

    # PREPAIDS
    ("Prepaids","Prepaid Business Insurance",           "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Prepaids","Prepaid Software Licensing",           "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Prepaids","Prepaid Technology Services",          "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Prepaids","Prepaid Service and Repair",           "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Prepaids","Prepaid Training",                     "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Prepaids","Prepaid Outbound Shipping",            "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Prepaids","Prepaid Trade Shows and Events",       "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Prepaids","Other Prepaid Expenses",               "Joe Guttenplan", "Joe Guttenplan", 4, "Monthly"),
    ("Prepaids","Review Prepaid Schedule",              "Joe Guttenplan", "Joe Guttenplan", 5, "Monthly"),
    ("Prepaids","Expiring Prepaid Analysis",            "Joe Guttenplan", "Joe Guttenplan", -5,"Monthly"),

    # SALES TAX
    ("Sales Tax","Sales Tax Allocation",                "Joe Guttenplan", "Joe Guttenplan", 8, "Monthly"),
    ("Sales Tax","Create Bill for Sales Tax",           "Joe Guttenplan", "Joe Guttenplan", 10,"Monthly"),
    ("Sales Tax","Begin Sales Tax Analysis / Reconciliation", "Joe Guttenplan", "Joe Guttenplan", 5, "Monthly"),

    # DEBT
    ("Debt",    "Decathlon Interest Expense",           "Joe Guttenplan", "Joe Guttenplan", 1, "Monthly"),
    ("Debt",    "Monthly Decathlon Payment",            "Mandy Roberson", "Joe Guttenplan", 6, "Monthly"),
    ("Debt",    "Decathlon Reporting",                  "Joe Guttenplan", "Joe Guttenplan", 15,"Monthly"),

    # OPERATING EXPENSES
    ("Operating Expenses","Monthly Divvy Entry",        "Mandy Roberson", "Joe Guttenplan", 4, "Monthly"),
    ("Operating Expenses","Bank Fee Entry",             "Joe Guttenplan", "Kat Cary",        3, "Monthly"),
    ("Operating Expenses","Record Occupancy Expenses",  "Joe Guttenplan", "Joe Guttenplan",  -5,"Monthly"),
    ("Operating Expenses","Divvy Email — Expense Reconciliation Due", "Mandy Roberson", "Joe Guttenplan", -3, "Monthly"),
    ("Operating Expenses","Divvy Expense Upload and Reconciliation",  "Mandy Roberson", "Joe Guttenplan", 5,  "Monthly"),
    ("Operating Expenses","Utility Reconciliation",     "Mandy Roberson", "Joe Guttenplan", 5, "Monthly"),
    ("Operating Expenses","Shared Expenses to 7200 LL", "Mandy Roberson","Joe Guttenplan",  None,"Quarterly"),
    ("Operating Expenses","Email: MET Service Accrual reminder",      "Joe Guttenplan", "Joe Guttenplan", -5, "Monthly"),
    ("Operating Expenses","Email: Logistics freight/van accruals",    "Joe Guttenplan", "Joe Guttenplan", -5, "Monthly"),
    ("Operating Expenses","Email: Luvo inventory detail at month-end","Joe Guttenplan", "Ali Hilferty",   -5, "Monthly"),
    ("Operating Expenses","Email: IT costs for current month",        "Joe Guttenplan", "Joe Guttenplan", -5, "Monthly"),

    # EQUITY
    ("Equity",  "Additional Paid in Capital — Options", "Shaun Groat",   "Joe Guttenplan", None,"As Needed"),
    ("Equity",  "SAFE Note",                            "Shaun Groat",   "Joe Guttenplan", None,"As Needed"),
    ("Equity",  "Due from Shareholder",                 "Shaun Groat",   "Joe Guttenplan", None,"Monthly"),
    ("Equity",  "Equity Plan Conversions",              "Shaun Groat",   "Joe Guttenplan", None,"As Needed"),
    ("Equity",  "Equity Plan Awards",                   "Shaun Groat",   "Joe Guttenplan", None,"Quarterly"),

    # ADMINISTRATIVE
    ("Administrative","Refund Reclassification",        "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Clearing Invalid AP Transactions","Joe Guttenplan","Joe Guttenplan", None,"As Needed"),
    ("Administrative","Other Income",                   "Anita Savoj",   "Kat Cary",        None,"As Needed"),
    ("Administrative","Unpaid Customer Refunds",        "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Refund Reversal",                "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Incoming Wire Service Fees",     "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Customer Deposits",              "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Invoice VOID",                   "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Bad Debt Expense",               "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Financing Commissions",          "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Sales Tax Adjustment",           "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","KOL Discounts",                  "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Sales Return",                   "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Restocking Fee",                 "Anita Savoj",   "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Fixed Asset Retirement or Place In Service","Joe Guttenplan","Joe Guttenplan",6,"Monthly"),
    ("Administrative","Reclass CC Fees for Cash Reporting","Anita Savoj","Joe Guttenplan", 6, "Monthly"),
    ("Administrative","Application of payments to interest income","Joe Guttenplan","Joe Guttenplan",6,"As Needed"),
    ("Administrative","Record and Reconcile Charge Backs","Anita Savoj", "Joe Guttenplan", None,"As Needed"),
    ("Administrative","Create Account Checklist",       "Joe Guttenplan","Joe Guttenplan", -20,"Monthly"),
    ("Administrative","Weekly AP Check Run",            "Ali Hilferty",  "Joe Guttenplan", None,"Weekly"),
    ("Administrative","Weekly AR Meeting",              "Anita Savoj",   "Joe Guttenplan", None,"Weekly"),
    ("Administrative","Applying Cash — Payroll Account","Marilyn Carson","Joe Guttenplan", 7,  "Monthly"),
    ("Administrative","Applying Cash — Cash Deposit Account","Kat Cary", "Joe Guttenplan", 7,  "Monthly"),
    ("Administrative","Applying Cash — CC Deposit Account","Kat Cary",  "Joe Guttenplan", 7,  "Monthly"),
    ("Administrative","Send Credit Card Links",         "Anita Savoj",   "Joe Guttenplan", None,"Daily"),
    ("Administrative","Incoming Credit Card Deposit",   "Anita Savoj",   "Joe Guttenplan", None,"Daily"),
    ("Administrative","Incoming Wire / ACH Deposit",    "Anita Savoj",   "Joe Guttenplan", None,"Daily"),
    ("Administrative","Create Sales Receipts — eBay",   "Anita Savoj",   "Joe Guttenplan", None,"Daily"),
    ("Administrative","Create Sales Receipts — Web Orders","Anita Savoj","Joe Guttenplan", None,"Daily"),
    ("Administrative","Create Web Tech-Time Orders",    "Anita Savoj",   "Joe Guttenplan", None,"Daily"),
    ("Administrative","Create Invoices for Incoming Sales Orders","Anita Savoj","Joe Guttenplan",None,"Daily"),
    ("Administrative","Depreciation of Fixed Assets",   "Joe Guttenplan","Joe Guttenplan", 4,  "Monthly"),

    # FINANCIAL REPORTING
    ("Financial Reporting","Open / Close Periods",      "Joe Guttenplan","Joe Guttenplan", None,"Monthly"),
    ("Financial Reporting","Daily Sales Report",        "Shaun Groat",   "Joe Guttenplan", None,"Daily"),
    ("Financial Reporting","Monthly Financial Report",  "Shaun Groat",   "Joe Guttenplan", 10, "Monthly"),
    ("Financial Reporting","Quarterly Financial Report (Investors)","Shaun Groat","Shaun Groat",20,"Quarterly"),
    ("Financial Reporting","Weekly Financial Tracker",  "Shaun Groat",   "Shaun Groat",    None,"Weekly"),
    ("Financial Reporting","Divvy Transaction Report",  "Mandy Roberson","Joe Guttenplan", None,"Weekly"),
    ("Financial Reporting","Cash Flow Analysis / Forecast","Joe Guttenplan","Joe Guttenplan",None,"Weekly"),
    ("Financial Reporting","Review all prior dated entries","Joe Guttenplan","Joe Guttenplan",7,"Monthly"),
    ("Financial Reporting","Review Trade in Clearing",  "Ali Hilferty",  "Joe Guttenplan", 4,  "Monthly"),
    ("Financial Reporting","Verify all transactions have a class","Kat Cary","Joe Guttenplan",6,"Monthly"),
    ("Financial Reporting","Get updated Service & Repair list","Kat Cary","Joe Guttenplan",None,"Monthly"),
    ("Financial Reporting","Review all prior period manual JEs","Joe Guttenplan","Shaun Groat",6,"Monthly"),
    ("Financial Reporting","Budgeting",                 "Shaun Groat",   "Joe Guttenplan", None,"Annually"),

    # FINANCIAL CONTROLS
    ("Financial Controls","Review all manual JEs",      "Joe Guttenplan","Shaun Groat",    6,  "Monthly"),
    ("Financial Controls","Review Transactions for Capitalization","Joe Guttenplan","Joe Guttenplan",5,"Monthly"),
    ("Financial Controls","Balance Sheet Flux",         "Joe Guttenplan","Joe Guttenplan", 8,  "Monthly"),
    ("Financial Controls","P&L Flux",                   "Joe Guttenplan","Joe Guttenplan", 8,  "Monthly"),
    ("Financial Controls","Monthly PO Audit",           "Joe Guttenplan","Kat Cary",        12, "Monthly"),
    ("Financial Controls","Verify Wire Instructions for Device Purchases","Joe Guttenplan","Joe Guttenplan",None,"As Needed"),
    ("Financial Controls","Scheduling Inventory Count", "Joe Guttenplan","Joe Guttenplan", None,"Annually"),

    # BALANCE SHEET RECONCILIATIONS
    ("Balance Sheet Reconciliations","Perigee AR / AP Reconciliation","Joe Guttenplan","Joe Guttenplan",None,"Monthly"),
]


def run():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON")
    cur = conn.cursor()

    print("Clearing sample data...")
    cur.execute("DELETE FROM task_activity")
    cur.execute("DELETE FROM tasks")
    cur.execute("DELETE FROM reconciliations")
    cur.execute("DELETE FROM users")
    cur.execute("DELETE FROM categories")
    cur.execute("DELETE FROM periods")

    print("Inserting real team members...")
    cur.executemany(
        "INSERT INTO users (id,name,initials,email,role,color) VALUES (?,?,?,?,?,?)",
        USERS)

    print("Inserting real categories...")
    cur.executemany(
        "INSERT INTO categories (id,name,sort_order) VALUES (?,?,?)",
        CATEGORIES)

    print("Inserting April 2026 period...")
    cur.execute(
        "INSERT INTO periods (id,label,start_date,end_date,is_active) VALUES (?,?,?,?,?)",
        (PERIOD["id"], PERIOD["label"], PERIOD["start_date"], PERIOD["end_date"], PERIOD["is_active"]))

    print(f"Importing {len(TASKS)} tasks...")
    for cat_name, task_name, assignee, reviewer, due_offset, frequency in TASKS:
        cat_id    = cid(cat_name)
        assign_id = uid(assignee)
        review_id = uid(reviewer)
        due_date  = calc_due(PE, due_offset)
        cur.execute("""
            INSERT INTO tasks
            (period_id, category_id, name, assignee_id, reviewer_id, due_date, status, review_status, notes)
            VALUES (1, ?, ?, ?, ?, ?, 'open', 'pending', ?)
        """, (cat_id, task_name, assign_id, review_id, due_date, f"Frequency: {frequency}"))

    conn.commit()
    conn.close()

    print(f"\n✓ Done! Imported {len(TASKS)} real tasks for April 2026 (Period 4)")
    print("✓ 7 real team members loaded")
    print("✓ 14 real categories loaded")
    print("\nRestart your Flask app and refresh the browser.")


if __name__ == "__main__":
    run()
