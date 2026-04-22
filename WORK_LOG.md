# Work Log

Append-only history of every Claude session. **Newest first.**

Each entry follows the format in `CLAUDE.md` § "At session end".

---

## 2026-04-21 / 2026-04-22 · Session `01WHgeQQepXjKUjMfgqL5KTT` · `claude/close-tracker-tools-JVRS3`

**Summary:** Major feature expansion for the close tracker. Added five MVP features (audit trail / calendar / bulk actions / recon attachments / checklist templates), reporting stack (TB snapshots + PDF close report), variance tools (flux analysis), QB write scope foundation (unified review queue + OAuth write flow), full QuickBooks data sync (23 entities, 3-year backfill, 15-min incremental), and a complete reporting layer (6 canned reports + drill-down modal + generic entity API + CSV exports).

**Commits (6, newest first):**

1. `2a315c3` — **Phase 3: reports + generic data access + drill-down.** 6 canned reports (customer ledger, vendor ledger, revenue by customer, expense by vendor, GL detail, by Jira epic). Generic `/api/qb/<entity>` list/detail/CSV endpoints with filters + pagination. Reports tab in UI with adaptive filter forms and click-through drill-down modal showing header + lines + raw QB JSON.
2. `e5f67ea` — **Phase 2: 13 more QB entities.** CreditMemo + lines, VendorCredit + lines, RefundReceipt + lines, Deposit + lines, Purchase + lines, Transfer, Estimate + lines, Employee, Class, Department, TaxCode, Term, PaymentMethod.
3. `77168ed` — **Phase 1: QuickBooks data sync engine (read-only).** Entity registry pattern, generic `sync_entity()` with paging + incremental via `Metadata.LastUpdatedTime`, upsert on QB `Id`, `raw_json` capture, per-entity `qb_sync_state` tracking, 15-min APScheduler job. 10 core entities: Account, Customer, Vendor, Item, Invoice + lines, Bill + lines, Payment + applied lines, BillPayment + applied lines, SalesReceipt + lines, JournalEntry + lines. Jira Epic ID extracted from QB CustomField array into typed `jira_epic_id` columns at header and line level. Admin Integrations UI with per-entity record counts, Resync buttons, and Full Backfill (3 yr) button.
4. `88e46c3` — **Flux analysis + unified QB review queue foundation.** `/api/flux` endpoint compares two TB snapshots with `%` and `$` thresholds, flags new/removed accounts. Added Flux sub-view under Trial Balance tab. `pending_posts` table (idempotency via `source`+`external_id`) + Review Queue tab with Post / Dismiss / Reopen / Link / Delete actions. `qb_post()` helper parallels `qb_get()`. `/qb/connect` initiates OAuth with `com.intuit.quickbooks.accounting` write scope; `/qb/callback` validates state. Settings → Integrations sub-tab lists QB (live connect) + placeholders for Bill.com / Authnet / PandaDoc / Shopify / Jira / Teams.
5. `f214761` — **Trial balance snapshots + close report PDF.** New `tb_snapshots` + `tb_snapshot_rows` tables. Admin-only snapshot endpoint pulls all active QB accounts (name, type, subtype, classification, balance) and freezes them. Trial Balance top-level tab with snapshot list + per-classification subtotals (Asset / Liability / Equity / Revenue / Expense) + drill-in + CSV export. Close report PDF via `reportlab` (KPIs, progress by category + team member, open/attention, reconciliation table, variance call-outs, signoff block). Added `reportlab>=4.0` to requirements.
6. `045c41c` — **Audit trail, calendar, bulk actions, recon attachments, templates.** Audit trail timeline in task modal + dedicated Activity Log tab + CSV export. Monthly calendar view of tasks by due date. Bulk-select checkboxes in Checklist with bulk status / assignee / reviewer updates (logged to `task_activity` with `bulk_*` action prefixes). Roll-forward endpoint + modal to copy tasks between periods with configurable day shift. `recon_attachments` table + upload/list/download/delete endpoints (25 MB cap, `secure_filename` + UUID stored name) + paperclip modal on each recon row. `templates` + `template_items` tables with full CRUD, "Save Current Period as Template", and one-click "Instantiate into Period". Added `.gitignore` for pycache, local DB, and uploads/.

**Schema additions (all idempotent `CREATE TABLE IF NOT EXISTS`):**

- `recon_attachments`
- `templates`, `template_items`
- `tb_snapshots`, `tb_snapshot_rows`
- `pending_posts` (unique index on `source`+`external_id`)
- `qb_sync_state`
- 23 QB entity tables: `qb_accounts`, `qb_customers`, `qb_vendors`, `qb_items`, `qb_employees`, `qb_classes`, `qb_departments`, `qb_tax_codes`, `qb_terms`, `qb_payment_methods`, `qb_invoices` + `qb_invoice_lines`, `qb_bills` + `qb_bill_lines`, `qb_payments` + `qb_payment_lines`, `qb_bill_payments` + `qb_bill_payment_lines`, `qb_sales_receipts` + `qb_sales_receipt_lines`, `qb_journal_entries` + `qb_journal_entry_lines`, `qb_credit_memos` + `qb_credit_memo_lines`, `qb_vendor_credits` + `qb_vendor_credit_lines`, `qb_refund_receipts` + `qb_refund_receipt_lines`, `qb_deposits` + `qb_deposit_lines`, `qb_purchases` + `qb_purchase_lines`, `qb_transfers`, `qb_estimates` + `qb_estimate_lines`
- Plus indexes on dates, customer/vendor IDs, account IDs, and `jira_epic_id` columns

**Files touched:** `app.py`, `init_db.py`, `static/index.html`, `requirements.txt`, `.gitignore` (new)

**New dependencies:** `reportlab>=4.0`, plus `werkzeug.utils.secure_filename` for uploads.

**Safety posture:** All QB reads use `qb_get()`. Writes to QB only happen when an admin clicks ⇨ Post on a Review Queue row (routes through `qb_post()`). Scheduled sync is strictly read-only, safe against production QB.

**Handoff notes for future sessions:**

- **Tier 1 backlog** (user-approved, next to build):
  0. Agent coordination scaffold (this work)
  1. Teams webhook notifications + overdue alerts *(needs: webhook URL from user)*
  2. Audit package export ZIP (tasks + recons + attachments + PDF + TB snapshot)
  3. Task dependencies (blocking graph)
  4. Threaded comments + @mentions on tasks
  5. OneDrive / SharePoint cloud-storage auto-link
- **Tier 2** (FloQast parity): amortization schedules, AutoRec bank matcher, tick marks, multi-period flux, close performance metrics, cash flow statement, standard workpaper templates, multi-step approval chains, SoD enforcement.
- **Tier 3** (integration feeders — all need credentials from user):
  - Bill.com tie-out
  - Authorize.net → Review Queue
  - PandaDoc → Review Queue
  - Shopify payouts → clearing recon
  - Jira epic tie-out *(still blocked on: price custom field name, delivery-date custom field name, device-ticket issue type, Cloud vs Server, project keys)*
- **Tier 4** (optional): SSO/SAML, custom report builder, time tracking, SOX controls module.
- **QB sync considerations:** 15-min cadence hits ~500 QB req/min limit with plenty of headroom for a typical business. If sync errors appear in `qb_sync_state`, check `last_error` per entity in Settings → Integrations.
- **Known pre-existing quirks** (not introduced by this session, not fixed):
  - Frontend `POST /api/users` and `POST /api/tasks` don't match backend routes (`/api/users/create`, `/api/tasks/create`). User creation/task creation via the Add modals may 405. Not in scope but worth flagging.
  - `setup_auth.py` must run after `init_db.py` to add `username`/`password_hash` columns on existing databases.
- **Open user questions:**
  - Teams webhook URL for #1
  - Whether to enforce a capability flag hard-blocking `qb_post()` as belt-and-suspenders over human approval
  - Jira field display names + project keys
  - Authnet sales-receipt line-item mapping: single "Web Sale" line, or map descriptions to QB products?
  - PandaDoc customer matching rule: email → name → new, or always review?

---
