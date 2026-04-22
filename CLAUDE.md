# CLAUDE.md — Agent Protocol

Every Claude session working on this repo **must** follow this protocol so multiple agents can work in parallel without silently overwriting each other's work.

---

## At session start

1. **Fetch latest state**: `git fetch origin && git branch -a` to see what other agents have branches in flight.
2. **Read `AGENT_STATUS.md`** to see what agents are currently active and which files they're holding.
3. **Read the top 1–3 entries of `WORK_LOG.md`** to catch up on what landed recently.
4. **Create your own branch** — never work on `main`, never work on another agent's branch:
   ```
   git checkout -b claude/<short-description>-<4-char-suffix>
   ```
   e.g., `claude/teams-notifications-XK91`, `claude/autorec-P2M4`.
5. **Claim yourself** by prepending an entry to the **Currently active** section of `AGENT_STATUS.md`:
   ```markdown
   ### <session-id> — <branch>
   - **Started:** YYYY-MM-DD HH:MM UTC
   - **Last activity:** YYYY-MM-DD HH:MM UTC
   - **Working on:** <short description>
   - **Files held:** <comma-separated list of files you plan to edit>
   - **Notes:** <anything future agents should know>
   ```
6. Commit + push that claim **immediately** so other agents can see it:
   ```
   git add AGENT_STATUS.md
   git commit -m "claim session <id>"
   git push -u origin <branch>
   ```

## While working

- **Commit and push often** — every 15–30 minutes or at logical milestones. This is your insurance against lost work.
- **Before touching a file**, re-check `AGENT_STATUS.md`. If another agent lists it in "Files held," coordinate with the user or pick a different task.
- **Update your own entry** in `AGENT_STATUS.md` when your "Files held" list changes or when a long gap passes. Keep "Last activity" fresh.
- **Never force-push** (`--force`, `-f`). Never rewrite history of pushed commits.
- **Never edit another agent's `AGENT_STATUS.md` entry** — only the owning session (or the user) should touch it.

## At session end

1. **Append a new entry** to `WORK_LOG.md` (newest first, at the top) covering:
   - Session ID + branch name + date
   - One-paragraph summary of what you built / fixed
   - Every commit SHA with a one-line description
   - Files touched
   - Schema additions (new tables, new columns)
   - New dependencies
   - Handoff notes: blockers, open user questions, context future agents need
2. **Remove your entry** from "Currently active" in `AGENT_STATUS.md`.
3. **Final commit + push**:
   ```
   git add WORK_LOG.md AGENT_STATUS.md
   git commit -m "wrap session <id>"
   git push
   ```

## File ownership conventions

- **`init_db.py`** — database schema. Additive only (new tables / new columns). Never drop or rename existing columns without an explicit migration plan approved by the user.
- **`app.py`** — Flask backend. Group new endpoints under a clearly-commented section header (e.g., `# ── AutoRec ───`).
- **`static/index.html`** — monolithic React UI. New top-level components go above `navItems`. New nav items get added to the `navItems` array. Always verify `{` and `}` balance after edits.
- **`requirements.txt`** — pin new deps with `>=` minimum version.
- **`closeapp.db`** — local SQLite, gitignored. Each environment has its own.
- **`uploads/`** — user-uploaded attachments, gitignored.

## Safety rules

- **Never commit** `closeapp.db`, `.env`, `*.pyc`, or anything in `uploads/`.
- **Never use `--no-verify`** to skip pre-commit hooks.
- **Never `git reset --hard`** on a pushed branch.
- **Never delete another agent's branch.**
- **Never write to `main` directly** — always via merge from a feature branch.
- **Never write to QuickBooks** except through the Review Queue (admin-approved single-item posts). All QB reads use `qb_get()`; `qb_post()` is only called from `/api/pending_posts/<id>/post`.

## Pre-commit sanity checks

- Syntax: `python3 -c "import ast; ast.parse(open('app.py').read())"`
- JSX brace balance:
  ```
  python3 -c "import re; s=re.search(r'<script type=\"text/babel\">(.*?)</script>', open('static/index.html').read(), re.DOTALL).group(1); print(s.count('{')==s.count('}'))"
  ```
- For significant backend additions: write a Flask-test-client smoke test (examples are throughout `WORK_LOG.md`).

## Open questions for the user

Before blocking on a user answer, check the "Handoff notes" of the most recent `WORK_LOG.md` entry — the question may already be tracked there.
