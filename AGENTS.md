# AGENTS.md — Read Before Touching This Repo

This file is the source of truth for any AI agent (Claude, Copilot, Cursor,
etc.) working on CloseTool. It is also valid as `CLAUDE.md`. If guidance here
conflicts with a passing remark in chat, **this file wins** unless the user
explicitly overrides it in writing.

---

## 0. Pre-flight: are you in the right place?

Before doing **anything** — reading files, running commands, planning —
verify all three:

1. **Canonical project path** (Windows):
   `C:\Users\Joe\OneDrive - Healthcare Markets DBA\Desktop\Claude Projects\CloseTool`
   This is the *only* folder that contains the real CloseTool. Other
   `app.py` files on Joe's machine (`C:\Users\Joe\app.py`,
   `C:\Users\Joe\Downloads\app.py`, `C:\Users\Joe\Desktop\Claude Projects\close-tracker\app.py`)
   are stale graveyards. Do not edit them. Do not "merge" from them.
2. **You are inside a git repo whose remote is**
   `gutte001-lgtm/-C-Users-Joe-OneDrive...-Desktop-Accounting-Tools`.
   Run `git remote -v` to confirm. If it says anything else (or "fatal:
   not a git repository"), you are in the wrong folder — stop and tell
   the user.
3. **You are not in `C:\Users\Joe`.** That folder accidentally became a
   git repo once. Never run `git init`, `git add`, or `git commit` from
   `C:\Users\Joe` or any folder outside the canonical project path.
   If `git status` from `C:\Users\Joe` ever shows a branch name,
   the home-folder `.git` has reappeared and must be deleted before
   doing anything else.

Sanity check — run inside the project folder, all should pass:

```
git remote -v        # → ...gutte001-lgtm/...Accounting-Tools
git rev-parse --show-toplevel   # → ...\Claude Projects\CloseTool
ls app.py            # → file exists
```

---

## 1. The #1 rule: there is no login screen

CloseTool runs locally on the owner's machine (`http://127.0.0.1:5000`) as a
single-tenant accounting tool. The login screen has been **permanently
removed**. Do not reintroduce it, and do not add any auth gate — session,
token, basic-auth, OAuth, SSO, magic link, PIN, or otherwise — without
explicit written instruction from the repo owner (Joe).

### How "no login" is wired today

Backend (`app.py`):
- `get_current_user()` always returns user id `DEFAULT_USER_ID` (1 = Joe, admin).
- `login_required` and `admin_required` are **no-op pass-throughs**. The
  decorators are left on routes intentionally so that if auth is ever
  reinstated on purpose, the surface area is already marked. Do not strip
  them — that's churn, and it loses the signal.
- `/api/auth/me` always responds `authenticated: true` with Joe's profile.
- `/api/auth/login` and `/api/auth/logout` have been deleted. If a stale
  client calls them the 404 is intentional.
- Neither `session` nor `check_password_hash` nor `generate_password_hash`
  are imported anymore.

Database / `init_db.py`:
- The `users` table has no `username` or `password_hash` columns. Don't
  add them back.
- Don't ALTER TABLE the schema to re-introduce auth columns. The legacy
  `setup_auth.py` script has been deleted from the repo for this reason.

Frontend (`static/index.html`):
- The `LoginScreen` component has been deleted.
- The `authChecked` state and the `if(!currentUser) return <LoginScreen/>`
  gate have been deleted. On load, the app calls `/api/auth/me`, seeds
  `currentUser` with Joe, and drops straight into the dashboard.
- The "Sign Out" button has been removed from the sidebar.
- `handleLogout` has been deleted.
- The Add User and Edit User modals do not collect `username` or
  `password`. The Settings → Team Members table shows `Email`, not
  `Username`. Don't add those fields back.

### If the user asks you to re-add auth

1. Ask first. Confirm scope (who needs to log in, is it multi-user now,
   network-exposed?).
2. Update this file in the same PR.
3. Do not just "wire up the existing login screen" — it no longer exists.

---

## 2. Why this matters (the "crossed swords" incident)

On 2026-04-21, an agent claimed to have removed the login screen overnight on
branch `claude/fix-login-screen-removal-2EuuX`. In fact, **nothing was
committed or pushed** — only the initial commit existed. The user came back
the next morning, still saw the login screen, and (reasonably) lost trust.

Lessons, in priority order:

1. **If you say you did it, it must be committed AND pushed to the named
   branch.** "It works on my scratch disk" is not done. Run
   `git log --oneline origin/<branch>` before declaring victory.
2. **Verify the change actually reaches the user.** For UI changes that
   means: boot the app, hit the URL, confirm the old screen is gone. A
   passing test or a clean diff is not proof the user will see the fix.
3. **Do not leave the task partway and claim completion.** If you ran out of
   turns, say so explicitly in the final message so the next agent picks up
   the right thread.
4. **Never undo a previous agent's completed work without a stated reason.**
   If you find the login screen back in `index.html`, treat it as a
   regression — check git history, ask the user, and restore the no-auth
   state. Do not "helpfully" add auth back because it looks like a missing
   feature.

---

## 3. Project shape (quick map)

- `app.py` — Flask API + static file server. Single file on purpose.
- `init_db.py` — schema + seed data. Idempotent; safe to re-run.
- `static/index.html` — Single-file React app (Babel-standalone, no build
  step). Edit this file directly.
- `closeapp.db` — SQLite, created on first run. Git-ignored.
- `requirements.txt` — pip deps.

(There used to be a `setup_auth.py` here that added username/password
columns. It has been deleted. See Section 1.)

### API conventions

- Resource creation is `POST /api/<resource>` (not `/api/<resource>/create`).
  This applies to `users`, `categories`, `tasks`, `periods`, and
  `reconciliations`. The frontend assumes this convention — don't reintroduce
  the `/create` suffix.

Run: `python app.py` → `http://127.0.0.1:5000`.

---

## 4. Working rules

- **Don't rebuild the toolchain.** No bundler, no TS migration, no component
  library. It's intentionally a single React file.
- **Don't add auth plumbing as "scaffolding for later."** YAGNI.
- **Don't commit `closeapp.db`, `.env`, or anything under `__pycache__/`.**
- **Branch discipline.** Develop on the feature branch the user named in
  the task; never push to `main` without explicit permission.
- **Before declaring a UI task done**: start the server, `curl` the affected
  endpoints, and confirm the rendered HTML no longer contains the removed
  element (`grep` it).
- **Be honest about scope.** If the user asked for X and you also noticed Y,
  mention Y — don't silently fix it, don't silently ignore it.

### Branch hygiene

CloseTool has historically accumulated long-lived parallel branches
(`claude/fix-login-screen-removal-...`, `claude/fix-accounting-button-...`,
`claude/close-tool-next-steps-...`) that diverge from each other and
from `main`. This is the source of most "which copy is real?" confusion.

- **Always start from `main`.** Before opening a new feature branch:
  `git checkout main && git pull origin main`. Don't branch off a
  half-finished `claude/...` branch unless the user explicitly says so.
- **Merge back to `main` as soon as a feature works.** A green branch
  that sits unmerged for a week becomes a merge conflict. After the
  user confirms a fix is good in the browser, propose merging to `main`
  and deleting the branch.
- **One open feature branch at a time, ideally.** If a second branch is
  already open, ask the user whether to land it first or rebase on top of
  it before starting the new work.
- **Never delete a branch the user hasn't seen working.** Confirm it's
  merged (or its work is captured elsewhere) before deletion.

### Don't leave scratch files in the project root

Past sessions have left behind files like `app.OLD.py`, `app_new.py`,
`debug_recon.py`, `test_login.py`, `frontend_api.jsx`, `Hello.py`. These
make it impossible to tell what's real. Rules:

- **No `*.OLD.py`, `*_new.py`, `*_old.*`, `_backup.*` files.** If you need
  to keep an old version around, that's what git history is for — make a
  commit instead.
- **No throwaway scripts in the project root.** If you genuinely need a
  one-off debug script, put it under `scratch/` (which is in
  `.gitignore`) and tell the user it's there.
- **If you find existing scratch files**, list them for the user and ask
  which to delete — don't silently remove them, and don't silently
  leave them lying around.

---

## 5. Quick sanity checklist for the next agent

Before you push anything that touches auth or the index page:

- [ ] `grep -n "LoginScreen\|handleLogin\|handleLogout\|/api/auth/login\|/api/auth/logout" static/index.html` returns nothing.
- [ ] `grep -n "check_password_hash\|session\[" app.py` returns nothing.
- [ ] `curl -s http://127.0.0.1:5000/api/auth/me` returns `"authenticated": true` with no cookie sent.
- [ ] `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/api/dashboard` returns `200`, not `401`.
- [ ] `git log origin/<your-branch> --oneline` shows your new commit.

If any of those fail, the task is not done.

---

## 6. Closing out a feature branch

When the user confirms a fix works in the browser:

1. From the project folder, on the feature branch:
   `git checkout main && git pull origin main`
   `git merge --no-ff <feature-branch>`
   `git push origin main`
2. Delete the local and remote branches:
   `git branch -d <feature-branch>`
   `git push origin --delete <feature-branch>`
3. Tell the user the branch is closed and which commit on `main` carries
   the fix.

Do not skip step 1's `git pull origin main` — `main` may have moved
forward via another branch's merge while you were working.

