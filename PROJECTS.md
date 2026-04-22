# Claude Projects — Master Index

This repo is the shared workspace for all Claude-assisted projects in this
folder. **Every agent should read this file before starting work, and update
it when finishing.** The goal is to prevent agents from overwriting each
other's changes or duplicating effort.

---

## Active Projects

### close-tool/
Flask-based month-end close checklist, reconciliation tracker, and
QuickBooks sync tool. Single-file frontend in `close-tool/static/index.html`,
SQLite backend at `close-tool/closeapp.db`.

- **Language / stack:** Python 3 + Flask + SQLite + APScheduler
- **Entrypoint:** `python close-tool/app.py` (runs on port 5000)
- **One-time setup:** `python close-tool/init_db.py` then
  `python close-tool/import_checklist.py` then `python close-tool/setup_auth.py`
- **Env vars:** `SECRET_KEY`, `QB_CLIENT_ID`, `QB_CLIENT_SECRET`,
  `QB_REDIRECT_URI`, `QB_REALM_ID`, `QB_ENVIRONMENT` (see `.env`, not committed)
- **Current period:** April 2026 (Period 4, 4-4-5 calendar)
- **Owner:** Joe Guttenplan

---

## Agent Coordination Rules

1. **Read first.** Before editing, read this file and the `README` (if any)
   inside the project folder you intend to touch.
2. **Stay in your lane.** Do not modify files in a project folder other than
   the one you were asked to work on, unless the task explicitly spans
   multiple projects.
3. **Declare active work.** Add a row to the "In Progress" table below at
   the start of a session; remove or update it when finished.
4. **One branch per concern.** Use a dedicated branch named
   `claude/<short-task-slug>` for each task. Do not commit unrelated changes
   together.
5. **Log outcomes.** When a session produces a meaningful change, append a
   line to the "Change Log" section with date, project, and one-sentence
   summary.
6. **Never delete another agent's in-progress work** without checking the
   "In Progress" table and the Git reflog first.

---

## In Progress

| Started (UTC)        | Agent / Session         | Project    | Branch                          | Summary                                      |
| -------------------- | ----------------------- | ---------- | ------------------------------- | -------------------------------------------- |
| _none_               |                         |            |                                 |                                              |

---

## Change Log

| Date       | Project    | Change                                                                 |
| ---------- | ---------- | ---------------------------------------------------------------------- |
| 2026-04-22 | (repo)     | Reorganized: moved close tool into `close-tool/`, added `PROJECTS.md`. |
| 2026-04-22 | close-tool | Initial commit — Flask month-end close tool.                           |

---

## Adding a New Project

1. Create a new top-level folder (kebab-case, e.g. `invoice-parser/`).
2. Put all code for that project inside it. Use `__file__`-relative paths so
   the project stays self-contained.
3. Add an entry to the "Active Projects" section above with stack,
   entrypoint, and owner.
4. If the project has its own dependencies, keep them in a
   `<project>/requirements.txt`. Do not add a shared top-level
   `requirements.txt`.
