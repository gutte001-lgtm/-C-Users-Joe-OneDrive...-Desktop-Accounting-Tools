# Active Agent Status

**Last updated:** 2026-04-22

Live "who is doing what right now" list. Managed by each Claude session per `CLAUDE.md`.

---

## Currently active

_No agents currently active._

---

## Entry format

When a session starts, it prepends an entry here:

```markdown
### <session-id> — <branch-name>
- **Started:** YYYY-MM-DD HH:MM UTC
- **Last activity:** YYYY-MM-DD HH:MM UTC
- **Working on:** <short description>
- **Files held:** app.py, static/index.html
- **Notes:** <anything future agents should know>
```

When the session ends, it moves the contents of its entry into a new `WORK_LOG.md` entry and **removes** its entry from here.
