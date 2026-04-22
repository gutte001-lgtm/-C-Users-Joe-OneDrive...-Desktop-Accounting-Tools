See [AGENTS.md](./AGENTS.md). That file is the source of truth for all AI
agents working on this repo — same rules apply to Claude.

**Rule 0:** There is no login screen. Do not add one. See AGENTS.md §1.

**Rule 1:** Before writing any code, check for prior work on parallel
`claude/*` branches (`git fetch --all && git branch -r | grep claude/`).
If another session already did (or half-did) the task, surface it to the
user instead of redoing it. See AGENTS.md §4a.

**Rule 2:** The default branch is `master` (not `main`). Start every
feature branch from `master` and merge back to `master` when confirmed.

**Rule 3:** The historical branch ledger in AGENTS.md §7 is the map of
what lives on each unmerged branch. Update it when you merge or delete
a branch.
