# Configurable Kanban Statuses Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the kanban status machine configurable via `config/statuses.config.json` — adding `Blocked` and `Ready to deploy` (terminal, commit-coupled), removing `Completed`, and assigning each status an owner (team or single agent) that both gates and routes work.

**Architecture:** One global JSON board config becomes the single source of truth for both state machines (features, tasks). All docs (vocabulary, lifecycle, team-roles, orchestration, role briefs, adapters) defer to it; adapters keep their current values only as shipped defaults. A `validate-board` launcher subcommand (python3-backed) enforces structural rules and runs before every team launch. Spec: `docs/superpowers/specs/2026-07-06-kanban-status-config-design.md`.

**Tech Stack:** Bash 3.2-portable shell (launcher), python3 (JSON validation only), Markdown docs. No new dependencies.

## Global Constraints

- Terminal task status is named exactly **`Ready to deploy`** (NOT "Ready for production", NOT "Done", NOT "Completed").
- Bracket notation everywhere: `[Planned]`, `[Active]`, `[Review]`, `[Blocked]`, `[Ready to deploy]`, `[Resolved]` — exact case.
- Generic status `[Completed]` must not survive anywhere outside git history and `.workspace/` scratch files.
- `bin/launch-team.sh` stays bash 3.2-portable (no associative arrays, no `${var,,}`); JSON parsing only via `python3`.
- Owner field is exactly one of `{"role": "<name>"}` or `{"team": "<preset>"}`. Abstract role names: `implementer`, `reviewer`, `coordinator`, `finalizer`; concrete roles resolve to `roles/<name>.md` or `teams/roles/<name>.md`; teams resolve to `teams/<name>.md`.
- Blocked vs andon stay distinct: `[Blocked]` = work can't proceed (a configured status with an owner); andon = process is broken (no status write, stop and report).
- All work happens on branch `feature/agent-teams`. Commit after every task.

---

### Task 1: Default board config + config pointer

**Files:**
- Create: `config/statuses.config.json`
- Modify: `config/project-management.config.md` (Optional Behaviour Flags block, lines 61–65)

**Interfaces:**
- Produces: `config/statuses.config.json` with top-level keys `features.statuses[]` and `tasks.statuses[]`; per-status fields `name`, `initial?`, `terminal?`, `requiresCommit?`, `owner` (`{"role":...}` or `{"team":...}`), `transitions[]`, `tool{}`. Every later task reads this file.

- [ ] **Step 1: Create `config/statuses.config.json`**

```json
{
  "features": {
    "statuses": [
      { "name": "Planned", "initial": true,
        "owner": { "role": "team-lead" },
        "transitions": ["Active"],
        "tool": { "Linear": "Planned", "Jira": "To Do", "GitHubIssues": "milestone open, no task started", "Markdown": "[Planned]" } },
      { "name": "Active",
        "owner": { "role": "team-lead" },
        "transitions": ["Resolved"],
        "tool": { "Linear": "In Progress", "Jira": "In Progress", "GitHubIssues": "milestone open, >=1 task active (derived)", "Markdown": "[Active]" } },
      { "name": "Resolved", "terminal": true,
        "owner": { "role": "team-lead" },
        "transitions": [],
        "tool": { "Linear": "Completed", "Jira": "Done", "GitHubIssues": "milestone closed", "Markdown": "[Resolved]" } }
    ]
  },
  "tasks": {
    "statuses": [
      { "name": "Planned", "initial": true,
        "owner": { "role": "team-lead" },
        "transitions": ["Active"],
        "tool": { "Linear": "Todo", "Jira": "To Do", "GitHubIssues": "open + label status:planned", "Markdown": "[Planned]" } },
      { "name": "Active",
        "owner": { "role": "implementer" },
        "transitions": ["Review", "Blocked"],
        "tool": { "Linear": "In Progress", "Jira": "In Progress", "GitHubIssues": "open + label status:active", "Markdown": "[Active]" } },
      { "name": "Review",
        "owner": { "role": "reviewer" },
        "transitions": ["Active", "Ready to deploy", "Blocked"],
        "tool": { "Linear": "In Review", "Jira": "In Review", "GitHubIssues": "open + label status:review", "Markdown": "[Review]" } },
      { "name": "Blocked",
        "owner": { "role": "team-lead" },
        "transitions": ["Planned", "Active", "Review"],
        "tool": { "Linear": "Blocked", "Jira": "Blocked", "GitHubIssues": "open + label status:blocked", "Markdown": "[Blocked]" } },
      { "name": "Ready to deploy", "terminal": true, "requiresCommit": true,
        "owner": { "role": "integrator" },
        "transitions": [],
        "tool": { "Linear": "Done", "Jira": "Done", "GitHubIssues": "closed", "Markdown": "[Ready to deploy]" } }
    ]
  }
}
```

Note the task-status tool values match the adapters' existing shipped defaults (Linear `Todo`, not the spec's illustrative `Backlog`).

- [ ] **Step 2: Verify it parses**

Run: `python3 -c "import json; c=json.load(open('config/statuses.config.json')); print(len(c['tasks']['statuses']), 'task statuses')"`
Expected: `5 task statuses`

- [ ] **Step 3: Add the pointer to `config/project-management.config.md`**

Replace the Optional Behaviour Flags code block:

```
TEAM_MODE=false        # true enables the status-ownership model in reference/team-roles.md
STRICT_STATUS=true     # true = refuse an action if the item is not in the expected status
                       #        (the "andon cord" — see reference/lifecycle.md)
```

with:

```
TEAM_MODE=false        # true enables the status-ownership model in reference/team-roles.md
STRICT_STATUS=true     # true = before any write, verify the current status and that the
                       #        intended move is in that status's transitions list
                       #        (the "andon cord" — see reference/lifecycle.md)
STATUS_CONFIG=config/statuses.config.json   # the kanban board: statuses, transitions,
                                            # owners, per-tool mappings (skill-relative path)
```

- [ ] **Step 4: Commit**

```bash
git add config/statuses.config.json config/project-management.config.md
git commit -m "feat: add configurable kanban board config (statuses.config.json)"
```

---

### Task 2: `validate-board` subcommand + board in composed prompts (TDD)

**Files:**
- Modify: `bin/launch-team.sh` (add `validate_board()` after `roster_of()` ~line 51; extend `compose_prompt()` ~line 95; add `validate-board` case + call it in `team` case ~line 131; extend usage comment lines 5–11 and the `*)` usage string)
- Test: `tests/launcher-test.sh`

**Interfaces:**
- Consumes: `config/statuses.config.json` (Task 1).
- Produces: `bin/launch-team.sh validate-board [config-path]` — exit 0 + `board config OK: <path>` on stdout, exit 1 with `validate-board: <problem>` lines on stderr otherwise. `compose_prompt` output now ends with a `# Board config` section containing the JSON. The `team` subcommand validates before launching.

- [ ] **Step 1: Add failing tests to `tests/launcher-test.sh`**

The fixture (line 20–21) copies `roles reference bin teams` and then creates `config/` — add the board config to the fixture. After line 21 (`mkdir -p .claude/skills/pm/config`) insert:

```bash
cp "$SKILL_DIR/config/statuses.config.json" .claude/skills/pm/config/
```

Insert this block before the `# -- status + stop` section (line 103):

```bash
# -- validate-board: shipped config passes --------------------------------------
check "validate-board accepts shipped config" "$LAUNCH" validate-board

# -- validate-board: prompt composition includes the board ----------------------
check "prompt contains board config" grep -q '"Ready to deploy"' .teamwork/test-feature/prompts/backend.md

# -- validate-board: each broken config is refused with the right message -------
bad() { # bad <desc> <needle> <json>
  local desc="$1" needle="$2" json="$3" out
  printf '%s' "$json" > "$TMP/bad.json"
  if out="$("$LAUNCH" validate-board "$TMP/bad.json" 2>&1)"; then
    echo "FAIL: $desc (accepted)"; FAILURES=$((FAILURES+1))
  elif printf '%s' "$out" | grep -q "$needle"; then
    echo "ok: $desc"
  else
    echo "FAIL: $desc (wrong message: $out)"; FAILURES=$((FAILURES+1))
  fi
}
MINF='"features":{"statuses":[{"name":"P","initial":true,"owner":{"role":"team-lead"},"transitions":["R"]},{"name":"R","terminal":true,"owner":{"role":"team-lead"},"transitions":[]}]}'
bad "invalid JSON refused"            "invalid JSON" '{nope'
bad "two initials refused"            "exactly one initial" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"initial\":true,\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "unknown transition refused"      "undefined status" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Nope\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "unreachable status refused"      "unreachable" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]},{\"name\":\"Island\",\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]}]}}"
bad "terminal with outbound refused"  "terminal status must have empty transitions" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"A\"]}]}}"
bad "bad owner refused"               "unknown role" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"nobody-such\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "two-key owner refused"           "exactly one of" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\",\"team\":\"full-stack\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "requiresCommit on initial refused" "not allowed on the initial" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"requiresCommit\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"Z\"]},{\"name\":\"Z\",\"terminal\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[]}]}}"
bad "no terminal refused"             "at least one terminal" "{$MINF,\"tasks\":{\"statuses\":[{\"name\":\"A\",\"initial\":true,\"owner\":{\"role\":\"team-lead\"},\"transitions\":[\"A\"]}]}}"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bash tests/launcher-test.sh 2>&1 | tail -20`
Expected: FAIL lines for every new check (the subcommand doesn't exist yet — usage error), ending `N FAILURE(S)`.

- [ ] **Step 3: Implement `validate_board()` in `bin/launch-team.sh`**

Insert after `roster_of()` (after line 51):

```bash
validate_board() { # validate_board [config-path] — structural checks on the board config
  local cfg="${1:-$SKILL_DIR/config/statuses.config.json}"
  [ -f "$cfg" ] || die "no board config: $cfg"
  command -v python3 >/dev/null 2>&1 || die "validate-board requires python3"
  python3 - "$cfg" "$SKILL_DIR" <<'PYEOF'
import json, sys, os
cfg_path, skill_dir = sys.argv[1], sys.argv[2]
try:
    with open(cfg_path) as f:
        cfg = json.load(f)
except ValueError as e:
    print("validate-board: invalid JSON: %s" % e, file=sys.stderr); sys.exit(1)

ABSTRACT_ROLES = {"implementer", "reviewer", "coordinator", "finalizer"}
errors = []

def role_exists(name):
    return (name in ABSTRACT_ROLES
            or os.path.isfile(os.path.join(skill_dir, "roles", name + ".md"))
            or os.path.isfile(os.path.join(skill_dir, "teams", "roles", name + ".md")))

def team_exists(name):
    return os.path.isfile(os.path.join(skill_dir, "teams", name + ".md"))

for machine in ("features", "tasks"):
    statuses = cfg.get(machine, {}).get("statuses")
    if not isinstance(statuses, list) or not statuses:
        errors.append("%s: missing or empty 'statuses' list" % machine); continue
    names = [s.get("name") for s in statuses]
    for d in sorted(set(n for n in names if names.count(n) > 1)):
        errors.append("%s: duplicate status name '%s'" % (machine, d))
    by_name = dict((s.get("name"), s) for s in statuses)
    initials = [s for s in statuses if s.get("initial")]
    if len(initials) != 1:
        errors.append("%s: exactly one initial status required, found %d" % (machine, len(initials)))
    if not any(s.get("terminal") for s in statuses):
        errors.append("%s: at least one terminal status required" % machine)
    for s in statuses:
        name = s.get("name") or "<unnamed>"
        trans = s.get("transitions")
        if not isinstance(trans, list):
            errors.append("%s/%s: 'transitions' must be a list" % (machine, name)); trans = []
        for t in trans:
            if t not in by_name:
                errors.append("%s/%s: transition to undefined status '%s'" % (machine, name, t))
        if s.get("terminal") and trans:
            errors.append("%s/%s: terminal status must have empty transitions" % (machine, name))
        if s.get("requiresCommit") and s.get("initial"):
            errors.append("%s/%s: requiresCommit not allowed on the initial status" % (machine, name))
        owner = s.get("owner")
        if not isinstance(owner, dict) or len(owner) != 1 or list(owner)[0] not in ("role", "team"):
            errors.append("%s/%s: owner must be exactly one of {\"role\": ...} or {\"team\": ...}" % (machine, name))
        else:
            kind, val = list(owner.items())[0]
            if kind == "role" and not role_exists(val):
                errors.append("%s/%s: unknown role '%s'" % (machine, name, val))
            if kind == "team" and not team_exists(val):
                errors.append("%s/%s: unknown team preset '%s'" % (machine, name, val))
    if len(initials) == 1:
        seen, stack = set(), [initials[0].get("name")]
        while stack:
            n = stack.pop()
            if n in seen: continue
            seen.add(n)
            t = by_name.get(n, {}).get("transitions")
            for nxt in (t if isinstance(t, list) else []):
                if nxt in by_name: stack.append(nxt)
        for n in by_name:
            if n not in seen:
                errors.append("%s: status '%s' unreachable from the initial status" % (machine, n))

if errors:
    for e in errors: print("validate-board: %s" % e, file=sys.stderr)
    sys.exit(1)
print("board config OK: %s" % cfg_path)
PYEOF
}
```

- [ ] **Step 4: Wire the subcommand, the `team` pre-check, and prompt composition**

In the `case` statement add before `*)`:

```bash
  validate-board)
    [ $# -le 2 ] || die "usage: validate-board [config-path]"
    validate_board "${2:-}"
    ;;
```

In the `team)` case, after `roster="$(roster_of "$preset")"` validation and before the `for role` loop, add:

```bash
    validate_board >/dev/null
```

In `compose_prompt()`, after `cat "$CONFIG"` (line 94) and before the closing `} > "$out"`, add:

```bash
    if [ -f "$SKILL_DIR/config/statuses.config.json" ]; then
      echo
      echo "---"
      echo "# Board config (config/statuses.config.json)"
      cat "$SKILL_DIR/config/statuses.config.json"
    fi
```

Update the usage comment (line 5–11) and the final `die "usage: launch-team.sh {team|start|relaunch|worktree|status|stop} ..."` to include `validate-board`:

```bash
    die "usage: launch-team.sh {team|start|relaunch|worktree|validate-board|status|stop} ..."
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `bash tests/launcher-test.sh 2>&1 | tail -20`
Expected: `ALL PASS`

- [ ] **Step 6: Commit**

```bash
git add bin/launch-team.sh tests/launcher-test.sh
git commit -m "feat: validate-board subcommand; compose board config into agent prompts"
```

---

### Task 3: Rewrite `reference/vocabulary.md` status model

**Files:**
- Modify: `reference/vocabulary.md:33-66` (Status Model section), `:87` (invariant 3)

**Interfaces:**
- Consumes: `config/statuses.config.json` field names (Task 1).
- Produces: the canonical prose rule "next status = a status in the current status's `transitions` list" that Tasks 4–9 reference.

- [ ] **Step 1: Replace the entire `## Status Model` section (lines 33–66, up to but not including `## Identifiers`) with:**

```markdown
## Status Model

Statuses are **configured, not fixed**. The single source of truth is
`config/statuses.config.json`: for features and for tasks it defines the status list,
each status's legal outbound `transitions`, its `owner` — the team or single agent that
works items sitting in that status — and per-adapter `tool` mappings.

Rules that hold for every board:

- **Bracket notation.** Write any status exactly as `[Status Name]` — bracketed, exact
  case, greppable (`[Planned]`, `[Ready to deploy]`).
- **Exactly one `initial` status** per machine — where new items are created.
- **At least one `terminal` status** — where work ends; it has no outbound transitions.
- **`requiresCommit`** — entering such a status is atomically coupled to a successful
  commit, performed by that status's owner.
- **"Next status" means a status listed in the current status's `transitions`.** Any
  other move is illegal — an **andon cord** condition (see `lifecycle.md`).

### The default board (shipped)

Features: `[Planned]` → `[Active]` → `[Resolved]`.

Tasks:

| Status | Owner (default) | Transitions to | Notes |
|---|---|---|---|
| `[Planned]` | team-lead | Active | initial |
| `[Active]` | implementer | Review, Blocked | |
| `[Review]` | reviewer | Active, Ready to deploy, Blocked | rework returns to Active |
| `[Blocked]` | team-lead | Planned, Active, Review | work is stuck; owner unblocks |
| `[Ready to deploy]` | integrator | — | terminal; `requiresCommit` |

This table is an **example** — the JSON is authoritative. Projects add, rename, or
remove statuses by editing the config; no other file changes as long as owners and
tool mappings are set. Validate edits with `bin/launch-team.sh validate-board`.
```

- [ ] **Step 2: Update invariant 3 (line 87)**

Old: `3. **Status is never skipped.** Move through the state machine in order.`
New: `3. **Status moves follow the configured \`transitions\` graph.** Never skip, invent, or reverse a move the board does not define.`

- [ ] **Step 3: Verify and commit**

Run: `grep -c 'Completed' reference/vocabulary.md`
Expected: `0`

```bash
git add reference/vocabulary.md
git commit -m "docs: vocabulary defers status model to statuses.config.json"
```

---

### Task 4: Rewrite `reference/lifecycle.md` scenarios

**Files:**
- Modify: `reference/lifecycle.md` (Scenario 2 step 2–3, Scenario 4 tail, Scenario 5, new Blocked scenario, Scenario 7 intro, quick-reference table)

**Interfaces:**
- Consumes: vocabulary rule from Task 3; config from Task 1.
- Produces: scenario numbering — Blocked becomes **Scenario 7**, andon shifts to **8**, connect/switch tools to **9**. Tasks 5–9 cite "Scenario 7 (Block)" and "Scenario 8 (andon)".

- [ ] **Step 1: Scenario 2 — config-driven start**

Replace step 2 (lines 40–41):

```markdown
2. **Verify the status is the board's initial status** (`[Planned]` on the default
   board). If it isn't and `STRICT_STATUS=true`, pull the **andon cord** (Scenario 8).
   Don't start work on something already `[Active]` elsewhere.
```

- [ ] **Step 2: Scenario 4 — transitions-graph wording**

Replace the closing paragraph (lines 76–77):

```markdown
If review finds problems: **move the [task] back to `[Active]`**, fix, and return to
`[Review]`. Backward moves are legal exactly where `config/statuses.config.json` lists
them (on the default board: `Review → Active`, plus the `Blocked` returns).
```

- [ ] **Step 3: Replace Scenario 5 entirely**

```markdown
## Scenario 5 — Finalize a [task]

Only after the work is reviewed **and** verified (tests/build green, change actually does
what the [task] asked):

1. Confirm the [task] is in `[Review]`. If not, andon cord.
2. The terminal status carries `requiresCommit: true` on the default board: **commit the
   work and move the [task] to `[Ready to deploy]` as one atomic step** — never one
   without the other. Cite the commit hash in the completion comment.
3. If **all** [tasks] in the [feature] have reached the terminal status, move the
   [feature] to `[Resolved]`.

`[Ready to deploy]` means: reviewed, verified, committed — awaiting deployment by humans.
**Never** move work there that was skipped, partially done, or has failing tests — see
the fail-loud invariant.
```

- [ ] **Step 4: Insert new Scenario 7 (Block) after Scenario 6, renumber old 7→8, 8→9**

```markdown
## Scenario 7 — Block a [task]

When the *work* cannot proceed — missing dependency, unanswered question, broken
external service — and it isn't a process failure (that's the andon cord, Scenario 8):

1. **Add a comment** stating what is blocking, what was tried, and what would unblock.
2. **Move the [task] to `[Blocked]`** via the adapter. The board's owner of `[Blocked]`
   (default: team-lead) now owns resolving it.
3. The `[Blocked]` owner works the blocker and, once cleared, **moves the [task] back**
   to the appropriate working status (`Planned`, `Active`, or `Review` on the default
   board) with a comment saying what changed.
```

Also update the two cross-references to the old numbering: Scenario 2 step 2 already says "Scenario 8" (Step 1 above); line 41's original "(Scenario 7)" occurrences elsewhere: search `Scenario 7` and `Scenario 8` and fix each to the new numbers.

- [ ] **Step 5: Update the quick-reference table (lines 136–147)**

```markdown
| Scenario | Writes |
|---|---|
| 1 Plan | create `[feature]` `[Planned]`; create `[tasks]` `[Planned]` |
| 2 Start | `[task]` → `[Active]` (feature → `[Active]` on first) |
| 3 Diverge | comment only |
| 4 Review | `[task]` → `[Review]` (or back to `[Active]` on rework) |
| 5 Finalize | commit + `[task]` → `[Ready to deploy]` (atomic); feature → `[Resolved]` when all done |
| 6 New work | create `[task]` `[Planned]` |
| 7 Block | comment + `[task]` → `[Blocked]`; owner routes it back when cleared |
| 8 Andon | **no write** — stop and report |
```

- [ ] **Step 6: Verify and commit**

Run: `grep -n 'Completed\|Scenario 7 — Andon\|Scenario 8 — Connect' reference/lifecycle.md`
Expected: no `[Completed]` matches; andon is Scenario 8; connect/switch is Scenario 9.

```bash
git add reference/lifecycle.md
git commit -m "docs: lifecycle scenarios follow the configured board; add Block scenario"
```

---

### Task 5: Rewrite `reference/team-roles.md` ownership as config-derived

**Files:**
- Modify: `reference/team-roles.md:34-49` (Transition ownership section)

**Interfaces:**
- Consumes: ownership rule from spec §2; default board from Task 1.
- Produces: the sentence "the owner of status S is the only party allowed to work items in S and to perform S's outbound transitions" — role briefs (Task 7) restate it.

- [ ] **Step 1: Replace the `## Transition ownership` section (table and intro, lines 34–49) with:**

```markdown
## Status ownership — derived from the board config

Ownership is no longer a hard-coded table. `config/statuses.config.json` assigns every
status an `owner` — a single agent (`{"role": ...}`) or a team (`{"team": ...}`). One
rule derives everything:

> **The owner of status S is the only party allowed to work items sitting in S, and the
> only one allowed to perform S's outbound transitions.**

Two refinements:

- **Entering a `requiresCommit` status** is performed by *that* status's owner, atomically
  with the commit (on the default board: the integrator commits and moves `[Review]` →
  `[Ready to deploy]` after both approvals exist).
- **Routing:** when an item enters a status, the mover notifies the new owner's mailbox
  (`reference/orchestration.md` → *Status routing*). A `{"team": ...}` owner is reached
  via that team's lead, who dispatches internally.

Worked example — the default board:

| Status | Owner | May perform |
|---|---|---|
| `[Planned]` | team-lead (Coordinator) | create [tasks]; sanction claims (`Planned → Active`) |
| `[Active]` | implementer | `Active → Review` (with `[review-request]`), `Active → Blocked` |
| `[Review]` | reviewer | `Review → Active` (findings); approval hands off to the integrator for `Review → Ready to deploy` |
| `[Blocked]` | team-lead | `Blocked → Planned / Active / Review` once cleared |
| `[Ready to deploy]` | integrator | terminal — the atomic commit+move that enters it |

Feature statuses: the team-lead owns all three (`Planned`, `Active`, `Resolved`) and
moves `[feature]` → `[Resolved]` only after the completion checklist passes.

If any role finds a [task] in an unexpected status, it **pulls the andon cord**: stop,
don't guess, escalate to the Coordinator (concrete role: `team-lead`).
```

- [ ] **Step 2: Update the coupling rules section (lines 53–63)**

Old first bullet: `- **Completion is coupled to a commit.** The Finalizer never marks \`[Completed]\` without a corresponding successful commit, and never commits a track without moving its [task] to \`[Completed]\`. The two are one atomic step.`
New: `- **Entering a \`requiresCommit\` status is coupled to a commit.** The Finalizer never moves a [task] to \`[Ready to deploy]\` without a corresponding successful commit, and never commits a track without the move. The two are one atomic step.`

- [ ] **Step 3: Verify and commit**

Run: `grep -c 'Completed' reference/team-roles.md`
Expected: `0`

```bash
git add reference/team-roles.md
git commit -m "docs: team-roles ownership derived from board config"
```

---

### Task 6: Update `reference/orchestration.md` — routing rule + terminal rename

**Files:**
- Modify: `reference/orchestration.md` (pipeline lines 98–115, integration lines 134–151, new Status routing section after line 83, supervision line 158–161, recovery line 186)

**Interfaces:**
- Consumes: routing semantics (spec §2), Scenario numbers from Task 4.
- Produces: `## Status routing` section that role briefs and team-roles cite.

- [ ] **Step 1: Insert after the Structured comments table (after line 83):**

```markdown
## Status routing

The board (`config/statuses.config.json`, composed into your startup prompt) assigns
every status an owner. **Whenever you move an item into a status, notify the new
owner's mailbox** (and, as always, the move itself lands as tracker state). If the
owner is a `{"team": ...}`, send to that team's lead, who dispatches internally.
The owner of a status is the only role that works items sitting in it and the only
one that performs its outbound transitions.
```

- [ ] **Step 2: Update the pipeline block (lines 100–115)**

In the fenced diagram replace the integrator line and the closing paragraph:

Old line: `      → integrator: verify lists == diff, stage explicitly, run VALIDATE_*,` / `        merge to the feature branch, commit, move to [Completed]   (atomic pair)`
New: `      → integrator: verify lists == diff, stage explicitly, run VALIDATE_*,` / `        merge to the feature branch, commit, move to [Ready to deploy] (atomic pair)`

Old paragraph (113–115): `The port's state machine is untouched: gates live in comments, statuses move only \`[Planned] → [Active] → [Review] → [Completed]\` (rework: \`[Review] → [Active]\`).`
New:

```markdown
Gates live in comments; statuses move only along the `transitions` graph in
`config/statuses.config.json`. Default board: `[Planned] → [Active] → [Review] →
[Ready to deploy]`, rework `[Review] → [Active]`, and `[Blocked]` as the parking
status for stuck work (owner: team-lead — see lifecycle Scenario 7).
```

- [ ] **Step 3: Integration section — rename terminal (lines 136–151)**

- Line 137: `marks \`[Completed]\`` → `marks \`[Ready to deploy]\``
- Line 147: `then immediately move the [task] to \`[Completed]\`` → `then immediately move the [task] to \`[Ready to deploy]\``
- Line 150: `When every [task] is \`[Completed]\`` → `When every [task] is \`[Ready to deploy]\``

- [ ] **Step 4: Supervision + recovery generalization**

- In Detect/Stuck (line 159–161) append a bullet: `- **Parked** — a [task] sitting in \`[Blocked]\` with no new comment past the threshold; the team-lead owns driving it out.`
- Line 186: `query the tracker for [tasks] assigned to your role in \`[Active]\`/\`[Review]\`` → `query the tracker for [tasks] assigned to your role in any non-terminal status`

- [ ] **Step 5: Verify and commit**

Run: `grep -c '\[Completed\]' reference/orchestration.md`
Expected: `0`

```bash
git add reference/orchestration.md
git commit -m "docs: orchestration adds status routing; terminal is Ready to deploy"
```

---

### Task 7: Update the 7 role briefs

**Files:**
- Modify: `roles/backend.md:39-43`, `roles/frontend.md:20-22`, `roles/integrator.md:3-7,33,49`, `roles/team-lead.md:13-14,51-52`, `roles/reviewer.md:26-28`, `roles/qa.md` (no status change needed — verify only), `roles/principal-architect.md` (no status change needed — verify only)

**Interfaces:**
- Consumes: ownership rule (Task 5), Scenario 7 Block (Task 4).
- Produces: none (leaf docs).

- [ ] **Step 1: `roles/backend.md` — allowed transitions + terminal rename**

Replace lines 39–43:

```markdown
- Merge, commit to the feature branch, or change any status except
  `[Planned]→[Active]` (claim), `[Active]→[Review]` (request review),
  `[Active]→[Blocked]` (stuck — with a comment saying what would unblock; the
  team-lead owns `[Blocked]`), and `[Review]→[Active]` (rework — moving your own
  [task] back when `[review-findings]` require fixes).
- Move anything to `[Ready to deploy]` — that is the integrator's atomic commit+move.
- Work around a failure. Process broken (adapter error, unexpected status) → `[andon]`
  + mailbox to `team-lead`; work stuck → `[Blocked]` (lifecycle Scenario 7).
```

- [ ] **Step 2: `roles/frontend.md` — backward-move wording (lines 20–22)**

Old: `your [task] back: comment, move \`[Review]→[Active]\` (this is the one legal backward move), adapt, re-request review.`
New: `your [task] back: comment, move \`[Review]→[Active]\` (rework, per the board's transitions), adapt, re-request review.`

- [ ] **Step 3: `roles/integrator.md` — terminal rename**

- Line 4: `commits, and marks [tasks] \`[Completed]\`` → `commits, and marks [tasks] \`[Ready to deploy]\``
- Line 33: `move the [task] to \`[Completed]\` via the adapter` → `move the [task] to \`[Ready to deploy]\` via the adapter`
- Line 49: `- Mark \`[Completed]\` without a commit, or commit without marking \`[Completed]\`.` → `- Mark \`[Ready to deploy]\` without a commit, or commit without the move — they are one atomic pair.`

- [ ] **Step 4: `roles/team-lead.md` — Blocked ownership + checklist rename**

After line 14 (`- The feature-completion checklist and moving the [feature] to \`[Resolved]\`.`) add:

```markdown
- The `[Blocked]` queue: you own every [task] in `[Blocked]` — drive each blocker to
  resolution and route the [task] back to its working status (lifecycle Scenario 7).
```

Line 52: `- every [task] is \`[Completed]\` with a commit hash cited;` → `- every [task] is \`[Ready to deploy]\` with a commit hash cited;`

- [ ] **Step 5: `roles/reviewer.md` — approval handoff (lines 26–28)**

Old: `Send problems immediately as one \`[review-findings]\` comment with numbered items — the [task] goes back to \`[Active]\`; the implementer fixes and re-requests.`
New: `Send problems immediately as one \`[review-findings]\` comment with numbered items — the [task] goes back to \`[Active]\`; the implementer fixes and re-requests. On approval, your \`[review-approval]\` (plus the architecture approval) hands the [task] to the integrator, who performs the atomic commit + move to \`[Ready to deploy]\`.`

- [ ] **Step 6: Verify and commit**

Run: `grep -rn '\[Completed\]' roles/`
Expected: no matches.

```bash
git add roles/
git commit -m "docs: role briefs follow board ownership; Blocked flow; Ready to deploy"
```

---

### Task 8: Adapters defer to the board config

**Files:**
- Modify: `adapters/_TEMPLATE.md:36-52`, `adapters/Linear.md`, `adapters/Jira.md`, `adapters/GitHubIssues.md`, `adapters/Markdown.md` (each: Feature + Task Status Mapping sections; setup section gets one line)

**Interfaces:**
- Consumes: `tool` map semantics from Task 1.
- Produces: none (leaf docs).

- [ ] **Step 1: `adapters/_TEMPLATE.md` — replace both mapping sections (lines 36–51) with:**

```markdown
## Status Mapping

Statuses come from `config/statuses.config.json` — each status's `tool` map holds this
adapter's concrete value under the `"<ToolName>"` key. This adapter's *mechanism* for
setting a status is: <how a status is represented and changed in this tool>.

**Missing mapping = andon.** If a status has no `"<ToolName>"` entry, or the tool's
workspace lacks the mapped state, stop and report — never invent a fallback status.

Shipped defaults (the default board):

| Status | <ToolName> |
|---|---|
| `[Planned]` | <...> |
| `[Active]` | <...> |
| `[Review]` | <...> |
| `[Blocked]` | <...> |
| `[Ready to deploy]` | <...> |

Feature statuses `[Planned]` / `[Active]` / `[Resolved]` map to <...>.
```

- [ ] **Step 2: `adapters/Linear.md` — same structure, concrete values**

Replace the Feature Status Mapping and Task Status Mapping sections with the template
structure from Step 1, filled in: mechanism = *issue workflow state (team-configurable
names); project state for features*. Task defaults: Planned→Todo, Active→In Progress,
Review→In Review, Blocked→Blocked, Ready to deploy→Done. Features: Planned→Planned,
Active→In Progress, Resolved→Completed. Keep the existing note that Linear team states
are renameable. Add to the *MCP / CLI Setup* section:

```markdown
> Make sure every status in `config/statuses.config.json` has a matching workflow state
> in your Linear team (e.g. create a "Blocked" state) — a missing state is an andon stop.
```

- [ ] **Step 3: `adapters/Jira.md` — same, concrete values**

Mechanism = *workflow transition on the Story/Epic*. Task defaults: Planned→To Do,
Active→In Progress, Review→In Review, Blocked→Blocked, Ready to deploy→Done. Features
(Epic): Planned→To Do, Active→In Progress, Resolved→Done. Keep the existing
customized-workflow note. Same setup line as Step 2, adapted: statuses must exist as
workflow states/transitions in the Jira project.

- [ ] **Step 4: `adapters/GitHubIssues.md` — same, concrete values**

Mechanism = *open/closed + one `status:*` label (setting a status removes the previous
`status:*` label)*. Task defaults: Planned→open + `status:planned`, Active→open +
`status:active`, Review→open + `status:review`, Blocked→open + `status:blocked`,
Ready to deploy→closed. Features (milestone): unchanged derivation, Resolved→closed.
Setup line: create the `status:*` labels for every non-terminal status in the board.

- [ ] **Step 5: `adapters/Markdown.md` — config-verbatim rule**

Replace both mapping sections with:

```markdown
## Status Mapping

Status is literal bracket text (on the feature's title line; at the end of a task's
`##` header). This adapter writes each status's `"Markdown"` value from
`config/statuses.config.json` verbatim — custom boards work with no setup at all.

Shipped defaults: `[Planned]`, `[Active]`, `[Review]`, `[Blocked]`,
`[Ready to deploy]` for tasks; `[Planned]`, `[Active]`, `[Resolved]` for features.
```

- [ ] **Step 6: Verify and commit**

Run: `grep -rn '\[Completed\]' adapters/`
Expected: no matches.

```bash
git add adapters/
git commit -m "docs: adapters defer status mapping to the board config"
```

---

### Task 9: README, SKILL.md, teams/_PLAYBOOK.md

**Files:**
- Modify: `SKILL.md:22-24,62-68`, `README.md:79-82,220-224,266-270,299-302` + new board subsection in the configuration part, `teams/_PLAYBOOK.md:20-22,51-56`

**Interfaces:**
- Consumes: everything above.
- Produces: none (leaf docs).

- [ ] **Step 1: `SKILL.md` golden rule (line 23)**

Old: `> user — use only the generic vocabulary — terms \`[feature]\`, \`[task]\`, \`[subtask]\` and statuses \`[Planned]\`/\`[Active]\`/\`[Review]\`/\`[Completed]\`. Never write "issue", "epic",`
New: `> user — use only the generic vocabulary — terms \`[feature]\`, \`[task]\`, \`[subtask]\` and the statuses defined in \`config/statuses.config.json\` (default board: \`[Planned]\`/\`[Active]\`/\`[Review]\`/\`[Blocked]\`/\`[Ready to deploy]\`). Never write "issue", "epic",`

- [ ] **Step 2: `SKILL.md` invariants (lines 63–68)**

```markdown
- **Never skip a status transition.** Legal moves are the `transitions` graph in
  `config/statuses.config.json` (default board:
  `[Planned]` → `[Active]` → `[Review]` → `[Ready to deploy]`, rework `[Review]` → `[Active]`,
  `[Blocked]` for stuck work).
- **When `STRICT_STATUS=true`, verify the current status before writing** and that the
  intended move is in its `transitions` list. If not, pull the andon cord instead of
  forcing the change.
- **`[Ready to deploy]` means verified-done** — reviewed, tests/build green, and committed
  (the move and the commit are one atomic step). Never mark work done that was skipped
  or is failing.
```

- [ ] **Step 3: `README.md` status mentions**

- Line 81: `Complete task 1.     → verified + [Completed]` → `Finalize task 1.     → verified, committed + [Ready to deploy]`
- Line 223: `- *"Send it to review"* / *"Complete it"* → \`[Review]\` → \`[Completed]\`` → `- *"Send it to review"* / *"Finalize it"* → \`[Review]\` → \`[Ready to deploy]\``
- Line 268: `\`[Completed]\` (commit and completion are one atomic step).` → `\`[Ready to deploy]\` (commit and the move are one atomic step).`
- Line 301: `[Planned] [Active] [Review] [Completed]` → `statuses from statuses.config.json` (keep the ASCII box aligned — pad with spaces to the same width).

- [ ] **Step 4: `README.md` — add a board subsection in the configuration section**

Immediately after the existing tracker-selection explanation (the part describing
`config/project-management.config.md`), insert:

```markdown
### Configure your board

`config/statuses.config.json` defines the kanban board: every status, its legal
`transitions`, its `owner` (the team or single agent that works items in that status),
and per-tracker `tool` mappings. Default board: `Planned → Active → Review → Ready to
deploy`, with `Blocked` as the parking status for stuck work. Add, rename, or remove
statuses by editing the JSON — then run `bin/launch-team.sh validate-board` to check it.
Make sure your tracker has a matching state for every status (the Markdown tracker
needs nothing).
```

- [ ] **Step 5: `teams/_PLAYBOOK.md`**

- Line 22: `every other required approval for that [task] is already on record. Work is "done" only after QA's approval AND the integrator's merge + \`[Completed]\`.` → `every other required approval for that [task] is already on record. Work is "done" only after QA's approval AND the integrator's merge + \`[Ready to deploy]\`.`
- Line 53: `the approvals and file lists, validates, merges, commits, and marks \`[Completed]\` — the atomic pair. Every preset roster includes it.` → `the approvals and file lists, validates, merges, commits, and marks \`[Ready to deploy]\` — the atomic pair. Every preset roster includes it.`
- Line 54: `7. **Close.** When all [tasks] are \`[Completed]\`: the architect runs the feature` → `7. **Close.** When all [tasks] are \`[Ready to deploy]\`: the architect runs the feature`

- [ ] **Step 6: Verify and commit**

Run: `grep -rn '\[Completed\]' README.md SKILL.md teams/_PLAYBOOK.md`
Expected: no matches.

```bash
git add README.md SKILL.md teams/_PLAYBOOK.md
git commit -m "docs: README/SKILL/playbook document the configurable board"
```

---

### Task 10: Final sweep and full test run

**Files:**
- Test: `tests/launcher-test.sh` (run only)

**Interfaces:**
- Consumes: all prior tasks.

- [ ] **Step 1: Sweep for leftovers**

Run: `grep -rn '\[Completed\]\|Ready for production' --include='*.md' --include='*.sh' --include='*.json' . | grep -v '.git/' | grep -v '.workspace/' | grep -v '.remember/' | grep -v 'docs/superpowers/'`
Expected: no output. (The spec/plan under `docs/superpowers/` legitimately mention the old names when describing the change; `.workspace/` is scratch history.)

Also run: `grep -rn 'Ready for production' docs/superpowers/plans/`
Expected: no output.

- [ ] **Step 2: Full test suite**

Run: `bash tests/launcher-test.sh`
Expected: `ALL PASS`

- [ ] **Step 3: Validate the shipped board**

Run: `bin/launch-team.sh validate-board`
Expected: `board config OK: .../config/statuses.config.json`

- [ ] **Step 4: Commit anything the sweep fixed; otherwise no-op**

```bash
git add -u && git commit -m "chore: final sweep for configurable board rollout" || echo "nothing to fix"
```
