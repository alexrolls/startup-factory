# Agent Team Orchestration — Design

**Date:** 2026-07-06
**Status:** Approved by user (interactive brainstorming session)
**Scope:** Extend the existing tool-agnostic project-management skill with an
LLM-agnostic multi-agent orchestration layer, and close the LLM-agnosticism gaps in
the existing bundle (MCP-only adapters, Claude-only install docs).

---

## 1. Goals

1. A **cross-functional team of AI agents** — potentially different LLMs/harnesses
   (Claude Code, Codex, Gemini CLI, Aider, …) — works on `[tasks]` of one `[feature]`
   largely independently.
2. A **Team Lead** agent supervises: detects stuck/conflicting/crashed agents and
   unblocks them autonomously, escalating to the human only as a last resort.
3. A **Principal Architect** agent holds technical veto authority: approves the
   feature's technical shape, gates every task behind a design review, and
   participates in every code review.
4. Everything is **framework-, language-, tracker-, and LLM-agnostic**: a few plain
   Markdown files + one launcher script, reusable in any repository.
5. Trackers are reachable via **MCP or API keys (REST)** — no harness capability is
   assumed beyond files, shell, and git.

Non-goals: building a runtime/daemon, changing the existing port (vocabulary,
statuses), or supporting non-git VCS in v1.

## 2. Architecture: two bounded contexts

```
┌────────────────────────────────────────────────────────────┐
│  ORCHESTRATION CONTEXT (new)                                │
│  roles/*.md · reference/orchestration.md ·                  │
│  config/team.config.md · bin/launch-team.sh                 │
│  who does what · how agents talk · how the lead unblocks    │
└──────────────────────────┬─────────────────────────────────┘
                           │ consumes only the port
┌──────────────────────────▼─────────────────────────────────┐
│  WORK-TRACKING CONTEXT (existing, interface unchanged)      │
│  reference/vocabulary.md · reference/lifecycle.md ·         │
│  adapters/<Tool>.md · config/project-management.config.md   │
└────────────────────────────────────────────────────────────┘
```

- Shared kernel / ubiquitous language: `reference/vocabulary.md` (`[feature]`,
  `[task]`, `[Planned]/[Active]/[Review]/[Completed]`, opaque IDs, banned terms).
- The orchestration context never names a tracker or an LLM. Trackers are behind the
  adapter port; LLMs are behind the launcher's command templates.
- The port's status state machine is **not extended**. Orchestration gates (design
  approval, dual review approval) are recorded as structured comments on the
  `[task]`, not as new statuses — so every existing adapter keeps working unchanged.

## 3. Coordination model (hybrid)

### 3.1 PM tool = single source of durable truth

- **Claiming** a `[task]` IS the `[Planned] → [Active]` transition plus setting the
  assignee to the role name, followed by a read-back verification (`STRICT_STATUS`).
  If the read-back shows another claimant, back off — the other agent won.
- **All coordination artifacts are comments on the `[task]`**: design notes, PA
  approvals/pushbacks, divergence notes, review findings, approvals with file lists,
  escalations. A decision that traveled by mailbox is not binding until it lands in
  the tracker.
- This is what makes the team LLM- and machine-agnostic: a Codex implementer and a
  Claude reviewer coordinate purely through Linear/Jira/GitHub/Markdown.

### 3.2 File mailboxes = low-latency transport, never truth

- Layout: `.teamwork/<team>/mailbox/<role>/NNN-<from>.md` — append-only numbered
  message files. Agents check their mailbox between work steps.
- Heartbeats: each agent rewrites `.teamwork/<team>/heartbeats/<role>` with a
  timestamp, its current `taskId`, and a one-line state between steps.
- `<team>` = the feature's git branch name.
- **Degradation rule:** no shared filesystem → skip mailboxes and heartbeats, poll
  the tracker instead. Same protocol, higher latency, nothing breaks.

### 3.3 Isolation and integration

- **One implementer per `[task]`** (claim-transition ownership enforces it).
- **One git worktree per implementer**: `.teamwork/<team>/worktrees/<role>-<taskId>`,
  branched off the feature branch.
- **Single Integrator** is the only agent that merges to the feature branch, and the
  only one that marks `[Completed]` — always atomically coupled with the merge/commit.

## 4. Roles (seven fixed briefs in `roles/`)

| Role | Persistence | Writes code? | Owns |
|---|---|---|---|
| team-lead | persistent | never | Planning (Scenario 1), roster composition, launching, supervision loop, unblock ladder, reassignment, feature-completion checklist |
| principal-architect | persistent | never | Planning approval, per-task design gate, architecture half of every code review, updating upcoming `[task]` descriptions from divergence notes |
| integrator | persistent | never (merges only) | Dual-approval verification, atomic staging by explicit file list, project validation commands, commit coupled with `[Completed]` |
| backend | per-task | yes | Claim → design note → implement in own worktree → divergence notes → "API ready" signal to frontend |
| frontend | per-task | yes | Same loop; mocks until "API ready"; design note states architectural impact |
| qa | per-task | tests only | Tests merged work; files discovered bugs as new `[tasks]` (Scenario 6); never fixes silently |
| reviewer | per-task | never | Three-phase review; approval message with explicit file list |

Rules:

- **Per-task roles are stateless.** Everything needed is on the `[task]`; business
  rules are repeated in every task description (implementers read only their task).
  A relaunched agent resumes purely from tracker state.
- **Authority split:** Team Lead owns process and people; Principal Architect owns
  technical decisions; scope/business-rule disputes escalate to the human.
- The Lead collapses the roster for small features (no frontend task → no frontend
  agent). Role files never change; the roster does.
- Role briefs are lean (~60–100 lines): mission, transition ownership, work loop,
  what to write where, non-negotiables. Shared mechanics live once in
  `reference/orchestration.md`.
- **QA work is itself tracked as `[tasks]`** (test tasks created during planning or
  via Scenario 6) and flows through the same lifecycle — claim, design note (test
  plan), implement, review, integrate. There is no side-channel QA step.

## 5. Task lifecycle with Principal Architect gates

The PA has three mandatory checkpoints:

1. **Feature planning.** The Lead drafts the feature/task breakdown; the PA reviews
   the technical shape (task boundaries, backend design, contracts, data model) and
   must approve **before anything is created in the tracker**.
2. **Design gate — every task, before any code.** After claiming, the implementer
   posts a **design note** comment (approach, API/contract changes, data-model
   changes, affected components) and pings the PA. The PA approves or pushes back
   with required changes; the loop repeats until approval. No implementation before
   PA approval. Backend tasks always get a full design review; frontend tasks state
   their architectural impact and can be fast-tracked ("no architectural impact —
   proceed").
3. **Code review — every task.** On `[Active] → [Review]`, two reviews run in
   parallel: the Reviewer's three-phase review and the PA's architecture review
   (design-note conformance, boundary violations, coupling, contract drift). The
   Integrator merges only with **both** approvals, each listing explicit file paths
   that must match `git diff --name-only` in the worktree.

Post-merge, the PA reads divergence notes and updates upcoming `[task]` descriptions
(blocking step before the next task set). The PA is the **only** role allowed to
edit task descriptions; implementers add comments only — the reviewer needs the
original ask.

### End-to-end flow per task

```
claim ([Planned]→[Active], assignee, read-back verify)
  → design note comment → PA approve (loop on pushback)
  → implement in worktree (subtasks as checklist; divergence notes as comments)
  → [Active]→[Review] + review-request comment (what changed, files, validation run)
  → Reviewer 3-phase ∥ PA architecture review   (findings → back to [Active], fix, re-review)
  → both approvals with explicit file lists
  → Integrator: verify approvals ∩ diff, stage explicitly, run VALIDATE_* commands,
    merge to feature branch, commit, mark [Completed]  (atomic pair)
  → PA divergence sweep updates upcoming [tasks]
  → feature [Resolved] when all [tasks] [Completed] (Lead runs completion checklist)
```

### Reviewer three-phase process (from PlatformPlatform, kept)

1. **Plan** — before reading any code: read the `[feature]` and `[task]`, extract all
   business rules/validations/edge cases, write an independent requirements
   checklist with an expected file list (anti-anchoring).
2. **Review** — per changed file, line by line; send findings immediately.
3. **Verify** — re-read fixes; every Phase-1 requirement gets a `file:line` citation
   and a test citation; approval list must equal the actual diff.

Anti-rationalization list applies ("it's just a warning", "pre-existing", "tools
passed so it must be fine" → all rejected).

## 6. Team Lead supervision loop

Perpetual cycle every `POLL_INTERVAL` (default ~2 min): read heartbeats, mailbox,
tracker; then act.

**Detects:**

1. **Stuck** — stale heartbeat; `[Active]` task with no comment past threshold;
   unanswered design note / question / review request (the PA is monitored like any
   agent — it is the hot path).
2. **Conflict** — two agents on one `[task]`; contradictory divergence notes; merge
   conflict reported by the Integrator; deadlock (A waits on B waits on A).
3. **Crash** — dead heartbeat + process gone.

**Unblock ladder (in order):**

1. **Message** the agent (mailbox ping + tracker comment) with a concrete
   question/instruction.
2. **Decide** — issue a binding process decision; technical disputes are delegated
   to the PA's ruling.
3. **Reassign** — revert the `[task]` to `[Planned]` with a handoff comment
   summarizing state; relaunch a fresh agent for it.
4. **Kill & relaunch** the wedged agent via `launch-team.sh relaunch <role>`; the
   replacement resumes from tracker state.
5. **Escalate to the human** — only for scope/business-rule questions, destructive
   actions, or after two failed unblock attempts. Escalation = tracker comment
   tagged to the user + an entry in `.teamwork/<team>/ESCALATIONS.md`.

**Hard limits on the Lead:** it never overrides the Integrator's validation failures
or the PA's technical veto (andon cord outranks the Lead — "zero tolerance, no
overrides"). During autonomous operation it never blocks the team waiting on an
interactive user prompt; it uses the escalation channel instead.

## 7. LLM-agnostic execution

### 7.1 Launcher

`bin/launch-team.sh`:

- Reads `config/team.config.md` for role → command templates:

  ```
  TEAM_LEAD_CMD="claude -p --dangerously-skip-permissions {prompt_file}"
  BACKEND_CMD="codex exec --approve-for-me {prompt_file}"
  REVIEWER_CMD="gemini --yolo {prompt_file}"
  ```

- Composes each agent's startup prompt from plain files — `roles/<role>.md` +
  `reference/orchestration.md` + team/feature identifiers — into
  `.teamwork/<team>/prompts/<role>.md`.
- Creates worktrees for implementers.
- Starts each agent in a tmux session per team (one window per agent — observable).
- `relaunch <role>` restarts a single agent (used by the Lead's ladder step 4).

### 7.2 Capability matrix & degradation

`orchestration.md` closes with the protocol's generic capability needs — file
read/write, shell, tracker access (via adapter), git + worktrees, long-running
loop — and per-harness notes. Inherited rule: **a missing capability degrades
explicitly, never silently** (no shared FS → poll tracker; no tmux → plain
background processes; agent must state what it could not verify).

### 7.3 Tracker access via API keys (adapter upgrades)

Linear and Jira adapters gain an **Access mechanisms** section with two peer
options, selected by a config line:

- **MCP** (as today), for harnesses with MCP clients.
- **REST via API key** — Linear GraphQL with `LINEAR_API_KEY`, Jira REST with
  `JIRA_API_TOKEN` — concrete `curl` templates for every row of the existing
  Operations table.

GitHubIssues already has the dual shape (`gh` CLI / MCP); Markdown needs nothing.

## 8. Error handling & recovery

Three fail-loud layers:

1. **Agent-level andon cord** — unexpected status, failed adapter operation, failed
   validation, blocked: stop, comment on the `[task]`, notify the Lead. Never work
   around, never fabricate.
2. **Lead-level unblock ladder** (§6).
3. **Human escalation** (§6, step 5).

**Recovery is trivial because the tracker is the truth:** a relaunched agent reads
its role brief, queries the tracker for its assigned `[Active]` task, reads the
comment trail (design note, PA approval, findings), and resumes. No session state
exists outside the tracker + worktree.

## 9. File plan

**New (9 files):**

| File | Content |
|---|---|
| `reference/orchestration.md` | The protocol: mailboxes/heartbeats, claiming, design gate, dual review, divergence-note rules, unblock ladder, escalation, recovery, capability matrix |
| `roles/team-lead.md` | Role brief |
| `roles/principal-architect.md` | Role brief |
| `roles/integrator.md` | Role brief |
| `roles/backend.md` | Role brief |
| `roles/frontend.md` | Role brief |
| `roles/qa.md` | Role brief |
| `roles/reviewer.md` | Role brief |
| `config/team.config.md` | Role→CLI map, `POLL_INTERVAL`, stuck thresholds, `.teamwork` root, `VALIDATE_BUILD`/`VALIDATE_TEST`/`VALIDATE_LINT` commands (keeps the Integrator framework-agnostic) |
| `bin/launch-team.sh` | Deliberately small: compose prompts, create worktrees, start/relaunch agents in tmux |

**New total: 10 artifacts** (9 Markdown files + 1 shell script).

**Changed (5 files):**

| File | Change |
|---|---|
| `SKILL.md` | Route team requests ("run a team on this feature", "launch the team") to the orchestration layer; reference `roles/` and `orchestration.md` in Mandatory Preparation when `TEAM_MODE=true` |
| `reference/team-roles.md` | Becomes the bridge: transition-ownership table extended with PA and Lead rows (design gate, dual approval), points to `roles/` for full briefs |
| `reference/lifecycle.md` | Scenario 2 gains the design-gate step; Scenario 3 fixed to the divergence protocol (comments are additive; only the PA edits descriptions) |
| `adapters/Linear.md`, `adapters/Jira.md` | Access-mechanisms section: MCP + REST/API-key with `curl` templates per operation |
| `README.md` | Orchestration overview diagram; host install/invocation matrix (Claude Code, Codex, Aider, Cursor, generic) modeled on ultra-review's |

## 10. Testing story

The `Markdown` adapter + a two-agent roster (team-lead + one backend implementer,
both possibly the same LLM) is a complete offline integration test of the protocol:
claiming, design gate (lead doubles as PA in the smoke test), mailboxes, heartbeats,
review, integration — no tracker account, network, or API key required. This is the
recommended first run in the README.

## 11. Decisions log (from the brainstorming session)

| Decision | Choice |
|---|---|
| Coordination medium | Hybrid: PM tool = durable truth; file mailboxes = low-latency transport; degrade to pure polling |
| Team roster | Fixed cross-functional roles (7, incl. Principal Architect added during review) |
| Execution | Launcher script + per-role CLI command templates + git worktree per implementer |
| Lead autonomy | Full (message → decide → reassign → kill/relaunch), human escalation as last resort |
| Packaging | Layered extension of this repo; orchestration context consumes the existing PM port |
| Status model | Unchanged — gates are structured comments, not new statuses |
| PA authority | Veto at planning, per-task design gate, and every code review; sole editor of task descriptions |
