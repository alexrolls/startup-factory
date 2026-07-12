# Agent Squad PM

**Ship faster with an AI engineering squad you can see, steer, and trust.**

Agent Squad PM turns Linear, Jira, GitHub Issues, or local Markdown into the
control plane for agentic development. Give the squad a feature and it plans,
designs, implements, reviews, validates, and integrates the work while your
project-management tool remains the single source of truth.

You get the speed of task-level parallelism without giving up control. Safe work
runs concurrently; architecture, QA, and integration stay behind explicit
gates. Plans, ownership, progress, decisions, evidence, blockers, and delivery
state remain visible where your team already manages the project.

![Agent Squad PM demo](exports/execmatchai-issues-57s-70s.gif)

```text
[feature] -> design gate -> safe parallel [tasks] -> review -> QA -> validated integration -> [Ready to deploy]
```

## Why Agent Squad PM

| Advantage | What it gives you |
|---|---|
| **Move fast without merge chaos** | A deterministic dispatcher launches only design-approved, dependency-ready, resource-safe work. Each attempt gets its own task branch and worktree; integration stays serialized. |
| **See the whole delivery, not just agent output** | One live `[progress]` record per `[task]` and one `[digest]` per `[feature]` show tracker status, execution stage, actor, and attempt in your project-management tool. |
| **Use the right model for each job** | Mix Claude, Codex, Gemini, or any file-reading CLI by role, then route individual tasks to fast, standard, or strong model profiles. |
| **Keep quality gates explicit** | Architecture approval precedes implementation. Review uses an exact package, QA re-runs required checks, and the integrator runs your build, test, and lint commands before merging. |
| **Recover instead of restarting** | Immutable task packets, durable events, checkpoint branches, an idempotent outbox, and attempt-aware relaunches make interrupted work inspectable and recoverable. |
| **Keep your stack and your tracker** | The same workflow runs across languages, frameworks, LLMs, and project-management tools. Start offline with Markdown and switch adapters without rewriting the process. |

## Full transparency in your tracker

Agent Squad PM treats the tracker as the durable collaboration surface, not a
status board updated after the real work happened. The local runtime makes
coordination fast, but the information a human needs to supervise delivery is
projected back into the configured tool.

| You can inspect | How it stays visible |
|---|---|
| Scope and execution order | `[features]`, `[tasks]`, dependencies, resource declarations, and legal board transitions |
| Design decisions | Structured design notes, pushback, approvals, conditions, and numbered architecture checklists |
| Live progress | A mechanically updated `[progress]` record on every task and a compact `[digest]` across the feature |
| Validation and review | Evidence records, changed-file lists, review findings, exact artifact paths, and explicit `NOT validated` declarations |
| Blockers and human decisions | Proven `blocked-by` relationships plus escalations with a question, options, and a default if you are unavailable |
| Delivery | The integrated commit, completed validation gates, and the final move to `[Ready to deploy]` |

Use as much of the system as your project needs:

| Layer | What it gives you | Where |
|---|---|---|
| **1. PM port** | One AI agent creates/tracks/completes `[features]` and `[tasks]` in any tracker through one tool-agnostic workflow. | `SKILL.md`, `reference/`, `adapters/` |
| **2. Governed squad** | A lead coordinates, an architect gates design, specialists implement, QA verifies, and an integrator alone writes the feature branch. | `reference/orchestration.md`, `roles/` |
| **3. Task-driven runtime** | Event-driven dispatch, bounded parallel waves, model routing, exact review packages, durable handoffs, and recoverable integration. | `bin/dispatch.sh`, `bin/runtime-state.py`, `bin/integrate-task.sh` |
| **4. Preset teams** | Five ready-made rosters for full-stack, backend, frontend, security, and infrastructure work, launchable with one command. | `teams/`, `bin/launch-team.sh` |

Everything is inspectable: plain Markdown, shell scripts, small Python utilities,
and git. There is no coordinator service or database to host. The system is
**language-, framework-, tracker-, and LLM-agnostic** because it manages the
delivery contract around the code rather than assuming anything about the stack.

---

## Table of contents

- [Why Agent Squad PM](#why-agent-squad-pm)
- [Full transparency in your tracker](#full-transparency-in-your-tracker)
- [Requirements](#requirements)
- [Quick Start (2 minutes, no accounts)](#quick-start-2-minutes-no-accounts)
- [Install into your repository](#install-into-your-repository)
- [Connect your LLM](#connect-your-llm)
- [Connect your tracker](#connect-your-tracker)
- [Configure](#configure)
- [Use it](#use-it)
- [The five preset teams](#the-five-preset-teams)
- [How it works](#how-it-works)
- [Directory map](#directory-map)
- [Extend it](#extend-it)
- [Troubleshooting](#troubleshooting)

---

## Requirements

**Minimum (single agent):** a git repository, a POSIX shell, and any agentic LLM
CLI or IDE that can read files (Claude Code, Codex CLI, Gemini CLI, Aider,
Cursor, Windsurf, Cline, …).

**For multi-agent teams, additionally:** the launcher (`bin/launch-team.sh`) needs
`bash` + `git`; every implementation task uses a task branch and isolated
worktree. `tmux` is optional but recommended — without it, agents run as
background processes.

**Tracker access is optional.** The default `Markdown` tracker stores everything
in local files, so you can run the whole thing offline. Connect Linear/Jira/GitHub
when you're ready — via MCP **or** a plain REST API key.

---

## Quick Start (2 minutes, no accounts)

The fastest win: one AI agent managing work in local Markdown files. No tracker
account, no API key, no config changes — `Markdown` is the default.

1. **Copy this bundle into your repo** (Claude Code's natural home shown; any
   agent can read it from any path):

   ```bash
   mkdir -p .claude/skills
   cp -R /path/to/this/bundle .claude/skills/agent_squad_pm
   ```

2. **Ask your agent, in plain language:**

   ```
   Plan a feature: add CSV export to the reports page.
   ```

   The skill creates a `[feature]` and a handful of `[tasks]` as Markdown files
   under `.workspace/task-manager/`. Then drive them:

   ```
   Start task 1.        → moves it to [Active], implements it
   Send task 1 to review.
   Finalize task 1.     → verified, committed + [Ready to deploy]
   ```

That's the whole loop — plan → start → review → complete — in generic vocabulary
that works identically on every tracker. When you're ready for a real tracker or
a full team, keep reading.

> **Sanity-check the runtime** (no LLM calls, no cost):
> `bash tests/run-all.sh` should finish with `ALL TESTS PASS`.

---

## Install into your repository

The bundle is just files. Put it wherever your agent looks for skills/rules, or
anywhere and point the agent at `SKILL.md`.

| Harness | Install location | How the agent picks it up |
|---|---|---|
| **Claude Code** | `.claude/skills/agent_squad_pm/` | Auto-loaded by the skill's description; just ask in natural language |
| **Codex CLI** | anywhere, e.g. `.codex/pm/` | `codex exec "Read .codex/pm/SKILL.md and plan a feature …"` |
| **Aider** | anywhere | `aider --read pm/SKILL.md`, then instruct |
| **Cursor / Windsurf / Cline** | the tool's rules dir | reference `SKILL.md` in chat |
| **Anything else** | anywhere | point the agent at `SKILL.md` |

### Update an installed copy

From any repository where the skill is installed in Claude Code's default
location, run:

```bash
bash .claude/skills/agent_squad_pm/bin/update-installed-skill.sh
```

Or ask Claude:

```
Fetch latest Agent Squad PM skill.
```

The updater fetches `main` from
`https://github.com/alexrolls/agent_squad_pm.git`, syncs the bundle into
`.claude/skills/agent_squad_pm`, and preserves existing project config files by
default:

- `config/project-management.config.md`
- `config/team.config.md`
- `config/statuses.config.json`

To replace those config files with upstream defaults too:

```bash
bash .claude/skills/agent_squad_pm/bin/update-installed-skill.sh --overwrite-config
```

To install or update a non-default location:

```bash
bash /path/to/agent_squad_pm/bin/update-installed-skill.sh --install-dir .codex/pm
```

Multi-agent teams work on a git branch and use a task branch plus **git
worktree** for every implementation attempt, so the bundle must live inside a
git repository. `.teamwork/` and `.workspace/` are already git-ignored.

Two execution modes (`config/team.config.md` → `EXECUTION`) share the same
task-branch/worktree isolation: **`sequential`** runs one task worker at a time;
**`parallel`** dispatches dependency/resource-safe waves, bounded by
`MAX_ACTIVE_IMPLEMENTERS` (default 2 when unset). Gate roles and integration
remain serialized where required.

---

## Connect your LLM

There are two modes, and they connect to your LLM differently.

### Single agent — nothing to connect

You already run an agent (Claude Code, Codex, …). The skill is *instructions that
agent reads*, so there is no separate connection: install the bundle and talk to
your agent normally. Your existing LLM credentials are used as-is.

### Multi-agent teams — map each role to a CLI command

`config/team.config.md` is the **entire LLM coupling**: one line per role giving
the shell command that runs that role. The launcher composes each agent's startup
prompt into a file and substitutes its path for `{prompt_file}`.

```
TEAM_LEAD_CMD="claude -p \"$(cat '{prompt_file}')\" --permission-mode acceptEdits"
BACKEND_CMD="codex exec --full-auto \"$(cat '{prompt_file}')\""
REVIEWER_CMD="gemini --yolo \"$(cat '{prompt_file}')\""
TEAM_DEFAULT_CMD="claude -p \"$(cat '{prompt_file}')\" --permission-mode acceptEdits"
```

Command templates for common CLIs:

| LLM / CLI | Command template |
|---|---|
| Claude Code | `claude -p "$(cat '{prompt_file}')" --permission-mode acceptEdits` |
| Codex CLI | `codex exec --full-auto "$(cat '{prompt_file}')"` |
| Gemini CLI | `gemini --yolo "$(cat '{prompt_file}')"` |
| Any file-reading CLI | `yourcli --prompt-file {prompt_file}` |

**Mixing LLMs is the design intent** — e.g. Claude to lead and architect, Codex to
implement, Gemini to review for diversity. Same-LLM teams work too.

Optional `TASK_FAST_CMD`, `TASK_STANDARD_CMD`, and `TASK_STRONG_CMD` overrides
route individual task packets by explicit `model-profile:`, conservative risk
classification, or a bounded low-risk fast path for documentation, formatting,
and structurally small test/config tasks. Missing overrides fall back to the
role command.

### Harness mode — teammates as subagents, no CLI processes

If your harness can spawn subagents and message them (e.g. Claude Code's Agent
tool), skip the command map entirely: compose each role's startup prompt with
`bin/launch-team.sh compose <team> <featureId> <role> [preset]` and spawn the
role natively with it. Harness messages replace mailboxes, harness idle
notifications replace heartbeats, and the tracker stays the source of truth —
see `reference/orchestration.md` → *Harness mode*.

**Command resolution per role:** explicit `<ROLE>_CMD` value → used; `<ROLE>_CMD=null`
→ role disabled; **absent** → falls back to `TEAM_DEFAULT_CMD`. That fallback is
why the many specialized preset-team roles need no per-role keys — set
`TEAM_DEFAULT_CMD` once and only override the roles you want on a different model.

> ⚠️ **Safety:** those templates use auto-approve flags (`acceptEdits`,
> `--full-auto`, `--yolo`) so agents can work unattended. Workers may commit
> untrusted checkpoints only to task branches; only the integrator writes the
> feature branch. Every implementer is isolated in its own git worktree — but still run teams on a branch you can
> throw away, and review the tracker before merging to your main branch.

---

## Connect your tracker

Pick one tracker in `config/project-management.config.md`:

```
PRODUCT_MANAGEMENT_TOOL=Markdown      # or Linear, Jira, GitHubIssues
```

Then wire its access (skip entirely for `Markdown`):

| Tracker | Access options | What to set |
|---|---|---|
| **Markdown** | none — local files | `MARKDOWN_ROOT` (default `.workspace/task-manager`) |
| **Linear** | MCP **or** REST API key | `LINEAR_ACCESS=mcp\|rest`; for `rest`, export `LINEAR_API_KEY` |
| **Jira** | MCP **or** REST API token | `JIRA_ACCESS=mcp\|rest`, `JIRA_PROJECT_KEY`; for `rest`, export `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` |
| **GitHub Issues** | `gh` CLI **or** GitHub MCP | `GITHUB_REPO` (or infer from git remote), `GITHUB_USE_MCP` |

The **REST/API-key** paths mean harnesses without an MCP client (Codex, Aider,
plain scripts) are first-class. Each `adapters/<Tool>.md` has an *Access
mechanisms* section with the exact setup (MCP config block or `curl` templates).

**Credentials live in environment variables, never in the config files.** Switching
trackers later is a one-line change to `PRODUCT_MANAGEMENT_TOOL` — no workflow,
prompt, or role brief mentions a tracker by name.

---

## Configure

Two files, each the "one file you edit per project" for its layer.

### `config/project-management.config.md` — the tracker

| Key | Meaning | Default |
|---|---|---|
| `PRODUCT_MANAGEMENT_TOOL` | Active tracker (matches an `adapters/<Name>.md`) | `Markdown` |
| per-tool block | Access mode + defaults for the active tracker (see above) | — |
| `TEAM_MODE` | `true` enables the multi-agent status-ownership model | `false` |
| `STRICT_STATUS` | `true` = refuse an action if a `[task]` isn't in the expected status (the "andon cord") | `true` |

> Set **`TEAM_MODE=true`** before running a team.

### Configure your board

`config/statuses.config.json` defines the kanban board: every status, its legal
`transitions`, its `owner` (the team or single agent that works items in that status),
and per-tracker `tool` mappings. Default board: `Planned → Active → Review → Ready to
deploy`, with `Blocked` as the parking status for stuck work. Add, rename, or remove
statuses by editing the JSON — then run `bin/launch-team.sh validate-board` to check it.
Make sure your tracker has a matching state for every status (the Markdown tracker
needs nothing).

### `config/team.config.md` — the team (only for multi-agent)

| Section | Keys | Purpose |
|---|---|---|
| Role → command | `TEAM_LEAD_CMD`, `PRINCIPAL_ARCHITECT_CMD`, `INTEGRATOR_CMD`, `BACKEND_CMD`, `FRONTEND_CMD`, `QA_CMD`, `REVIEWER_CMD`, `TEAM_DEFAULT_CMD` | Which CLI runs each role ([see above](#multi-agent-teams--map-each-role-to-a-cli-command)) |
| Task model routing | `TASK_FAST_CMD`, `TASK_STANDARD_CMD`, `TASK_STRONG_CMD` | Optional task-level command overrides selected from packet metadata and conservative risk classification; each falls back to the role command |
| Coordination | `TEAMWORK_ROOT` (`.teamwork`), `POLL_INTERVAL_SECONDS` (120), `STUCK_AFTER_MINUTES` (15), `ESCALATE_AFTER_ATTEMPTS` (2), `TRACKER_WRITERS` (`all`), `EXECUTION` (`sequential`), `MAX_ACTIVE_IMPLEMENTERS` (`null`) | Event-driven supervision with polling fallback; `TRACKER_WRITERS=lead` enables a durable single-writer outbox; `sequential` allows one task worker and `parallel` schedules dependency/resource-safe waves (unset cap defaults to 2) |
| Validation | `VALIDATE_BUILD`, `VALIDATE_TEST`, `VALIDATE_LINT`, `VALIDATE_SCRIPT` | Your stack's commands; the integrator runs them before every merge (`null` = skip). `VALIDATE_SCRIPT` replaces the three with one repo-owned script that receives the changed-file list |

Point the `VALIDATE_*` commands at your real build/test/lint (e.g.
`VALIDATE_TEST="pytest"`) — this is the only place the framework-agnostic
integrator learns about your stack.

---

## Use it

### One agent

Just talk to your agent in the generic vocabulary:

- *"Plan a feature: …"* → creates a `[feature]` + `[tasks]`
- *"Start task ENG-142"* → `[Active]`, then implements
- *"Send it to review"* / *"Finalize it"* → `[Review]` → `[Ready to deploy]`
- *"Switch the tracker to Linear"* → follows the adapter's setup

### A whole team

1. Set `TEAM_MODE=true`, configure `config/team.config.md` (roles + `VALIDATE_*`).
2. Create a feature branch — its name **is** the team name:
   ```bash
   git checkout -b payments-revamp
   ```
3. Launch a preset roster:
   ```bash
   bin/launch-team.sh team deep-backend payments-revamp ENG-100
   #                        └ preset      └ branch/team    └ featureId
   ```
4. Watch it work:
   ```bash
   tmux attach -t team-payments-revamp        # live agent windows
   bin/launch-team.sh status payments-revamp  # role / state / heartbeat
   ```
   Progress lands in your tracker; anything needing you lands in
   `.teamwork/payments-revamp/ESCALATIONS.md`.
5. Stop it:
   ```bash
   bin/launch-team.sh stop payments-revamp
   ```

> The launcher path is relative to where you installed the bundle — e.g.
> `.claude/skills/agent_squad_pm/bin/launch-team.sh`.

**All launcher subcommands:**

**`bin/launch-team.sh` subcommands:**

| Command | Purpose |
|---|---|
| `team <preset> <team> <featureId>` | Launch a whole preset roster |
| `preflight <team> <featureId>` | Verify adapter access, workspace writability, and UTC pin — run once before any CLI team launch |
| `start <team> <featureId> <role>…` | Launch specific roles (custom teams) |
| `relaunch <team> <featureId> <role> [preset]` | Restart one crashed/wedged agent |
| `compose <team> <featureId> <role> [preset]` | Write a role's startup prompt **without spawning** — for running teammates as subagents inside your own harness (see `reference/orchestration.md` → *Harness mode*) |
| `start-task <team> <featureId> <role> <taskId> [attempt] [preset]` | Generate a packet and launch one task-scoped worker in its worktree |
| `compose-task <team> <featureId> <role> <taskId> [attempt] [preset]` | Generate a packet and lean startup prompt without spawning, for harness subagents |
| `worktree <team> <role> <taskId> [attempt]` | Create an implementer's isolated task worktree |
| `worktree-remove <team> <role> <taskId> [attempt]` | Remove a worktree and prune its registration |
| `status <team>` | Show each agent's state + last heartbeat |
| `stop <team>` | Stop the whole team |

**`bin/dispatch.sh` — the event loop:**

| Command | Purpose |
|---|---|
| `dispatch.sh <team> <featureId> --once [--dry-run] [--unblock=auto\|suggest\|off]` | One deterministic read-and-act pass |
| `dispatch.sh <team> <featureId> --watch [--unblock=…]` | Wake on runtime events with `POLL_INTERVAL_SECONDS` as a fallback — run in a persistent shell (tmux/nohup); **you own this process** |

> **CLI dispatch requires scriptable tracker access.** Linear and Jira default to MCP; set `LINEAR_ACCESS=rest` or `JIRA_ACCESS=rest` in `config/project-management.config.md` before running `dispatch.sh --watch`. Harness mode (`launch-team.sh compose`) supports MCP natively.

There is also `bin/tracker-ops.sh` — an ergonomic wrapper for the recurring
tracker operations (`claim`, `state`, `comment` with the body from a file/stdin,
`update-comment <id> <file>`, `upsert-progress`, `upsert-digest`, `integrate
<hash>`, `export`) over the scriptable access mechanisms (Linear/Jira REST,
`gh`, Markdown files). The adapter docs remain the spec; MCP sessions use their
native tools instead.

**The flow every team follows:** the Principal Architect leads (plans with the
Product Manager, gates each `[task]`'s design before any code, reviews
architecture) → the dispatcher creates immutable task packets and isolated
worktrees → specialists checkpoint their task branches → the **Senior QA
Engineer is the final review gate** over an exact review package → the
integrator validates and merges one task at a time, then idempotently marks it
`[Ready to deploy]`. Runtime events trigger PM progress and feature-digest
upserts. The lead detects stuck/conflicting/crashed agents and unblocks them —
message → decide → reassign → relaunch — escalating to you only as a last
resort.

---

## The five preset teams

| Preset | Roster | Use when |
|---|---|---|
| `full-stack` | Principal Software Architect · Senior Technical PM · Senior Full Stack Engineer · Senior QA | Features cutting through schema, API, and UI — the default |
| `deep-backend` | Principal Backend Architect · TPM · Senior Staff Engineer · Senior QA | Domain logic, data models, APIs, performance |
| `deep-frontend` | Principal Frontend Architect · TPM · Senior Frontend Engineer · Senior QA | UI architecture, client state, design systems, a11y |
| `deep-security` | Principal Security Architect · TPM · Senior Security Engineer · Senior Penetration Tester · Senior QA | Security features & hardening on your own codebase |
| `deep-infra` | Principal Cloud & Infrastructure Architect · TPM · Senior Cloud Engineer · Senior SRE · Senior QA | Cloud infra, IaC, delivery pipelines, reliability |

Every preset: the **Principal Architect leads**, the **Senior QA Engineer is the
final gate**, and a standard integrator owns serialized feature-branch commits
and recoverable tracker finalization. Details in
[`teams/README.md`](teams/README.md).

---

## How it works

The PM layer applies the **ports-and-adapters (hexagonal) pattern**: your
workflows and agents speak one stable vocabulary; a one-line config selects which
adapter translates it to a concrete tracker.

```
                    ┌─────────────────────────────────────────┐
   Your agents  ───▶│            THE PORT (stable)             │
   speak only this  │  vocabulary.md · lifecycle.md            │
                    │  [feature] [task] [subtask]              │
                    │  statuses from statuses.config.json      │
                    └───────────────────┬─────────────────────┘
                                        │  one config line selects the adapter
                      ┌─────────────────┼──────────────────┐
                      ▼                 ▼                  ▼
              ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
              │ Linear.md    │  │ Jira.md      │  │ Markdown.md  │   ← swap freely
              └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
                     ▼                 ▼                 ▼
              Linear MCP/REST    Jira MCP/REST      local .md files
```

Teams add an **orchestration layer** on top, and the tracker stays the single
source of truth:

```
          PM tool (Linear/Jira/…) = single source of truth
 claims = locked transitions · progress = idempotent projected comments
                       ▲ via the adapter port ▲
 architect (leads) ── product manager ── engineers ── QA (final gate) ── integrator (commits)
                         └── one task packet + worktree per attempt ──┘
                       ▼ optional low-latency transport ▼
 .teamwork/<team>/  events · outbox · mailboxes · heartbeats  (polling fallback)
```

The dispatcher claims a `[task]` under a per-pass lock, generates its packet,
and launches exactly one attempt. Design notes, approvals, findings, and
escalations remain structured tracker comments. An append-only event journal
wakes local coordination quickly; the durable outbox serializes tracker writes
when `TRACKER_WRITERS=lead`; polling remains the distributed fallback.

---

## Directory map

```
├── README.md                         this guide
├── SKILL.md                          the operational skill your agent runs
├── config/
│   ├── project-management.config.md  ← EDIT: pick tracker, TEAM_MODE, STRICT_STATUS
│   └── team.config.md                ← EDIT (teams): role→CLI, timings, VALIDATE_*
├── reference/
│   ├── vocabulary.md                 the tool-agnostic contract (the port)
│   ├── lifecycle.md                  the scenarios: plan → work → review → complete
│   ├── team-roles.md                 status ownership across roles
│   └── orchestration.md              the multi-agent protocol
├── adapters/
│   ├── Markdown.md · Linear.md · Jira.md · GitHubIssues.md
│   └── _TEMPLATE.md                  scaffold for a new tracker
├── roles/                            the 7 base protocol roles
│   └── team-lead · principal-architect · integrator · backend · frontend · qa · reviewer
├── teams/
│   ├── README.md · _PLAYBOOK.md      how presets work + shared collaboration flow
│   ├── full-stack.md · deep-backend.md · deep-frontend.md · deep-security.md · deep-infra.md
│   └── roles/                        14 specialized role briefs
├── bin/
│   ├── launch-team.sh                role and task-instance launcher
│   ├── update-installed-skill.sh     refresh this skill from upstream
│   ├── dispatch.sh · dispatch-plan.py deterministic bounded scheduler
│   ├── runtime-state.py · task_metadata.py
│   │                                  event journal, metadata/routing, task packets
│   ├── submit-artifact.sh · process-outbox.sh
│   ├── review-package.sh · integrate-task.sh
│   └── tracker-ops.sh                idempotent tracker operations
└── tests/                            offline smoke tests (no LLM calls)
    └── run-all.sh                    tracker, runtime, dispatch, launcher, integration
```

---

## Extend it

Each extension is **one file**; nothing else changes.

- **New tracker:** copy `adapters/_TEMPLATE.md` → `adapters/<YourTool>.md`, fill the
  tables, set `PRODUCT_MANAGEMENT_TOOL=<YourTool>`.
- **New team:** copy any `teams/<preset>.md`, edit the charter, `ROSTER=` line, and
  review order. Include `integrator` in the roster.
- **New role:** add `teams/roles/<kebab-name>.md` with the standard sections
  (identity, **Protocol mapping**, responsibilities, decision authority,
  deliverables, handoffs, "you never"). The launcher resolves any role that has a
  brief in `roles/` or `teams/roles/`.

Keep the generic vocabulary (`[feature]`, `[task]`, the four statuses) and the
exact protocol markers — never invent new ones.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Agent says the tracker is unavailable | Re-check the adapter's *Access mechanisms* (MCP block or exported API-key env vars); the agent stops rather than fabricating — that's by design |
| `launch-team.sh` can't find a role | The role needs a brief in `roles/` or `teams/roles/`, and its `<ROLE>_CMD` (or `TEAM_DEFAULT_CMD`) must be set |
| A role won't launch in a preset | It's likely `<ROLE>_CMD=null` (explicitly disabled). Remove the line to fall back to `TEAM_DEFAULT_CMD` |
| No `tmux` | Agents run as background processes automatically; use `status`/`stop` and read logs under `.teamwork/<team>/pids/` |
| Team seems stuck | `bin/launch-team.sh status <team>` shows heartbeats; the lead auto-unblocks, and anything needing you is in `.teamwork/<team>/ESCALATIONS.md` |
| Want to verify the plumbing | `bash tests/run-all.sh` → `ALL TESTS PASS` (stub agents + local files; no LLM, no cost) |

---

## Credits

Inspired by the
[PlatformPlatform](https://github.com/platformplatform/PlatformPlatform/)
product-management architecture, developed by Thomas Jespersen.

---

## License

MIT License

Copyright (c) 2026 ExecMatchAi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
