# AI Project-Management & Team Orchestration Skill

Turn any agentic LLM into a disciplined engineering team that plans, builds,
reviews, and ships work through **your** project tracker — Linear, Jira, GitHub
Issues, or offline Markdown — without hard-coding a single tool or model.

It has three layers you can adopt one at a time:

| Layer | What it gives you | Where |
|---|---|---|
| **1. PM port** | One AI agent creates/tracks/completes `[features]` and `[tasks]` in any tracker through one tool-agnostic workflow. | `SKILL.md`, `reference/`, `adapters/` |
| **2. Orchestration** | A cross-functional team of agents (possibly *different* LLMs) works one feature in parallel — a lead unblocks, an architect gates design, an integrator commits. | `reference/orchestration.md`, `roles/`, `bin/launch-team.sh` |
| **3. Preset teams** | Five ready-made rosters (Full Stack, Deep Backend, Frontend, Security, Infra) — launch a whole team with one command. | `teams/` |

Everything is plain Markdown + one Bash launcher. It's **language-, framework-,
tracker-, and LLM-agnostic**: it manages *work*, not *code*, and assumes nothing
about your stack beyond files, a shell, and git.

---

## Table of contents

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
`bash` + `git` (it uses git worktrees to isolate agents). `tmux` is optional but
recommended — without it, agents run as background processes.

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
   cp -R /path/to/this/bundle .claude/skills/project-management
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
   Complete task 1.     → verified + [Completed]
   ```

That's the whole loop — plan → start → review → complete — in generic vocabulary
that works identically on every tracker. When you're ready for a real tracker or
a full team, keep reading.

> **Sanity-check the team launcher** (no LLM calls, no cost):
> `bash tests/launcher-test.sh` → should print `ALL PASS`.

---

## Install into your repository

The bundle is just files. Put it wherever your agent looks for skills/rules, or
anywhere and point the agent at `SKILL.md`.

| Harness | Install location | How the agent picks it up |
|---|---|---|
| **Claude Code** | `.claude/skills/project-management/` | Auto-loaded by the skill's description; just ask in natural language |
| **Codex CLI** | anywhere, e.g. `.codex/pm/` | `codex exec "Read .codex/pm/SKILL.md and plan a feature …"` |
| **Aider** | anywhere | `aider --read pm/SKILL.md`, then instruct |
| **Cursor / Windsurf / Cline** | the tool's rules dir | reference `SKILL.md` in chat |
| **Anything else** | anywhere | point the agent at `SKILL.md` |

Multi-agent teams use **git worktrees**, so the bundle must live inside a git
repository. `.teamwork/` and `.workspace/` are already git-ignored.

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

**Command resolution per role:** explicit `<ROLE>_CMD` value → used; `<ROLE>_CMD=null`
→ role disabled; **absent** → falls back to `TEAM_DEFAULT_CMD`. That fallback is
why the many specialized preset-team roles need no per-role keys — set
`TEAM_DEFAULT_CMD` once and only override the roles you want on a different model.

> ⚠️ **Safety:** those templates use auto-approve flags (`acceptEdits`,
> `--full-auto`, `--yolo`) so agents can work unattended. Each implementer is
> isolated in its own git worktree and only the integrator merges — but still run
> teams on a branch you can throw away, and review the tracker before merging to
> your main branch.

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

### `config/team.config.md` — the team (only for multi-agent)

| Section | Keys | Purpose |
|---|---|---|
| Role → command | `TEAM_LEAD_CMD`, `PRINCIPAL_ARCHITECT_CMD`, `INTEGRATOR_CMD`, `BACKEND_CMD`, `FRONTEND_CMD`, `QA_CMD`, `REVIEWER_CMD`, `TEAM_DEFAULT_CMD` | Which CLI runs each role ([see above](#multi-agent-teams--map-each-role-to-a-cli-command)) |
| Coordination | `TEAMWORK_ROOT` (`.teamwork`), `POLL_INTERVAL_SECONDS` (120), `STUCK_AFTER_MINUTES` (15), `ESCALATE_AFTER_ATTEMPTS` (2) | Timing of the lead's supervision loop |
| Validation | `VALIDATE_BUILD`, `VALIDATE_TEST`, `VALIDATE_LINT` | Your stack's commands; the integrator runs them before every merge (`null` = skip) |

Point the `VALIDATE_*` commands at your real build/test/lint (e.g.
`VALIDATE_TEST="pytest"`) — this is the only place the framework-agnostic
integrator learns about your stack.

---

## Use it

### One agent

Just talk to your agent in the generic vocabulary:

- *"Plan a feature: …"* → creates a `[feature]` + `[tasks]`
- *"Start task ENG-142"* → `[Active]`, then implements
- *"Send it to review"* / *"Complete it"* → `[Review]` → `[Completed]`
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
> `.claude/skills/project-management/bin/launch-team.sh`.

**All launcher subcommands:**

| Command | Purpose |
|---|---|
| `team <preset> <team> <featureId>` | Launch a whole preset roster |
| `start <team> <featureId> <role>…` | Launch specific roles (custom teams) |
| `relaunch <team> <featureId> <role> [preset]` | Restart one crashed/wedged agent |
| `worktree <team> <role> <taskId>` | Create an implementer's isolated worktree |
| `status <team>` | Show each agent's state + last heartbeat |
| `stop <team>` | Stop the whole team |

**The flow every team follows:** the Principal Architect leads (plans with the
Product Manager, gates each `[task]`'s design before any code, reviews
architecture) → specialists implement in isolated worktrees → the **Senior QA
Engineer is the final review gate** → the integrator merges and marks
`[Completed]` (commit and completion are one atomic step). The lead detects
stuck/conflicting/crashed agents and unblocks them — message → decide → reassign →
relaunch — escalating to you only as a last resort.

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
final gate**, and a standard integrator makes the atomic commit. Details in
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
                    │  [Planned] [Active] [Review] [Completed] │
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
   claims = status transitions · coordination = structured comments
                       ▲ via the adapter port ▲
 architect (leads) ── product manager ── engineers ── QA (final gate) ── integrator (commits)
                         └──── one git worktree per implementer ────┘
                       ▼ optional low-latency transport ▼
        .teamwork/<team>/  mailboxes · heartbeats  (degrades to tracker polling)
```

An agent claims a `[task]` by moving its status and setting itself as assignee;
all coordination (design notes, approvals, findings, escalations) are structured
comments on the `[task]`. File mailboxes/heartbeats under `.teamwork/` make this
fast when agents share a machine and degrade to tracker polling when they don't.

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
├── bin/launch-team.sh                the team launcher
└── tests/launcher-test.sh            offline smoke test (no LLM calls)
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
| Want to verify the plumbing | `bash tests/launcher-test.sh` → `ALL PASS` (uses a stub agent; no LLM, no cost) |

---

## Design credit

The PM pattern is generalized from the
[PlatformPlatform](https://github.com/platformplatform/PlatformPlatform/) codebase's
`.claude/reference/product-management/` design, extracted here so it can be reused
in any repository regardless of stack, tracker, or model.
