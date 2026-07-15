# <ToolName>

> Copy this file to `<ToolName>.md`, fill every section, then set
> `PRODUCT_MANAGEMENT_TOOL=<ToolName>` in `../config/project-management.config.md`.
> An adapter is *pure translation*: it maps the generic port
> (`../reference/vocabulary.md`) to one concrete tool. It must not add new lifecycle rules —
> those live in `../reference/lifecycle.md`.

## Summary

One or two sentences: what this tool is and how the agent talks to it (MCP server / CLI /
files / REST). State the access mechanism up front.

## MCP / CLI Setup

Exactly what the user must do once so operations work. For an MCP tool, the config block:

```json
{
  "mcpServers": {
    "<server-name>": { "type": "http", "url": "https://..." }
  }
}
```

For a CLI tool, the install/auth commands. For a file-based tool, "none".

## Terminology Mapping

| Generic term | <ToolName> |
|---|---|
| `[Feature]` | <e.g. Project / Epic / Milestone> |
| `[Task]` | <e.g. Issue / Story / Ticket> |
| `[Subtask]` | Bullet/checklist item in the [task] description |

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

## ID Mapping

| Generic ID | <ToolName> | Example |
|---|---|---|
| `featureId` | <what it is> | <...> |
| `taskId` | <what it is> | <...> |

## Operations

The concrete verb for each generic operation the lifecycle uses. Be explicit — name the
MCP tool / CLI command / file edit.

| Generic operation | How to perform it in <ToolName> |
|---|---|
| Create `[feature]` | <...> |
| Create `[task]` under a feature | <...> |
| Read a `[task]` | <...> |
| List `[tasks]` in a feature | <...> |
| Set `[task]` status | <...; document the human project-management action for outbound `[Blocked]`, while the deterministic backend must reject that outbound mutation> |
| Set `[feature]` status | <...> |
| Add a comment to a `[task]` | <...> |
| Add a comment once by delivery id | <how `comment-once` finds the exact `delivery-id:` token before creating a comment> |
| Update a comment | <edit by stable comment id, or explicitly refuse if the tool cannot preserve the protocol> |
| Export the `[tasks]` of a `[feature]` to a file | <how to dump id/title/status/assignee/description/comments as JSON — gives credential-less roles a read-only snapshot> |
| Scan `[tasks]` across the configured board scope | <scriptable, paginated discovery using generic status inputs and the normalized schema in `reference/automation.md`> |
| Upsert task runtime progress | <how to find and update one managed progress projection without duplicates> |
| Upsert feature runtime digest | <how to find and update one managed digest projection without duplicates> |
| Upsert feature deployment state | <how to find and update one managed `[deployment]` projection without duplicates> |
| Record a policy denial once | <how `record-denial` keys the `[DENIED ACTION]` projection by denial id> |
| Integrate a `[task]` once | <terminal transition plus exact commit comment, with read-back and duplicate suppression> |
| Set/read `[feature]` status | <how `feature-state` resolves, transitions, and reads back the generic feature status> |

> Unattended automation requires a deterministic backend module at
> `extensions/tracker-backends/<ToolName>.py`; the prose adapter alone is not
> executable. Do not edit the upstream-owned `bin/tracker-ops.sh` to register a
> custom tool. Export the lower-level `Backend` class documented in
> `extensions/tracker-backends/README.md`. The common broker keeps ownership of
> operation parsing, legal transitions, `[Blocked]`/`human-work` fences,
> idempotency gates, and status read-back. Implement every required primitive,
> including exhaustive `export` and `scan`, without bypassing that layer or
> making hand-built calls elsewhere. Every backend mutation must be idempotent
> where the port says it is and must read back the resulting state. The
> Operations table above remains the spec either way.

## Rules

- All operations use the mechanism above — never fabricate an update.
- On any failure: **stop and report** (andon cord). Never work around it.
- Never skip a status transition.
- <Any tool-specific gotchas: formatting quirks, rate limits, required fields.>

## Initialization

A cheap read that proves access works (e.g. list one item, `whoami`, check the file dir).
If it fails: stop, tell the user to fix `MCP / CLI Setup`, do not proceed.

> Executed **once by `launch-team.sh preflight`** (automatic before `team`), not
> per-agent. Agents receive the verified access mechanism (and, for MCP tools, the
> verified tool prefix) in their startup prompt and must not re-derive it.

## Automation contract

Document whether board-wide `scan` is available from a non-interactive process,
how it constrains scope, paginates, exposes revisions, and prevents duplicate
claims. MCP-only access is not a cron backend. If scriptable discovery is not
available, `pm-agent.py` must fail closed.

Scriptable HTTP/CLI implementations must use bounded calls. The bundled broker
honors `TRACKER_OPERATION_TIMEOUT_SECONDS` (1–300 seconds, default 60); custom
adapter subprocesses must not disable that deadline.

`export` must exhaust every [task] and every nested comment/label/dependency
page and emit `{adapter, featureId, exportedAt, tasks}`. `featureId` must equal
the requested identifier exactly. `tasks` must have unique, non-empty string
`taskId` values and normalized `title`, generic `status`, raw status,
`assignee`, `description`, `blockedBy`, `labels`, `updatedAt`, `revision`, and
`comments`. When the tool exposes attachments, also emit stable normalized
attachment metadata so resume review can detect additions, removals, and
changes. `scan` must exhaust the explicitly configured board scope and emit
schema-v1 `{adapter, scannedAt, statuses, items, orphans}` records; every item
uses the same normalized fields plus an exact `featureId`. Never silently omit
out-of-scope records from an allegedly exhaustive feature export—reject the
feature instead.

The normalized task shape is not best-effort. Reject an unknown/unmapped
generic status, a missing required field, an empty or duplicate task identity,
a non-list `blockedBy`/`labels`/`comments` value, or malformed nested values.
For scans, task identities are unique across the complete snapshot (not merely
within one feature). If the tool exposes a first-class dependency endpoint,
paginate it for every returned task; an unavailable/unsupported/unauthorized
endpoint is an andon, not an empty `blockedBy` fallback.

The deterministic status backend may enter `[Blocked]` only through the board's
configured authority and must reject every outbound `[Blocked]` transition.
Only the tool's human-operated surface may perform that move. For a locally held
task, a human return to queued begins the full communication-diff resume
barrier; direct movement to a working/review status is manual takeover. `[dependency-hold]`,
`[resume-review]`, and `[resume-plan]` comments are acted on only when the local
broker has a matching published launched-role capability receipt—tracker
authorship or copied marker text is never enough.

Document the tool-side workflow ACL or verified transition-provenance mechanism
that restricts outbound Blocked moves to human principals and denies every
automation/service identity. A normalized snapshot alone cannot prove the
actor; adapters without this control must not claim enforceable automatic human
resume and must keep autonomous portfolio automation disabled. Also document
label handling: `human-work` prevents new claims/launches
and stops/fences matching in-flight work on reconciliation.

Each comment must expose a stable `id`, `body`, author, and sortable `revision`;
remote tools also expose `createdAt` and `updatedAt`. A file adapter may use
null timestamps only when it supplies a monotonic exported revision. Sort
comments oldest-first by effective last modification (`updatedAt`, else
`createdAt`, else the adapter revision), then stable id. If exhaustive
pagination or deterministic ordering cannot be proven, fail closed: gate logic
treats the last comparable protocol comment as current.
Stable comment ids must be non-empty and unique within a task. Reject duplicate
ids, malformed timestamps/revisions, missing remote timestamps, and an input
sequence that is not already in that deterministic order. A file adapter's
documented null timestamps do not waive its sortable-revision requirement.
