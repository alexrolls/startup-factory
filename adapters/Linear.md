# Linear

## Summary

Linear is a hosted issue tracker. The agent talks to it through the **Linear MCP
server** (MCP tool calls like `list_issues`, `create_issue`) or the **Linear GraphQL
API with an API key** — `LINEAR_ACCESS` selects the mechanism (see below).

## Access mechanisms

Two peer mechanisms; `LINEAR_ACCESS` in `../config/project-management.config.md`
selects one. Use `rest` for harnesses without an MCP client (Codex, Aider, plain
scripts).

### mcp (default)

Add the Linear MCP server to your agent's MCP config, then authenticate in the
browser flow it triggers on first use:

```json
{
  "mcpServers": {
    "linear-server": { "type": "http", "url": "https://mcp.linear.app/mcp" }
  }
}
```

### rest — GraphQL with an API key

Create a personal API key in Linear (Settings → Security & access → API keys) and
export it as `LINEAR_API_KEY`. Every operation is a single `curl` against
`https://api.linear.app/graphql`:

```bash
lin() { curl -sf https://api.linear.app/graphql -H "Authorization: $LINEAR_API_KEY" -H "Content-Type: application/json" -d "$1" | jq -e 'if .errors then error(.errors[0].message) else . end'; }
```

State/team/project names must be resolved to ids first (see the Operations table's
lookup row). `jq -e` makes a GraphQL `errors` response a non-zero exit (andon cord).

Relevant config: `LINEAR_DEFAULT_TEAM`, `LINEAR_DEFAULT_PROJECT`, `LINEAR_ACCESS`.

> Make sure every status in `config/statuses.config.json` has a matching workflow state
> in your Linear team (e.g. create a "Blocked" state) — a missing state is an andon stop.

## Terminology Mapping

| Generic term | Linear |
|---|---|
| `[Feature]` | Project |
| `[Task]` | Issue |
| `[Subtask]` | Bullet point in the issue description |

## Status Mapping

Statuses come from `config/statuses.config.json` — each status's `tool` map holds this
adapter's concrete value under the `"Linear"` key. This adapter's *mechanism* for setting
a status is: issue workflow state (team-configurable names) for tasks; project state for
features.

**Missing mapping = andon.** If a status has no `"Linear"` entry, or the Linear team
lacks the mapped workflow state, stop and report — never invent a fallback status.

Shipped defaults (the default board):

| Status | Linear |
|---|---|
| `[Planned]` | Todo |
| `[Active]` | In Progress |
| `[Review]` | In Review |
| `[Blocked]` | Blocked |
| `[Ready to deploy]` | Done |

Feature statuses `[Planned]` / `[Active]` / `[Resolved]` map to Planned / In Progress /
Completed (Linear project states).

> Team workflow states are configurable in Linear. If a team renames "In Review", update
> the `"Linear"` values in `config/statuses.config.json` — the generic status names never
> change, only the tool-side values do.

## ID Mapping

| Generic ID | Linear | Example |
|---|---|---|
| `featureId` | Project id or name | `Payments revamp` |
| `taskId` | Issue identifier | `PP-445` |

## Operations

| Generic operation | mcp | rest (GraphQL via `lin`) |
|---|---|---|
| Lookup ids (teams, states, projects) | (implicit in MCP tools) | `lin '{"query":"{ teams { nodes { id name states { nodes { id name } } projects { nodes { id name } } } }"}'` — also look up project statuses: `lin '{"query":"{ projectStatuses { nodes { id name } } }"}'` (needed for `projectUpdate` `statusId`) |
| Create `[feature]` | `create_project` | `lin '{"query":"mutation { projectCreate(input: {name: \"<name>\", teamIds: [\"<teamId>\"]}) { project { id } } }"}'` |
| Create `[task]` under a feature | `create_issue` with `project` | `lin '{"query":"mutation { issueCreate(input: {title: \"<title>\", description: \"<md>\", teamId: \"<teamId>\", projectId: \"<featureId>\"}) { issue { id identifier } } }"}'` |
| Read a `[task]` | `get_issue` | `lin '{"query":"{ issue(id: \"<taskId>\") { identifier title description state { name } assignee { name } comments { nodes { body createdAt } } } }"}'` |
| List `[tasks]` in a feature | `list_issues` with `project` | `lin '{"query":"{ project(id: \"<featureId>\") { issues { nodes { identifier title state { name } assignee { name } } } } }"}'` |
| Set `[task]` status | `update_issue` with mapped `state` | `lin '{"query":"mutation { issueUpdate(id: \"<taskId>\", input: {stateId: \"<stateId>\"}) { success } }"}'` |
| Set `[task]` assignee | `update_issue` with `assignee` | `lin '{"query":"mutation { issueUpdate(id: \"<taskId>\", input: {assigneeId: \"<userId>\"}) { success } }"}'` |
| Set `[feature]` status | `update_project` | `lin '{"query":"mutation { projectUpdate(id: \"<featureId>\", input: {statusId: \"<statusId>\"}) { success } }"}'` |
| Add a comment to a `[task]` | `create_comment` | `lin '{"query":"mutation { commentCreate(input: {issueId: \"<taskId>\", body: \"<md>\"}) { success } }"}'` |
| Export the `[tasks]` of a `[feature]` to a file | read via `list_issues` + `get_issue`, write the JSON yourself | `bin/tracker-ops.sh export <featureId> <outfile>` |

> **Helper script.** For the `rest` mechanism, `bin/tracker-ops.sh` wraps the recurring
> operations — `claim`, `state`, `comment` (body from a file or stdin, so no shell-quoting
> of GraphQL payloads), `integrate <hash>`, `export`. This table remains the spec; the
> script is the ergonomic path. MCP sessions call the MCP tools directly instead.
> The `export` output gives credential-less roles a stable read-only snapshot
> (`<TEAMWORK_ROOT>/<team>/tasks.json` by convention — see `reference/orchestration.md`).

## Rules

- All operations use the active access mechanism (`LINEAR_ACCESS`: MCP tools or the
  GraphQL API). If a call fails: **stop immediately** and report the error
  (andon cord) — do not work around it.
- Never skip status updates; move issues through Todo → In Progress → In Review → Done.
- `featureId` is a Project id/name; `taskId` is an issue identifier like `PP-445`.
- Query a feature's tasks with `list_issues` + `project`, never by guessing identifiers.

## Initialization

- **mcp**: Call any read MCP tool (e.g. `list_issues` limited to 1) to confirm authentication.
  If unavailable or auth fails: stop the workflow and tell the user to fix the MCP setup.
- **rest**: Run `lin '{"query":"{ viewer { id name } }"}'` — must return your user. If it
  fails: stop and tell the user to check `LINEAR_API_KEY`.
