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

## Terminology Mapping

| Generic term | Linear |
|---|---|
| `[Feature]` | Project |
| `[Task]` | Issue |
| `[Subtask]` | Bullet point in the issue description |

## Feature Status Mapping

Linear Projects use states like Backlog / Planned / In Progress / Completed.

| Generic status | Linear (Project state) |
|---|---|
| `[Planned]` | Planned |
| `[Active]` | In Progress |
| `[Resolved]` | Completed |

## Task Status Mapping

| Generic status | Linear (Issue workflow state) |
|---|---|
| `[Planned]` | Todo |
| `[Active]` | In Progress |
| `[Review]` | In Review |
| `[Completed]` | Done |

> Team workflow states are configurable in Linear. If a team renames "In Review", update
> this table — the port never changes, only this mapping does.

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
