# Jira

## Summary

Jira is Atlassian's hosted issue tracker. The agent talks to it through the **Atlassian
MCP server** or the **Jira Cloud REST API with an API token** — `JIRA_ACCESS` selects
the mechanism (see below). Features map to Epics and tasks to Stories under a project key.

## Access mechanisms

Two peer mechanisms; `JIRA_ACCESS` in `../config/project-management.config.md`
selects one. Use `rest` for harnesses without an MCP client (Codex, Aider, plain
scripts).

### mcp (default)

Add the Atlassian MCP server and complete its OAuth flow on first use:

```json
{
  "mcpServers": {
    "atlassian": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.atlassian.com/v1/sse"]
    }
  }
}
```

Relevant config from `../config/project-management.config.md`:
`JIRA_PROJECT_KEY` (required to create items), `JIRA_DEFAULT_ASSIGNEE`.

### rest — Jira Cloud REST API v3 with an API token

Create an API token (id.atlassian.com → Security → API tokens) and export
`JIRA_BASE_URL` (e.g. `https://yourorg.atlassian.net`), `JIRA_EMAIL`, and
`JIRA_API_TOKEN`. Helper:

```bash
jira() { curl -sf -u "$JIRA_EMAIL:$JIRA_API_TOKEN" \
  -H "Content-Type: application/json" "$JIRA_BASE_URL$@"; }
```

Status changes in Jira are **transitions**: first `GET` the available transitions
for the item, find the one whose target status matches the mapped name, then `POST`
its id. Never guess transition ids. Non-2xx = failed operation → andon cord.

Descriptions and comment bodies use Atlassian Document Format; include this helper
next to `jira` so every body is a simple paragraph node:

```bash
adf() { jq -cn --arg t "$1" '{"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":$t}]}]}'; }
```

(`jq` handles JSON escaping; if `jq` is unavailable, escape the text yourself before splicing it into the body.)

## Terminology Mapping

| Generic term | Jira |
|---|---|
| `[Feature]` | Epic |
| `[Task]` | Story |
| `[Subtask]` | Bullet point in the story description |

## Feature Status Mapping

| Generic status | Jira (Epic) |
|---|---|
| `[Planned]` | To Do |
| `[Active]` | In Progress |
| `[Resolved]` | Done |

## Task Status Mapping

| Generic status | Jira (Story) |
|---|---|
| `[Planned]` | To Do |
| `[Active]` | In Progress |
| `[Review]` | In Review |
| `[Completed]` | Done |

> Jira workflows are per-project and often customized. If your board uses different status
> names (e.g. "Code Review", "Selected for Development"), edit these two tables only.

## ID Mapping

| Generic ID | Jira | Example |
|---|---|---|
| `featureId` | Epic key | `ENG-100` |
| `taskId` | Story key | `ENG-142` |

The `jira()` and `adf()` helpers above must be defined in your shell before running the rest-column commands.

## Operations

| Generic operation | mcp | rest (via `jira`) |
|---|---|---|
| Create `[feature]` | create an Epic in `JIRA_PROJECT_KEY` | `jira /rest/api/3/issue -X POST -d '{"fields":{"project":{"key":"<KEY>"},"issuetype":{"name":"Epic"},"summary":"<name>"}}'` |
| Create `[task]` under a feature | create a Story linked to the Epic | `jira /rest/api/3/issue -X POST -d '{"fields":{"project":{"key":"<KEY>"},"issuetype":{"name":"Story"},"summary":"<title>","description":'"$(adf "<text>")"',"parent":{"key":"<featureId>"}}}'` |
| Read a `[task]` | get the Story | `jira "/rest/api/3/issue/<taskId>?fields=summary,description,status,assignee,comment"` |
| List `[tasks]` in a feature | search by Epic | `jira "/rest/api/3/search?jql=parent=<featureId>"` |
| List available transitions | (implicit) | `jira "/rest/api/3/issue/<taskId>/transitions"` |
| Set `[task]`/`[feature]` status | transition the item | `jira "/rest/api/3/issue/<taskId>/transitions" -X POST -d '{"transition":{"id":"<transitionId>"}}'` |
| Set `[task]` assignee | update assignee | `jira "/rest/api/3/issue/<taskId>/assignee" -X PUT -d '{"accountId":"<accountId>"}'` |
| Add a comment to a `[task]` | add comment | `jira "/rest/api/3/issue/<taskId>/comment" -X POST -d '{"body":'"$(adf "<text>")"'}'` |

> `parent` and `jql=parent=` work in team-managed (NextGen) projects. In company-managed (classic) projects, link Stories to the Epic via the Epic Link field (commonly `customfield_10014`) and query with `jql="Epic Link" = <featureId>`.

## Rules

- ALL operations MUST use the active access mechanism (`JIRA_ACCESS`: MCP tools or the
  REST API). If ANY call fails: **STOP** and report (andon cord).
  Never work around a failure.
- NEVER skip status updates.
- Status changes are **transitions**, not direct field edits — a status may be unreachable
  from the current one; if a transition is missing, pull the andon cord rather than forcing
  it.
- `featureId` is an Epic key; `taskId` is a Story key.

## Initialization

- **mcp**: Call any read MCP tool (e.g. fetch the current user, or a 1-result JQL search) to
  confirm authentication. If unavailable or auth fails: stop and tell the user to fix the MCP
  setup.
- **rest**: Run `jira /rest/api/3/myself` — must return your account. If it fails: stop and
  tell the user to check `JIRA_BASE_URL`, `JIRA_EMAIL`, and `JIRA_API_TOKEN`.
