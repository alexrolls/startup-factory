# Project Management Configuration

This is the **one file you edit per project.** It selects the active tool and holds any
per-tool settings. The skill reads this file first, then loads the matching adapter from
`../adapters/<Tool>.md`.

---

## Active Tool

Set exactly one value. It must match an adapter filename in `../adapters/` (without `.md`).

```
PRODUCT_MANAGEMENT_TOOL=Markdown
```

Available out of the box: `Linear`, `Jira`, `GitHubIssues`, `Markdown`.
Add your own by creating `../adapters/<Name>.md` (copy `_TEMPLATE.md`).

> `Markdown` is the zero-setup default: it stores features and tasks as local files and
> needs no network, account, or MCP server. Switch to a real tool when you're ready.

---

## Per-Tool Settings

Only the block for your active tool is used. Leave the rest as-is. `null` means "let the
adapter/tool decide" (e.g. prompt, or use the tool's default).

### Linear
```
LINEAR_DEFAULT_TEAM=null          # Team key/name; REQUIRED and resolved exactly for automation
LINEAR_DEFAULT_PROJECT=null       # Optional default Project ([feature]) to file tasks into
LINEAR_ACCESS=mcp                 # mcp = Linear MCP server; rest = GraphQL API with LINEAR_API_KEY env var
```

### Jira
```
JIRA_PROJECT_KEY=null             # e.g. "ENG" — REQUIRED scope for automation and creation
JIRA_TASK_ISSUE_TYPE=Story         # Exact level-0 child type normalized as [task]; MUST NOT be Epic
JIRA_DEFAULT_ASSIGNEE=null        # Optional accountId or email
JIRA_ACCESS=mcp                   # mcp = Atlassian MCP server; rest = REST API with JIRA_BASE_URL/JIRA_EMAIL/JIRA_API_TOKEN env vars
```

### GitHubIssues
```
GITHUB_REPO=null                  # "owner/repo"; explicit value REQUIRED for automation
GITHUB_USE_MCP=false              # false = use the `gh` CLI; true = use the GitHub MCP server
```

### Markdown
```
MARKDOWN_ROOT=.workspace/task-manager   # Where feature/task files live (repo-relative)
```

---

## Optional Behaviour Flags

Apply regardless of tool.

```
TEAM_MODE=true         # false opts out to the single-agent workflow
STRICT_STATUS=true     # true = before any write, verify the current status and that the
                       #        intended move is in that status's transitions list
                       #        (the "andon cord" — see reference/lifecycle.md)
STATUS_CONFIG=config/statuses.config.json   # the kanban board: statuses, transitions,
                                            # owners, per-tool mappings (skill-relative path)
```
