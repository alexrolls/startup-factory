# Tracker access

Wiring one project-management tool to Startup Factory. The workflow itself is
tool-neutral — no prompt or role brief names a tracker — so this is the only
place a project declares which board it uses and how to reach it.

Pick one tracker in [`config/project-management.config.md`](../config/project-management.config.md):

```
PRODUCT_MANAGEMENT_TOOL=Markdown      # or Linear, Jira, GitHubIssues
```

Then wire its access (skip entirely for `Markdown`):

| Tracker | Access options | What to set |
|---|---|---|
| **Markdown** | none — local files | `MARKDOWN_ROOT` (default `.workspace/task-manager`) |
| **Linear** | MCP **or** REST API key | `LINEAR_ACCESS=mcp\|rest`; for `rest`, export `LINEAR_API_KEY` |
| **Jira** | MCP **or** REST API token | `JIRA_ACCESS=mcp\|rest`, exact `JIRA_PROJECT_KEY` and child `JIRA_TASK_ISSUE_TYPE`; for `rest`, export `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` |
| **GitHub Issues** | `gh` CLI **or** GitHub MCP | `GITHUB_REPO` (explicitly required for automation; interactive use may infer from git remote), `GITHUB_USE_MCP` |

The **REST/API-key** paths mean harnesses without an MCP client (Codex, Aider,
plain scripts) are first-class. Each [`adapters/<Tool>.md`](../adapters/) has an *Access
mechanisms* section with the exact setup (MCP, REST/`curl`, `gh`, or local-file
instructions as appropriate).
Scriptable remote operations have a 60-second inner deadline by default;
operators may set `TRACKER_OPERATION_TIMEOUT_SECONDS` to an integer from 1
through 300, while automation's `operationTimeoutSeconds` remains the outer
process-group bound.

**Credentials live in environment variables, never in the config files.** Once
access is configured, switching among shipped adapters is a one-line change to
`PRODUCT_MANAGEMENT_TOOL`; no workflow, prompt, or role brief mentions a tracker
by name. A new tool also needs its adapter contract and deterministic
[`tracker-ops.sh`](../bin/tracker-ops.sh) backend before unattended dispatch or automation can use it.
