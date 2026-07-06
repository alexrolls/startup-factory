# GitHub Issues

## Summary

Uses native GitHub Issues, grouped by Milestone. Default access is the **`gh` CLI** (no MCP
server required); set `GITHUB_USE_MCP=true` to use the GitHub MCP server instead. A
`[feature]` is a Milestone, a `[task]` is an Issue, task status is carried by labels, and
`[Completed]` closes the issue.

## MCP / CLI Setup

**CLI (default):** install and authenticate the GitHub CLI once:

```bash
gh auth login          # one-time, interactive
gh auth status         # verify
```

Repo comes from `GITHUB_REPO` in `../config/project-management.config.md`, or is inferred
from the current git remote when that is `null`. Create the four status labels once:

```bash
gh label create "status:planned" --color BFD4F2 2>/dev/null || true
gh label create "status:active"  --color 0E8A16 2>/dev/null || true
gh label create "status:review"  --color FBCA04 2>/dev/null || true
```
(`[Completed]` needs no label — it's the closed state.)

**MCP (optional):** add the GitHub MCP server and set `GITHUB_USE_MCP=true`:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "<token>" }
    }
  }
}
```

## Terminology Mapping

| Generic term | GitHub |
|---|---|
| `[Feature]` | Milestone |
| `[Task]` | Issue |
| `[Subtask]` | Task-list checkbox (`- [ ] ...`) in the issue body |

## Feature Status Mapping

Milestones only have open/closed, so most feature status is *derived from its tasks*.

| Generic status | GitHub (Milestone) |
|---|---|
| `[Planned]` | Open, no task started |
| `[Active]` | Open, ≥1 task in progress (derived) |
| `[Resolved]` | Closed |

## Task Status Mapping

| Generic status | GitHub (Issue) |
|---|---|
| `[Planned]` | Open + label `status:planned` (or no status label) |
| `[Active]` | Open + label `status:active` |
| `[Review]` | Open + label `status:review` |
| `[Completed]` | Closed |

> Setting a status label means **removing the previous** status label and adding the new
> one — never leave two status labels on one issue.

## ID Mapping

| Generic ID | GitHub | Example |
|---|---|---|
| `featureId` | Milestone number or title | `Payments revamp` / `3` |
| `taskId` | Issue number | `142` |

## Operations

CLI column assumes `-R <GITHUB_REPO>` is appended when `GITHUB_REPO` is set.

| Generic operation | `gh` CLI |
|---|---|
| Create `[feature]` | `gh api repos/:owner/:repo/milestones -f title="<name>" -f description="<...>"` |
| Create `[task]` under a feature | `gh issue create --title "<t>" --body "<...>" --milestone "<featureId>" --label status:planned` |
| Read a `[task]` | `gh issue view <taskId> --comments` |
| List `[tasks]` in a feature | `gh issue list --milestone "<featureId>" --state all` |
| Set `[task]` status | `gh issue edit <taskId> --remove-label "status:planned" --add-label "status:active"` (remove the label matching the [task]'s current status — read it first; globs do not work with `--remove-label`) |
| Set `[task]` → `[Completed]` | `gh issue close <taskId>` |
| Reopen (rework) | `gh issue reopen <taskId> --add-label status:active` |
| Set `[feature]` → `[Resolved]` | `gh api -X PATCH repos/:owner/:repo/milestones/<n> -f state=closed` |
| Add a comment to a `[task]` | `gh issue comment <taskId> --body "<...>"` |

## Rules

- Every write goes through `gh` (or the GitHub MCP tools when `GITHUB_USE_MCP=true`). On a
  non-zero exit / MCP error: **stop and report** (andon cord). Never fake success.
- Exactly one `status:*` label at a time on an open issue.
- `[Completed]` = closed; reopening for rework re-adds `status:active`.
- `featureId` is a Milestone (title or number); `taskId` is an Issue number.

## Initialization

Run `gh auth status` (CLI) or a 1-item list via MCP to confirm access. If it fails: stop
and tell the user to run `gh auth login` / fix the token — do not proceed.
