# Markdown

## Summary

A **zero-setup, offline** tool: features and tasks are plain Markdown files on disk. No
account, network, or MCP server. It simulates the same feature→task→status structure as
Linear/Jira/GitHub using files, so you can adopt the whole workflow before committing to a
hosted tool — or keep using it permanently for solo/local projects.

## MCP / CLI Setup

None. All operations are ordinary file reads/writes with your normal editing tools.

The root directory comes from `MARKDOWN_ROOT` in
`../config/project-management.config.md` (default `.workspace/task-manager`).

> **Tip:** keep the task-manager files out of your product's git history — either add
> `MARKDOWN_ROOT` to `.gitignore`, or make it a nested repository. That keeps churny status
> edits from polluting your codebase commits. (Optional; a plain tracked folder works too.)

## Terminology Mapping

| Generic term | Markdown |
|---|---|
| `[Feature]` | A feature file, `feature.md` (one per feature folder) |
| `[Task]` | A numbered `##` section within the feature file |
| `[Subtask]` | A `-` bullet under a task section |

## Feature Status Mapping

Status is literal bracket text on the feature's title line.

| Generic status | Markdown |
|---|---|
| `[Planned]` | `[Planned]` |
| `[Active]` | `[Active]` |
| `[Resolved]` | `[Resolved]` |

## Task Status Mapping

Status is literal bracket text at the end of the task's `##` header.

| Generic status | Markdown |
|---|---|
| `[Planned]` | `[Planned]` |
| `[Active]` | `[Active]` |
| `[Review]` | `[Review]` |
| `[Completed]` | `[Completed]` |

## ID Mapping

| Generic ID | Markdown | Example |
|---|---|---|
| `featureId` | Path to the feature file | `.workspace/task-manager/2026-07-06-payments-revamp/feature.md` |
| `taskId` | Task number within the file | `2` |

## File Structure

```
<MARKDOWN_ROOT>/
  └─ yyyy-MM-dd-<feature-slug>/
       └─ feature.md
```

### `feature.md` format

```markdown
# Payments revamp [Planned]

**Purpose:** Let tenants pay by card.
**NOT included:** Refunds, invoicing.
**Dependencies:** Billing service must expose a charge endpoint.

## 1 Add payment method form [Planned]

**Assignee:** —

Build the card-entry form and validation.

- Card number + expiry + CVC fields
- Client-side Luhn check

## 2 Wire charge endpoint [Planned]

**Assignee:** —

Call the billing charge endpoint on submit.

- Handle decline responses
- Show success state
```

## Operations

| Generic operation | How |
|---|---|
| Create `[feature]` | Create `<MARKDOWN_ROOT>/<date>-<slug>/feature.md` with title line `# <name> [Planned]` and the Purpose/NOT included/Dependencies block |
| Create `[task]` under a feature | Append a `## <n> <title> [Planned]` section (next sequential `n`) with `**Assignee:** —`, description, and `-` subtasks |
| Read a `[task]` | Read the file; locate the `## <taskId> ...` section |
| List `[tasks]` in a feature | Read the file; every `##` section is a task |
| Set `[task]` status | Edit that section's header, replacing the trailing `[Status]` |
| Set `[task]` assignee | Edit the `**Assignee:**` line in that section; use the role name verbatim (e.g. `backend`) |
| Set `[feature]` status | Edit the `#` title line's trailing `[Status]` |
| Add a comment to a `[task]` | Append a `> <marker> (yyyy-MM-dd): <content>` line under the task section, where `<marker>` is the exact orchestration marker (e.g. `[design-note]`, `[review-approval]`) or `note` for free-form comments |

## Rules

- Task numbers are sequential within a file and never reused, even after completion.
- Task headers always carry a number **and** a status: `## 3 Title [Active]`.
- Every task section has exactly one `**Assignee:**` line (value: a role name or `—` for unclaimed).
- `featureId` is a file path; `taskId` is a task number (`1`, `2`, `3`).
- Change status only by editing the bracket text — keep exactly one status per header.
- Comment markers must be exact (e.g. `[design-note]`, `[review-approval]`) — never paraphrase them.
- Editing files can't "fail" the way an API can, but a missing folder/file is still an
  andon-cord stop: create the structure, don't silently write to the wrong place.

## Initialization

If `<MARKDOWN_ROOT>` does not exist, create it (an empty directory is enough — no tool
needed). Then proceed. Confirm the path is inside the repo unless the user says otherwise.
