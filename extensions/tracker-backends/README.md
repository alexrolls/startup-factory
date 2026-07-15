# Custom tracker backends

Put one Python backend module here for each custom project-management adapter:

```text
extensions/tracker-backends/<AdapterName>.py
```

`<AdapterName>` must exactly match `PRODUCT_MANAGEMENT_TOOL` and
`adapters/<AdapterName>.md`. It may contain letters, digits, `_`, and `-`, and
must start with a letter. Shipped adapters remain implemented inside
`bin/tracker-ops.sh`; this directory is for project-owned adapters only. The
module must be a regular, non-symlink file; it is loaded directly, never through
shell command evaluation.

Export `Backend`, a class whose constructor accepts one context dictionary with
`adapter`, `skill_dir`, `pm_config`, `task_statuses`, `feature_statuses`, and
`operation_timeout_seconds`. It must implement these lower-level primitives:

- `current_status`, `current_labels`, `set_state`, `set_assignee`
- `current_feature_status`, `set_feature_state`
- `comment`, `comment_exists`, `update_comment`, `integration_comment_exists`
- `upsert_progress`, `upsert_digest`, `upsert_deployment`
- `export`, `scan`

`bin/tracker-ops.sh` keeps ownership of normalized operation parsing, legal
transitions, the human-only exit from `[Blocked]`, `human-work` mutation fences,
claim/integration idempotency, and status read-back. The backend implements the
tool primitives without bypassing that common layer. Its `scan` and `export`
results still pass the core normalized-schema checks. Backend upserts and remote
mutations must remain idempotent and read back tool state; raise an exception on
any unsupported, ambiguous, partial, timed-out, or unverified result.

Do not edit `bin/tracker-ops.sh` to register a custom backend. That file is
upstream-owned and replaced during updates. Destination-only modules in this
directory are project-owned and preserved by the installer; its ownership
manifest still removes a backend that was shipped by upstream and later
retired.

For autonomous operation, keep the whole Startup Factory installation in the
protected external location described in `reference/automation.md`. Repository
files and mode bits are not an OS security boundary. For production delivery,
also pin the module in the protected deployment config as
`trustedCodeDigests["tracker-backend.<AdapterName>.py"]`. The PM supervisor and
release executor capture that exact digest into both protected code snapshots;
an unpinned, missing, or changed backend fails closed.
