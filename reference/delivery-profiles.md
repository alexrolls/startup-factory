# Delivery profiles

Startup Factory has one risk-based delivery policy with three profiles. It
reuses `delivery-profile`, `model-profile`, tiered/parallel review, and Safe
Turbo; it is not a second workflow.

| Profile | Intended scope | Model floor | Core review/checklists | Implementation concurrency | Forced supporting gates |
| --- | --- | --- | --- | --- | --- |
| `micro` | Small, declared, ordinary documentation-only work | `fast` | Invariant full core review | Only when `parallel-safe` is explicitly true | None beyond task/preset gates |
| `standard` | Declared ordinary code, tests, or broader documentation | `standard` | Invariant full core review | Only when `parallel-safe` is explicitly true | None beyond task/preset gates |
| `high-risk` | Absent/unknown scope, security/auth/credentials, deploy/release/production, control-plane or policy work, operations, destructive/unsafe changes, or ambiguous exact evidence | `strong` | Invariant full core review | Exclusive | QA and Security |

`delivery-profile: auto` selects the inferred profile. An explicit `micro`,
`standard`, or `high-risk` is a minimum, never a waiver: a requested profile
may raise rigor but cannot lower the inferred profile. Existing
`model-profile` values work the same way; the stronger of the task choice,
legacy heuristic, and delivery-profile floor wins.

Only the model floor, implementation concurrency, and forced supporting
QA/Security gates vary by delivery profile. Core design/review roles, their
checklists, and the team preset's `REVIEW_MODE` remain invariant; the profile
does not apply a reduced checklist or an alternate review mode.

High-risk path rules use normalized path components and bounded filename
classes, not four or five project-specific examples. They cover common
authentication/session/CSRF/credential surfaces, credential artifacts,
migration/schema paths, dependency manifests and lockfiles, CI and deployment
roots, container manifests, and Terraform and other common
infrastructure-as-code files. Similar ordinary names such as `author.py`,
`schematic_view.py`, or `chart_renderer.py` do not match those component/name
rules. Identifier normalization exposes camel-case and acronym boundaries, so
names such as `csrfProtection`, `refreshToken`, and `rbacPolicy` are covered
without treating `author`, `releaseDate`, `designTokens`, a generic React hook,
or a workshop session as a security or release operation. A repeated `files:`
metadata declaration is ambiguous and therefore classifies as `high-risk`.

## Two monotonic decisions

The task-time decision uses the title, description, declared files/resources,
and work kind. It controls implementation model routing and whether a task can
share a parallel implementation wave. Missing file metadata is unknown scope
and therefore `high-risk`: legacy tasks receive the strong model floor,
exclusive implementation, QA, and Security until their file scope is declared.

At review request publication, Startup Factory reclassifies the exact committed
`Review-Base-Commit..Task-Branch-Head` diff. Actual paths, modes, statuses,
line counts, binary data, patch content, and declared-file agreement are part
of that decision. The request binds the monotonic union of:

- task-declared gates;
- authenticated team-preset gates;
- exact-diff profile gates.

The dispatcher independently recomputes that decision, and the integrator
recomputes it again against the exact package commits. A malformed request,
missing Git object, unreadable repository, oversized/unreadable patch, empty
diff, or other classification ambiguity becomes `high-risk`; it never removes
a gate. For example, a ticket described as a documentation `micro` change that
actually edits authentication code must collect both QA and Security approval.
Git classification and exact review-package creation/replay use the same
bounded runner: one absolute executable resolved from the controlled system
path, a minimal child environment, disabled lazy fetch and replace objects, all
transport protocols denied, no external diff or text conversion, deterministic
diff options, bounded input/output, a wall-clock deadline, and process-group
termination. Target blobs are inspected independently of diff attributes.
Normal binary changes are emitted as Git binary patches; if versioned
attributes try to force NUL-bearing data into a text patch, package creation
fails closed instead of emitting raw NUL or incomplete evidence. Package
creation therefore cannot inherit executable
search, diff-helper, credential, transport, or lazy-object authority from the
caller or repository, and the integrator byte-for-byte regenerates that package
before accepting it. A repository-configured `core.attributesFile` and ignored
submodules cannot hide changes. Versioned `.gitattributes` remains part of the
reviewed repository contract; `.git/info/attributes` is protected Git metadata
and must remain outside agent write authority.

Every review request and approval must contain exactly one unambiguous `Files:`
declaration. Duplicate declarations, duplicate paths, contradictory approval
lists, mixed separators, and unquoted whitespace-only lists fail closed. The
publication boundary compares the request list to the exact committed diff;
later dispatch and integration checks preserve that binding.

Integration constructs a canonical tree as a disjoint overlay of the reviewed
task objects onto the exact feature-branch base. If the feature branch changed
any reviewed path (including a parent/child path), integration stops for rebase
and re-review. The Integrator materializes only that tree, and the credentialed
finalizer independently reproduces and compares its tree ID before any tracker
mutation. Repository-local merge drivers are never used for reviewed content.

## Authority that profiles never change

Every profile preserves all of the following:

- distinct Team Lead, Principal Architect, and Sceptical Architect review
  decisions;
- Product, Principal Architect, and Sceptical Architect design decisions;
- exact-package evidence and independently bound validation;
- immutable deny rules and the Integrator's sole merge authority;
- credential-separated release and production authority.

Safe Turbo may use the profile's model floor and declared implementation
concurrency only after its existing readiness checks pass. Review scheduling
continues to come from the authenticated team preset. Safe Turbo cannot reduce
the core review board or its checklists, bypass an inferred high-risk profile,
or grant release/production authority.

## Examples

```text
files: docs/quickstart.md
delivery-profile: auto
parallel-safe: true
```

This can be `micro` if the exact diff remains small ordinary documentation.

```text
files: src/widget.py
delivery-profile: micro
parallel-safe: true
```

This is at least `standard`; the `micro` request cannot lower it.

```text
files: src/auth.py
delivery-profile: standard
parallel-safe: true
```

This is `high-risk`, runs exclusively, uses the strong model floor, and
requires QA plus Security. The explicit `standard` and `parallel-safe` fields
cannot weaken those decisions.
