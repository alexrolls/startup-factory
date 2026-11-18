# EGM-assisted planning

Use this workflow only when `bin/planning.py preflight --runtime <runtime>`
resolves `PLANNING_PROVIDER=egm` and validates `EGM_PLUGIN_ROOT`. Start with
`reference/planning.md` for provider selection and the shared handoff contract.

This is **Startup Factory's portable adaptation** of Google's
[Elephant-Goldfish Model](https://github.com/google/elephant-goldfish-model).
It uses the upstream canonical skills, reviewer personas, and document
standards from a complete external bundle. It narrows the interaction policy
and default review budget to fit Factory planning. Do not claim that this compact
flow ran the full upstream brainstorming or five-stage review pipeline.

## Install the complete bundle and opt in

Keep EGM outside the Startup Factory bundle and the project's source tree. For
example, choose a new external directory, clone the complete repository there,
and check out a reviewed revision:

```bash
git clone https://github.com/google/elephant-goldfish-model.git /absolute/tools/egm
git -C /absolute/tools/egm checkout --detach 72d06f52a2482885d9a64bd24b291c6e8628942c
```

This revision was the research baseline, not a claim that every host has been
live-tested. A complete host-plugin installation may also supply the external
root if it includes the required shared resources. Copying only `skills/` is
insufficient: retain the manifest, skills, `agents/`,
`resources/document_standards/`, and referenced documentation. Do not put the
checkout inside the installed Factory skill or vendor its prompts into Factory.

In the installed `config/planning.config.md`, select:

```text
PLANNING_PROVIDER=egm
EGM_PLUGIN_ROOT=/absolute/tools/egm
EGM_SPEC_ROOT=docs/egm/specs
EGM_PLAN_ROOT=docs/egm/plans
```

Then, using the installed skill's paths, run:

```bash
python3 bin/planning.py preflight --runtime codex
```

Use `deepseek-harness`, `claude`, or `other` for those planning sessions.
`EGM_PLUGIN_ROOT=null` is the unconfigured default and cannot satisfy an explicit
EGM selection. A missing or incomplete root fails instead of silently selecting
native planning. The launcher includes the validated root and bundle digest in
the EGM startup context; use that exact root to read the upstream files.

Upstream EGM documents native plugin integration for Codex and Claude Code.
DeepSeek Harness and other compatible file-reading CLIs use this Factory adapter;
no native EGM plugin install command or upstream DeepSeek support is implied.
Read the selected bundle's `docs/harnesses.md` and, for a native Codex session,
`docs/codex.md`. Factory's local preflight is not a live host conformance test.

## Factory interaction and authority policy

When applying EGM inside Factory, these explicit adaptations replace upstream
requirements for repeated section approvals and mandatory author selection of
every architectural alternative:

- Read the project and existing decisions first. Batch only unresolved material
  questions. Reuse established approval and honor delegated technical choices;
  record your choice, rationale, and any consequential assumption.
- A complete supplied specification may take the shared `spec-provided` fast
  path. Do not reopen settled requirements or require a new ideation ritual.
- Present a concrete specification and plan for any still-required design
  approval. Ask the user only when their answer changes the product or scope,
  resolves a material contradiction, or is required by the existing approval
  boundary. The provider does not grant itself approval.
- Default to the compact review below. Additional personas and rounds are a
  scoped escalation for material risks, not a mandatory seven-reviewer swarm.
- Keep implementation, tracker creation/status transitions, mandatory gate
  publication, worktrees, dispatch, integration, and release with Factory.
  EGM reviews are advisory planning evidence, even when performed by fresh agents.

The parent agent is the author/resolver with project history. Reviewers receive
only the written inputs and their explicit reading lists. A different persona in
the same conversation is self-review, not a fresh Goldfish review.

## Compact requirements-to-plan workflow

1. **Load the canonical material.** Read `skills/egm-brainstorm/SKILL.md`,
   `skills/egm-draft/SKILL.md`,
   `resources/document_standards/feature-spec-standard.md`, and
   `resources/document_standards/implementation-readiness-standard.md` from
   the validated EGM root. Apply the Factory interaction policy above instead
   of entering upstream's repeated interactive gates.
2. **Shape the brief.** For `brainstormed`, write a bounded concepts brief in a
   per-[feature] planning directory. Capture the user, problem, measurable
   outcome, goals/non-goals, constraints, alternatives, known risks, and decisions
   still needed. For `spec-provided`, check those inputs without inventing new
   commitments. Use separate per-[feature] paths rather than shared scratch files.
3. **Write the specification.** Save it under `EGM_SPEC_ROOT`, describing current
   behavior, proposed behavior, interfaces and data effects, failure cases,
   alternatives and trade-offs, acceptance criteria, and material limits.
   Link source material that a later reviewer actually needs. Compare the draft
   to the brief: identify contradictions, omissions, and new decisions; label
   delegated choices and resolve material disagreements.
4. **Write the implementation plan.** Save it under `EGM_PLAN_ROOT`. Map each
   requirement to a bounded [task] and verification. Define exact file boundaries,
   interfaces, dependencies, migrations/compatibility and rollout where relevant.
   Resolve architectural decisions before implementation without transcribing
   every function body. The plan is an input to Factory's own task shaping.
5. **Run the two fresh reviews below.** Start them independently with no parent
   conversation history. Use a host-enforced read-only tool profile where
   available; do not give a reviewer edit, implementation, or approval authority.
6. **Resolve and report.** Keep both paraphrases and raw findings. Consolidate
   duplicates with stable finding ids, severity, affected scope, rationale, and
   disposition: fixed, contested with evidence, accepted risk, or open. Retry a
   failed reviewer once; a second failure is `not run`, never zero findings.
   Have the appropriate fresh reviewer check material fixes once. Stop the
   compact flow with residual findings and limitations recorded; do not invent
   convergence or silently accept a blocker on the user's behalf.
7. **Bind and hand off.** Complete any required design approval, commit the final
   specification and plan, then create the handoff. Continue with Factory
   Lifecycle Scenarios 1 and 10. Record review artifacts alongside the planning
   inputs so humans can inspect what was actually reviewed.

### Reviewer 1: document comprehension

Spawn a new reviewer with no parent turns. In Codex's collaboration tool this
means `fork_turns="none"`; inspect the actual tool schema on other hosts instead
of guessing a parameter. Give it:

```text
Read <validated-egm-root>/agents/comprehension.md first.
Mode: REVIEW.
TargetFile: <absolute-specification-path>; SemanticTarget: full file.
Review the document alone. Do not read the concepts brief, conversation,
implementation plan, or codebase. Do not modify files or run builds.
Return both persona-required paraphrases, then severity, affected scope,
and rationale for each finding. If there are none, say so explicitly.
```

The parent compares **What this proposes** and **How the existing system works,
per this document** with the intended behavior. A plausible but wrong paraphrase
exposes missing explanations that a term checklist can miss.

### Reviewer 2: implementation readiness

Spawn another new reviewer without parent turns. Give it the plan,
specification, a small explicit list of relevant source/contract files, and:

```text
Read <validated-egm-root>/agents/implementation_readiness.md first.
Mode: REVIEW.
TargetFile: <absolute-plan-path>; SemanticTarget: full file.
Standard: <validated-egm-root>/resources/document_standards/implementation-readiness-standard.md.
GoldfishContext: <specification and explicit relevant source-file list>.
Check requirement coverage, exact file boundaries and interfaces, unresolved
architectural decisions, dependencies, compatibility, and verification.
Do not modify files or run implementation. Return findings with severity,
affected scope, and rationale; explicitly report if there are none.
```

For significant alternatives or codebase uncertainty, add `agents/design_critic.md`
with the feature standard or `agents/codebase_details.md` with the readiness
standard in a separate fresh review. Read the persona file before use. A compact
review does not satisfy a requested full upstream EGM review; if that is requested,
follow `skills/egm-review/SKILL.md` and record the actual completed stages.

## Isolation, limits, and evidence

Fresh parent-turn context and exclusion of host instruction files are separate
properties. Project/user `AGENTS.md` may still be supplied by the host. Keep
stable workspace conventions there; put assumptions reviewers must challenge in
explicit review criteria. Record the host's limits and never claim complete
instruction isolation merely because a reviewer was fresh.

If the host cannot create fresh contexts, stop the EGM review step, preserve the
draft, and report `not run`. The user may explicitly choose native self-review,
but that is a provider change, not a successful EGM review. A headless reviewer
may not silently omit required evidence and still claim completeness.

This adapter validates local prerequisites and composes instructions. It does
not automatically prove review execution, model quality, isolation, or genuine
read-only enforcement for Codex, DeepSeek Harness, or another CLI. Verify those
properties through an authorized live run before claiming that host qualified.

For an EGM-assisted Codex session, after committing both inputs:

```bash
bash bin/launch-team.sh planning-handoff full-stack \
  docs/egm/specs/export.md docs/egm/plans/export.md brainstormed codex
```

Recreate the handoff if a bound document or bundle changes. The validated inputs
seed planning; Factory's cross-[task] consistency, contracts, architectural
challenge, product sign-off, and authenticated approval requirements still apply.
