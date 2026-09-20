# Reproducible governed delivery walkthrough

This walkthrough exercises a small documentation delivery on a disposable
repository. It produces no deployment and grants no production authority. It is
reproducible at the process boundary; latency and model output still depend on
the selected agent runtime, so record them rather than presenting this document
as a benchmark result. This checked-in document contains no execution result,
and Startup Factory 0.2.0 does not ship the OS sandbox runner required for
authenticated team publication.

## Prerequisites

- macOS or Linux with Git, Bash, Python 3.10 through 3.14, and `uv`/`uvx`;
- an already-provisioned, operator-approved external sandbox runner that
  implements the invocation and isolation contract in
  [`orchestration.md`](orchestration.md). It must be a protected executable
  outside this fixture and the installed runtime; this walkthrough does not
  provide or certify one;
- authenticated agent commands for the configured team roles;
- access to an approved Python package index or cache containing the exact
  build-tool versions below. Keep index credentials in the operator environment,
  never in this repository or a copied command.

## Create the fixture

```bash
mkdir startup-factory-walkthrough
cd startup-factory-walkthrough
SF_TARGET="$(pwd -P)"
git init
git config user.name "Walkthrough User"
git config user.email "walkthrough@example.invalid"
printf '# Walkthrough\n' > README.md
git add README.md
git commit -m 'Create walkthrough fixture'
git switch -c walkthrough/governed-doc-change
```

Use a dedicated directory and a non-production repository. Do not reuse a
checkout containing credentials or unrelated uncommitted work.

## Install the exact candidate

For a published release, pin its version as shown below. For a release-candidate
test, use a clean Startup Factory source checkout and build the canonical bundle
plus distributions from the exact commit. The following commands reproduce the
package layout used by release CI. First change to a separate, clean Startup
Factory source checkout; do not run these commands from the disposable target
created above. Run the blocks in the same shell so `SF_TARGET`, `SF_BUILD`, and
`SF_VERSION` remain available; after resuming a shell, set those variables again
to their exact absolute values.

```bash
: "${SF_TARGET:?set SF_TARGET to the disposable walkthrough repository}"
cd /absolute/path/to/clean/startup-factory-source
SF_SOURCE="$(pwd -P)"
SF_COMMIT="$(git rev-parse HEAD)"
SF_VERSION="$(python3 -c 'import pathlib,re; v=re.findall(r"(?m)^version = \"([0-9]+\.[0-9]+\.[0-9]+)\"$", pathlib.Path("pyproject.toml").read_text()); assert len(v) == 1; print(v[0])')"
SF_BUILD="$(mktemp -d "${TMPDIR:-/tmp}/startup-factory-rc.XXXXXX")"
python3 -m venv "$SF_BUILD/build-env"
"$SF_BUILD/build-env/bin/python" -m pip install --disable-pip-version-check \
  build==1.3.0 packaging==26.2 pyproject-hooks==1.2.0 \
  setuptools==83.0.0 wheel==0.47.0
python3 packaging/build_bundle.py --repo "$SF_SOURCE" \
  --commit "$SF_COMMIT" --version "$SF_VERSION" \
  --output "$SF_BUILD/startup-factory-$SF_VERSION.tar.gz"
mkdir -p "$SF_BUILD/package/src/startup_factory_cli/resources" "$SF_BUILD/dist"
git archive "$SF_COMMIT" | tar -x -C "$SF_BUILD/package"
cp "$SF_BUILD/startup-factory-$SF_VERSION.tar.gz" \
  "$SF_BUILD/package/src/startup_factory_cli/resources/startup-factory.tar.gz"
python3 -c 'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]); print(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}")' \
  "$SF_BUILD/package/src/startup_factory_cli/resources/startup-factory.tar.gz" \
  > "$SF_BUILD/package/src/startup_factory_cli/resources/startup-factory.tar.gz.sha256"
SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$SF_COMMIT")"
export SOURCE_DATE_EPOCH
"$SF_BUILD/build-env/bin/python" -m build --no-isolation \
  --outdir "$SF_BUILD/dist" "$SF_BUILD/package"
"$SF_BUILD/build-env/bin/python" tests/packaging/test_packaging_metadata.py \
  --canonicalize-sdist "$SF_BUILD"/dist/*.tar.gz "$SOURCE_DATE_EPOCH"
python3 -c 'import hashlib,pathlib,sys; [print(hashlib.sha256(p.read_bytes()).hexdigest(), p) for p in map(pathlib.Path, sys.argv[1:])]' \
  "$SF_BUILD/startup-factory-$SF_VERSION.tar.gz" "$SF_BUILD"/dist/*
cd "$SF_TARGET"
```

From the disposable walkthrough repository, install through that built wheel
and pass the exact local bundle explicitly:

```bash
: "${SF_BUILD:?set SF_BUILD to the retained release-candidate build directory}"
: "${SF_VERSION:?set SF_VERSION to the exact candidate version}"
uvx --from "$SF_BUILD/dist/startup_factory-$SF_VERSION-py3-none-any.whl" \
  startup-factory install --agent codex \
  --bundle "$SF_BUILD/startup-factory-$SF_VERSION.tar.gz"
uvx --from "$SF_BUILD/dist/startup_factory-$SF_VERSION-py3-none-any.whl" \
  startup-factory verify --agent codex
uvx --from "$SF_BUILD/dist/startup_factory-$SF_VERSION-py3-none-any.whl" \
  startup-factory init --agent codex --mode team \
  --product-management-tool Markdown --apply
```

Retain the printed bundle, wheel, and sdist names and SHA-256 values with the
exact commit. This single build supports the walkthrough only; beta
reproducibility evidence still requires two distinctly identified clean builds
and an identical canonical release-set digest. Use the published-version
commands below only after that version exists.

```bash
uvx startup-factory@0.2.0 install --agent codex
uvx startup-factory@0.2.0 init --agent codex --mode team \
  --product-management-tool Markdown --apply
uvx startup-factory@0.2.0 verify --agent codex
```

## Configure the protected team boundary

Create a project-specific lifecycle directory as the human operator; this
per-user fixture does not require `sudo`:

```bash
SF_LIFECYCLE="$HOME/.local/state/startup-factory/walkthrough/lifecycle"
umask 077
mkdir -p -- "$SF_LIFECYCLE"
chmod 700 -- "$SF_LIFECYCLE"
SF_LIFECYCLE="$(cd "$SF_LIFECYCLE" && pwd -P)"
: "${SF_SANDBOX_RUNNER:?set this to the canonical path of the pre-provisioned runner}"
```

Do not create `SF_SANDBOX_RUNNER` from this repository or substitute a shell
pass-through script: the external runner must actually enforce worktree-only
writes and hide broker state, host credentials, and unauthorized network and
process surfaces. Set the four existing assignments in the installed
`.agents/skills/startup-factory/config/team.config.md` to:

```text
TRACKER_WRITERS=broker
AGENT_SANDBOX_RUNNER="<the exact SF_SANDBOX_RUNNER path>"
AGENT_SANDBOX_ENFORCED=true
BROKER_LIFECYCLE_ROOT="<the exact SF_LIFECYCLE path>"
```

For Claude Code, edit the equivalent runtime below `.claude/skills/`. Configure
the runner so workers cannot list, read, write, create, rename, or remove
lifecycle records; only the launch-specific connect-only publication transport
may be exposed.

For the locally built release candidate, run the offline structural doctor:

```bash
uvx --from "$SF_BUILD/dist/startup_factory-$SF_VERSION-py3-none-any.whl" \
  startup-factory doctor --agent codex --mode team
```

For the published-version alternative, use:

```bash
uvx startup-factory@0.2.0 doctor --agent codex --mode team
```

The report must show `tracker-writer-boundary.configured`,
`sandbox-runner.configured`, and `lifecycle-authority.configured` as `pass`.
It remains yellow because offline doctor deliberately does not execute the
runner, authenticate agent commands, contact the tracker, or grant approval.
After the `[feature]` exists, the installed
`bin/launch-team.sh doctor <preset> <team> <featureId>` probe must also succeed
before persistent roles start. A null runner, `AGENT_SANDBOX_ENFORCED=false`, or
manual/unauthenticated launch cannot produce the authenticated review and
integration trail required below.

## Exercise a validated pack

```bash
mkdir -p .startup-factory/plans
uvx --from "$SF_BUILD/dist/startup_factory-$SF_VERSION-py3-none-any.whl" \
  startup-factory integration-pack preview tracker-markdown \
  --agent codex --project . --json \
  > .startup-factory/plans/tracker-markdown.json
uvx --from "$SF_BUILD/dist/startup_factory-$SF_VERSION-py3-none-any.whl" \
  startup-factory integration-pack apply \
  .startup-factory/plans/tracker-markdown.json --agent codex --project .
uvx --from "$SF_BUILD/dist/startup_factory-$SF_VERSION-py3-none-any.whl" \
  startup-factory integration-pack doctor tracker-markdown \
  --agent codex --project .
```

The saved plan contains absolute local paths and filesystem identities. Keep
`.startup-factory/plans/` transient and uncommitted, and remove the plan after
this exercise.

Expected result: `--project .` identifies this disposable host repository,
while tracker apply changes at most the installed runtime file
`.agents/skills/startup-factory/config/project-management.config.md`. It never
writes a host-repository `config/` path. For Claude Code the runtime path starts
`.claude/skills/`; CI and deployment packs instead create inactive templates at
their declared host-repository targets. A retry is idempotent, and doctor
reports configuration, local detection, credential policy/name presence, and
`proof: unknown` as separate facts. Local doctor never authenticates a
provider; only a separately protected external adapter may supply authenticated
evidence. Doctor does not make a network request or print a credential value.
Consequently the local command exits `1` with a yellow report after successful
local setup: the exact external proof is still unknown. Markdown reports
credentials as `not-required`; hosted adapters retain their own authentication
boundary.

## Run the delivery

Send this exact intent to the configured agent:

```text
Use the installed Startup Factory with the Markdown adapter. Create one [feature]
named “Document local development” and one [task] that changes only README.md.
Add a Local development heading and one sentence saying this repository is a
disposable walkthrough. Keep production and release disabled. Show the plan and
wait for scope approval before implementation.
```

After approving the bounded scope:

```text
Start the task, preserve the isolated task branch, run the relevant validation,
and submit the exact package for every required independent review. Finalize the
task only when current approvals bind that package. Do not deploy or release.
```

## Conditional expected result

The following is expected only after the external runner and launcher doctor
satisfy the protected runtime prerequisites. It is a checklist for captured
evidence, not a claim that this repository has already completed the run.

- One `[feature]` and one `[task]` exist in the Markdown board using configured
  statuses and generic vocabulary.
- The task declares only `README.md`; a wider actual diff escalates rather than
  retaining the micro profile.
- Product scope and both architecture decisions remain required. Micro may use
  a lower model floor and explicitly declared parallel-safe implementation, but
  it cannot change the preset review mode or core checklists, or remove the
  three core review decisions or exact-package evidence.
- The reviewed file set is exactly `README.md`, validation is current, and the
  task reaches the configured integration terminal state.
- No release executor, deployment credential, production mutation, or published
  release is involved. No release is an expected and required outcome here.

Record the start/end UTC timestamps, cold or warm state, exact version/commit,
runtime/model, operating system, hardware, retries, review/rework time, and any
runtime-reported token or cost data. Give every expected agent-runtime
invocation a stable run id in the environment manifest and retain the complete
sorted roster; the protected usage recorder must attest that its records cover
that roster exactly. For each unavailable field, store `null` plus a specific
reason and render it as `unknown` only in summaries. Follow the delivery
benchmark methodology before using the result in a beta-readiness decision.

## Capture governed execution evidence

Documentation and a successful local command are not execution evidence. The
protected walkthrough operator must retain the native audit records and emit a
strict `governed-walkthrough-execution` artifact for the exact candidate and
canonical release set. That artifact binds all of the following:

- the disposable fixture commit, task ID, exact `README.md` changed-file set,
  and environment-manifest digest;
- the `micro` profile-decision digest, the same changed-file set, no supporting
  review gates, and explicit confirmation that core review and exact-package
  evidence remained required;
- the selected `tracker-markdown` pack digest, saved-plan digest, validation
  result, configured doctor result, and unauthenticated local proof reported as
  `unknown`;
- the authenticated review publication trail: schema-v2 broker receipt digests
  for the request and all three core approvals, the schema-v8 approval-evidence
  digest, and the exact review-package digest;
- the completed schema-v2 integration transaction ID, commit, transaction
  digest, and its bindings to the same review package and approval evidence;
- ordered start/end timestamps, exact integer-millisecond duration, and a raw
  evidence digest; and
- four explicit false values proving release and deployment were both disabled
  and unattempted.

The readiness checker also requires the walkthrough fixture commit, task ID,
pack ID/digest, and environment-manifest digest to equal the benchmark fixture
bindings. A prose assertion, direct tracker comment, schema-v1/legacy review,
different pack, or enabled/attempted release or deployment fails closed. The
secret-free normalized artifact carries only hashes and identifiers; credentials
and private logs stay in the protected evidence system.
