# DeepSeek Harness Runtime Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DeepSeek Harness (`dsh`) a first-class, documented, and tested LLM runtime for Startup Factory role commands, on the same tier as Codex CLI and Gemini CLI.

**Architecture:** Startup Factory has no per-LLM adapter layer — a runtime is one shell command template per role in `config/team.config.md`, spawned via `env -i <allowlist> /bin/bash -c "<template>"`. DeepSeek Harness's one-shot mode (`dsh --profile headless "<task>"`) prints the final assistant answer to stdout and exits 0/1, which matches this contract exactly. The integration is therefore: characterization tests, documentation (command template + credential/home setup), and a first-class installer `--agent` mapping. **No orchestrator code changes.**

**Tech Stack:** Bash (launcher + tests), Python (installer CLI + unittest), Markdown config/docs. DeepSeek Harness itself: Node.js, npm package `@deepseek-ai/dsh`.

**Spec:** The "Background: verified facts" section below — this plan was researched directly from `deepseek-ai/deepseek-harness@master` (2026-08-23) and this repo at `codex/release-0.1.9`; there is no separate spec document.

## Global Constraints

- Do NOT add a third runtime-family enum value. `classify_command_runtime()` / `harness_runtime()` (`bin/launch-team.sh:644-736`) legally return only `claude` or `other`. DeepSeek Harness is classified `other`, same as Codex and Gemini. (Rationale in "Rejected options" below.)
- `config/team.config.md` keys are read with plain `grep '^KEY='` — one `KEY=value` per line inside fenced blocks, no spaces around `=`.
- Tests must stay offline: no network, no real LLM calls, stub executables only (existing pattern: `tests/launcher-test.sh:168-184`).
- `AGENT_ENV_ALLOWLIST` is documented as non-secret names only; API keys belong in `AGENT_SANDBOX_HOME` state files, not the allowlist.
- Version stays `0.1.9`; this plan does not bump it. (If a release later includes this work, the bump must touch `pyproject.toml:7`, `README.md:71`, and `tests/packaging/test_packaging_metadata.py:126,:277` together.)
- All test suites run via `bash tests/run-all.sh`; individual suites via `bash tests/launcher-test.sh` and `python3 -m pytest tests/packaging/test_cli_installer.py -q` (or `python3 -m unittest`).

---

## Background: verified facts

### DeepSeek Harness (`dsh`) — from deepseek-ai/deepseek-harness@master

- Open-source agent harness by DeepSeek AI ("everything is a plugin", Cordis-based). MIT license. **Developer preview: breaking changes are expected** — pin the npm version in docs.
- Install: `npm install -g @deepseek-ai/dsh` → binary `dsh` (requires Node.js). `npx @deepseek-ai/dsh` also works but has cold-start latency — do not use npx inside role command templates.
- **One-shot mode (the integration surface):** `dsh --profile headless "task text"` — creates one fresh persisted agent session, submits the task, waits for quiescence, prints the **last non-empty assistant text to stdout**, and exits **0 for `completed`, 1 otherwise**. Successful runs write nothing to stderr and open no port. Task text is a positional argument; a missing/whitespace task is a usage error. (Source: `apps/cli/reference/README.md`, `packages/bundle/headless/README.md`.)
- No interactive follow-up in headless mode: one submitted task per process — exactly the Startup Factory execution model.
- Workspace = invoking directory. Loads `AGENTS.md` or `CLAUDE.md` from it (65,536-byte render budget).
- Permissions: new sessions default to the `workspace-write` preset (bash + filesystem mutations confined to workspace + temp roots; reads and network unconfined). `DSH_PERMISSION_MODE` changes the process fallback. **No auto-approve flag is needed** — headless has no approval prompt surface.
- State/config home: `$DSH_HOME` (profiles under `$DSH_HOME/profiles/<name>`, user settings in `$DSH_HOME/settings.yaml`, credentials in `$DSH_HOME/.credentials.yaml`, machine-local overrides in `$DSH_HOME/cordis.patch.yml`). The `headless` profile auto-initializes on first use from shipped templates — no `pnpm` needed for the in-box bundles.
- Credential resolution order: inherited environment (`DEEPSEEK_API_KEY`) → `$DSH_HOME/.credentials.yaml` → invoking directory's `.env` → `$DSH_HOME/.env`.
- Model selection: process-wide default `{provider, model}` from the `agent-default-model` config row, layered under user settings; per-invocation override via `--patch <file.yml>` overlay (launcher flag, valid before the positional task). Other providers (Anthropic/OpenAI/custom OpenAI-compatible gateways) configurable in `$DSH_HOME/settings.yaml`.
- MCP client ships but no MCP server is enabled by default. Telemetry is local by default.
- Also exists but NOT used by this integration: Web UI (`dsh web`), Python SDK (`deepseek-harness-sdk`), ACP server (`packages/acp`), and — amusingly — dsh's own optional *subagent providers for Codex and Claude Code*.

### Startup Factory — integration points (repo `codex/release-0.1.9`)

- Runtime = command template string: `config/team.config.md` lines 26-40 (`<ROLE>_CMD`, `TEAM_DEFAULT_CMD`, `TASK_FAST/STANDARD/STRONG_CMD`). `{prompt_file}` is substituted with the composed prompt path; string-arg CLIs inline it via `$(cat '{prompt_file}')`.
- Spawn: `prepare_execution()` `bin/launch-team.sh:568-582` → `env -i <AGENT_ENV_ALLOWLIST values> /bin/bash -c "$command"`, via tmux window or background subprocess. Fully runtime-agnostic.
- Runtime classification: `classify_command_runtime()` `bin/launch-team.sh:644-711` returns `claude` (literal basename or explicit `STARTUP_FACTORY_LLM_RUNTIME=claude` prefix token) or `other`. Only consumer: Claude-only Superpowers prompt injection (`bin/launch-team.sh:1351`, `:1439`).
- Env: default `AGENT_ENV_ALLOWLIST="PATH TMPDIR LANG LC_ALL TERM NO_COLOR"` (`config/team.config.md:70`). Ambient `HOME` is refused; `HOME` is injected only from `AGENT_SANDBOX_HOME` (`config/team.config.md:75`, rules at `:163-167`). `DEEPSEEK_API_KEY` is *not* on the privileged blocklist (`privileged_agent_env_name`, `bin/launch-team.sh`), but allowlist policy says non-secret names only.
- Health check: `bin/launch-team.sh doctor <preset> <team> <featureId>` spawns each configured command with a random-token probe and checks stdout — works for any CLI unchanged.
- Installer: `--agent` choices `AGENTS = ("codex", "aider", "claude", "claude-code")` (`src/startup_factory_cli/cli.py:25`); mapping dict in `resolve_target()` (`src/startup_factory_cli/installer.py:501-506`). `bin/update-installed-skill.sh:595-609` auto-detects only `.agents/skills/` and `.claude/skills/` — dsh will use `.agents/`, so no change there.
- Delivery-risk classifier `bin/delivery_profile.py:30-74` already protects `.agents`, `agents.md`, `claude.md`. dsh keeps its state in `$DSH_HOME` (outside the repo) and reads `AGENTS.md` — **no new project dotdir → no change needed.**
- Tests: `tests/launcher-test.sh:168-260` (stub CLIs `claude`/`codex`/`gemini`/`custom-wrapper`, classification + Superpowers-injection assertions), `tests/task-runtime-test.sh` (task-packet level), `tests/packaging/test_cli_installer.py` (agent mapping).

### The command template (the heart of the integration)

```bash
dsh --profile headless "$(cat '{prompt_file}')"
```

- stdout = final answer only → compatible with `doctor` token probe.
- exit 0 only on completed → compatible with launcher failure detection.
- No auto-approve flag needed; default `workspace-write` sandbox is *stronger* than `--yolo`/`--full-auto` peers.

### Rejected options (do not implement)

- **Third runtime family (`deepseek`)**: the enum exists solely to gate Claude-only Superpowers prompt injection. dsh has no analogous plugin ecosystem to gate. YAGNI; `other` is full support.
- **Python SDK / ACP integration**: Startup Factory's contract is "spawn a CLI per role". The SDK/ACP would require a new long-lived-process supervisor — a different architecture, no benefit for this use case.
- **`.env` in the workdir for credentials**: dsh does read it, but that puts secrets inside the repo working tree agents can read/commit. Use `AGENT_SANDBOX_HOME` instead.

---

## File Structure

| File | Change |
|---|---|
| `tests/launcher-test.sh` | Add `dsh` stub + classification block (characterization) |
| `README.md` | Command-template table row; install-directory table row; dsh setup notes |
| `config/team.config.md` | Comment-level mention of the dsh template + credential note |
| `src/startup_factory_cli/cli.py` | Add `"deepseek-harness"` to `AGENTS` |
| `src/startup_factory_cli/installer.py` | Add `"deepseek-harness"` mapping |
| `tests/packaging/test_cli_installer.py` | New test for the mapping |

No changes to: `bin/launch-team.sh`, `bin/delivery_profile.py`, `bin/update-installed-skill.sh`, `packaging/bundle-spec.json` (all listed roots already ship the touched files).

---

### Task 1: Characterization test — `dsh` classifies as `other`, no Superpowers injection

**Files:**
- Modify: `tests/launcher-test.sh` (stub creation around lines 168-184; new block after the gemini block ending near line 213)

**Interfaces:**
- Consumes: existing test helpers `check`, `sed_i`, `$LAUNCH`, `$CFG_SANDBOX`, `TEAM_RUNNER=background`.
- Produces: nothing for later tasks; locks in the behavior Task 2 documents.

This is a characterization test: the behavior already works by construction, so the test passes immediately. Its job is to pin DeepSeek Harness support so a future refactor of `classify_command_runtime()` cannot silently break it.

- [ ] **Step 1: Add the `dsh` stub next to the existing stubs**

In `tests/launcher-test.sh`, in the stub-creation run (where `claude`, `codex`, `gemini`, `custom-wrapper` heredocs are written, lines ~168-184), append:

```bash
cat > dsh <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
```

and extend the `chmod` line to include it:

```bash
chmod +x claude codex gemini custom-wrapper dsh
```

- [ ] **Step 2: Add the classification block after the gemini block**

Immediately after the gemini assertions (the block ending `echo "ok: Gemini CLI command excludes Superpowers planning instructions"` / `fi`), insert:

```bash
sed_i 's|^FRONTEND_CMD=.*|FRONTEND_CMD="./dsh --profile headless \"$(cat '\''{prompt_file}'\'')\""|' "$CFG_SANDBOX"
TEAM_RUNNER=background "$LAUNCH" start dsh-planning FEAT-DSH frontend
dsh_prompt=.teamwork/dsh-planning/prompts/frontend.md
check "DeepSeek Harness command is classified as non-Claude" grep -q "LLM runtime family: other" "$dsh_prompt"
if grep -q "Claude + obra/superpowers planning" "$dsh_prompt"; then
  echo "FAIL: DeepSeek Harness command received Superpowers planning instructions"; FAILURES=$((FAILURES+1))
else
  echo "ok: DeepSeek Harness command excludes Superpowers planning instructions"
fi
```

Note the quoting: the `sed_i` replacement writes the *real* recommended template (with `$(cat '{prompt_file}')` inlined) into the config, so the test exercises the exact string users will copy. If the nested quoting fights you, the simpler file-arg form `FRONTEND_CMD="./dsh --profile headless {prompt_file}"` is an acceptable fallback — classification only inspects the command tokens, not the prompt-delivery style — but prefer the real template.

- [ ] **Step 3: Run the suite and verify it passes**

Run: `bash tests/launcher-test.sh`
Expected: PASS, including the two new `ok:`/`check` lines; `FAILURES` unchanged at 0.

- [ ] **Step 4: Run the full offline suite**

Run: `bash tests/run-all.sh`
Expected: PASS (guards against accidental breakage of neighboring blocks that reuse `FRONTEND_CMD`).

- [ ] **Step 5: Commit**

```bash
git add tests/launcher-test.sh
git commit -m "test: pin DeepSeek Harness (dsh) runtime classification as other"
```

---

### Task 2: Documentation — command template, credentials, and safety notes

**Files:**
- Modify: `README.md` ("Command templates for common CLIs" table, ~line 936; the safety/setup prose around it)
- Modify: `config/team.config.md` (blockquote after the role map, ~lines 41-48; the `AGENT_SANDBOX_HOME` rule prose, ~lines 163-167)

**Interfaces:**
- Consumes: the verified template from Background.
- Produces: the exact user-facing template string that Task 5 validates live.

- [ ] **Step 1: Add the README command-template row**

In `README.md`, extend the table (currently Claude Code / Codex CLI / Gemini CLI / Any file-reading CLI):

```markdown
| DeepSeek Harness | `dsh --profile headless "$(cat '{prompt_file}')"` |
```

Place it after the Gemini CLI row, before "Any file-reading CLI".

- [ ] **Step 2: Add a DeepSeek Harness setup note after the table**

Insert after the wrapper-marking paragraph (`FRONTEND_CMD="STARTUP_FACTORY_LLM_RUNTIME=claude ...`) and before "**Mixing LLMs is the design intent**":

```markdown
DeepSeek Harness (`dsh`) needs Node.js and a one-time global install —
`npm install -g @deepseek-ai/dsh` (pin a version; the project is in developer
preview with breaking changes). Its one-shot mode prints only the final answer
on stdout and exits non-zero on failure, so `doctor` and task dispatch work
unchanged. It needs no auto-approve flag: headless sessions run under dsh's own
`workspace-write` sandbox (writes confined to the working directory). Credentials
and model defaults live under `$DSH_HOME` (default: under `$HOME`) —
`.credentials.yaml` / `settings.yaml` — so when `AGENT_SANDBOX_HOME` is
configured, place the reviewed dsh state inside that sandbox home (or allowlist
a `DSH_HOME` pointing at reviewed state outside it). dsh is classified as
runtime family `other`, like Codex and Gemini.
```

- [ ] **Step 3: Mention dsh in `config/team.config.md`**

In the blockquote directly under the role-map code block (the one beginning "> Mixing LLMs is the design intent"), extend the first example sentence to include DeepSeek:

```markdown
> Mixing LLMs is the design intent — e.g. Claude for team-lead/principal-architect,
> Codex for the sceptical-architect, Senior Security Engineer, and implementers,
> Gemini or DeepSeek Harness (`dsh --profile headless "$(cat '{prompt_file}')"`)
> for review diversity.
```

And in the Rules section's `AGENT_SANDBOX_HOME` bullet (lines ~163-167), append one sentence:

```markdown
  For DeepSeek Harness, that state is `$DSH_HOME` (`.credentials.yaml`,
  `settings.yaml`, `profiles/headless/`), which resolves under `HOME` by default.
```

- [ ] **Step 4: Verify docs render and keys still parse**

Run: `bash tests/run-all.sh`
Expected: PASS (the team-config parser greps `^KEY=` lines; the edits above touch only comments/prose, so nothing may break — this run proves it).

Run: `grep -n 'dsh --profile headless' README.md config/team.config.md`
Expected: the three insertion sites are listed.

- [ ] **Step 5: Commit**

```bash
git add README.md config/team.config.md
git commit -m "docs: add DeepSeek Harness (dsh) command template and setup notes"
```

---

### Task 3: Installer — first-class `--agent deepseek-harness`

**Files:**
- Modify: `src/startup_factory_cli/cli.py:25` (`AGENTS` tuple)
- Modify: `src/startup_factory_cli/installer.py:501-506` (`mappings` dict in `resolve_target()`)
- Modify: `README.md` (install-directory table, ~line 661)
- Test: `tests/packaging/test_cli_installer.py`

**Interfaces:**
- Consumes: existing `InstallerHarness.install(agent=...)` test helper (`tests/packaging/test_cli_installer.py:162-176`), whose expected-path logic (`".claude/..." if agent.startswith("claude") else ".agents/..."`) already yields the right path for `deepseek-harness`.
- Produces: CLI accepts `--agent deepseek-harness` for `install`/`update`/`verify`/`uninstall`, resolving to `.agents/skills/startup-factory`.

dsh reads `AGENTS.md` natively and its ecosystem uses `.agents/` (the deepseek-harness repo itself carries a top-level `.agents/`), so it shares the generic Agent Skills path with Codex/Aider. No new convention directory → `bin/update-installed-skill.sh` and `bin/delivery_profile.py` stay untouched.

- [ ] **Step 1: Write the failing test**

Add to `tests/packaging/test_cli_installer.py`, next to `test_install_verify_and_agent_mappings`:

```python
    def test_install_supports_deepseek_harness_agent(self) -> None:
        target = self.install(agent="deepseek-harness")
        self.assertEqual(target, self.project / ".agents/skills/startup-factory")
        self.assertTrue((target / "SKILL.md").is_file())
        code, output, error = run_cli(
            "verify",
            "--agent",
            "deepseek-harness",
            "--project",
            str(self.project),
            "--json",
        )
        self.assertEqual((code, error), (0, ""), output + error)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/packaging/test_cli_installer.py -k deepseek -q`
Expected: FAIL — argparse rejects `--agent deepseek-harness` (invalid choice), surfacing as a non-zero CLI exit in the helper's assertion.

- [ ] **Step 3: Implement**

`src/startup_factory_cli/cli.py:25`:

```python
AGENTS = ("codex", "aider", "claude", "claude-code", "deepseek-harness")
```

`src/startup_factory_cli/installer.py` `resolve_target()` mappings:

```python
    mappings = {
        "codex": Path(".agents/skills/startup-factory"),
        "aider": Path(".agents/skills/startup-factory"),
        "claude": Path(".claude/skills/startup-factory"),
        "claude-code": Path(".claude/skills/startup-factory"),
        "deepseek-harness": Path(".agents/skills/startup-factory"),
    }
```

(Leave the no-agent auto-detection `candidates` list as-is — it dedupes by directory, and `.agents` is already first.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/packaging/test_cli_installer.py -q`
Expected: PASS (all installer tests, not just the new one).

- [ ] **Step 5: Add the README install-directory row**

In the "Choose the project path your agent supports" table (~`README.md:661`), after the Aider row:

```markdown
| **DeepSeek Harness** | `.agents/skills/startup-factory` | Reads `AGENTS.md` natively; add a pointer there or paste `SKILL.md` as the task |
```

Also update any README prose that enumerates `--agent` choices (search: `grep -n '\-\-agent' README.md`) to include `deepseek-harness`.

- [ ] **Step 6: Run the full suite**

Run: `bash tests/run-all.sh`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/startup_factory_cli/cli.py src/startup_factory_cli/installer.py tests/packaging/test_cli_installer.py README.md
git commit -m "feat: first-class --agent deepseek-harness installer mapping"
```

---

### Task 4: Model-tier routing recipe for `TASK_FAST/STANDARD/STRONG_CMD` (docs only)

**Files:**
- Modify: `README.md` (the paragraph introducing `TASK_FAST_CMD`/`TASK_STANDARD_CMD`/`TASK_STRONG_CMD`, ~line 957)

**Interfaces:**
- Consumes: dsh's `--patch <file.yml>` launcher flag and the `agent-default-model` `{provider, model}` config row (Background).
- Produces: a documented pattern users copy; nothing downstream.

Unlike `claude --model` or `codex -m`, dsh has no per-invocation model flag; the process default comes from the composed config. The supported per-invocation override is a `--patch` overlay. The exact patch-row key path depends on the composed tree, so the recipe teaches discovery via `--dump-config` instead of asserting a hardcoded row name.

- [ ] **Step 1: Add the recipe**

After the existing `TASK_*_CMD` paragraph, insert:

```markdown
DeepSeek Harness selects its model from the composed profile config rather than
a CLI flag. To route task tiers to different models, write one small overlay per
tier and reference it in the override command. Discover the exact row your dsh
version composes with `dsh --profile headless --dump-config`, copy the
`agent-default-model` row into e.g. `~/.dsh-overlays/strong.yml` with your
`{provider, model}` choice, then:

```
TASK_STRONG_CMD="dsh --profile headless --patch \"$HOME/.dsh-overlays/strong.yml\" \"$(cat '{prompt_file}')\""
```

`--patch` is a launcher flag, so it must appear before the positional task text.
Alternatively, point tiers at distinct `DSH_HOME` directories with different
`settings.yaml` model defaults (requires allowlisting `DSH_HOME` or a wrapper
script).
```

- [ ] **Step 2: Verify and commit**

Run: `bash tests/run-all.sh` — Expected: PASS (docs-only change).

```bash
git add README.md
git commit -m "docs: DeepSeek Harness model-tier routing via --patch overlays"
```

---

### Task 5: Live validation runbook (manual — needs Node.js and a DeepSeek API key)

**Files:** none committed. This task validates the plan's external assumptions against the real `dsh` binary; if any check fails, fix the docs from Tasks 2/4 before merging.

**Interfaces:**
- Consumes: everything above.
- Produces: a go/no-go on the documented template, recorded in the PR description.

- [ ] **Step 1: Install and smoke-test dsh standalone**

```bash
npm install -g @deepseek-ai/dsh
dsh --help
mkdir -p /tmp/dsh-probe && cd /tmp/dsh-probe
export DEEPSEEK_API_KEY=sk-...   # operator's key, never committed
dsh --profile headless "Reply with exactly: PROBE-OK"
echo "exit=$?"
```

Expected: stdout contains `PROBE-OK`; exit 0; stderr empty. Record the installed version (`dsh --version` / `-V`) and pin it in the README note from Task 2 Step 2.

Verify assumptions while here: (a) confirm where `$DSH_HOME` lands by default (expected: under `$HOME`) — `ls ~/.dsh* 2>/dev/null; env | grep DSH`; (b) confirm `--patch` + `--dump-config` behave as Task 4 documents: `dsh --profile headless --dump-config | grep -n -i 'agent-default-model' -A3`.

- [ ] **Step 2: Prepare a sandbox home with reviewed dsh state**

```bash
install -d -m 700 "$HOME/sf-agent-home"
# copy ONLY the minimum reviewed dsh state (credentials + settings) into it,
# at the same relative location dsh resolves under HOME (verified in Step 1):
cp -R "$HOME/.dsh" "$HOME/sf-agent-home/.dsh"   # adjust if Step 1 found a different path
```

Set in the target project's `config/team.config.md`: `AGENT_SANDBOX_HOME=$HOME/sf-agent-home` (absolute path, no variable — write the literal expansion).

- [ ] **Step 3: Run doctor with a dsh-mapped role**

In a scratch target project with Startup Factory installed (`uvx startup-factory install --agent deepseek-harness` — exercising Task 3), set:

```
REVIEWER_CMD="dsh --profile headless \"$(cat '{prompt_file}')\""
```

Run: `bin/launch-team.sh doctor <preset> <team> FEAT-DSH-DOCTOR`
Expected: the reviewer probe passes (random token echoed on stdout).

- [ ] **Step 4: One real single-role launch**

Run: `bin/launch-team.sh start dsh-live FEAT-DSH-LIVE reviewer`, watch `.teamwork/dsh-live/` for the prompt, pid marker, and the agent's mailbox/tracker behavior; confirm the dsh process exits 0 and its final message lands in the log.

- [ ] **Step 5: Record results**

Paste versions, the doctor output line, and any doc corrections into the PR description. If `dsh`'s flags or headless contract drifted from this plan (developer preview!), update Tasks 2/4 text in the same PR.

---

## Self-Review

- **Spec coverage:** Command template + classification (Task 1, 2), credentials/HOME model (Task 2, 5), installer path (Task 3), model routing (Task 4), live contract verification (Task 5). Non-changes (enum, delivery_profile, update-installed-skill, bundle-spec) are argued explicitly in Background/File Structure. ✓
- **Placeholder scan:** all code blocks are concrete; the only deliberately unpinned value is the dsh npm version, which Task 5 Step 1 pins from reality. ✓
- **Type consistency:** the agent id string `deepseek-harness` is identical across cli.py, installer.py, tests, and README; the command template string is identical across Task 1, 2, and 5. ✓
