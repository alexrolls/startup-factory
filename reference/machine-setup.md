# Installing on a new machine

Install Startup Factory with the release CLI as described in the
[README](../README.md#quick-start-local-markdown-no-tracker-account), then run
the commands below from the Git project where you will use it. Replace
`.claude/skills/startup-factory` with your installed skill path; for Codex the
usual path is `.agents/skills/startup-factory`.
Install the CLIs named by your team commands first. If you use only one CLI,
configure the role mappings to use it before setup.

## Provision and sign in

```bash
bash .claude/skills/startup-factory/bin/setup-machine.sh --skip-doctor
bash .claude/skills/startup-factory/bin/launch-team.sh login claude
bash .claude/skills/startup-factory/bin/launch-team.sh doctor
```

For Codex use `login codex`. The login command runs the CLI's interactive
authentication with the configured `AGENT_SANDBOX_HOME` and OS account identity.
Signing in through your ordinary CLI session uses a different home and may
leave the agents unauthenticated.

Setup is repeatable. It creates project-specific CLI-state and lifecycle
directories beneath `~/.local/share/sf/<project-hash>/` with mode `0700`, records
their absolute canonical paths in the installed `config/team.config.md`, and
creates the configured `MARKDOWN_ROOT` for the Markdown adapter. Supported
bare CLI executables in role commands are resolved to absolute installed paths;
prompt templates and CLI flags are preserved. This avoids editing each role by
hand when Homebrew's bin directory is excluded from the protected runtime PATH.
The discovered Claude and Codex paths also supply the login command.
For npm CLIs with an `env node` shebang, setup also pins a validated Node
interpreter so the CLI can start under the sanitized runtime PATH.

Existing configured paths are validated and retained. If a config was copied
from another laptop, set its obsolete `AGENT_SANDBOX_HOME` and
`BROKER_LIFECYCLE_ROOT` assignments to `null`, and restore obsolete absolute
CLI executable prefixes to their bare names before rerunning setup. It will
reject an unsafe existing directory instead of changing its permissions or
moving its contents. `--state-root /absolute/private/path` selects a different
base for newly provisioned state. The short `h` (CLI home) and `l` (lifecycle)
leaves keep publication socket paths within the macOS limit; setup rejects a
base that would make those paths too long. See `setup-machine.sh --help` for
the options.

Run `setup-machine.sh` without `--skip-doctor` to provision and immediately test
the configured team commands. The final doctor performs real LLM requests and
may incur normal provider usage. `--skip-doctor` prepares the machine offline
and leaves authentication/readiness verification pending.

Setup changes the installed team config; review these machine-specific changes
before committing an installed skill directory. Existing config-preserving
updates retain them. Configure the required team roster, validation commands,
and production isolation separately using the
[governed quickstart](quickstart.md).

## macOS Claude login and the keychain

An empty agent home may have no macOS keychain available. The login command
checks this before starting Claude. To explicitly share the current OS
account's keychain directory:

```bash
bash .claude/skills/startup-factory/bin/launch-team.sh login claude --share-macos-keychain
```

This links the agent home's `Library/Keychains` to your OS account's keychain
directory. Agent processes using that home can reach your existing keychain,
subject to macOS access controls. Choose this only when that credential access
is appropriate for your agents. The command preserves existing directories and
refuses conflicting destinations. It does not reset, replace, or copy your
original keychain.

If macOS displays **Keychain Not Found**, cancel it. **Never click Reset To
Defaults as part of Startup Factory setup.** For stronger separation, have your
administrator provision a separate usable keychain or a dedicated OS account
before login. Credentials and tokens belong in the CLI's protected credential
storage; keep them out of team config and `AGENT_ENV_ALLOWLIST`.

## Python discovery

Authority-bearing shell commands require a trusted Python 3.10 or newer.
Discovery considers caller-PATH Python first, the usual platform paths, and
versioned Homebrew installations, including `python@3.x/libexec/bin/python3`
and `bin/python3.x`. Candidates retain the canonical executable, ownership,
parent-permission, version, and identity checks used by the launcher.

If discovery fails, the error lists rejected candidates with reasons and a
concrete next command. Install a supported protected Python, then rerun setup.
An environment-managed interpreter used to install the package still needs to
meet the separate authority runtime trust rules.

## Doctor and installing through an AI agent

`launch-team.sh doctor` defaults to the `full-stack` preset and a
`doctor-check` workspace. You can still supply `doctor <preset> <team>
<featureId>` to check the intended roster. It tests each distinct command once
under the real sanitized agent environment. A timestamped
`preflight/doctor-result.json` in that team workspace records the result for
inspection; it supplies no permission to dispatch, integrate, or release.
Failures in the initial trusted-Python bootstrap or whole-file config parsing
occur before a result path can be resolved safely and produce only a terminal
diagnostic. Check the report timestamp against the command you just ran.

An AI agent may lack permission to create state outside the project or expose
your keychain. Run the shipped setup/login commands in your own terminal when
that applies, then let the agent inspect the doctor result. No shell-profile
edit is needed for versioned Homebrew Python discovery.
