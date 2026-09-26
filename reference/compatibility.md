# Compatibility and support

This checked-in document contains no exact-candidate run result. It records
product intent and the evidence rules for a release; only a fresh protected
compatibility artifact can change an exact candidate from Untested to Tested.

The labels have deliberately narrow meanings:

- **Claimed**: package metadata or the documented design intends the
  environment to work. This is not execution evidence.
- **Tested**: the beta-readiness artifact contains a successful, typed run for
  the exact candidate and canonical release set on a named environment.
- **Experimental**: the environment may be useful, but behavior or coverage is
  incomplete and no support commitment follows.
- **Untested**: no accepted exact-candidate evidence exists. Generic CI,
  historical runs, and local anecdotes do not change this label.

| Environment | Product position | Exact-candidate status in this document | Evidence boundary |
| --- | --- | --- | --- |
| Ubuntu Linux | Claimed | Untested | A release can mark it Tested only from the protected compatibility artifact described below. |
| Other Linux distributions | Experimental | Untested | POSIX similarity is not release evidence; record the exact distribution and environment before making a claim. |
| macOS | Claimed | Untested | Package metadata declares macOS, but this release package has no checked-in exact-candidate execution result. |
| Windows, native PowerShell/cmd | Unsupported | Untested | The runtime depends on Bash/POSIX behavior, Unix-style permissions, signals, and file locking. Do not claim native Windows support. |
| Windows Subsystem for Linux (WSL) | Experimental | Untested | The required typed Linux evidence excludes WSL; a separate future evidence contract would be required to change this status. |

## Runtime versions

- Python: package metadata permits Python 3.10 and newer, while the enumerated
  classifiers and this beta support policy make the narrower 3.10 through 3.14
  range the Claimed surface for 0.2.0. The open-ended installation floor avoids
  a packaging upper bound; it is not evidence for a future interpreter. Python
  3.15 and newer are unclaimed, Untested, and outside beta support even if an
  installer permits them. Beta readiness additionally requires a protected
  installed-release smoke on stable Python 3.10.x and a full runtime/package
  run on stable Python 3.14.x, both bound to the exact candidate and release-set
  digest. Only those evidence records are Tested; intermediate declared minors
  remain Untested unless separately evidenced. Governed shell entrypoints
  independently require a protected host
  interpreter at `/opt/homebrew/bin/python3`, `/usr/local/bin/python3`, or
  `/usr/bin/python3`; launcher/integration entrypoints also recognize a
  protected GitHub Actions toolcache interpreter. A pyenv, Nix, or uv-managed
  interpreter may run the package CLI but is not currently a supported broker
  interpreter unless the host also provides one of those protected locations.
  Generic launcher and broker command lookup is narrower than interpreter
  pinning: every accepted `PATH` directory chain must be root-owned and not
  group/world writable. User-owned Homebrew, pyenv, Nix, and local `bin`
  directories are excluded from that authority-bearing `PATH` even at mode
  `0700`; configure an intentionally untrusted agent CLI by absolute path or a
  dedicated sandbox wrapper instead. Production broker runtimes should be
  root-managed or run under a separate service identity; a user-managed
  standard-location interpreter relies on the documented identity recheck and
  OS sandbox boundary.
  Compatibility evidence must record both the test-runner and broker interpreter
  paths and versions rather than assuming they are the same.
- Git: required for exact-package identity, worktrees, and integration.
- Bash and standard POSIX utilities: required by the orchestration runtime.
- Safe project-config mutation requires the platform and target filesystem to
  support atomic name exchange (`renameatx_np` on macOS or `renameat2` on
  Linux). Initialization and tracker-pack apply fail closed when it is absent;
  there is no non-atomic fallback.
- Optional agent CLIs and tracker credentials: required only for their selected
  adapters. Their compatibility and usage reporting vary by provider.

## Support boundary

The supported beta surface is the released Python installer, the embedded
bundle it verifies, the documented adapters, and the offline validation suite.
Provider accounts, CI runners, deployment platforms, and third-party agent
runtimes remain subject to their own service terms and compatibility policies.

Before filing a compatibility issue, record the Startup Factory version, exact
commit, operating system and version, Python/Git/Bash versions, selected adapter,
and a redacted failure. Never attach credentials or a private task payload.

## Exact-candidate evidence

The `exact-candidate-compatibility` beta artifact contains exactly two typed
Linux results: stable Python 3.10.x with `installed-release-smoke` scope and
stable Python 3.14.x with `full-runtime-package` scope. Each result binds the
candidate commit, canonical release-set SHA-256, named operating system,
architecture, Python/Git/Bash versions, timestamp, pass/fail/skip counts, and
distinct environment-manifest and raw-evidence digests. Exit code and failures
must be zero. Missing, stale, duplicated, differently scoped, or
candidate/release-set-mismatched results fail closed.
The required results must identify non-WSL Linux environments. Microsoft, WSL,
WSL1, or WSL2 markers in the bounded operating-system identity, and explicit
WSL markers in the environment ID, are rejected because WSL remains
Experimental and Untested for this beta.

This minimum contract proves only the recorded environments and scopes. It does
not turn every Claimed platform or Python version into Tested, and it does not
make Experimental or Untested environments supported.
