#!/usr/bin/env bash
# Opt-in only: exercises the real rootless Podman boundary and local pinned image.
set -euo pipefail

if [ "${STARTUP_FACTORY_REAL_RUNTIME_PROBE:-0}" != 1 ]; then
  echo "SKIP: set STARTUP_FACTORY_REAL_RUNTIME_PROBE=1 with manifest/worktree inputs for the real Linux boundary probe"
  exit 0
fi
[ "$(uname -s)" = Linux ] || { echo "runtime boundary probe requires Linux" >&2; exit 1; }
manifest="${STARTUP_FACTORY_RUNTIME_MANIFEST:?set STARTUP_FACTORY_RUNTIME_MANIFEST}"
worktree="${STARTUP_FACTORY_PROBE_WORKTREE:?set STARTUP_FACTORY_PROBE_WORKTREE to a disposable standalone clone}"
runner="$(dirname "$manifest")/runner"
[ -f "$manifest" ] && [ ! -L "$manifest" ] && [ -x "$runner" ] && [ ! -L "$runner" ] \
  || { echo "runtime manifest/runner is unsafe" >&2; exit 1; }
[ -d "$worktree/.git" ] && [ ! -L "$worktree/.git" ] && [ ! -e "$worktree/.git/commondir" ] \
  || { echo "probe worktree is not a standalone clone" >&2; exit 1; }

AWS_ACCESS_KEY_ID=must-not-cross GITHUB_TOKEN=must-not-cross \
  "$runner" --workdir "$worktree" -- /bin/sh -eu -c '
    test -d .git && test ! -e .git/commondir
    test -z "${AWS_ACCESS_KEY_ID:-}" && test -z "${GITHUB_TOKEN:-}"
    test ! -S /var/run/docker.sock && test ! -S /run/podman/podman.sock
    test ! -e /root/.aws && test ! -e /root/.ssh
    marker=.startup-factory-boundary-probe-$$
    : > "$marker" && rm -f "$marker"
    printf "%s\n" runtime-boundary-probe-pass
  ' | grep -qx runtime-boundary-probe-pass

echo "real Linux runtime boundary probe: PASS (evidence only; readiness is unchanged)"
