#!/bin/bash
# Rendered and installed externally by `startup-factory runtime-kit`.
# The placeholders are immutable manifest bindings, not runtime input.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin

engine=@@ENGINE@@
image=@@IMAGE@@
manifest=@@MANIFEST@@
network=@@NETWORK@@
expected_engine_sha256=@@ENGINE_SHA256@@
expected_manifest_sha256=@@MANIFEST_SHA256@@

die() { printf 'startup-factory-runner: %s\n' "$*" >&2; exit 1; }
sha256_file() {
  /usr/bin/python3 - "$1" <<'PY'
import hashlib, os, stat, sys
path=sys.argv[1]
fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode): raise SystemExit(1)
 digest=hashlib.sha256()
 while True:
  block=os.read(fd,65536)
  if not block: break
  digest.update(block)
 print(digest.hexdigest())
finally: os.close(fd)
PY
}

[ "$(sha256_file "$engine")" = "$expected_engine_sha256" ] || die "engine digest changed"
[ "$(sha256_file "$manifest")" = "$expected_manifest_sha256" ] || die "runtime manifest changed"
[ "$#" -ge 4 ] && [ "$1" = --workdir ] && [ "$3" = -- ] || die "usage: runner --workdir <absolute-standalone-clone> -- <argv...>"
workdir="$2"; shift 3
[ "$#" -gt 0 ] || die "missing command"
case "$workdir" in /*) ;; *) die "workdir must be absolute" ;; esac
[ -d "$workdir/.git" ] && [ ! -L "$workdir/.git" ] || die "workdir must be a standalone clone with an in-tree .git directory"
canonical_workdir="$(cd "$workdir" && pwd -P)"
[ "$canonical_workdir" = "$workdir" ] || die "workdir must be canonical and non-symlinked"

uid="$(id -u)"; gid="$(id -g)"
host_env=(
  -i
  "PATH=/usr/bin:/bin"
  "HOME=/nonexistent"
  "XDG_RUNTIME_DIR=/run/user/$uid"
)
container_env=(
  --env HOME=/home/agent
  --env AWS_EC2_METADATA_DISABLED=true
)
for name in STARTUP_FACTORY_ROLE STARTUP_FACTORY_TEAM STARTUP_FACTORY_FEATURE_ID \
  STARTUP_FACTORY_PRESET STARTUP_FACTORY_EXECUTION_KIND STARTUP_FACTORY_TASK_ID \
  STARTUP_FACTORY_ATTEMPT STARTUP_FACTORY_INSTANCE STARTUP_FACTORY_CANONICAL_REPO \
  STARTUP_FACTORY_CANONICAL_WORKSPACE STARTUP_FACTORY_TASK_WORKTREE \
  STARTUP_FACTORY_OUTBOX_CAPABILITY_ID STARTUP_FACTORY_OUTBOX_CAPABILITY_SECRET \
  STARTUP_FACTORY_OUTBOX_CAPABILITY_EXPIRES_AT STARTUP_FACTORY_MODEL_GATEWAY_ENDPOINT \
  STARTUP_FACTORY_MODEL_SESSION_CAPABILITY; do
  [ -z "${!name:-}" ] || container_env+=(--env "$name=${!name}")
done

exec /usr/bin/env "${host_env[@]}" "$engine" run --rm --pull=never \
  --read-only --userns=keep-id --user "$uid:$gid" --cap-drop=ALL \
  --security-opt=no-new-privileges --pids-limit=256 --memory=2g --cpus=2 \
  --network="$network" --ulimit nofile=1024:1024 \
  --tmpfs /home/agent:rw,nodev,nosuid,noexec,size=256m \
  --tmpfs /tmp:rw,nodev,nosuid,noexec,size=256m \
  --tmpfs /run:rw,nodev,nosuid,noexec,size=64m \
  --mount "type=bind,src=$canonical_workdir,dst=$canonical_workdir,rw" \
  --workdir "$canonical_workdir" "${container_env[@]}" "$image" "$@"
