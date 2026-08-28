#!/bin/sh
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

: "${STARTUP_FACTORY_V27_PROBE_JSON:?set the canonical manifest-bound supervisor probe JSON}"
: "${STARTUP_FACTORY_V27_PREEXEC_CONTEXT:?set the exact manifest controller pre-exec context}"
: "${STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT:?set the exact manifest supervisor process context}"
: "${STARTUP_FACTORY_V27_EXEC_CONTEXT:?set the exact manifest supervisor executable context}"
: "${STARTUP_FACTORY_V27_OUTPUT:?set the absolute output executable path}"
: "${STARTUP_FACTORY_V27_LAUNCHER_OUTPUT:?set the absolute launcher output executable path}"
: "${STARTUP_FACTORY_V27_MANIFEST_TEMPLATE:?set the absolute native manifest template path}"
: "${STARTUP_FACTORY_V27_MANIFEST_OUTPUT:?set the absolute generated native manifest path}"
: "${STARTUP_FACTORY_V27_OCI_RUNTIME_BINARY:?set the absolute pinned OCI runtime binary path}"

case "$STARTUP_FACTORY_V27_OUTPUT" in
  /*) ;;
  *) echo "STARTUP_FACTORY_V27_OUTPUT must be absolute" >&2; exit 2 ;;
esac
case "$STARTUP_FACTORY_V27_LAUNCHER_OUTPUT" in
  /*) ;;
  *) echo "STARTUP_FACTORY_V27_LAUNCHER_OUTPUT must be absolute" >&2; exit 2 ;;
esac
case "$STARTUP_FACTORY_V27_MANIFEST_TEMPLATE" in
  /*) ;;
  *) echo "STARTUP_FACTORY_V27_MANIFEST_TEMPLATE must be absolute" >&2; exit 2 ;;
esac
case "$STARTUP_FACTORY_V27_MANIFEST_OUTPUT" in
  /*) ;;
  *) echo "STARTUP_FACTORY_V27_MANIFEST_OUTPUT must be absolute" >&2; exit 2 ;;
esac
case "$STARTUP_FACTORY_V27_OCI_RUNTIME_BINARY" in
  /usr/bin/crun) ;;
  *) echo "STARTUP_FACTORY_V27_OCI_RUNTIME_BINARY must be /usr/bin/crun" >&2; exit 2 ;;
esac

case "$STARTUP_FACTORY_V27_PROBE_JSON" in
  *'
'*) echo "STARTUP_FACTORY_V27_PROBE_JSON must be one canonical line" >&2; exit 2 ;;
esac
probe_digest_slot='"supervisorSha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"'
case "$STARTUP_FACTORY_V27_PROBE_JSON" in
  *"$probe_digest_slot"*) ;;
  *) echo "STARTUP_FACTORY_V27_PROBE_JSON must contain the exact runtime self-digest slot" >&2; exit 2 ;;
esac
probe_c=$(printf '%s' "$STARTUP_FACTORY_V27_PROBE_JSON" | sed 's/\\/\\\\/g; s/"/\\"/g')
preexec_context_c=$(printf '%s' "$STARTUP_FACTORY_V27_PREEXEC_CONTEXT" | sed 's/\\/\\\\/g; s/"/\\"/g')
supervisor_context_c=$(printf '%s' "$STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT" | sed 's/\\/\\\\/g; s/"/\\"/g')
exec_context_c=$(printf '%s' "$STARTUP_FACTORY_V27_EXEC_CONTEXT" | sed 's/\\/\\\\/g; s/"/\\"/g')

cc -std=c17 -O2 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -Wall -Wextra -Werror -Wformat=2 -Wconversion -Wshadow \
  -I"$script_dir" \
  "-DSTARTUP_FACTORY_V27_PREEXEC_CONTEXT=\"$preexec_context_c\"" \
  "-DSTARTUP_FACTORY_V27_EXEC_CONTEXT=\"$exec_context_c\"" \
  -o "$STARTUP_FACTORY_V27_LAUNCHER_OUTPUT" \
  "$script_dir/startup-factory-beads-launcher-v27.c"

cc -std=c17 -O2 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -Wall -Wextra -Werror -Wformat=2 -Wconversion -Wshadow -pthread \
  -I"$script_dir" \
  "-DSTARTUP_FACTORY_V27_PROBE_JSON=\"$probe_c\"" \
  "-DSTARTUP_FACTORY_V27_SUPERVISOR_CONTEXT=\"$supervisor_context_c\"" \
  "-DSTARTUP_FACTORY_V27_EXEC_CONTEXT=\"$exec_context_c\"" \
  -o "$STARTUP_FACTORY_V27_OUTPUT" \
  "$script_dir/startup-factory-beads-supervisor-v27.c"

# The supervisor replaces the zero slot with a direct /proc/self/exe digest at
# probe time. Runnable identities are computed from compiled files, never C
# source bytes. The root-only generator installs one canonical manifest with a
# same-directory fsync+rename transaction after both compilations succeed.
/usr/bin/python3 "$script_dir/generate-native-manifest-v27.py" \
  --template "$STARTUP_FACTORY_V27_MANIFEST_TEMPLATE" \
  --launcher-source "$script_dir/startup-factory-beads-launcher-v27.c" \
  --launcher-binary "$STARTUP_FACTORY_V27_LAUNCHER_OUTPUT" \
  --supervisor-source "$script_dir/startup-factory-beads-supervisor-v27.c" \
  --supervisor-binary "$STARTUP_FACTORY_V27_OUTPUT" \
  --oci-runtime-binary "$STARTUP_FACTORY_V27_OCI_RUNTIME_BINARY" \
  --output "$STARTUP_FACTORY_V27_MANIFEST_OUTPUT"
