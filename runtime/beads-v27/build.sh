#!/bin/sh
set -eu
umask 077

: "${STARTUP_FACTORY_V27_PROBE_JSON:?set the canonical manifest-bound supervisor probe JSON}"
: "${STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT:?set the exact manifest supervisor process context}"
: "${STARTUP_FACTORY_V27_EXEC_CONTEXT:?set the exact manifest supervisor executable context}"
: "${STARTUP_FACTORY_V27_OUTPUT:?set the absolute output executable path}"

case "$STARTUP_FACTORY_V27_OUTPUT" in
  /*) ;;
  *) echo "STARTUP_FACTORY_V27_OUTPUT must be absolute" >&2; exit 2 ;;
esac

case "$STARTUP_FACTORY_V27_PROBE_JSON" in
  *'
'*) echo "STARTUP_FACTORY_V27_PROBE_JSON must be one canonical line" >&2; exit 2 ;;
esac
probe_c=$(printf '%s' "$STARTUP_FACTORY_V27_PROBE_JSON" | sed 's/\\/\\\\/g; s/"/\\"/g')
supervisor_context_c=$(printf '%s' "$STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT" | sed 's/\\/\\\\/g; s/"/\\"/g')
exec_context_c=$(printf '%s' "$STARTUP_FACTORY_V27_EXEC_CONTEXT" | sed 's/\\/\\\\/g; s/"/\\"/g')

exec cc -std=c17 -O2 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
  -Wall -Wextra -Werror -Wformat=2 -Wconversion -Wshadow \
  "-DSTARTUP_FACTORY_V27_PROBE_JSON=\"$probe_c\"" \
  "-DSTARTUP_FACTORY_V27_SUPERVISOR_CONTEXT=\"$supervisor_context_c\"" \
  "-DSTARTUP_FACTORY_V27_EXEC_CONTEXT=\"$exec_context_c\"" \
  -o "$STARTUP_FACTORY_V27_OUTPUT" \
  runtime/beads-v27/startup-factory-beads-supervisor-v27.c
