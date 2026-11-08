#!/usr/bin/env bash
# Provision private machine state using the installed, trusted Python runtime.
set -euo pipefail
umask 077
STARTUP_FACTORY_CALLER_PATH="${PATH:-/usr/bin:/bin}"
operator_home="${HOME:-}"
PATH=/usr/bin:/bin
export PATH
unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTHONUSERBASE
unset PYTHONNOUSERSITE PYTHONSAFEPATH PYTHONDONTWRITEBYTECODE
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH
script_directory="${BASH_SOURCE[0]%/*}"
[ "$script_directory" != "${BASH_SOURCE[0]}" ] || script_directory=.
SKILL_DIR="$(cd "$script_directory/.." && pwd -P)"
. "$SKILL_DIR/bin/authority-bootstrap.sh"
# Help also works before selecting a target Git project.
for argument in "$@"; do
  case "$argument" in
    --help|-h) project="$PWD"; break ;;
  esac
done
if [ -z "${project:-}" ]; then
  project="$(/usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
    git -c core.hooksPath=/dev/null -c core.fsmonitor=false -C "$PWD" rev-parse --show-toplevel)" || {
    echo 'setup-machine: run this command from the target Git project' >&2
    exit 1
  }
fi
authority_python -c '
import sys
sys.path.insert(0, sys.argv[1])
from startup_factory_cli.machine_setup import main
raise SystemExit(main(sys.argv[2:]))
' "$SKILL_DIR/src" --skill-dir "$SKILL_DIR" --project "$project" \
  --operator-home "$operator_home" --caller-path "$STARTUP_FACTORY_CALLER_PATH" "$@"
