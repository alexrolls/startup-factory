#!/usr/bin/env bash
# Trusted Python bootstrap for authority-bearing shell entrypoints.
# This file is sourced only from the installed skill directory after callers
# pin PATH to OS tools and derive SKILL_DIR without an external command.

canonical_authority_executable() {
  local candidate="$1" target directory count=0
  case "$candidate" in /*) ;; *) return 1 ;; esac
  while [ -L "$candidate" ]; do
    count=$((count + 1)); [ "$count" -le 32 ] || return 1
    target="$(/usr/bin/readlink "$candidate")" || return 1
    case "$target" in
      /*) candidate="$target" ;;
      *) candidate="$(/usr/bin/dirname "$candidate")/$target" ;;
    esac
  done
  directory="$(cd -P -- "$(/usr/bin/dirname "$candidate")" 2>/dev/null && pwd -P)" \
    || return 1
  printf '%s/%s\n' "$directory" "$(/usr/bin/basename "$candidate")"
}

authority_python_file_identity() {
  local output
  if output="$(/usr/bin/stat -f '%d:%i:%p:%u:%g:%z:%m:%c' "$1" 2>/dev/null)"; then
    printf '%s\n' "$output"
  elif output="$(/usr/bin/stat -c '%d:%i:%f:%u:%g:%s:%Y:%Z' "$1" 2>/dev/null)"; then
    printf '%s\n' "$output"
  else
    return 1
  fi
}

authority_python_parent_chain_is_protected() {
  local executable="$1" directory remainder part current metadata owner mode
  directory="$(/usr/bin/dirname "$executable")" || return 1
  remainder="${directory#/}"
  current=""
  local components=()
  IFS=/ read -r -a components <<< "$remainder"
  for part in "${components[@]}"; do
    [ -n "$part" ] || continue
    current="$current/$part"
    if metadata="$(/usr/bin/stat -f '%u:%Lp' "$current" 2>/dev/null)"; then
      :
    elif metadata="$(/usr/bin/stat -c '%u:%a' "$current" 2>/dev/null)"; then
      :
    else
      return 1
    fi
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    case "$owner:$mode" in
      *[!0-9:]*|:*) return 1 ;;
    esac
    [ "$owner" -eq 0 ] || [ "$owner" -eq "$EUID" ] || return 1
    mode=$((8#$mode))
    if [ $((mode & 8#22)) -ne 0 ]; then
      # Homebrew intentionally delegates its prefix to the installing user.
      # World-writable components are never accepted.
      if [[ "$executable" == /opt/homebrew/* \
          && "$current" == /opt/homebrew* \
          && "$owner" -eq "$EUID" \
          && $((mode & 8#2)) -eq 0 ]]; then
        :
      else
        return 1
      fi
    fi
  done
}

select_authority_python() {
  local candidate canonical identity observed caller_entry
  local candidates=() caller_entries=()
  IFS=: read -r -a caller_entries <<< "${STARTUP_FACTORY_CALLER_PATH:-}"
  for caller_entry in "${caller_entries[@]}"; do
    case "$caller_entry" in
      /*) candidates+=("$caller_entry/python3") ;;
    esac
  done
  # Known platform paths remain deterministic fallbacks. Caller-PATH entries
  # are considered first so actions/setup-python's protected toolcache runtime
  # is not silently replaced by an older distribution interpreter.
  candidates+=(/opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3)
  for candidate in "${candidates[@]}"; do
    case "$candidate" in
      "$SKILL_DIR"/*|/tmp/*|/private/tmp/*) continue ;;
    esac
    canonical="$(canonical_authority_executable "$candidate" 2>/dev/null || true)"
    [ -n "$canonical" ] && [ -f "$canonical" ] && [ -x "$canonical" ] || continue
    case "$canonical" in
      "$SKILL_DIR"/*|/tmp/*|/private/tmp/*) continue ;;
      /usr/*|/opt/homebrew/Cellar/*|/opt/hostedtoolcache/*|/Library/Frameworks/Python.framework/*) ;;
      *) continue ;;
    esac
    authority_python_parent_chain_is_protected "$candidate" || continue
    [ "$candidate" = "$canonical" ] \
      || authority_python_parent_chain_is_protected "$canonical" \
      || continue
    identity="$(authority_python_file_identity "$canonical" 2>/dev/null || true)"
    [ -n "$identity" ] || continue
    if /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/tmp LANG=C LC_ALL=C \
      "$canonical" -I -B -c '
import os, stat, sys
path = sys.argv[1]
info = os.stat(path)
valid = (
    sys.version_info >= (3, 10)
    and os.path.realpath(sys.executable) == path
    and stat.S_ISREG(info.st_mode)
    and not info.st_mode & 0o022
    and info.st_uid in {0, os.geteuid()}
)
raise SystemExit(0 if valid else 1)
' "$canonical"; then
      observed="$(authority_python_file_identity "$canonical" 2>/dev/null || true)"
      [ -n "$observed" ] && [ "$observed" = "$identity" ] || continue
      printf '%s\t%s\n' "$canonical" "$identity"
      return 0
    fi
  done
  return 1
}

authority_python_selection="$(select_authority_python)" || {
  echo "authority-bootstrap: trusted canonical Python >=3.10 is unavailable" >&2
  exit 1
}
AUTHORITY_PYTHON="${authority_python_selection%%$'\t'*}"
AUTHORITY_PYTHON_IDENTITY="${authority_python_selection#*$'\t'}"

verify_authority_python() {
  local observed
  [ -f "$AUTHORITY_PYTHON" ] && [ -x "$AUTHORITY_PYTHON" ] && [ ! -L "$AUTHORITY_PYTHON" ] \
    || { echo "authority-bootstrap: trusted Python disappeared or changed type" >&2; return 1; }
  observed="$(authority_python_file_identity "$AUTHORITY_PYTHON")" \
    || { echo "authority-bootstrap: cannot inspect trusted Python" >&2; return 1; }
  [ "$observed" = "$AUTHORITY_PYTHON_IDENTITY" ] \
    || { echo "authority-bootstrap: trusted Python identity changed" >&2; return 1; }
}

authority_python() {
  verify_authority_python || return 1
  /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/tmp LANG=C LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 "$AUTHORITY_PYTHON" -I -B "$@"
}

authority_runtime_python() {
  verify_authority_python || return 1
  if [ $# -gt 0 ]; then
    case "$1" in
      "$SKILL_DIR"/bin/*.py)
        local script="$1"
        shift
        "$AUTHORITY_PYTHON" -I -B -c '
import runpy, sys
script, module_dir = sys.argv[1:3]
sys.argv = [script, *sys.argv[3:]]
sys.path.insert(0, module_dir)
runpy.run_path(script, run_name="__main__")
' "$script" "$SKILL_DIR/bin" "$@"
        return
        ;;
    esac
  fi
  "$AUTHORITY_PYTHON" -I -B "$@"
}
