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

authority_python_homebrew_candidates() {
  local prefix="$1" candidate version
  # Versioned Homebrew formulas do not always install an unversioned python3
  # in bin. Only the two fixed prefixes below are used by the selector.
  for candidate in "$prefix"/opt/python@3.[0-9]*/libexec/bin/python3 \
    "$prefix"/bin/python3.[0-9]*; do
    [ -e "$candidate" ] || [ -L "$candidate" ] || continue
    case "$candidate" in
      "$prefix"/bin/python3.*)
        version="${candidate##*/python3.}"
        case "$version" in ''|*[!0-9]*) continue ;; esac
        ;;
    esac
    printf '%s\n' "$candidate"
  done
}

select_authority_python() {
  local candidate canonical identity observed caller_entry prefix probe_message
  local seen=$'\n'
  local candidates=() caller_entries=() rejections=()
  IFS=: read -r -a caller_entries <<< "${STARTUP_FACTORY_CALLER_PATH:-}"
  # Bash 3.2 treats an empty array as unset under nounset.
  for caller_entry in "${caller_entries[@]-}"; do
    case "$caller_entry" in
      /*) candidates+=("$caller_entry/python3") ;;
    esac
  done
  # Known platform paths remain deterministic fallbacks. Caller-PATH entries
  # are considered first so actions/setup-python's protected toolcache runtime
  # is not silently replaced by an older distribution interpreter.
  candidates+=(/opt/homebrew/bin/python3 /usr/local/bin/python3)
  for prefix in /opt/homebrew /usr/local; do
    while IFS= read -r candidate; do
      candidates+=("$candidate")
    done < <(authority_python_homebrew_candidates "$prefix")
  done
  candidates+=(/usr/bin/python3)
  for candidate in "${candidates[@]}"; do
    case "$seen" in *$'\n'"$candidate"$'\n'*) continue ;; esac
    seen="${seen}${candidate}"$'\n'
    case "$candidate" in
      "$SKILL_DIR"/*|/tmp/*|/private/tmp/*)
        rejections+=("$candidate: outside the approved executable locations")
        continue ;;
    esac
    canonical="$(canonical_authority_executable "$candidate" 2>/dev/null || true)"
    if [ -z "$canonical" ] || [ ! -f "$canonical" ] || [ ! -x "$canonical" ]; then
      rejections+=("$candidate: missing, not executable, or cannot resolve its canonical path")
      continue
    fi
    case "$canonical" in
      "$SKILL_DIR"/*|/tmp/*|/private/tmp/*)
        rejections+=("$candidate: canonical path is outside the approved executable locations")
        continue ;;
      /usr/*|/opt/homebrew/Cellar/*|/opt/hostedtoolcache/*|/Library/Frameworks/Python.framework/*) ;;
      *) rejections+=("$candidate: canonical path is outside the approved executable locations"); continue ;;
    esac
    if ! authority_python_parent_chain_is_protected "$candidate" \
      || { [ "$candidate" != "$canonical" ] \
        && ! authority_python_parent_chain_is_protected "$canonical"; }; then
      rejections+=("$candidate: parent directory ownership or permissions are unsafe")
      continue
    fi
    identity="$(authority_python_file_identity "$canonical" 2>/dev/null || true)"
    if [ -z "$identity" ]; then
      rejections+=("$candidate: cannot inspect executable identity")
      continue
    fi
    if probe_message="$(/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/tmp LANG=C LC_ALL=C \
      "$canonical" -I -B -c '
import os, stat, sys
path = sys.argv[1]
info = os.stat(path)
if sys.version_info < (3, 10):
    raise SystemExit("Python %s is too old; version 3.10 or newer is required" % sys.version.split()[0])
if not (
    os.path.realpath(sys.executable) == path
    and stat.S_ISREG(info.st_mode)
    and not info.st_mode & 0o022
    and info.st_uid in {0, os.geteuid()}
):
    raise SystemExit("executable identity, ownership, or permissions are unsafe")
' "$canonical" 2>&1)"; then
      observed="$(authority_python_file_identity "$canonical" 2>/dev/null || true)"
      if [ -z "$observed" ] || [ "$observed" != "$identity" ]; then
        rejections+=("$candidate: executable identity changed during verification")
        continue
      fi
      printf '%s\t%s\n' "$canonical" "$identity"
      return 0
    else
      rejections+=("$candidate: ${probe_message:-isolated Python verification failed}")
    fi
  done
  printf 'authority-bootstrap: Python candidates rejected:\n' >&2
  printf '  - %s\n' "${rejections[@]}" >&2
  return 1
}

authority_python_selection="$(select_authority_python)" || {
  echo "authority-bootstrap: trusted canonical Python >=3.10 is unavailable" >&2
  echo "On macOS, install a supported Python with: brew install python" >&2
  echo "Or add an existing protected Python >=3.10 directory to PATH and rerun the command." >&2
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
