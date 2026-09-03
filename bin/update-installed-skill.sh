#!/usr/bin/env bash
# update-installed-skill.sh — install or refresh a legacy/source-managed copy.
set -euo pipefail

REMOTE_URL="${STARTUP_FACTORY_REMOTE_URL:-https://github.com/alexrolls/startup-factory.git}"
REMOTE_REF="${STARTUP_FACTORY_REF:-main}"
SKILL_NAME="${STARTUP_FACTORY_SKILL_NAME:-startup-factory}"
OWNERSHIP_MANIFEST_NAME=".startup-factory-owned-files"
OWNERSHIP_HASHES_NAME=".startup-factory-owned-hashes"
RELEASE_BUNDLE_MANIFEST_NAME=".startup-factory-bundle.json"
RELEASE_PROVENANCE_NAME=".startup-factory-install.json"
SOURCE_PROVENANCE_NAME=".startup-factory-source-install.json"

install_dir=""
overwrite_config=false
dry_run=false
tmp=""
stage_dir=""
backup_dir=""
lock_dir=""
change_plan=""
change_count=0
lock_acquired=false
old_install_moved=false
new_install_placed=false

CONFIG_FILES=(
  config/project-management.config.md
  config/planning.config.md
  config/team.config.md
  config/statuses.config.json
  config/automation.config.json
  config/deployment.config.json
  config/guardrails.config.json
)

die() {
  echo "update-installed-skill: $*" >&2
  exit 1
}

cleanup() {
  local cleanup_status=$?
  if $old_install_moved && ! $new_install_placed && \
      [ -n "$backup_dir" ] && [ -e "$backup_dir" ] && [ ! -e "$install_dir" ]; then
    mv "$backup_dir" "$install_dir" 2>/dev/null || true
  fi
  if [ -n "$stage_dir" ] && [ -e "$stage_dir" ]; then
    rm -rf "$stage_dir" || true
  fi
  if $lock_acquired && [ -n "$lock_dir" ] && [ -d "$lock_dir" ]; then
    rm -rf "$lock_dir" || true
  fi
  if [ -n "$tmp" ] && [ -d "$tmp" ]; then
    rm -rf "$tmp" || true
  fi
  return "$cleanup_status"
}

usage() {
  cat <<EOF
Usage: update-installed-skill.sh [options]

Fetch Startup Factory from Git and transactionally sync it into a new or
legacy/source-managed skill directory. Release-CLI installations are
intentionally refused because this compatibility updater cannot retain their
canonical bundle provenance. From a standalone source checkout, an existing
.agents or .claude installation is selected when unambiguous; otherwise the
fallback target is .claude/skills/startup-factory.
Requires git, rsync, and python3.

Options:
  --install-dir PATH     Update this skill directory instead of auto-detecting.
  --remote-url URL       Git remote to fetch from.
                         Default: $REMOTE_URL
  --ref REF              Branch, tag, or commit to fetch.
                         Default: $REMOTE_REF
  --overwrite-config     Replace the seven canonical local config files with
                         upstream defaults. Other project-owned files survive.
  --dry-run              Show changes without writing the destination.
  -h, --help             Show this help.

Environment overrides:
  STARTUP_FACTORY_REMOTE_URL
  STARTUP_FACTORY_REF
  STARTUP_FACTORY_SKILL_NAME
EOF
}

is_safe_relative_path() {
  local safe_path="$1"
  case "$safe_path" in
    ""|/*|"."|".."|./*|../*|*/./*|*/../*|*/.|*/..|*//*|*\\*) return 1 ;;
    *$'\n'*|*$'\r'*|*$'\t'*) return 1 ;;
  esac
  return 0
}

canonicalize_destination() {
  local destination="$1"
  local probe suffix probe_name probe_parent physical_probe
  [ ! -L "$destination" ] || die "install directory must not be a symlink; use its canonical path"

  probe="$destination"
  suffix=""
  while [ ! -e "$probe" ] && [ ! -L "$probe" ]; do
    probe_name="$(basename "$probe")"
    suffix="/$probe_name$suffix"
    probe_parent="$(dirname "$probe")"
    [ "$probe_parent" != "$probe" ] || die "cannot resolve install destination: $destination"
    probe="$probe_parent"
  done

  [ -d "$probe" ] || die "install destination has a non-directory ancestor: $probe"
  physical_probe="$(cd "$probe" && pwd -P)" || die "cannot resolve install destination: $destination"
  printf '%s%s\n' "$physical_probe" "$suffix"
}

has_git_marker_at_or_above() {
  local current_path="$1"
  local parent_path
  while :; do
    if [ -e "$current_path/.git" ] || [ -L "$current_path/.git" ]; then
      return 0
    fi
    parent_path="$(dirname "$current_path")"
    [ "$parent_path" != "$current_path" ] || return 1
    current_path="$parent_path"
  done
}

read_config_value() {
  local config_path="$1"
  local config_key="$2"
  local config_line config_value
  config_line="$(grep -m1 "^${config_key}=" "$config_path" 2>/dev/null || true)"
  [ -n "$config_line" ] || {
    printf '\n'
    return
  }
  config_value="${config_line#*=}"
  config_value="${config_value%%#*}"
  config_value="$(printf '%s' "$config_value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  case "$config_value" in
    \"*\") config_value="${config_value#\"}"; config_value="${config_value%\"}" ;;
    \'*\') config_value="${config_value#\'}"; config_value="${config_value%\'}" ;;
  esac
  [ "$config_value" != "null" ] || config_value=""
  printf '%s\n' "$config_value"
}

validate_regular_relative_file() {
  local relative_file="$1"
  local file_label="$2"
  local file_path relative_parent current_parent old_ifs parent_part
  local -a parent_parts
  is_safe_relative_path "$relative_file" || die "$file_label is not a safe skill-relative path: $relative_file"

  file_path="$install_dir/$relative_file"
  [ -e "$file_path" ] || [ -L "$file_path" ] || die "$file_label is missing: $relative_file"
  [ ! -L "$file_path" ] && [ -f "$file_path" ] || \
    die "$file_label is not a regular file: $relative_file"

  relative_parent="$(dirname "$relative_file")"
  if [ "$relative_parent" != "." ]; then
    current_parent="$install_dir"
    old_ifs="$IFS"
    IFS=/
    read -r -a parent_parts <<< "$relative_parent"
    IFS="$old_ifs"
    for parent_part in "${parent_parts[@]}"; do
      current_parent="$current_parent/$parent_part"
      [ ! -L "$current_parent" ] && [ -d "$current_parent" ] || \
        die "$file_label has a non-directory or symlink ancestor: $relative_file"
    done
  fi
}

validate_existing_target() {
  local target_git_root top_entries
  if [ ! -e "$install_dir" ] && [ ! -L "$install_dir" ]; then
    return
  fi
  [ ! -L "$install_dir" ] && [ -d "$install_dir" ] || \
    die "install destination exists and is not a regular directory: $install_dir"

  target_git_root=""
  if target_git_root="$(git -C "$install_dir" rev-parse --show-toplevel 2>/dev/null)"; then
    target_git_root="$(cd "$target_git_root" && pwd -P)"
    [ "$install_dir" != "$target_git_root" ] || die "refusing to install at a Git repository root"
  elif has_git_marker_at_or_above "$install_dir"; then
    die "cannot safely inspect Git context for install destination: $install_dir"
  fi

  if [ -e "$install_dir/$RELEASE_PROVENANCE_NAME" ] || \
      [ -L "$install_dir/$RELEASE_PROVENANCE_NAME" ] || \
      [ -e "$install_dir/$RELEASE_BUNDLE_MANIFEST_NAME" ] || \
      [ -L "$install_dir/$RELEASE_BUNDLE_MANIFEST_NAME" ]; then
    die "release-managed installation detected; use the versioned startup-factory CLI to update it"
  fi

  top_entries="$tmp/top-level-entries"
  find "$install_dir" -mindepth 1 -maxdepth 1 -print -quit > "$top_entries" || \
    die "cannot inspect install destination: $install_dir"
  if [ -s "$top_entries" ]; then
    if [ ! -f "$install_dir/SKILL.md" ] || [ -L "$install_dir/SKILL.md" ] || \
        ! grep -Eq '^name:[[:space:]]*startup-factory[[:space:]]*$' "$install_dir/SKILL.md"; then
      die "non-empty install directory is not an existing Startup Factory installation: $install_dir"
    fi
    if { [ ! -f "$install_dir/bin/update-installed-skill.sh" ] || \
          [ -L "$install_dir/bin/update-installed-skill.sh" ]; } && \
        [ -n "$(find "$install_dir" -mindepth 1 -maxdepth 1 ! -name SKILL.md -print -quit)" ]; then
      die "Startup Factory marker found, but destination is neither a complete installation nor a SKILL.md-only repair target: $install_dir"
    fi
  fi
}

validate_owned_manifest() {
  local owned_path owned_hash owned_extra
  ownership_manifest="$install_dir/$OWNERSHIP_MANIFEST_NAME"
  ownership_hashes="$install_dir/$OWNERSHIP_HASHES_NAME"
  has_ownership_manifest=false
  has_ownership_hashes=false

  if [ -e "$ownership_manifest" ] || [ -L "$ownership_manifest" ]; then
    [ ! -L "$ownership_manifest" ] && [ -f "$ownership_manifest" ] || \
      die "installed ownership manifest is not a regular file"
    : > "$tmp/seen-owned-paths"
    while IFS= read -r owned_path || [ -n "$owned_path" ]; do
      is_safe_relative_path "$owned_path" || \
        die "installed ownership manifest contains an unsafe path"
      ! grep -Fqx -- "$owned_path" "$tmp/seen-owned-paths" || \
        die "installed ownership manifest contains duplicate paths"
      printf '%s\n' "$owned_path" >> "$tmp/seen-owned-paths"
    done < "$ownership_manifest"
    if ! grep -Fqx 'SKILL.md' "$ownership_manifest" || \
        ! grep -Fqx 'bin/update-installed-skill.sh' "$ownership_manifest"; then
      die "installed ownership manifest is incomplete"
    fi
    has_ownership_manifest=true
  fi

  if [ -e "$ownership_hashes" ] || [ -L "$ownership_hashes" ]; then
    $has_ownership_manifest || die "installed ownership hashes exist without an ownership manifest"
    [ ! -L "$ownership_hashes" ] && [ -f "$ownership_hashes" ] || \
      die "installed ownership hashes are not a regular file"
    : > "$tmp/seen-owned-hashes"
    while IFS=$'\t' read -r owned_hash owned_path owned_extra || \
        [ -n "$owned_hash$owned_path$owned_extra" ]; do
      case "$owned_hash" in
        *[!0-9a-f]*|"") die "installed ownership hashes contain an invalid object id" ;;
      esac
      [ "${#owned_hash}" -eq 40 ] || [ "${#owned_hash}" -eq 64 ] || \
        die "installed ownership hashes contain an invalid object id"
      if [ -n "$owned_extra" ] || ! is_safe_relative_path "$owned_path"; then
        die "installed ownership hashes contain an unsafe path"
      fi
      grep -Fqx -- "$owned_path" "$ownership_manifest" || \
        die "installed ownership hashes name an unowned path"
      ! grep -Fqx -- "$owned_path" "$tmp/seen-owned-hashes" || \
        die "installed ownership hashes contain duplicate paths"
      printf '%s\n' "$owned_path" >> "$tmp/seen-owned-hashes"
    done < "$ownership_hashes"
    has_ownership_hashes=true
  fi
}

is_old_owned() {
  local relative_file="$1"
  $has_ownership_manifest && grep -Fqx -- "$relative_file" "$ownership_manifest"
}

old_owned_hash() {
  local relative_file="$1"
  if ! $has_ownership_hashes; then
    printf '\n'
    return
  fi
  awk -F '\t' -v wanted="$relative_file" '$2 == wanted { print $1; exit }' "$ownership_hashes"
}

current_file_matches_old_hash() {
  local relative_file="$1"
  local expected_hash current_hash
  expected_hash="$(old_owned_hash "$relative_file")"
  [ -n "$expected_hash" ] || return 1
  current_hash="$(git hash-object "$install_dir/$relative_file" 2>/dev/null)" || return 1
  [ "$current_hash" = "$expected_hash" ]
}

add_preserved_path() {
  local relative_file="$1"
  is_safe_relative_path "$relative_file" || die "project-owned path is unsafe: $relative_file"
  if ! grep -Fqx -- "$relative_file" "$preserved_paths"; then
    printf '%s\n' "$relative_file" >> "$preserved_paths"
  fi
}

collect_preserved_paths() {
  local config_file pm_config configured_status_path bad_local_path local_files
  local local_file relative_file source_file
  preserved_paths="$tmp/preserved-paths"
  : > "$preserved_paths"
  locally_modified_paths="$tmp/locally-modified-paths"
  : > "$locally_modified_paths"
  validate_owned_manifest

  if [ ! -d "$install_dir" ]; then
    return
  fi

  bad_local_path="$tmp/bad-local-path"
  find "$install_dir" -type l -print -quit > "$bad_local_path" || \
    die "cannot inspect existing installation"
  [ ! -s "$bad_local_path" ] || \
    die "existing installation contains a symlink: $(sed -n '1p' "$bad_local_path")"
  find "$install_dir" ! -type d ! -type f -print -quit > "$bad_local_path" || \
    die "cannot inspect existing installation"
  [ ! -s "$bad_local_path" ] || \
    die "existing installation contains a non-regular path: $(sed -n '1p' "$bad_local_path")"

  if ! $overwrite_config; then
    for config_file in "${CONFIG_FILES[@]}"; do
      if [ -e "$install_dir/$config_file" ] || [ -L "$install_dir/$config_file" ]; then
        validate_regular_relative_file "$config_file" "preserved config"
        add_preserved_path "$config_file"
      fi
    done

    pm_config="config/project-management.config.md"
    if [ -f "$install_dir/$pm_config" ]; then
      configured_status_path="$(read_config_value "$install_dir/$pm_config" STATUS_CONFIG)"
      configured_status_path="${configured_status_path:-config/statuses.config.json}"
      validate_regular_relative_file "$configured_status_path" "configured STATUS_CONFIG"
      add_preserved_path "$configured_status_path"
    fi
  fi

  local_files="$tmp/local-files"
  find "$install_dir" -type f -print0 > "$local_files" || \
    die "cannot enumerate existing installation"
  while IFS= read -r -d '' local_file; do
    relative_file="${local_file#"$install_dir"/}"
    case "$relative_file" in
      "$OWNERSHIP_MANIFEST_NAME"|"$OWNERSHIP_HASHES_NAME"|"$SOURCE_PROVENANCE_NAME") continue ;;
    esac
    is_safe_relative_path "$relative_file" || die "existing installation contains an unsafe path"
    if grep -Fqx -- "$relative_file" "$preserved_paths"; then
      continue
    fi

    source_file="$checkout/$relative_file"
    if [ -e "$source_file" ] || [ -L "$source_file" ]; then
      if ! $has_ownership_manifest || is_old_owned "$relative_file"; then
        # An upstream-owned file is replaced by the incoming version. If the
        # project edited it since it was installed, that edit is about to be
        # discarded — silently, which is how a local fix gets reverted by a
        # routine sync and nobody notices until the behaviour it fixed returns.
        # The install already records the hash it wrote, so say so.
        if $has_ownership_hashes && [ -f "$local_file" ] && \
           ! current_file_matches_old_hash "$relative_file" && \
           ! { [ -f "$source_file" ] && cmp -s "$local_file" "$source_file"; }; then
          printf '%s\n' "$relative_file" >> "$locally_modified_paths"
        fi
        continue
      fi
      if [ -f "$source_file" ] && cmp -s "$local_file" "$source_file"; then
        continue
      fi
      die "new upstream path collides with project-owned path: $relative_file"
    fi

    if current_file_matches_old_hash "$relative_file"; then
      continue
    fi
    add_preserved_path "$relative_file"
  done < "$local_files"
}

copy_preserved_path() {
  local relative_file="$1"
  local source_file destination_file destination_parent
  validate_regular_relative_file "$relative_file" "preserved project file"
  source_file="$install_dir/$relative_file"
  destination_file="$stage_dir/$relative_file"
  destination_parent="$(dirname "$destination_file")"

  if [ -e "$destination_parent" ] && [ ! -d "$destination_parent" ]; then
    die "upstream file collides with project-owned directory: $relative_file"
  fi
  mkdir -p "$destination_parent"
  if [ -d "$destination_file" ]; then
    die "upstream directory collides with project-owned file: $relative_file"
  fi
  cp -p "$source_file" "$destination_file"
}

validate_staged_runtime() {
  local staged_pm_config selected_tool selected_adapter staged_status_path validation_error
  staged_pm_config="$stage_dir/config/project-management.config.md"
  [ -f "$staged_pm_config" ] && [ ! -L "$staged_pm_config" ] || \
    die "staged project-management config is missing or invalid"

  selected_tool="$(read_config_value "$staged_pm_config" PRODUCT_MANAGEMENT_TOOL)"
  [ -n "$selected_tool" ] || die "staged project-management config does not select a tool"
  selected_adapter="adapters/$selected_tool.md"
  is_safe_relative_path "$selected_adapter" || die "selected project-management adapter is unsafe: $selected_tool"
  [ -f "$stage_dir/$selected_adapter" ] && [ ! -L "$stage_dir/$selected_adapter" ] || \
    die "selected project-management adapter is missing from the staged update: $selected_adapter"

  staged_status_path="$(read_config_value "$staged_pm_config" STATUS_CONFIG)"
  staged_status_path="${staged_status_path:-config/statuses.config.json}"
  is_safe_relative_path "$staged_status_path" || \
    die "staged STATUS_CONFIG is not a safe skill-relative path: $staged_status_path"
  [ -f "$stage_dir/$staged_status_path" ] && [ ! -L "$stage_dir/$staged_status_path" ] || \
    die "staged STATUS_CONFIG is missing or invalid: $staged_status_path"

  if ! validation_error="$(python3 - "$stage_dir/$staged_status_path" "$selected_tool" 2>&1 <<'PY'
import json
import sys

path, selected_tool = sys.argv[1:]

try:
    with open(path, encoding="utf-8") as handle:
        board = json.load(handle)
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit("cannot load JSON: %s" % exc)

if not isinstance(board, dict):
    raise SystemExit("root must be an object")

for entity in ("features", "tasks"):
    group = board.get(entity)
    statuses = group.get("statuses") if isinstance(group, dict) else None
    if not isinstance(statuses, list) or not statuses:
        raise SystemExit("%s.statuses must be a non-empty list" % entity)

    names = []
    for index, status in enumerate(statuses):
        context = "%s.statuses[%d]" % (entity, index)
        if not isinstance(status, dict):
            raise SystemExit("%s must be an object" % context)
        name = status.get("name")
        if not isinstance(name, str) or not name.strip():
            raise SystemExit("%s.name must be a non-empty string" % context)
        if name in names:
            raise SystemExit("%s contains duplicate status name %r" % (entity, name))
        names.append(name)
        mapping = status.get("tool")
        selected_mapping = mapping.get(selected_tool) if isinstance(mapping, dict) else None
        if not isinstance(selected_mapping, str) or not selected_mapping.strip():
            raise SystemExit("%s status %r has no non-empty %s mapping"
                             % (entity, name, selected_tool))
        transitions = status.get("transitions")
        if not isinstance(transitions, list) or any(
                not isinstance(target, str) or not target for target in transitions):
            raise SystemExit("%s status %r transitions must be a list of status names"
                             % (entity, name))

    initial = [status["name"] for status in statuses if status.get("initial") is True]
    if len(initial) != 1:
        raise SystemExit("%s must define exactly one initial status (found %d)"
                         % (entity, len(initial)))
    terminal = [status["name"] for status in statuses if status.get("terminal") is True]
    if not terminal:
        raise SystemExit("%s must define at least one terminal status" % entity)
    known = set(names)
    for status in statuses:
        unknown = [target for target in status["transitions"] if target not in known]
        if unknown:
            raise SystemExit("%s status %r references unknown transition(s): %s"
                             % (entity, status["name"], ", ".join(unknown)))
PY
  )"; then
    die "staged STATUS_CONFIG is incompatible: $validation_error"
  fi
}

build_stage() {
  local relative_file
  rsync -a --checksum --delete --exclude .git "$checkout"/ "$stage_dir"/
  while IFS= read -r relative_file || [ -n "$relative_file" ]; do
    [ -n "$relative_file" ] || continue
    copy_preserved_path "$relative_file"
  done < "$preserved_paths"

  cp "$new_ownership_manifest" "$stage_dir/$OWNERSHIP_MANIFEST_NAME"
  cp "$new_ownership_hashes" "$stage_dir/$OWNERSHIP_HASHES_NAME"
  printf '{"schemaVersion":1,"name":"startup-factory","sourceCommit":"%s"}\n' \
    "$resolved_commit" > "$stage_dir/$SOURCE_PROVENANCE_NAME"
  chmod 0644 \
    "$stage_dir/$OWNERSHIP_MANIFEST_NAME" \
    "$stage_dir/$OWNERSHIP_HASHES_NAME" \
    "$stage_dir/$SOURCE_PROVENANCE_NAME"
  validate_staged_runtime
}

create_change_plan() {
  local comparison_target="$install_dir"
  if [ ! -d "$comparison_target" ]; then
    comparison_target="$tmp/empty-destination"
    mkdir -p "$comparison_target"
  fi
  change_plan="$tmp/change-plan"
  rsync -a --checksum --delete --dry-run --itemize-changes \
    "$stage_dir"/ "$comparison_target"/ > "$change_plan"
  change_count="$(awk 'NF { count++ } END { print count + 0 }' "$change_plan")"
}

snapshot_existing_target() {
  local output_path="$1"
  local snapshot_files="$tmp/snapshot-files"
  local snapshot_unsorted="$tmp/snapshot-unsorted"
  local snapshot_file snapshot_relative snapshot_hash
  : > "$snapshot_unsorted"

  if [ ! -d "$install_dir" ]; then
    printf 'MISSING\n' > "$output_path"
    return
  fi

  find "$install_dir" -type l -print -quit > "$tmp/snapshot-bad-path" || \
    die "cannot snapshot the existing installation"
  [ ! -s "$tmp/snapshot-bad-path" ] || \
    die "installation changed to contain a symlink while the update was staged"
  find "$install_dir" ! -type d ! -type f -print -quit > "$tmp/snapshot-bad-path" || \
    die "cannot snapshot the existing installation"
  [ ! -s "$tmp/snapshot-bad-path" ] || \
    die "installation changed to contain a non-regular path while the update was staged"

  find "$install_dir" -type f -print0 > "$snapshot_files" || \
    die "cannot snapshot the existing installation"
  while IFS= read -r -d '' snapshot_file; do
    snapshot_relative="${snapshot_file#"$install_dir"/}"
    is_safe_relative_path "$snapshot_relative" || \
      die "existing installation contains an unsafe path"
    snapshot_hash="$(git hash-object "$snapshot_file")" || \
      die "cannot snapshot existing installation path: $snapshot_relative"
    printf '%s\t%s\n' "$snapshot_hash" "$snapshot_relative" >> "$snapshot_unsorted"
  done < "$snapshot_files"
  LC_ALL=C sort "$snapshot_unsorted" > "$output_path"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-dir)
      [ "$#" -ge 2 ] || die "--install-dir requires a path"
      install_dir="$2"
      shift 2
      ;;
    --remote-url)
      [ "$#" -ge 2 ] || die "--remote-url requires a URL"
      REMOTE_URL="$2"
      shift 2
      ;;
    --ref)
      [ "$#" -ge 2 ] || die "--ref requires a branch, tag, or commit"
      REMOTE_REF="$2"
      shift 2
      ;;
    --overwrite-config)
      overwrite_config=true
      shift
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

command -v git >/dev/null 2>&1 || die "git is required"
command -v rsync >/dev/null 2>&1 || die "rsync is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
case "$REMOTE_URL" in -*) die "remote URL must not begin with '-'" ;; esac
case "$REMOTE_REF" in -*) die "remote ref must not begin with '-'" ;; esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
script_skill_dir="$(cd "$script_dir/.." && pwd -P)"

if [ -z "$install_dir" ]; then
  source_repo_root=""
  if source_repo_root="$(git -C "$script_skill_dir" rev-parse --show-toplevel 2>/dev/null)"; then
    source_repo_root="$(cd "$source_repo_root" && pwd -P)"
  elif has_git_marker_at_or_above "$script_skill_dir"; then
    die "cannot safely inspect the source checkout; pass --install-dir"
  fi

  if [ -f "$script_skill_dir/SKILL.md" ] && [ -L "$script_skill_dir/SKILL.md" ]; then
    die "installed SKILL.md must not be a symlink"
  elif [ -f "$script_skill_dir/SKILL.md" ] && [ "$source_repo_root" != "$script_skill_dir" ]; then
    install_dir="$script_skill_dir"
  else
    repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || \
      die "not inside a Git repository; pass --install-dir"
    repo_root="$(cd "$repo_root" && pwd -P)"
    detected_install=""
    detected_count=0
    for candidate in \
      "$repo_root/.agents/skills/$SKILL_NAME" \
      "$repo_root/.claude/skills/$SKILL_NAME"
    do
      if [ -e "$candidate" ] || [ -L "$candidate" ]; then
        detected_install="$candidate"
        detected_count=$((detected_count + 1))
      fi
    done
    [ "$detected_count" -le 1 ] || \
      die "multiple project installations found; pass --install-dir"
    if [ "$detected_count" -eq 1 ]; then
      install_dir="$detected_install"
    else
      install_dir="$repo_root/.claude/skills/$SKILL_NAME"
    fi
  fi
fi

case "$install_dir" in
  /*) ;;
  *) install_dir="$(pwd -P)/$install_dir" ;;
esac
case "/$install_dir/" in
  */../*) die "install directory must not contain '..' path components" ;;
esac
install_dir="$(canonicalize_destination "$install_dir")"

home_dir=""
if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then
  home_dir="$(cd "$HOME" && pwd -P)"
fi
[ "$install_dir" != "/" ] || die "refusing to install at filesystem root"
[ -z "$home_dir" ] || [ "$install_dir" != "$home_dir" ] || die "refusing to install at the home directory"

tmp="$(mktemp -d)"
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

validate_existing_target

checkout="$tmp/source"
echo "Fetching $REMOTE_URL ($REMOTE_REF)"
git init -q "$checkout"
git -C "$checkout" remote add origin "$REMOTE_URL"
git -C "$checkout" fetch --quiet --depth 1 origin "$REMOTE_REF" || \
  die "unable to fetch ref '$REMOTE_REF' from $REMOTE_URL"
git -C "$checkout" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
resolved_commit="$(git -C "$checkout" rev-parse HEAD)"
case "$resolved_commit" in
  ""|*[!0-9a-f]*) die "fetched ref resolved to an invalid commit id" ;;
esac
if [ "${#resolved_commit}" -ne 40 ] && [ "${#resolved_commit}" -ne 64 ]; then
  die "fetched ref resolved to an invalid commit id"
fi

if [ ! -f "$checkout/SKILL.md" ] || [ -L "$checkout/SKILL.md" ] || \
    ! grep -Eq '^name:[[:space:]]*startup-factory[[:space:]]*$' "$checkout/SKILL.md"; then
  die "fetched ref is not a Startup Factory bundle"
fi
for forbidden_metadata in \
  "$OWNERSHIP_MANIFEST_NAME" \
  "$OWNERSHIP_HASHES_NAME" \
  "$RELEASE_BUNDLE_MANIFEST_NAME" \
  "$RELEASE_PROVENANCE_NAME" \
  "$SOURCE_PROVENANCE_NAME"
do
  [ ! -e "$checkout/$forbidden_metadata" ] && [ ! -L "$checkout/$forbidden_metadata" ] || \
    die "fetched bundle contains reserved installation metadata: $forbidden_metadata"
done
for required_dir in \
  adapters \
  bin \
  config \
  extensions \
  reference \
  roles \
  teams \
  tests
do
  [ -d "$checkout/$required_dir" ] && [ ! -L "$checkout/$required_dir" ] || \
    die "fetched Startup Factory bundle is incomplete: missing $required_dir/"
done
for required_file in \
  adapters/_TEMPLATE.md \
  adapters/GitHubIssues.md \
  adapters/Jira.md \
  adapters/Linear.md \
  adapters/Markdown.md \
  bin/dispatch.sh \
  bin/agent-health.py \
  bin/board-status.py \
  bin/heartbeat-status.py \
  bin/launch-team.sh \
  bin/process-lifecycle.py \
  bin/superpowers-planning.py \
  bin/pm-agent.py \
  bin/policy-check.py \
  bin/release-feature.py \
  bin/retrospective.py \
  bin/runtime-state.py \
  bin/ticket_content_security.py \
  bin/teamwork-path.py \
  bin/tracker-ops.sh \
  bin/update-installed-skill.sh \
  config/project-management.config.md \
  config/planning.config.md \
  config/team.config.md \
  config/statuses.config.json \
  config/automation.config.json \
  config/deployment.config.json \
  config/guardrails.config.json \
  extensions/tracker-backends/README.md \
  reference/automation.md \
  reference/deployment.md \
  reference/guardrails.md \
  reference/superpowers-planning.md \
  roles/senior-security-engineer.md \
  roles/team-lead.md \
  teams/_PLAYBOOK.md
do
  [ -f "$checkout/$required_file" ] && [ ! -L "$checkout/$required_file" ] || \
    die "fetched Startup Factory bundle is incomplete: missing $required_file"
done

tracked_paths="$tmp/tracked-paths"
git -C "$checkout" -c core.quotePath=false ls-files -z > "$tracked_paths" || \
  die "cannot enumerate fetched bundle"
new_ownership_manifest="$tmp/owned-files"
new_ownership_hashes="$tmp/owned-hashes"
: > "$new_ownership_manifest"
: > "$new_ownership_hashes"
while IFS= read -r -d '' owned_file; do
  is_safe_relative_path "$owned_file" || \
    die "bundle contains a path that ownership metadata cannot represent safely"
  [ -f "$checkout/$owned_file" ] && [ ! -L "$checkout/$owned_file" ] || \
    die "bundle contains a non-regular tracked path: $owned_file"
  printf '%s\n' "$owned_file" >> "$new_ownership_manifest"
  owned_hash="$(git hash-object "$checkout/$owned_file")" || \
    die "cannot hash fetched bundle path: $owned_file"
  printf '%s\t%s\n' "$owned_hash" "$owned_file" >> "$new_ownership_hashes"
done < "$tracked_paths"

install_parent="$(dirname "$install_dir")"
install_name="$(basename "$install_dir")"

report_locally_modified() {
  local count
  [ -n "${locally_modified_paths:-}" ] && [ -s "$locally_modified_paths" ] || return 0
  count="$(wc -l < "$locally_modified_paths" | tr -d ' ')"
  echo
  echo "WARNING: $count upstream file(s) were modified locally since they were installed."
  echo "The incoming version replaces them, so those local edits are discarded:"
  sed 's/^/  - /' "$locally_modified_paths"
  echo "Re-apply anything still needed, or upstream it so the next sync keeps it."
}

if $dry_run; then
  collect_preserved_paths
  stage_dir="$tmp/stage"
  mkdir -p "$stage_dir"
  build_stage
  create_change_plan
  cat "$change_plan"
  echo "Previewed Startup Factory changes for: $install_dir"
  echo "Resolved source commit: $resolved_commit"
  echo "Planned filesystem changes: $change_count"
  echo "Dry run complete; no destination files were written."
  report_locally_modified
else
  mkdir -p "$install_parent"
  lock_dir="$install_parent/.$install_name.startup-factory.lock"
  mkdir "$lock_dir" 2>/dev/null || \
    die "another updater is already running or a stale lock exists: $lock_dir"
  lock_acquired=true
  printf '%s\n' "$$" > "$lock_dir/pid"

  validate_existing_target
  collect_preserved_paths
  snapshot_existing_target "$tmp/target-before-stage"

  stage_dir="$(mktemp -d "$install_parent/.$install_name.stage.XXXXXX")"
  build_stage
  snapshot_existing_target "$tmp/target-after-stage"
  cmp -s "$tmp/target-before-stage" "$tmp/target-after-stage" || \
    die "installation changed while the update was staged; retry"
  create_change_plan

  backup_dir="$(mktemp -d "$install_parent/.$install_name.backup.XXXXXX")"
  rmdir "$backup_dir"
  if [ -d "$install_dir" ]; then
    mv "$install_dir" "$backup_dir"
    old_install_moved=true
  fi
  if ! mv "$stage_dir" "$install_dir"; then
    if $old_install_moved && [ ! -e "$install_dir" ]; then
      if mv "$backup_dir" "$install_dir"; then
        backup_dir=""
        old_install_moved=false
      fi
    fi
    die "failed to activate staged update"
  fi
  stage_dir=""
  new_install_placed=true

  if $old_install_moved; then
    rm -rf "$backup_dir"
    backup_dir=""
    old_install_moved=false
  fi
  rm -rf "$lock_dir"
  lock_dir=""
  lock_acquired=false

  echo "Updated Startup Factory skill at: $install_dir"
  echo "Resolved source commit: $resolved_commit"
  echo "Applied filesystem changes: $change_count"
  if ! $overwrite_config; then
    echo "Preserved existing project configuration and project-owned files."
  fi
  report_locally_modified
fi

target_repo="$(git -C "$install_dir" rev-parse --show-toplevel 2>/dev/null || true)"
if [ -n "$target_repo" ]; then
  case "$install_dir" in
    "$target_repo") rel_path="." ;;
    "$target_repo"/*) rel_path="${install_dir#"$target_repo"/}" ;;
    *) rel_path="$install_dir" ;;
  esac

  if git -C "$target_repo" check-ignore -q -- "$rel_path"; then
    echo
    echo "Git reporting: $rel_path is ignored; status and diff cannot show updater changes."
  else
    echo
    echo "Git status for $rel_path:"
    git -C "$target_repo" status --short -- "$rel_path" || true

    if ! $dry_run; then
      echo
      echo "Diff stat for $rel_path:"
      git -C "$target_repo" diff --stat -- "$rel_path" || true
    fi
  fi
fi
