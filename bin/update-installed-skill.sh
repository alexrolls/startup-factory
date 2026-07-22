#!/usr/bin/env bash
# update-installed-skill.sh — install or refresh a legacy/source-managed copy.
set -euo pipefail

REMOTE_URL="${STARTUP_FACTORY_REMOTE_URL:-https://github.com/alexrolls/startup-factory.git}"
REMOTE_REF="${STARTUP_FACTORY_REF:-main}"
SKILL_NAME="${STARTUP_FACTORY_SKILL_NAME:-startup-factory}"
OWNERSHIP_MANIFEST_NAME=".startup-factory-owned-files"
RELEASE_BUNDLE_MANIFEST_NAME=".startup-factory-bundle.json"
RELEASE_PROVENANCE_NAME=".startup-factory-install.json"

install_dir=""
overwrite_config=false
dry_run=false

die() {
  echo "update-installed-skill: $*" >&2
  exit 1
}

usage() {
  cat <<EOF
Usage: update-installed-skill.sh [options]

Fetch Startup Factory from Git and sync it into a new or legacy/source-managed
skill directory. Release-CLI installations are intentionally refused because
this compatibility updater cannot retain their canonical bundle provenance.
From a standalone source checkout, the fallback target is the current
repository's .claude/skills/startup-factory directory.

Options:
  --install-dir PATH     Update this skill directory instead of auto-detecting.
  --remote-url URL       Git remote to fetch from.
                         Default: $REMOTE_URL
  --ref REF              Branch, tag, or commit to fetch.
                         Default: $REMOTE_REF
  --overwrite-config     Replace local config files with the upstream defaults.
  --dry-run              Show rsync changes without writing them.
  -h, --help             Show this help.

Environment overrides:
  STARTUP_FACTORY_REMOTE_URL
  STARTUP_FACTORY_REF
  STARTUP_FACTORY_SKILL_NAME
EOF
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

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
script_skill_dir="$(cd "$script_dir/.." && pwd -P)"

if [ -z "$install_dir" ]; then
  source_repo_root="$(git -C "$script_skill_dir" rev-parse --show-toplevel 2>/dev/null || true)"
  if [ -n "$source_repo_root" ]; then
    source_repo_root="$(cd "$source_repo_root" && pwd -P)"
  fi
  if [ -f "$script_skill_dir/SKILL.md" ] && [ "$source_repo_root" != "$script_skill_dir" ]; then
    # Installed project/global skills are normally nested below a repository or
    # live outside Git entirely. Update the physical directory containing this
    # script, including canonical .agents paths reached through agent symlinks.
    install_dir="$script_skill_dir"
  else
    repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
    [ -n "$repo_root" ] || die "not inside a git repository; pass --install-dir"
    install_dir="$repo_root/.claude/skills/$SKILL_NAME"
  fi
fi

case "$install_dir" in
  /*) ;;
  *) install_dir="$(pwd -P)/$install_dir" ;;
esac
[ ! -L "$install_dir" ] || die "install directory must not be a symlink; use its canonical path"
case "/$install_dir/" in
  */../*) die "install directory must not contain '..' path components" ;;
esac
if [ -e "$install_dir" ] && [ ! -d "$install_dir" ]; then
  die "install destination exists and is not a directory: $install_dir"
fi
if [ -d "$install_dir" ]; then
  install_dir="$(cd "$install_dir" && pwd -P)"
fi

home_dir=""
if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then
  home_dir="$(cd "$HOME" && pwd -P)"
fi
[ "$install_dir" != "/" ] || die "refusing to install at filesystem root"
[ -z "$home_dir" ] || [ "$install_dir" != "$home_dir" ] || die "refusing to install at the home directory"

if [ -d "$install_dir" ]; then
  target_git_root="$(git -C "$install_dir" rev-parse --show-toplevel 2>/dev/null || true)"
  if [ -n "$target_git_root" ]; then
    target_git_root="$(cd "$target_git_root" && pwd -P)"
    [ "$install_dir" != "$target_git_root" ] || die "refusing to install at a Git repository root"
  fi

  if [ -e "$install_dir/$RELEASE_PROVENANCE_NAME" ] || \
      [ -L "$install_dir/$RELEASE_PROVENANCE_NAME" ] || \
      [ -e "$install_dir/$RELEASE_BUNDLE_MANIFEST_NAME" ] || \
      [ -L "$install_dir/$RELEASE_BUNDLE_MANIFEST_NAME" ]; then
    die "release-managed installation detected; use the versioned startup-factory CLI to update it"
  fi

  if [ -n "$(find "$install_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    if [ ! -f "$install_dir/SKILL.md" ] || \
        ! grep -Eq '^name:[[:space:]]*startup-factory[[:space:]]*$' "$install_dir/SKILL.md"; then
      die "non-empty install directory is not an existing Startup Factory installation: $install_dir"
    fi
    if [ ! -f "$install_dir/bin/update-installed-skill.sh" ] && \
        [ -n "$(find "$install_dir" -mindepth 1 -maxdepth 1 ! -name SKILL.md -print -quit 2>/dev/null)" ]; then
      die "Startup Factory marker found, but destination is neither a complete installation nor a SKILL.md-only repair target: $install_dir"
    fi
  fi
fi

tmp="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

checkout="$tmp/source"

echo "Fetching $REMOTE_URL ($REMOTE_REF)"
git init -q "$checkout"
git -C "$checkout" remote add origin "$REMOTE_URL"
git -C "$checkout" fetch --quiet --depth 1 origin "$REMOTE_REF" || \
  die "unable to fetch ref '$REMOTE_REF' from $REMOTE_URL"
git -C "$checkout" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD

if [ ! -f "$checkout/SKILL.md" ] || [ -L "$checkout/SKILL.md" ] || \
    ! grep -Eq '^name:[[:space:]]*startup-factory[[:space:]]*$' "$checkout/SKILL.md"; then
  die "fetched ref is not a Startup Factory bundle"
fi
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
  bin/dispatch.sh \
  bin/launch-team.sh \
  bin/superpowers-planning.py \
  bin/pm-agent.py \
  bin/policy-check.py \
  bin/release-feature.py \
  bin/runtime-state.py \
  bin/ticket_content_security.py \
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

new_ownership_manifest="$tmp/owned-files"
: > "$new_ownership_manifest"
while IFS= read -r -d '' owned_file; do
  case "$owned_file" in
    *$'\n'*) die "bundle contains a newline in a tracked path; ownership manifest cannot represent it safely" ;;
  esac
  printf '%s\n' "$owned_file" >> "$new_ownership_manifest"
done < <(git -C "$checkout" -c core.quotePath=false ls-files -z)

# Git checkouts can give different same-size file contents identical coarse
# mtimes during rapid successive updates. Checksum comparison avoids silently
# retaining stale runtime or config bytes.
ownership_manifest="$install_dir/$OWNERSHIP_MANIFEST_NAME"
has_ownership_manifest=false
if [ -f "$ownership_manifest" ] && [ ! -L "$ownership_manifest" ]; then
  has_ownership_manifest=true
fi
rsync_args=(-a --checksum --delete --exclude .git --exclude "/$OWNERSHIP_MANIFEST_NAME")
if ! $overwrite_config; then
  for file in \
    config/project-management.config.md \
    config/planning.config.md \
    config/team.config.md \
    config/statuses.config.json \
    config/automation.config.json \
    config/deployment.config.json \
    config/guardrails.config.json
  do
    if [ -e "$install_dir/$file" ] || [ -L "$install_dir/$file" ]; then
      # Excluding an existing config keeps rsync from touching or deleting it.
      # Missing config remains eligible, so newly shipped defaults are installed.
      rsync_args+=(--exclude "/$file")
    fi
  done
fi

# Files added under documented extension points belong to the project. A
# generated ownership manifest distinguishes them from files shipped by the
# previous bundle, so an upstream adapter/team/backend that is later retired is
# deleted instead of silently lingering forever.
for extension_dir in adapters extensions teams; do
  [ -d "$install_dir/$extension_dir" ] || continue
  while IFS= read -r -d '' local_extension; do
    relative_extension="${local_extension#"$install_dir"/}"
    case "$relative_extension" in
      *$'\n'*) die "extension path contains a newline and cannot be classified safely" ;;
    esac
    if [ ! -e "$checkout/$relative_extension" ] && [ ! -L "$checkout/$relative_extension" ]; then
      if ! $has_ownership_manifest || \
          ! grep -Fqx -- "$relative_extension" "$ownership_manifest"; then
        rsync_args+=(--exclude "/$relative_extension")
      fi
    elif $has_ownership_manifest && \
        ! grep -Fqx -- "$relative_extension" "$ownership_manifest"; then
      paths_match=false
      if [ -L "$local_extension" ] && [ -L "$checkout/$relative_extension" ]; then
        [ "$(readlink "$local_extension")" = "$(readlink "$checkout/$relative_extension")" ] && paths_match=true
      elif [ -f "$local_extension" ] && [ -f "$checkout/$relative_extension" ] && \
          cmp -s "$local_extension" "$checkout/$relative_extension"; then
        paths_match=true
      fi
      $paths_match || die "new upstream extension collides with project-owned path: $relative_extension"
    fi
  done < <(find "$install_dir/$extension_dir" \( -type f -o -type l \) -print0)
done

rsync_target="$install_dir"
if $dry_run; then
  rsync_args+=(--dry-run --itemize-changes)
  if [ ! -d "$install_dir" ]; then
    # Simulate a fresh destination entirely inside the disposable checkout
    # workspace. A first-install preview must not create the requested path.
    rsync_target="$tmp/empty-destination"
    mkdir -p "$rsync_target"
  fi
else
  mkdir -p "$install_dir"
fi

rsync "${rsync_args[@]}" "$checkout"/ "$rsync_target"/

if $dry_run; then
  echo "Previewed Startup Factory changes for: $install_dir"
  echo "Dry run complete; no files were written."
else
  manifest_tmp="$(mktemp "$install_dir/$OWNERSHIP_MANIFEST_NAME.tmp.XXXXXX")"
  cp "$new_ownership_manifest" "$manifest_tmp"
  chmod 0644 "$manifest_tmp"
  mv -f "$manifest_tmp" "$ownership_manifest"
  echo "Updated Startup Factory skill at: $install_dir"
  if ! $overwrite_config; then
    echo "Preserved existing local config and extension files when present."
  fi
fi

target_repo="$(git -C "$install_dir" rev-parse --show-toplevel 2>/dev/null || true)"
if [ -n "$target_repo" ]; then
  case "$install_dir" in
    "$target_repo") rel_path="." ;;
    "$target_repo"/*) rel_path="${install_dir#"$target_repo"/}" ;;
    *) rel_path="$install_dir" ;;
  esac

  echo
  echo "Git status for $rel_path:"
  git -C "$target_repo" status --short -- "$rel_path" || true

  if ! $dry_run; then
    echo
    echo "Diff stat for $rel_path:"
    git -C "$target_repo" diff --stat -- "$rel_path" || true
  fi
fi
