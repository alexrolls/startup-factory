#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEFAULT_STATUS_FIXTURE="$ROOT/tests/fixtures/statuses.default-profile.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0

check() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "ok: $description"
  else
    echo "FAIL: $description"
    FAILURES=$((FAILURES + 1))
  fi
}

UPSTREAM="$TMP/upstream"
TARGET="$TMP/target"
mkdir -p \
  "$UPSTREAM/adapters" \
  "$UPSTREAM/bin" \
  "$UPSTREAM/config" \
  "$UPSTREAM/extensions/tracker-backends" \
  "$UPSTREAM/reference" \
  "$UPSTREAM/roles" \
  "$UPSTREAM/teams" \
  "$UPSTREAM/tests" \
  "$TARGET"
git -C "$UPSTREAM" init -q -b main
git -C "$UPSTREAM" config user.email test@example.com
git -C "$UPSTREAM" config user.name Test
git -C "$TARGET" init -q -b main
git -C "$TARGET" config user.email test@example.com
git -C "$TARGET" config user.name Test

cp "$ROOT/bin/update-installed-skill.sh" "$UPSTREAM/bin/update-installed-skill.sh"
chmod 755 "$UPSTREAM/bin/update-installed-skill.sh"
printf '%s\n' '---' 'name: startup-factory' 'description: Test fixture.' '---' > "$UPSTREAM/SKILL.md"
printf 'runtime-v1\n' > "$UPSTREAM/runtime.txt"
printf 'upstream-adapter-v1\n' > "$UPSTREAM/adapters/BuiltIn.md"
printf 'retired-adapter-v1\n' > "$UPSTREAM/adapters/Retired.md"
for adapter in GitHubIssues Jira Linear Markdown; do
  printf 'fixture adapter:%s\n' "$adapter" > "$UPSTREAM/adapters/$adapter.md"
done
for required_file in \
  adapters/_TEMPLATE.md \
  bin/dispatch.sh \
  bin/launch-team.sh \
  bin/superpowers-planning.py \
  bin/pm-agent.py \
  bin/policy-check.py \
  bin/release-feature.py \
  bin/retrospective.py \
  bin/runtime-state.py \
  bin/ticket_content_security.py \
  bin/tracker-ops.sh \
  extensions/tracker-backends/README.md \
  reference/automation.md \
  reference/deployment.md \
  reference/guardrails.md \
  reference/superpowers-planning.md \
  roles/senior-security-engineer.md \
  roles/team-lead.md \
  teams/_PLAYBOOK.md
do
  printf 'fixture:%s\n' "$required_file" > "$UPSTREAM/$required_file"
done
printf 'fixture\n' > "$UPSTREAM/tests/.fixture"

CONFIG_FILES=(
  project-management.config.md
  planning.config.md
  team.config.md
  statuses.config.json
  automation.config.json
  deployment.config.json
  guardrails.config.json
)

write_status_fixture() {
  local destination="$1"
  local fixture_version="$2"
  python3 - "$DEFAULT_STATUS_FIXTURE" "$destination" "$fixture_version" <<'PY'
import json
import sys

source, destination, fixture_version = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    board = json.load(handle)
for group_name in ("features", "tasks"):
    for status in board[group_name]["statuses"]:
        status["tool"]["BuiltIn"] = "fixture:%s:%s" % (
            fixture_version, status["name"])
board["fixtureVersion"] = fixture_version
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(board, handle, indent=2)
    handle.write("\n")
PY
}

for name in "${CONFIG_FILES[@]}"; do
  printf 'upstream-v1:%s\n' "$name" > "$UPSTREAM/config/$name"
done
write_status_fixture "$UPSTREAM/config/statuses.config.json" v1
printf '%s\n' \
  'PRODUCT_MANAGEMENT_TOOL=BuiltIn' \
  'STATUS_CONFIG=config/statuses.config.json' \
  'upstream-v1:project-management.config.md' \
  > "$UPSTREAM/config/project-management.config.md"

git -C "$UPSTREAM" add .
git -C "$UPSTREAM" commit -qm fixture-v1
V1_COMMIT="$(git -C "$UPSTREAM" rev-parse HEAD)"

FRESH_PREVIEW="$TARGET/.agents/skills/preview-startup-factory"
env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$ROOT/bin/update-installed-skill.sh" \
    --install-dir "$FRESH_PREVIEW" --dry-run > "$TMP/fresh-preview.out"
check "fresh-install dry-run does not create the destination" test ! -e "$FRESH_PREVIEW"
check "fresh-install dry-run reports a preview" grep -q 'Previewed Startup Factory changes' "$TMP/fresh-preview.out"

PARTIAL_INSTALL="$TARGET/.agents/skills/partial-startup-factory"
mkdir -p "$PARTIAL_INSTALL"
cp "$UPSTREAM/SKILL.md" "$PARTIAL_INSTALL/SKILL.md"
env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$ROOT/bin/update-installed-skill.sh" \
    --install-dir "$PARTIAL_INSTALL" --dry-run > "$TMP/partial-preview.out"
check "SKILL.md-only generic install can be repaired" grep -q 'Previewed Startup Factory changes' "$TMP/partial-preview.out"
check "repair dry-run leaves partial install unchanged" test ! -e "$PARTIAL_INSTALL/bin"
env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$ROOT/bin/update-installed-skill.sh" --install-dir "$PARTIAL_INSTALL" \
    > "$TMP/partial-repair.out"
check "SKILL.md-only generic install is repaired transactionally" \
  test -x "$PARTIAL_INSTALL/bin/update-installed-skill.sh"

for tool in Linear Jira GitHubIssues Markdown; do
  TOOL_PROJECT="$TMP/project with spaces-$tool"
  mkdir -p "$TOOL_PROJECT"
  if [ "$tool" != "Markdown" ]; then
    git -C "$TOOL_PROJECT" init -q -b main
  fi
  case "$tool" in
    Linear)
      TOOL_INSTALL="$TOOL_PROJECT/.agents/skills/startup-factory"
      TOOL_SETTING='LINEAR_DEFAULT_TEAM=PLATFORM'
      ;;
    Jira)
      TOOL_INSTALL="$TOOL_PROJECT/.claude/skills/startup-factory"
      TOOL_SETTING='JIRA_PROJECT_KEY=ENG'
      ;;
    GitHubIssues)
      TOOL_INSTALL="$TOOL_PROJECT/custom skills/startup-factory"
      TOOL_SETTING='GITHUB_REPO=acme/widgets'
      ;;
    Markdown)
      TOOL_INSTALL="$TOOL_PROJECT/global startup-factory"
      TOOL_SETTING='MARKDOWN_ROOT=.local/project-board'
      ;;
  esac
  env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$ROOT/bin/update-installed-skill.sh" --install-dir "$TOOL_INSTALL" \
      > "$TMP/$tool-install.out"
  printf '%s\n' \
    "PRODUCT_MANAGEMENT_TOOL=$tool" \
    "$TOOL_SETTING" \
    'STATUS_CONFIG=config/statuses.config.json' \
    > "$TOOL_INSTALL/config/project-management.config.md"
  cp "$TOOL_INSTALL/config/project-management.config.md" "$TMP/$tool-project-management.config.md"
  env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$TOOL_INSTALL/bin/update-installed-skill.sh" > "$TMP/$tool-update.out"
  check "$tool project-management settings survive a path-safe update" \
    cmp -s "$TMP/$tool-project-management.config.md" \
      "$TOOL_INSTALL/config/project-management.config.md"
done

IGNORED_INSTALL="$TARGET/.agents/skills/ignored-startup-factory"
printf '/.agents/skills/ignored-startup-factory/\n' >> "$TARGET/.git/info/exclude"
env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$ROOT/bin/update-installed-skill.sh" --install-dir "$IGNORED_INSTALL" \
    > "$TMP/ignored-install.out"
check "gitignored installation reports why Git status cannot show changes" \
  grep -q 'is ignored; status and diff cannot show updater changes' "$TMP/ignored-install.out"
check "gitignored installation still records source provenance" \
  grep -Fqx \
    "{\"schemaVersion\":1,\"name\":\"startup-factory\",\"sourceCommit\":\"$V1_COMMIT\"}" \
    "$IGNORED_INSTALL/.startup-factory-source-install.json"

INSTALL="$TARGET/.agents/skills/startup-factory"
mkdir -p \
  "$INSTALL/adapters" \
  "$INSTALL/bin" \
  "$INSTALL/config" \
  "$INSTALL/extensions/tracker-backends" \
  "$INSTALL/teams/commands" \
  "$INSTALL/teams/roles"
cp "$ROOT/bin/update-installed-skill.sh" "$INSTALL/bin/update-installed-skill.sh"
cp "$UPSTREAM/SKILL.md" "$INSTALL/SKILL.md"
printf 'stale\n' > "$INSTALL/stale-runtime.txt"
printf 'custom-adapter\n' > "$INSTALL/adapters/Acme.md"
printf 'custom-backend\n' > "$INSTALL/extensions/tracker-backends/Acme.py"
printf 'custom-team\n' > "$INSTALL/teams/acme.md"
printf 'custom-role\n' > "$INSTALL/teams/roles/acme-specialist.md"
printf 'custom-command\n' > "$INSTALL/teams/commands/acme-command.md"
for name in project-management.config.md planning.config.md team.config.md statuses.config.json deployment.config.json guardrails.config.json; do
  printf 'project-owned:%s\n' "$name" > "$INSTALL/config/$name"
done
write_status_fixture "$INSTALL/config/statuses.config.json" project
cp "$INSTALL/config/statuses.config.json" "$TMP/status-board-before-initial.json"
printf '%s\n' \
  'PRODUCT_MANAGEMENT_TOOL=BuiltIn' \
  'STATUS_CONFIG=config/statuses.config.json' \
  'project-owned:project-management.config.md' \
  > "$INSTALL/config/project-management.config.md"

env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/install.out"

check "nested .agents installation updates itself" test -f "$INSTALL/runtime.txt"
check "updater does not create a second .claude installation" test ! -e "$TARGET/.claude"
check "unverifiable destination-only runtime is preserved conservatively" test -f "$INSTALL/stale-runtime.txt"
check "newly introduced automation config is installed" \
  cmp -s "$UPSTREAM/config/automation.config.json" "$INSTALL/config/automation.config.json"
check "installed ownership manifest is created" test -f "$INSTALL/.startup-factory-owned-files"
check "installed ownership hashes are created" test -f "$INSTALL/.startup-factory-owned-hashes"
check "source-managed provenance records the resolved commit" \
  grep -Fqx \
    "{\"schemaVersion\":1,\"name\":\"startup-factory\",\"sourceCommit\":\"$V1_COMMIT\"}" \
    "$INSTALL/.startup-factory-source-install.json"
check "generated source provenance is not treated as an upstream-owned file" \
  sh -c "! grep -Fqx '.startup-factory-source-install.json' '$INSTALL/.startup-factory-owned-files'"
check "custom adapter survives synchronization" grep -qx 'custom-adapter' "$INSTALL/adapters/Acme.md"
check "custom tracker backend survives synchronization" grep -qx 'custom-backend' "$INSTALL/extensions/tracker-backends/Acme.py"
check "custom team survives synchronization" grep -qx 'custom-team' "$INSTALL/teams/acme.md"
check "custom team role survives synchronization" grep -qx 'custom-role' "$INSTALL/teams/roles/acme-specialist.md"
check "custom team command survives synchronization" grep -qx 'custom-command' "$INSTALL/teams/commands/acme-command.md"

for name in project-management.config.md planning.config.md team.config.md statuses.config.json deployment.config.json guardrails.config.json; do
  if [ "$name" = "statuses.config.json" ]; then
    check "existing $name is preserved" \
      cmp -s "$TMP/status-board-before-initial.json" "$INSTALL/config/$name"
  else
    check "existing $name is preserved" \
      grep -qx "project-owned:$name" "$INSTALL/config/$name"
  fi
done

write_status_fixture "$INSTALL/config/jira-statuses.config.json" custom
cp "$INSTALL/config/jira-statuses.config.json" "$TMP/custom-board-before.json"
sed 's#STATUS_CONFIG=config/statuses.config.json#STATUS_CONFIG=config/jira-statuses.config.json#' \
  "$INSTALL/config/project-management.config.md" > "$TMP/project-management.config.md"
mv "$TMP/project-management.config.md" "$INSTALL/config/project-management.config.md"
printf 'pattern-adapter\n' > "$INSTALL/adapters/[special].md"
printf 'adapters/Acme.md\n' >> "$INSTALL/.startup-factory-owned-files"
env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/conservative-update.out"
check "configured custom STATUS_CONFIG survives synchronization" \
  cmp -s "$TMP/custom-board-before.json" "$INSTALL/config/jira-statuses.config.json"
check "extension names containing rsync pattern characters survive" \
  grep -qx 'pattern-adapter' "$INSTALL/adapters/[special].md"
check "an ownership path without a verified hash cannot delete a project file" \
  grep -qx 'custom-adapter' "$INSTALL/adapters/Acme.md"
check "a repaired ownership manifest drops a false project-owned path" \
  sh -c "! grep -Fqx 'adapters/Acme.md' '$INSTALL/.startup-factory-owned-files'"

(cd "$TARGET" && \
  env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$ROOT/bin/update-installed-skill.sh" --dry-run > "$TMP/source-autodetect.out")
CANONICAL_INSTALL="$(cd "$INSTALL" && pwd -P)"
check "source-mode invocation detects the existing .agents installation" \
  grep -q "Previewed Startup Factory changes for: $CANONICAL_INSTALL" "$TMP/source-autodetect.out"
check "source-mode detection does not create a second .claude installation" \
  test ! -e "$TARGET/.claude"

printf 'project-future-adapter\n' > "$INSTALL/adapters/Future.md"
printf 'upstream-future-adapter\n' > "$UPSTREAM/adapters/Future.md"
git -C "$UPSTREAM" add .
git -C "$UPSTREAM" commit -qm fixture-extension-collision
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/collision.out" 2>&1; then
  echo "FAIL: new upstream extension overwrote a project-owned path"
  FAILURES=$((FAILURES + 1))
elif grep -q 'new upstream path collides with project-owned path: adapters/Future.md' "$TMP/collision.out" && \
    grep -qx 'project-future-adapter' "$INSTALL/adapters/Future.md"; then
  echo "ok: new upstream extension collision fails before mutation"
else
  echo "FAIL: new upstream extension collision produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi
rm "$UPSTREAM/adapters/Future.md"

mkdir -p "$INSTALL/adapters/OwnedDir"
printf 'project-owned-child\n' > "$INSTALL/adapters/OwnedDir/custom.md"
printf 'upstream-file\n' > "$UPSTREAM/adapters/OwnedDir"
git -C "$UPSTREAM" add .
git -C "$UPSTREAM" commit -qm fixture-ancestor-collision
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/ancestor-collision.out" 2>&1; then
  echo "FAIL: upstream file replaced a project-owned directory"
  FAILURES=$((FAILURES + 1))
elif grep -q 'upstream file collides with project-owned directory: adapters/OwnedDir/custom.md' \
      "$TMP/ancestor-collision.out" && \
    grep -qx 'project-owned-child' "$INSTALL/adapters/OwnedDir/custom.md"; then
  echo "ok: ancestor collision fails before installation mutation"
else
  echo "FAIL: ancestor collision produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi
rm "$UPSTREAM/adapters/OwnedDir"

printf 'runtime-v2\n' > "$UPSTREAM/runtime-v2.txt"
printf 'upstream-adapter-v2\n' > "$UPSTREAM/adapters/BuiltIn.md"
rm "$UPSTREAM/adapters/Retired.md"
for name in "${CONFIG_FILES[@]}"; do
  printf 'upstream-v2:%s\n' "$name" > "$UPSTREAM/config/$name"
done
write_status_fixture "$UPSTREAM/config/statuses.config.json" v2
printf '%s\n' \
  'PRODUCT_MANAGEMENT_TOOL=BuiltIn' \
  'STATUS_CONFIG=config/statuses.config.json' \
  'upstream-v2:project-management.config.md' \
  > "$UPSTREAM/config/project-management.config.md"
git -C "$UPSTREAM" add .
git -C "$UPSTREAM" commit -qm fixture-v2
V2_COMMIT="$(git -C "$UPSTREAM" rev-parse HEAD)"

before_configs="$TMP/before-configs"
mkdir -p "$before_configs"
cp "$INSTALL"/config/* "$before_configs"/
cp "$INSTALL/.startup-factory-source-install.json" "$TMP/provenance-before-dry-run.json"
env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$INSTALL/bin/update-installed-skill.sh" --dry-run > "$TMP/dry-run.out"

check "dry-run reports a new runtime file" grep -q 'runtime-v2.txt' "$TMP/dry-run.out"
check "dry-run reports a planned change count" grep -Eq 'Planned filesystem changes: [1-9][0-9]*' "$TMP/dry-run.out"
check "dry-run does not install the new runtime file" test ! -e "$INSTALL/runtime-v2.txt"
check "dry-run leaves source provenance byte-identical" \
  cmp -s "$TMP/provenance-before-dry-run.json" "$INSTALL/.startup-factory-source-install.json"
for name in "${CONFIG_FILES[@]}"; do
  check "dry-run leaves $name byte-identical" \
    cmp -s "$before_configs/$name" "$INSTALL/config/$name"
done

env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/update.out"
check "real update installs the new runtime file" test -f "$INSTALL/runtime-v2.txt"
check "upstream-owned adapter is updated" grep -qx 'upstream-adapter-v2' "$INSTALL/adapters/BuiltIn.md"
check "retired upstream adapter is deleted" test ! -e "$INSTALL/adapters/Retired.md"
check "real update reports its filesystem change count" \
  grep -Eq 'Applied filesystem changes: [1-9][0-9]*' "$TMP/update.out"
check "real update refreshes deterministic source provenance" \
  grep -Fqx \
    "{\"schemaVersion\":1,\"name\":\"startup-factory\",\"sourceCommit\":\"$V2_COMMIT\"}" \
    "$INSTALL/.startup-factory-source-install.json"
for name in "${CONFIG_FILES[@]}"; do
  check "real update still preserves $name" \
    cmp -s "$before_configs/$name" "$INSTALL/config/$name"
done

INVALID_BOARD_INSTALL="$TARGET/.agents/skills/invalid-board-startup-factory"
cp -R "$INSTALL" "$INVALID_BOARD_INSTALL"
printf 'not-json\n' > "$INVALID_BOARD_INSTALL/config/jira-statuses.config.json"
cp "$INVALID_BOARD_INSTALL/runtime-v2.txt" "$TMP/runtime-before-invalid-board"
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$INVALID_BOARD_INSTALL/bin/update-installed-skill.sh" \
      > "$TMP/invalid-board.out" 2>&1; then
  echo "FAIL: update accepted an invalid configured status board"
  FAILURES=$((FAILURES + 1))
elif grep -q 'staged STATUS_CONFIG is incompatible: cannot load JSON:' \
      "$TMP/invalid-board.out" && \
    cmp -s "$TMP/runtime-before-invalid-board" "$INVALID_BOARD_INSTALL/runtime-v2.txt" && \
    grep -qx 'not-json' "$INVALID_BOARD_INSTALL/config/jira-statuses.config.json"; then
  echo "ok: invalid configured status board is rejected readably before mutation"
else
  echo "FAIL: invalid configured status board produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi

cp "$UPSTREAM/adapters/BuiltIn.md" "$TMP/BuiltIn.md"
rm "$UPSTREAM/adapters/BuiltIn.md"
git -C "$UPSTREAM" add .
git -C "$UPSTREAM" commit -qm fixture-missing-selected-adapter
cp "$INSTALL/runtime-v2.txt" "$TMP/runtime-before-missing-adapter"
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/missing-adapter.out" 2>&1; then
  echo "FAIL: update removed the selected project-management adapter"
  FAILURES=$((FAILURES + 1))
elif grep -q 'selected project-management adapter is missing from the staged update' \
      "$TMP/missing-adapter.out" && \
    cmp -s "$TMP/runtime-before-missing-adapter" "$INSTALL/runtime-v2.txt" && \
    test -f "$INSTALL/adapters/BuiltIn.md"; then
  echo "ok: missing selected adapter is rejected before installation mutation"
else
  echo "FAIL: missing selected adapter produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi
cp "$TMP/BuiltIn.md" "$UPSTREAM/adapters/BuiltIn.md"
git -C "$UPSTREAM" add .
git -C "$UPSTREAM" commit -qm fixture-restore-selected-adapter

env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" \
  bash "$INSTALL/bin/update-installed-skill.sh" \
    --ref "$V2_COMMIT" --dry-run > "$TMP/commit-ref.out"
check "an exact commit is accepted by --ref" grep -q 'Previewed Startup Factory changes' "$TMP/commit-ref.out"

env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$INSTALL/bin/update-installed-skill.sh" --overwrite-config > "$TMP/overwrite.out"
for name in "${CONFIG_FILES[@]}"; do
  check "overwrite-config replaces $name" \
    cmp -s "$UPSTREAM/config/$name" "$INSTALL/config/$name"
done
check "overwrite-config still preserves a custom adapter" grep -qx 'custom-adapter' "$INSTALL/adapters/Acme.md"
check "overwrite-config still preserves a custom tracker backend" grep -qx 'custom-backend' "$INSTALL/extensions/tracker-backends/Acme.py"
check "overwrite-config still preserves a custom team" grep -qx 'custom-team' "$INSTALL/teams/acme.md"

if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$ROOT/bin/update-installed-skill.sh" \
      --install-dir "$TARGET" > "$TMP/git-root.out" 2>&1; then
  echo "FAIL: Git repository root was accepted as an install destination"
  FAILURES=$((FAILURES + 1))
elif grep -q 'refusing to install at a Git repository root' "$TMP/git-root.out"; then
  echo "ok: Git repository root is rejected"
else
  echo "FAIL: Git repository root produced the wrong error"
  FAILURES=$((FAILURES + 1))
fi

UNRELATED="$TMP/unrelated"
mkdir -p "$UNRELATED"
printf 'keep-me\n' > "$UNRELATED/sentinel.txt"
cp "$UPSTREAM/SKILL.md" "$UNRELATED/SKILL.md"
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$ROOT/bin/update-installed-skill.sh" \
      --install-dir "$UNRELATED" > "$TMP/unrelated.out" 2>&1; then
  echo "FAIL: unrelated non-empty destination was accepted"
  FAILURES=$((FAILURES + 1))
elif grep -q 'neither a complete installation nor a SKILL.md-only repair target' "$TMP/unrelated.out" && \
    grep -qx 'keep-me' "$UNRELATED/sentinel.txt"; then
  echo "ok: unrelated non-empty destination is rejected without mutation"
else
  echo "FAIL: unrelated destination produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi

MISSING_BUILTIN_UPSTREAM="$TMP/missing-builtin-upstream"
git clone -q "$UPSTREAM" "$MISSING_BUILTIN_UPSTREAM"
git -C "$MISSING_BUILTIN_UPSTREAM" config user.email test@example.com
git -C "$MISSING_BUILTIN_UPSTREAM" config user.name Test
git -C "$MISSING_BUILTIN_UPSTREAM" rm -q adapters/Jira.md
git -C "$MISSING_BUILTIN_UPSTREAM" commit -qm missing-jira-adapter
cp "$INSTALL/runtime-v2.txt" "$TMP/runtime-before-missing-builtin"
if env STARTUP_FACTORY_REMOTE_URL="$MISSING_BUILTIN_UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/missing-builtin.out" 2>&1; then
  echo "FAIL: source missing a shipped tracker adapter was accepted"
  FAILURES=$((FAILURES + 1))
elif grep -q 'bundle is incomplete: missing adapters/Jira.md' "$TMP/missing-builtin.out" && \
    cmp -s "$TMP/runtime-before-missing-builtin" "$INSTALL/runtime-v2.txt"; then
  echo "ok: source missing a shipped tracker adapter is rejected before mutation"
else
  echo "FAIL: missing shipped tracker adapter produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi

INCOMPLETE_UPSTREAM="$TMP/incomplete-upstream"
mkdir -p "$INCOMPLETE_UPSTREAM"
git -C "$INCOMPLETE_UPSTREAM" init -q -b main
git -C "$INCOMPLETE_UPSTREAM" config user.email test@example.com
git -C "$INCOMPLETE_UPSTREAM" config user.name Test
printf '%s\n' '---' 'name: startup-factory' 'description: Incomplete fixture.' '---' > "$INCOMPLETE_UPSTREAM/SKILL.md"
git -C "$INCOMPLETE_UPSTREAM" add .
git -C "$INCOMPLETE_UPSTREAM" commit -qm incomplete-fixture
cp "$INSTALL/runtime-v2.txt" "$TMP/runtime-before-invalid"
if env STARTUP_FACTORY_REMOTE_URL="$INCOMPLETE_UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/invalid-source.out" 2>&1; then
  echo "FAIL: incomplete source bundle was accepted"
  FAILURES=$((FAILURES + 1))
elif grep -q 'bundle is incomplete' "$TMP/invalid-source.out" && \
    cmp -s "$TMP/runtime-before-invalid" "$INSTALL/runtime-v2.txt"; then
  echo "ok: incomplete source bundle is rejected before destination mutation"
else
  echo "FAIL: incomplete source bundle produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi

SYMLINK_CONFIG_INSTALL="$TARGET/.agents/skills/symlink-config-startup-factory"
CENTRAL_CONFIG="$TMP/central-config"
cp -R "$INSTALL" "$SYMLINK_CONFIG_INSTALL"
mv "$SYMLINK_CONFIG_INSTALL/config" "$CENTRAL_CONFIG"
ln -s "$CENTRAL_CONFIG" "$SYMLINK_CONFIG_INSTALL/config"
cp "$CENTRAL_CONFIG/project-management.config.md" "$TMP/pm-before-symlink"
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$SYMLINK_CONFIG_INSTALL/bin/update-installed-skill.sh" \
      > "$TMP/symlink-config.out" 2>&1; then
  echo "FAIL: updater replaced a symlinked config directory"
  FAILURES=$((FAILURES + 1))
elif grep -q 'existing installation contains a symlink' "$TMP/symlink-config.out" && \
    test -L "$SYMLINK_CONFIG_INSTALL/config" && \
    cmp -s "$TMP/pm-before-symlink" "$CENTRAL_CONFIG/project-management.config.md"; then
  echo "ok: symlinked config directory is rejected without changing project settings"
else
  echo "FAIL: symlinked config directory produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi

TRANSACTION_INSTALL="$TARGET/.agents/skills/transaction-startup-factory"
cp -R "$INSTALL" "$TRANSACTION_INSTALL"
cp "$TRANSACTION_INSTALL/runtime-v2.txt" "$TMP/runtime-before-rsync-failure"
FAKE_BIN="$TMP/fake-bin"
mkdir -p "$FAKE_BIN"
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -eu' \
  'for last_arg in "$@"; do' \
  '  :' \
  'done' \
  'stage_target="${last_arg%/}"' \
  'mkdir -p "$stage_target"' \
  'printf "partial-stage\\n" > "$stage_target/runtime-v2.txt"' \
  'exit 23' \
  > "$FAKE_BIN/rsync"
chmod 755 "$FAKE_BIN/rsync"
if env PATH="$FAKE_BIN:$PATH" STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$TRANSACTION_INSTALL/bin/update-installed-skill.sh" \
      > "$TMP/rsync-failure.out" 2>&1; then
  echo "FAIL: injected rsync failure unexpectedly succeeded"
  FAILURES=$((FAILURES + 1))
elif cmp -s "$TMP/runtime-before-rsync-failure" "$TRANSACTION_INSTALL/runtime-v2.txt" && \
    test ! -e "$TARGET/.agents/skills/.transaction-startup-factory.startup-factory.lock" && \
    test -z "$(find "$TARGET/.agents/skills" -maxdepth 1 \
      \( -name '.transaction-startup-factory.stage.*' \
         -o -name '.transaction-startup-factory.backup.*' \) -print -quit)"; then
  echo "ok: failed staging leaves the original installation intact and cleans up"
else
  echo "FAIL: failed staging changed the installation or left transaction debris"
  FAILURES=$((FAILURES + 1))
fi

RACE_INSTALL="$TARGET/.agents/skills/race-startup-factory"
cp -R "$INSTALL" "$RACE_INSTALL"
cp "$RACE_INSTALL/runtime-v2.txt" "$TMP/runtime-before-config-race"
RACE_BIN="$TMP/race-bin"
mkdir -p "$RACE_BIN"
REAL_RSYNC="$(command -v rsync)"
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -eu' \
  'printf "\\nCONCURRENT_EDIT=true\\n" >> "$RACE_CONFIG"' \
  'exec "$REAL_RSYNC" "$@"' \
  > "$RACE_BIN/rsync"
chmod 755 "$RACE_BIN/rsync"
if env PATH="$RACE_BIN:$PATH" REAL_RSYNC="$REAL_RSYNC" \
    RACE_CONFIG="$RACE_INSTALL/config/project-management.config.md" \
    STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$RACE_INSTALL/bin/update-installed-skill.sh" \
      > "$TMP/config-race.out" 2>&1; then
  echo "FAIL: concurrent project-management edit was silently replaced"
  FAILURES=$((FAILURES + 1))
elif grep -q 'installation changed while the update was staged' "$TMP/config-race.out" && \
    grep -qx 'CONCURRENT_EDIT=true' "$RACE_INSTALL/config/project-management.config.md" && \
    cmp -s "$TMP/runtime-before-config-race" "$RACE_INSTALL/runtime-v2.txt" && \
    test ! -e "$TARGET/.agents/skills/.race-startup-factory.startup-factory.lock"; then
  echo "ok: concurrent project-management edits abort activation and remain intact"
else
  echo "FAIL: concurrent project-management edit handling produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi

LOCKED_INSTALL="$TARGET/.agents/skills/locked-startup-factory"
cp -R "$INSTALL" "$LOCKED_INSTALL"
EXISTING_LOCK="$TARGET/.agents/skills/.locked-startup-factory.startup-factory.lock"
mkdir "$EXISTING_LOCK"
printf 'first-updater\n' > "$EXISTING_LOCK/owner"
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$LOCKED_INSTALL/bin/update-installed-skill.sh" \
      > "$TMP/existing-lock.out" 2>&1; then
  echo "FAIL: updater ignored an existing installation lock"
  FAILURES=$((FAILURES + 1))
elif grep -q 'another updater is already running or a stale lock exists' \
      "$TMP/existing-lock.out" && \
    grep -qx 'first-updater' "$EXISTING_LOCK/owner"; then
  echo "ok: a competing updater cannot remove or bypass the existing lock"
else
  echo "FAIL: existing installation lock handling produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi
rm -rf "$EXISTING_LOCK"

printf '%s\n' '{"schemaVersion":1,"name":"startup-factory"}' \
  > "$INSTALL/.startup-factory-install.json"
printf '%s\n' '{"schemaVersion":1,"name":"startup-factory"}' \
  > "$INSTALL/.startup-factory-bundle.json"
cp "$INSTALL/runtime-v2.txt" "$TMP/runtime-before-release-managed"
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/release-managed.out" 2>&1; then
  echo "FAIL: legacy updater accepted a release-managed installation"
  FAILURES=$((FAILURES + 1))
elif grep -q 'release-managed installation detected' "$TMP/release-managed.out" && \
    cmp -s "$TMP/runtime-before-release-managed" "$INSTALL/runtime-v2.txt" && \
    test -f "$INSTALL/.startup-factory-install.json" && \
    test -f "$INSTALL/.startup-factory-bundle.json" && \
    ! grep -q '^Fetching ' "$TMP/release-managed.out"; then
  echo "ok: legacy updater refuses release-managed installs without changing provenance"
else
  echo "FAIL: release-managed refusal produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi

mkdir -p "$TMP/real-destination"
ln -s "$TMP/real-destination" "$TARGET/symlink-install"
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$ROOT/bin/update-installed-skill.sh" \
      --install-dir "$TARGET/symlink-install" > "$TMP/symlink.out" 2>&1; then
  echo "FAIL: symlink install destination was accepted"
  FAILURES=$((FAILURES + 1))
elif grep -q 'install directory must not be a symlink' "$TMP/symlink.out"; then
  echo "ok: symlink install destination is rejected"
else
  echo "FAIL: symlink destination produced the wrong error"
  FAILURES=$((FAILURES + 1))
fi

echo "---"
if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES updater test(s) failed"
  exit 1
fi
echo "ALL PASS"
