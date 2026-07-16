#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
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
for required_file in \
  adapters/_TEMPLATE.md \
  bin/dispatch.sh \
  bin/launch-team.sh \
  bin/superpowers-planning.py \
  bin/pm-agent.py \
  bin/policy-check.py \
  bin/release-feature.py \
  bin/runtime-state.py \
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
for directory in tests; do
  printf 'fixture\n' > "$UPSTREAM/$directory/.fixture"
done

CONFIG_FILES=(
  project-management.config.md
  planning.config.md
  team.config.md
  statuses.config.json
  automation.config.json
  deployment.config.json
  guardrails.config.json
)
for name in "${CONFIG_FILES[@]}"; do
  printf 'upstream-v1:%s\n' "$name" > "$UPSTREAM/config/$name"
done

git -C "$UPSTREAM" add .
git -C "$UPSTREAM" commit -qm fixture-v1

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

env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/install.out"

check "nested .agents installation updates itself" test -f "$INSTALL/runtime.txt"
check "updater does not create a second .claude installation" test ! -e "$TARGET/.claude"
check "stale upstream-owned runtime is deleted" test ! -e "$INSTALL/stale-runtime.txt"
check "newly introduced automation config is installed" \
  cmp -s "$UPSTREAM/config/automation.config.json" "$INSTALL/config/automation.config.json"
check "installed ownership manifest is created" test -f "$INSTALL/.startup-factory-owned-files"
check "custom adapter survives synchronization" grep -qx 'custom-adapter' "$INSTALL/adapters/Acme.md"
check "custom tracker backend survives synchronization" grep -qx 'custom-backend' "$INSTALL/extensions/tracker-backends/Acme.py"
check "custom team survives synchronization" grep -qx 'custom-team' "$INSTALL/teams/acme.md"
check "custom team role survives synchronization" grep -qx 'custom-role' "$INSTALL/teams/roles/acme-specialist.md"
check "custom team command survives synchronization" grep -qx 'custom-command' "$INSTALL/teams/commands/acme-command.md"

for name in project-management.config.md planning.config.md team.config.md statuses.config.json deployment.config.json guardrails.config.json; do
  check "existing $name is preserved" \
    grep -qx "project-owned:$name" "$INSTALL/config/$name"
done

printf 'project-future-adapter\n' > "$INSTALL/adapters/Future.md"
printf 'upstream-future-adapter\n' > "$UPSTREAM/adapters/Future.md"
git -C "$UPSTREAM" add .
git -C "$UPSTREAM" commit -qm fixture-extension-collision
if env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
    bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/collision.out" 2>&1; then
  echo "FAIL: new upstream extension overwrote a project-owned path"
  FAILURES=$((FAILURES + 1))
elif grep -q 'new upstream extension collides with project-owned path: adapters/Future.md' "$TMP/collision.out" && \
    grep -qx 'project-future-adapter' "$INSTALL/adapters/Future.md"; then
  echo "ok: new upstream extension collision fails before mutation"
else
  echo "FAIL: new upstream extension collision produced the wrong result"
  FAILURES=$((FAILURES + 1))
fi
rm "$UPSTREAM/adapters/Future.md"

printf 'runtime-v2\n' > "$UPSTREAM/runtime-v2.txt"
printf 'upstream-adapter-v2\n' > "$UPSTREAM/adapters/BuiltIn.md"
rm "$UPSTREAM/adapters/Retired.md"
for name in "${CONFIG_FILES[@]}"; do
  printf 'upstream-v2:%s\n' "$name" > "$UPSTREAM/config/$name"
done
git -C "$UPSTREAM" add .
git -C "$UPSTREAM" commit -qm fixture-v2
V2_COMMIT="$(git -C "$UPSTREAM" rev-parse HEAD)"

before_configs="$TMP/before-configs"
mkdir -p "$before_configs"
cp "$INSTALL"/config/* "$before_configs"/
env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$INSTALL/bin/update-installed-skill.sh" --dry-run > "$TMP/dry-run.out"

check "dry-run reports a new runtime file" grep -q 'runtime-v2.txt' "$TMP/dry-run.out"
check "dry-run does not install the new runtime file" test ! -e "$INSTALL/runtime-v2.txt"
for name in "${CONFIG_FILES[@]}"; do
  check "dry-run leaves $name byte-identical" \
    cmp -s "$before_configs/$name" "$INSTALL/config/$name"
done

env STARTUP_FACTORY_REMOTE_URL="$UPSTREAM" STARTUP_FACTORY_REF=main \
  bash "$INSTALL/bin/update-installed-skill.sh" > "$TMP/update.out"
check "real update installs the new runtime file" test -f "$INSTALL/runtime-v2.txt"
check "upstream-owned adapter is updated" grep -qx 'upstream-adapter-v2' "$INSTALL/adapters/BuiltIn.md"
check "retired upstream adapter is deleted" test ! -e "$INSTALL/adapters/Retired.md"
for name in "${CONFIG_FILES[@]}"; do
  check "real update still preserves $name" \
    cmp -s "$before_configs/$name" "$INSTALL/config/$name"
done

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
