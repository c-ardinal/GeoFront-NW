#!/usr/bin/env bash
# One command for the checks of this repository; prints a result table (each check's own exit code, log per check).
#   scripts/verify.sh                quick: selftests compose leak-scan doctor
#   scripts/verify.sh full           + e2e-open e2e-auth resilience backup-restore upgrade arm64
#   scripts/verify.sh <check>...     any of the names below
# Checks:
#   selftests       build every self-built image (their build-time selftests) and run each selftest again in a clean container
#   compose         compose config resolves: demo (no .env), testbed/testbed.env, a LAN exposure with login (dummy values),
#                   a config directory outside the tree (OBS_CONFIG_DIR, mounted at /config) and the CI's bake file
#   leak-scan       scripts/leak_scan.py selftest + the working tree (no NG); `scripts/leak-scan.sh --history` separately
#   doctor          scripts/doctor.sh on this tree's .env (needs tools init first; on a fresh clone it says what is missing)
#   e2e-open        scripts/e2e-fresh.sh open   (new install, 127.0.0.1 without login, testbed instead of devices)
#   e2e-auth        scripts/e2e-fresh.sh auth   (with login; E2E_LAN_IP=<LAN IP> for a real LAN bind)
#   resilience      scripts/resilience.sh on the e2e-auth project (REBOOT_CMD for the host-restart equivalent)
#   backup-restore  scripts/backup-restore.sh from the e2e-auth project into a new one
#   upgrade         scripts/upgrade.sh (data volumes of bb2f21d = P6 -> this tree)
#   arm64           scripts/arm64.sh (pulled images' arm64 digests, arm64 builds of tools / flowd / analyzer)
# Throwaway projects are obs-e2e-*, removed with `down -v` at the end; the main project is never touched (only built).
# Env: VERIFY_LOGS (default ${TMPDIR:-/tmp}/obs-verify-<time>), E2E_DIR, E2E_LAN_IP, REBOOT_CMD, ARM64_IMAGES.
set -u
. "$(dirname "$0")/lib.sh"
S="$ROOT/scripts"
case "${1:-quick}" in
  quick) set -- selftests compose leak-scan doctor ;;
  full) set -- selftests compose leak-scan e2e-open e2e-auth resilience backup-restore upgrade arm64 ;;
esac
LOGS="${VERIFY_LOGS:-${TMPDIR:-/tmp}/obs-verify-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$LOGS"
export E2E_DIR="${E2E_DIR:-$LOGS/e2e}"
needs_auth_kept=0
case " $* " in *" resilience "*|*" backup-restore "*) needs_auth_kept=1 ;; esac

selftests() {
  local fail=0 v="${GEOFRONT_VERSION:-local}" g=ghcr.io/c-ardinal/geofront-nw
  dc --profile demo --profile prod --profile testbed --profile capture --profile tools build || return 1
  run1() { local n="$1"; shift; echo "== $n"; docker run --rm "$@"; local r=$?; echo "rc=$r"; [ "$r" = 0 ] || fail=1; }
  run1 mask-api --entrypoint python "$g-mask-api:$v" mask_api.py --selftest
  run1 notify-relay --entrypoint python "$g-notify-relay:$v" relay.py --selftest
  run1 analyzer -e HOME=/tmp --entrypoint python "$g-analyzer:$v" analyzer.py --selftest
  run1 flowd --entrypoint python "$g-flowd:$v" flowd.py --selftest
  run1 demo-gen --entrypoint python "$g-demo-gen:$v" demo_gen.py --selftest
  run1 capture --entrypoint python "$g-capture:$v" capture.py --selftest
  run1 testbed --entrypoint python geofront-nw-testbed:local device.py --selftest
  run1 tools --entrypoint python -v "$ROOT:/selftest:ro" -e OBS_WORK=/selftest -e OBS_CONFIG=/tmp/cfg -e OBS_GENERATED=/tmp/gen \
    -e OBS_VOLUMES=/tmp/vol "$g-tools:$v" /app/obs.py --selftest
  return "$fail"
}

compose_cfg() {
  local f="$LOGS/lan-dummy.env" fail=0
  printf '%s\n' COMPOSE_PROFILES=prod OBS_BIND=192.0.2.10 OBS_PUBLIC_URL=https://192.0.2.10:8080 \
    GF_ADMIN_PASSWORD=dummy-dummy-dummy "OBS_AUTH_SESSION_SECRET=$(rand 48)" "OBS_AUTH_STORAGE_KEY=$(rand 48)" \
    "OBS_AUTH_PROXY_KEY=$(rand 32)" > "$f"
  dc --profile demo config -q && echo "demo OK" || fail=1
  dc --env-file "$ROOT/testbed/testbed.env" config -q && echo "testbed OK" || fail=1
  dc --env-file "$f" config -q && echo "LAN + login OK" || fail=1
  # R1: a config directory outside the tree is what the tools services mount at /config
  mkdir -p "$LOGS/cfg-outside"
  OBS_CONFIG_DIR="$LOGS/cfg-outside" dc --profile tools config 2>/dev/null | grep -qF "source: $LOGS/cfg-outside" \
    && echo "OBS_CONFIG_DIR mount OK" || { echo "NG: OBS_CONFIG_DIR is not mounted at /config"; fail=1; }
  # the testbed's repository files resolve also with a config directory set (/work paths, not /config)
  local inv
  inv="$(OBS_CONFIG_DIR="$LOGS/cfg-outside" dc --env-file "$ROOT/testbed/testbed.env" --profile tools config 2>/dev/null |
    sed -n 's/^ *OBS_INVENTORY: //p' | head -1)"
  case "$inv" in
    /work/*) [ -f "$ROOT/${inv#/work/}" ] && echo "testbed inventory with OBS_CONFIG_DIR OK ($inv)" ||
      { echo "NG: testbed inventory $inv does not exist in the tree"; fail=1; } ;;
    *) echo "NG: testbed inventory '$inv' does not resolve against /work (OBS_CONFIG_DIR set)"; fail=1 ;;
  esac
  docker buildx bake -f "$ROOT/compose.yaml" -f "$ROOT/.github/docker-bake.hcl" --print release > /dev/null && echo "bake OK" || fail=1
  return "$fail"
}

run_check() {
  case "$1" in
    selftests) selftests ;;
    compose) compose_cfg ;;
    leak-scan) "$PY" "$S/leak_scan.py" --selftest && bash "$S/leak-scan.sh" ;;
    doctor) bash "$S/doctor.sh" ;;
    e2e-open) bash "$S/e2e-fresh.sh" open ;;
    e2e-auth) KEEP=$needs_auth_kept bash "$S/e2e-fresh.sh" auth ;;
    resilience) bash "$S/resilience.sh" ;;
    backup-restore) bash "$S/backup-restore.sh" ;;
    upgrade) bash "$S/upgrade.sh" ;;
    arm64) bash "$S/arm64.sh" ;;
    *) echo "unknown check: $1"; return 2 ;;
  esac
}

rows=()
fail=0
for c in "$@"; do
  log "== $c (log: $LOGS/$c.log)"
  t0=$(date +%s)
  run_check "$c" > "$LOGS/$c.log" 2>&1
  r=$?
  [ "$r" = 0 ] || fail=1
  rows+=("$(printf '%-15s | %-3s | %5ss | %s' "$c" "$([ "$r" = 0 ] && echo OK || echo NG)" $(( $(date +%s) - t0 )) "$LOGS/$c.log")")
  grep -E '^\[(NG)\]|NG:' "$LOGS/$c.log" | head -5 >&2
done
if [ "$needs_auth_kept" = 1 ]; then
  down_project obs-e2e-auth
fi
printf '\n%-15s | %-3s | %6s | %s\n' check rc time log
printf '%s\n' "----------------+-----+--------+------------------------------"
printf '%s\n' "${rows[@]}"
exit "$fail"
