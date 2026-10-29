#!/usr/bin/env bash
# backup -> restore round trip with login, into another project (= another host): users, Authelia's data, the proxy's
# CA (caddy-data: same root certificate, so the devices need no new registration), Prometheus, Loki and
# Alertmanager's silences must be the same afterwards. Source: the project `KEEP=1 scripts/e2e-fresh.sh auth` leaves.
#   scripts/backup-restore.sh        Env: E2E_DIR; KEEP=1 leaves the restored project running; E2E_CONFIG=outside for
#                                    the R1 layout (config in OBS_CONFIG_DIR = <tree>-config on both sides)
# docs/operations.md backup and restore procedure: backup --include-env, stop, restore --with-config --yes, up -d.
set -u
. "$(dirname "$0")/lib.sh"
BASE="${E2E_DIR:-${TMPDIR:-/tmp}/obs-e2e}"
SRC="$BASE/auth"; DST="$BASE/restore"
export COMPOSE_PROJECT_NAME=obs-e2e-auth DC_DIR="$SRC"
# E2E_CONFIG=outside: both "hosts" keep their config in OBS_CONFIG_DIR = <tree>-config (as `E2E_CONFIG=outside e2e-fresh.sh`)
outside=0; [ "${E2E_CONFIG:-tree}" = outside ] && outside=1
[ "$outside" = 1 ] && export OBS_CONFIG_DIR="$SRC-config"
SRC_CFG="$(cfg_dir)"
set -a; . "$SRC/e2e.env"; set +a
[ -n "$(dc ps --status running -q proxy)" ] || die "source project not running: KEEP=1 scripts/e2e-fresh.sh auth"
rc=0
AT=$(( $(date +%s) - 60 ))
state --make-silence "h1 backup check" >/dev/null || die "silence"
dc stop loki alertmanager >/dev/null 2>&1  # flush: Loki's WAL, Alertmanager's silences (stop for an exact copy)
dc start loki alertmanager >/dev/null 2>&1
wait_healthy 300 || die "source not healthy"
before="$(state --at "$AT")" || die "state (source)"
log "source: $before"
out="$(dc run --rm -T tools backup --include-env)" || die "backup: $out"
printf '%s\n' "$out"
arch="$(printf '%s' "$out" | grep -o 'backups/obs-backup-[0-9-]*\.tar\.gz' | head -1)"
[ -n "$arch" ] || die "no archive name"
printf '%s' "$out" | grep -q caddy || { log "NG: caddy (CA) not in the archive"; rc=1; }
dc stop >/dev/null 2>&1  # the source host is gone (its ports are reused by the restored one)

export COMPOSE_PROJECT_NAME=obs-e2e-restore DC_DIR="$DST"
down_project "$COMPOSE_PROJECT_NAME"
copy_tree "$DST" || die "copy"
if [ "$outside" = 1 ]; then
  export OBS_CONFIG_DIR="$DST-config"
  rm -rf "$OBS_CONFIG_DIR" && (umask 077 && mkdir -p "$OBS_CONFIG_DIR") || die "config dir"
fi
DST_CFG="$(cfg_dir)"
trap '[ "${KEEP:-0}" = 1 ] || down_project "$COMPOSE_PROJECT_NAME"' EXIT  # also on a failure: no stack left behind
mkdir -p "$DST_CFG/backups" && cp "$SRC_CFG/$arch" "$DST_CFG/$arch"
log "restore $arch into a new project with empty volumes"
dc run --rm -T tools restore "$arch" --with-config --yes || die "restore"
# the restored .env is the source host's; only this test's project-specific lines differ (both projects on one host)
set_env COMPOSE_PROJECT_NAME "$COMPOSE_PROJECT_NAME"
set_env TESTBED_RTX_NAME obs-e2e-restore-rtx; set_env TESTBED_WLX_NAME obs-e2e-restore-wlx
[ "$outside" = 1 ] && set_env OBS_CONFIG_DIR "$OBS_CONFIG_DIR"  # the restored .env names the source's directory
sed -i "s/obs-e2e-auth-rtx/obs-e2e-restore-rtx/; s/obs-e2e-auth-wlx/obs-e2e-restore-wlx/" "$DST_CFG/inventory/devices.yaml"
dc up -d --build > "$DST/up.log" 2>&1 || { tail -n 30 "$DST/up.log" >&2; die "up"; }
wait_healthy 900 || die "restored not healthy"
after="$(state --at "$AT")" || die "state (restored)"
log "restored: $after"
"$PY" - "$before" "$after" <<'EOF' || rc=1
import json, sys
a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
bad = 0
for k in sorted(a):
    ok = a[k] == b[k] and a[k] not in (None, [], "0") and not str(a[k]).startswith("error")
    bad += not ok
    print(f"[{'OK' if ok else 'NG'}] {k}: {str(a[k])[:60]} -> {str(b[k])[:60]}")
sys.exit(1 if bad else 0)
EOF
dc cp proxy:/data/caddy/pki/authorities/local/root.crt "$DST/root.crt" >/dev/null 2>&1
cmp -s "$SRC/root.crt" "$DST/root.crt"; [ $? = 0 ] && log "OK: same root certificate" || { log "NG: root certificate changed"; rc=1; }
log "the restored screens with the source's root certificate and the same users"
"$PY" "$ROOT/scripts/probe.py" screens --url "$E2E_URL" --ca "$SRC/root.crt" || rc=1
dc run --rm -T tools check --syslog-wait 30 >/dev/null 2>&1 || { log "NG: tools check on the restored project"; rc=1; }
[ "$rc" = 0 ] && log "OK: backup / restore round trip" || log "NG: backup / restore round trip"
exit "$rc"
