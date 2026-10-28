#!/usr/bin/env bash
# Update from an older version's data volumes (README 「更新」): the old version (default bb2f21d = P6) runs on the demo
# profile in a throwaway project until it has data and a silence; then this tree takes over the same volumes with
# `up -d --build --remove-orphans` and the old .env. Checks: tools check all OK, the old metrics / syslog / silence /
# Grafana users unchanged at the same time, the retired grafana-guard container gone, new services (Authelia) up.
#   scripts/upgrade.sh [old-ref]     Env: E2E_DIR (default ${TMPDIR:-/tmp}/obs-e2e); KEEP=1 leaves it running;
#   UPGRADE_MIGRATE=1 (default): then `tools migrate-config` to a config directory outside the tree, up with it, same data
set -u
. "$(dirname "$0")/lib.sh"
OLD="${1:-bb2f21d}"
export COMPOSE_PROJECT_NAME="obs-e2e-upgrade"
BASE="${E2E_DIR:-${TMPDIR:-/tmp}/obs-e2e}"
OLD_DIR="$BASE/upgrade-old"; NEW_DIR="$BASE/upgrade-new"
export DC_DIR="$OLD_DIR"
down_project "$COMPOSE_PROJECT_NAME"
rm -rf "$OLD_DIR" && mkdir -p "$OLD_DIR" && git -C "$ROOT" archive "$OLD" | tar -C "$OLD_DIR" -xf - || die "git archive $OLD"
copy_tree "$NEW_DIR" || die "copy"
trap '[ "${KEEP:-0}" = 1 ] || down_project "$COMPOSE_PROJECT_NAME"' EXIT  # also on a failure: no stack left behind
mkdir -p "$OLD_DIR/scripts" && cp "$ROOT/scripts/state.py" "$OLD_DIR/scripts/"  # the old tree has no scripts/
# demo-gen's fixed host port 127.0.0.1:9116, in both test copies only: the test runs next to a running demo stack
sed -i 's/"127.0.0.1:9116:9116"/"127.0.0.1:49116:9116"/' "$OLD_DIR/compose.yaml" "$NEW_DIR/compose.yaml"
cat > "$OLD_DIR/.env" <<EOF
COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME
COMPOSE_PROFILES=demo
OBS_PORT=48080
PROM_LOCAL_PORT=48090
GRAFANA_LOCAL_PORT=48030
SYSLOG_PORT=48514
GF_ADMIN_PASSWORD=e2e-gf-$(rand)
OBS_GRAFANA_NET=172.31.253.32/29
OBS_GRAFANA_PROXY_IP=172.31.253.34
OBS_GRAFANA_NET_DYNAMIC=172.31.253.36/30
EOF
chmod 600 "$OLD_DIR/.env"
log "old version $OLD: up"
dc up -d --build > "$OLD_DIR/up.log" 2>&1 || { tail -n 30 "$OLD_DIR/up.log" >&2; die "old up"; }
wait_healthy 900 || die "old not healthy"
sleep 120  # a few scrapes and syslog lines to compare
AT=$(( $(date +%s) - 60 ))
state --make-silence "h1 upgrade check" >/dev/null || die "silence on the old version"
sleep 2
dc stop alertmanager >/dev/null 2>&1  # Alertmanager writes its silences to disk on shutdown (else every 15 min)
dc start alertmanager >/dev/null 2>&1; sleep 5
before="$(state --at "$AT")" || die "state (old)"
log "old: $before"
log "update: git pull equivalent (same .env and volumes) -> up -d --build --remove-orphans"
cp "$OLD_DIR/.env" "$NEW_DIR/.env"
export DC_DIR="$NEW_DIR"
export OBS_CONFIG_DIR="$NEW_DIR"  # the legacy layout (config in the tree) until migrate-config below
dc up -d --build --remove-orphans > "$NEW_DIR/up.log" 2>&1 || { tail -n 30 "$NEW_DIR/up.log" >&2; die "new up"; }
wait_healthy 900 || die "new not healthy"
rc=0
dc run --rm -T tools check --syslog-wait 30 || { log "NG: tools check"; rc=1; }
after="$(state --at "$AT")" || die "state (new)"
log "new: $after"
kept() {
  "$PY" - "$1" "$2" <<'EOF'
import json, sys
a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
bad = 0
for k in ("prom_up_samples_10m", "prom_ifHCInOctets", "loki_syslog_lines_10m", "silences", "grafana_users"):
    ok = a[k] == b[k] and a[k] not in (None, [], "0") and not str(a[k]).startswith("error")
    bad += not ok
    print(f"[{'OK' if ok else 'NG'}] {k} kept: {str(a[k])[:60]} -> {str(b[k])[:60]}")
sys.exit(1 if bad else 0)
EOF
}
kept "$before" "$after" || rc=1
if [ "${UPGRADE_MIGRATE:-1}" = 1 ]; then
  # R1: the same installation moves its config out of the tree (tools migrate-config) and keeps its data volumes
  export OBS_CONFIG_DIR="$BASE/upgrade-config"
  rm -rf "$OBS_CONFIG_DIR" && (umask 077 && mkdir -p "$OBS_CONFIG_DIR") || die "config dir"
  log "migrate-config -> $OBS_CONFIG_DIR"
  dc run --rm -T tools migrate-config || die "migrate-config"
  grep -q "^COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME$" "$OBS_CONFIG_DIR/.env" || die "project name not pinned"
  dc up -d --remove-orphans > "$NEW_DIR/up-migrated.log" 2>&1 || { tail -n 30 "$NEW_DIR/up-migrated.log" >&2; die "up (migrated)"; }
  wait_healthy 900 || die "migrated not healthy"
  dc run --rm -T tools check --syslog-wait 30 || { log "NG: tools check (migrated)"; rc=1; }
  migrated="$(state --at "$AT")" || die "state (migrated)"
  log "migrated: $migrated"
  kept "$before" "$migrated" || rc=1
fi
if docker ps -a --format '{{.Names}}' | grep -q "^$COMPOSE_PROJECT_NAME-grafana-guard"; then log "NG: orphan grafana-guard remains"; rc=1
else log "OK: grafana-guard (retired) removed by --remove-orphans"; fi
[ "$(dc ps --status running -q authelia)" ] && log "OK: authelia (new) running" || { log "NG: authelia not running"; rc=1; }
[ "$rc" = 0 ] && log "OK: upgrade from $OLD" || log "NG: upgrade from $OLD"
exit "$rc"
