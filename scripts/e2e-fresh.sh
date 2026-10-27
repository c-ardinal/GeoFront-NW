#!/usr/bin/env bash
# New installation from scratch, end to end, in a throwaway compose project (own name, empty volumes, other ports):
# a `git clone`-like copy of this tree -> tools init (non-interactive) -> [user add] -> scripts/doctor.sh ->
# up --profile prod + testbed (simulated devices instead of the real ones) -> tools check all OK -> doctor again ->
# scripts/probe.py (command-center, APIs, Grafana admin; with login: HTTPS with the new CA, roles).
#   scripts/e2e-fresh.sh open            127.0.0.1, no login
#   scripts/e2e-fresh.sh auth            login: OBS_AUTH=1 on 127.0.0.1, or E2E_LAN_IP=<this host's LAN IP> for a LAN bind
# Env: E2E_DIR (where the copies go, default ${TMPDIR:-/tmp}/obs-e2e), KEEP=1 leaves the project running (for
# scripts/resilience.sh / scripts/backup-restore.sh), otherwise it is removed with `down -v` (its own volumes only).
# Secrets are random per run and stay in the copy's .env (outside the repository).
set -u
. "$(dirname "$0")/lib.sh"
MODE="${1:-open}"
case "$MODE" in
  open) N=2; OBS_PORT=28080 ;;
  auth) N=3; OBS_PORT=38080 ;;
  *) die "usage: $0 open|auth" ;;
esac
export COMPOSE_PROJECT_NAME="obs-e2e-$MODE"
export DC_DIR="${E2E_DIR:-${TMPDIR:-/tmp}/obs-e2e}/$MODE"
E="$DC_DIR/e2e.env"  # this run's secrets for the other scripts (outside the repository)

down_project "$COMPOSE_PROJECT_NAME"
copy_tree "$DC_DIR" || die "copy"
trap '[ "${KEEP:-0}" = 1 ] || down_project "$COMPOSE_PROJECT_NAME"' EXIT  # also on a failure: no stack left behind
GF="e2e-gf-$(rand)"; AU="e2e-auth-$(rand)"; PV="e2e-priv-$(rand)"; CM="e2e-c-$(rand 6)"
ADMIN="e2eadmin:E2e-admin-$(rand)"; VIEWER="e2eview:E2e-view-$(rand)"
RTX="$COMPOSE_PROJECT_NAME-rtx"; WLX="$COMPOSE_PROJECT_NAME-wlx"
bind=(); url="http://127.0.0.1:$OBS_PORT"
if [ "$MODE" = auth ]; then
  if [ -n "${E2E_LAN_IP:-}" ]; then bind=(--bind "$E2E_LAN_IP"); url="https://$E2E_LAN_IP:$OBS_PORT"
  else bind=(--auth); url="https://127.0.0.1:$OBS_PORT"; fi
fi
log "init ($MODE, $url) in $DC_DIR"
dc run --rm -T -e GF_ADMIN_PASSWORD="$GF" -e SNMP_V3_AUTH_PASS="$AU" -e SNMP_V3_PRIV_PASS="$PV" -e SNMP_COMMUNITY="$CM" \
  tools init --yes --snmp-user obs-e2e --port "$OBS_PORT" --syslog-port "${N}8514" "${bind[@]}" \
  --device "rtx1300,rtx,$RTX:1161" --device "wlx413,wlx,$WLX:1161,yamaha_v2c" --wan rtx1300:lan2 || die "tools init"
# the testbed instead of the real devices, and this project's own names / ports / subnet (next to other stacks)
set_env COMPOSE_PROFILES prod,testbed
set_env COMPOSE_PROJECT_NAME "$COMPOSE_PROJECT_NAME"
set_env TESTBED_RTX_NAME "$RTX"; set_env TESTBED_WLX_NAME "$WLX"
set_env PROM_LOCAL_PORT "${N}8090"; set_env GRAFANA_LOCAL_PORT "${N}8030"
set_env OBS_GRAFANA_NET "172.31.253.$((N * 8))/29"; set_env OBS_GRAFANA_PROXY_IP "172.31.253.$((N * 8 + 2))"
set_env OBS_GRAFANA_NET_DYNAMIC "172.31.253.$((N * 8 + 4))/30"
if [ "${E2E_CAPTURE:-0}" = 1 ]; then
  # + the capture profile on the testbed's own bridge (testbed-traffic -> ring -> flowd -> Prometheus). Linux host only;
  # Docker Desktop / WSL: the host network is a VM's, so only with CAPTURE_ALLOW_VM=1 (the path, not the LAN)
  set_env COMPOSE_PROFILES prod,testbed,capture; set_env OBS_CAPTURE 1
  dc create > "$DC_DIR/create.log" 2>&1 || die "create (log: $DC_DIR/create.log)"
  net="$(docker network inspect -f '{{.Id}}' "${COMPOSE_PROJECT_NAME}_default")" || die "network"
  set_env CAPTURE_IFACE "br-${net:0:12}"
  [ "$(uname -s)" = Linux ] && [ "${E2E_CAPTURE_ALLOW_VM:-0}" != 1 ] || set_env CAPTURE_ALLOW_VM 1
fi
(umask 077; printf 'E2E_URL=%s\nE2E_GF_PW=%s\nE2E_ADMIN=%s\nE2E_VIEWER=%s\n' "$url" "$GF" "$ADMIN" "$VIEWER" > "$E")
if [ "$MODE" = auth ]; then
  dc run --rm -T -e OBS_USER_PASSWORD="${ADMIN#*:}" tools user add "${ADMIN%%:*}" --role admin || die "user add admin"
  dc run --rm -T -e OBS_USER_PASSWORD="${VIEWER#*:}" tools user add "${VIEWER%%:*}" --role viewer || die "user add viewer"
fi
log "doctor (before up)"
bash "$ROOT/scripts/doctor.sh" || die "doctor before up"
log "up --build"
dc up -d --build > "$DC_DIR/up.log" 2>&1 || { tail -n 30 "$DC_DIR/up.log" >&2; die "up (log: $DC_DIR/up.log)"; }
wait_healthy 900 || die "not healthy"
log "tools check"
dc run --rm -T tools check || die "tools check"
log "doctor (running)"
bash "$ROOT/scripts/doctor.sh" || die "doctor running"
if [ "${E2E_CAPTURE:-0}" = 1 ]; then
  log "capture: waiting for flows from the ring (rotation 60 s + FLOWD_DELAY_S 90 s)"
  for _ in $(seq 60); do
    dc exec -T prometheus wget -qO- 'http://127.0.0.1:9090/api/v1/query?query=count(obs_flow_bytes_total)' 2>/dev/null | grep -q '"value"' && break
    sleep 5
  done
  dc exec -T prometheus wget -qO- 'http://127.0.0.1:9090/api/v1/query?query=count(obs_flow_bytes_total)' | grep -q '"value"' || die "no flows from capture"
  dc run --rm -T tools capture status || die "capture status"
  log "OK: capture -> flowd -> Prometheus"
fi
ca=()
if [ "$MODE" = auth ]; then
  dc cp proxy:/data/caddy/pki/authorities/local/root.crt "$DC_DIR/root.crt" || die "root.crt"
  ca=(--ca "$DC_DIR/root.crt")
fi
log "probe $url"
E2E_GF_PW="$GF" E2E_ADMIN="$ADMIN" E2E_VIEWER="$VIEWER" "$PY" "$ROOT/scripts/probe.py" screens --url "$url" "${ca[@]}" || die "probe"
if [ "${KEEP:-0}" = 1 ]; then
  log "OK: kept running ($COMPOSE_PROJECT_NAME, $DC_DIR)"
else
  log "OK: removing ($COMPOSE_PROJECT_NAME)"
fi
