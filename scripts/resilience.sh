#!/usr/bin/env bash
# Failure / restart resilience on a running project with login (default: the one `KEEP=1 scripts/e2e-fresh.sh auth`
# leaves): each of loki / prometheus / authelia / mask-api / notify-relay is stopped alone -> the screens' APIs fail in
# the way the screen turns DEGRADED / STALE (an error, never an empty 200) or fail closed (Authelia) -> started again ->
# everything answers again by itself. Optional host-reboot equivalent: REBOOT_CMD (e.g. "sudo systemctl restart docker",
# Docker Desktop: "docker desktop restart") -> every container back by its restart policy -> tools check all OK.
#   scripts/resilience.sh [project [tree]]   default obs-e2e-auth in ${E2E_DIR:-${TMPDIR:-/tmp}/obs-e2e}/auth
#   Env: E2E_DIR, REBOOT_CMD. The project is never taken from COMPOSE_PROJECT_NAME: it stops services one by one, so a
#   running installation (yamaha-observatory-trial / -testbed) is used only when it is named here explicitly.
#   REBOOT_CMD: on Linux "sudo systemctl restart docker" (or a real reboot by hand); never "docker desktop restart"
#   (on Docker Desktop 4.55 it left the engine unable to start).
set -u
. "$(dirname "$0")/lib.sh"
export COMPOSE_PROJECT_NAME="${1:-obs-e2e-auth}"
export DC_DIR="${2:-${E2E_DIR:-${TMPDIR:-/tmp}/obs-e2e}/auth}"
[ -f "$DC_DIR/e2e.env" ] || die "$DC_DIR/e2e.env missing (the URL and test users of an e2e-fresh.sh run): KEEP=1 scripts/e2e-fresh.sh auth"
set -a; . "$DC_DIR/e2e.env"; set +a
CA="$DC_DIR/root.crt"
P_PROM='/prom/api/v1/query?query=up'
P_LOKI='/loki/loki/api/v1/query_range?query=%7Bjob%3D%22syslog%22%7D&limit=1'
rc=0

# -> "login=<st> root=<st> prom=<st> loki=<st>"
codes() {
  "$PY" "$ROOT/scripts/probe.py" status --url "$E2E_URL" --ca "$CA" / "$P_PROM" "$P_LOKI" 2>/dev/null |
    awk '$1 == "login" { l = $2 } $1 == "/" { r = $2 } index($1, "/prom/") == 1 { p = $2 } index($1, "/loki/") == 1 { k = $2 }
         END { printf "login=%s root=%s prom=%s loki=%s", l, r, p, k }'
}

# poll until the codes match the extended regex $2 (max $1 s) -> the last codes on stdout, status 0 / 1
until_codes() {
  local t0 c; t0=$(date +%s)
  while :; do
    c="$(codes)"
    if printf '%s' "$c" | grep -Eq "$2"; then printf '%s' "$c"; return 0; fi
    [ $(( $(date +%s) - t0 )) -ge "$1" ] && { printf '%s' "$c"; return 1; }
    sleep 3
  done
}

verdict() {  # name ok detail
  if [ "$2" = 0 ]; then printf '[OK] %s  (%s)\n' "$1" "$3"; else printf '[NG] %s  (%s)\n' "$1" "$3"; rc=1; fi
}

ALL_OK='login=200 root=200 prom=200 loki=200'
c="$(until_codes 30 "$ALL_OK")"; verdict "before: all answer" $? "$c"
# service | what the screens must see while it is down (an error status where the screen marks the source failed)
while read -r svc want; do
  dc stop "$svc" >/dev/null 2>&1
  c="$(until_codes 60 "$want")"; verdict "$svc stopped -> $want" $? "$c"
  if [ "$svc" = notify-relay ]; then
    out="$(dc run --rm -T tools check --syslog-wait 0 2>&1)"
    printf '%s' "$out" | grep -Eq 'notify-relay +\| NG'; verdict "notify-relay stopped -> tools check NG for it" $? "$(printf '%s' "$out" | grep -E 'notify-relay' | head -1)"
  fi
  dc start "$svc" >/dev/null 2>&1
  c="$(until_codes 180 "$ALL_OK")"; verdict "$svc started -> back by itself" $? "$c"
done <<'EOF'
loki login=200 root=200 prom=200 loki=5[0-9][0-9]
prometheus login=200 root=200 prom=5[0-9][0-9] loki=200
mask-api login=200 root=200 prom=5[0-9][0-9] loki=5[0-9][0-9]
authelia login=(0|5[0-9][0-9]) root=(0|5[0-9][0-9]|302|401)
notify-relay login=200 root=200 prom=200 loki=200
EOF
if [ -n "${REBOOT_CMD:-}" ]; then
  log "host restart equivalent: $REBOOT_CMD"
  before="$(dc ps -q | xargs docker inspect -f '{{.Name}} {{.State.StartedAt}}' | sort)"
  eval "$REBOOT_CMD"
  for _ in $(seq 120); do docker info >/dev/null 2>&1 && break; sleep 5; done
  wait_healthy 900; verdict "after the restart: every service healthy again (restart: unless-stopped)" $? "$(dc ps --format '{{.Service}}:{{.Health}}' | tr '\n' ' ')"
  after="$(dc ps -q | xargs docker inspect -f '{{.Name}} {{.State.StartedAt}}' | sort)"
  [ "$before" != "$after" ]; verdict "containers were really restarted" $? "$(printf '%s\n' "$after" | wc -l) containers"
  c="$(until_codes 180 "$ALL_OK")"; verdict "after the restart: screens answer" $? "$c"
  dc run --rm -T tools check --syslog-wait 30 >/dev/null 2>&1; verdict "after the restart: tools check all OK" $? ""
fi
exit "$rc"
