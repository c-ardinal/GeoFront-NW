#!/usr/bin/env bash
# Preflight before `docker compose up` (tools doctor with the host's facts): Docker Engine / compose versions, CPU
# architecture, NTP, ports already in use on this host, the leak scan of this tree; then the config location, .env,
# inventory, users, certificate, disk, memory and the
# clock in the tools container. Nothing talks to a device. Exit 1 when anything is NG.
#   scripts/doctor.sh                      (this repository's config: OBS_CONFIG_DIR, else the legacy .env in the tree)
#   DC_DIR=<tree> COMPOSE_PROJECT_NAME=<p> scripts/doctor.sh   (another tree / project: scripts/e2e-fresh.sh)
. "$(dirname "$0")/lib.sh"

command -v docker >/dev/null || die "docker がありません (https://docs.docker.com/engine/install/)"
engine="$(docker version -f '{{.Server.Version}}' 2>/dev/null)" || die "Docker Engine に接続できません (sudo systemctl start docker / docker グループ)"
compose="$(docker compose version --short 2>/dev/null)" || die "docker compose (plugin) がありません (apt install docker-compose-plugin)"
arch="$(docker version -f '{{.Server.Arch}}' 2>/dev/null)"
ntp="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"

args=(-e "OBS_DOCTOR_ENGINE=$engine" -e "OBS_DOCTOR_COMPOSE=$compose" -e "OBS_DOCTOR_ARCH=$arch" -e "OBS_DOCTOR_NTP=$ntp")
# ports this project's running containers publish are its own (not a clash): "tcp:127.0.0.1:8080 ..."
project="${COMPOSE_PROJECT_NAME:-$(dc config 2>/dev/null | sed -n 's/^name: //p' | head -1)}"
own="$(docker ps --filter "label=com.docker.compose.project=$project" --format '{{.Ports}}' 2>/dev/null | sed 's/, /\n/g' |
  sed -nE 's#^(.*):([0-9]+)->[0-9]+/(tcp|udp)$#\3:\1:\2#p' | tr '\n' ' ')"
args+=(-e "OBS_DOCTOR_OWN=$own")
[ -n "${PROM_LOCAL_PORT:-}" ] && args+=(-e "PROM_LOCAL_PORT=$PROM_LOCAL_PORT")  # compose takes it from the shell before .env
# the host's listeners; when no tool can read them OBS_DOCTOR_LISTEN stays unset and doctor says WARN (never "free")
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)  # Git Bash on Windows (Docker Desktop): Windows' netstat
    if out="$(netstat -an 2>/dev/null)" && printf '%s' "$out" | grep -q LISTENING; then
      args+=(-e "OBS_DOCTOR_LISTEN=$(printf '%s\n' "$out" | awk '$1 == "TCP" && $4 == "LISTENING" { printf "tcp:%s ", $2 } $1 == "UDP" { printf "udp:%s ", $2 }')")
    fi ;;
  *)
    if command -v ss >/dev/null && out="$(ss -Hltnu 2>/dev/null)"; then
      args+=(-e "OBS_DOCTOR_LISTEN=$(printf '%s\n' "$out" | awk 'NF { printf "%s:%s ", $1, $5 }') ")
    fi ;;
esac
# data that must never be committed, in this tree (scripts/leak-scan.sh; git is not in the tools image)
tree="${DC_DIR:-$ROOT}"
if [ -n "$PY" ] && [ -e "$tree/.git" ] && command -v git >/dev/null; then
  if out="$("$PY" "$tree/scripts/leak_scan.py" 2>&1)"; then leak=OK
  else leak="NG $(printf '%s\n' "$out" | grep -c '^  NG') 件 (値は scripts/leak-scan.sh で)"; fi
else
  leak="省略 (git の作業ツリーではない、または python3 なし)"
fi
args+=(-e "OBS_DOCTOR_LEAK=$leak")
dc run --rm -T "${args[@]}" tools doctor
