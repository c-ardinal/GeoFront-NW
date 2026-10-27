# Shared helpers for scripts/*.sh (sourced, bash). Linux (Raspberry Pi) and Git Bash on Windows (Docker Desktop).
#   DC_DIR   the compose project's directory (default: this repository)
#   COMPOSE_PROJECT_NAME  (exported by the caller) another project = other volumes / containers / networks
export MSYS_NO_PATHCONV=1  # Git Bash: pass /work, /vol/... to docker unchanged
export PYTHONIOENCODING=utf-8
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })"
PY="$(command -v python3 || command -v python || true)"
case "$("$PY" -c 'print(1)' 2>/dev/null)" in 1) ;; *) PY="$(command -v python || true)" ;; esac  # Windows' python3 stub

# the config directory (R1): OBS_CONFIG_DIR when set (its .env via --env-file once it exists), else the tree (legacy)
cfg_dir() { printf '%s' "${OBS_CONFIG_DIR:-${DC_DIR:-$ROOT}}"; }
dc() {
  # a tree with the ./geofront wrapper: the same config / secret (*_FILE) resolution as the operator's commands. A
  # throwaway tree (DC_DIR) keeps its config in the tree unless OBS_CONFIG_DIR says otherwise (never ~/.config/geofront)
  if [ -f "${DC_DIR:-$ROOT}/geofront" ]; then
    OBS_CONFIG_DIR="${OBS_CONFIG_DIR:-${DC_DIR:-}}" bash "${DC_DIR:-$ROOT}/geofront" "$@"
    return
  fi
  local e=() off=()  # an older tree (scripts/upgrade.sh): plain compose
  if [ -n "${OBS_CONFIG_DIR:-}" ]; then
    if [ -f "$OBS_CONFIG_DIR/.env" ]; then e=(--env-file "$OBS_CONFIG_DIR/.env"); else off=(COMPOSE_DISABLE_ENV_FILE=1); fi
  fi
  env "${off[@]}" docker compose --project-directory "${DC_DIR:-$ROOT}" -f "${DC_DIR:-$ROOT}/compose.yaml" "${e[@]}" "$@"
}

# remove a throwaway project by name (containers, networks, its volumes) without its compose file: also when the copy
# of the tree is not there (yet). Run from / so that no compose.yaml in the current directory is picked up.
down_project() {
  case "$1" in obs-e2e-*) ;; *) die "down_project: only throwaway obs-e2e-* projects, not $1" ;; esac
  (cd / && docker compose -p "$1" down -v --remove-orphans >/dev/null 2>&1)
}

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "NG: $*"; exit 1; }

# random secret for a throwaway project (never written to the repository)
rand() { od -An -tx1 -N"${1:-12}" /dev/urandom | tr -d ' \n'; }

# set KEY=VALUE in the config's .env (replace the line or append)
set_env() {
  local f; f="$(cfg_dir)/.env"
  if grep -q "^$1=" "$f" 2>/dev/null; then
    sed -i "s|^$1=.*|$1=$2|" "$f"
  else
    printf '%s=%s\n' "$1" "$2" >> "$f"
  fi
}

# copy the repository as `git clone` would see it (tracked + untracked, not ignored: no .env, inventory, backups) to $1
copy_tree() {
  rm -rf "$1" && mkdir -p "$1" || return 1
  git -C "$ROOT" ls-files -z -co --exclude-standard | (cd "$ROOT" && tar --null -T - -cf -) | tar -C "$1" -xf -
}

# wait until every running service with a healthcheck is healthy and none is restarting / exited with an error
wait_healthy() {
  local timeout="${1:-600}" t0 bad states
  t0=$(date +%s)
  while :; do
    states="$(dc ps -a --format '{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}' 2>/dev/null)"
    bad="$(printf '%s\n' "$states" | awk -F'|' 'NF && !(($2 == "running" && ($3 == "healthy" || $3 == "")) || ($2 == "exited" && $4 == "0"))')"
    [ -n "$states" ] && [ -z "$bad" ] && return 0
    if [ $(( $(date +%s) - t0 )) -ge "$timeout" ]; then
      log "not healthy after ${timeout}s:"; printf '%s\n' "$bad" >&2; return 1
    fi
    sleep 5
  done
}

# JSON state of the data (Prometheus / Loki / Alertmanager / Grafana / Authelia / CA) at time $1, from inside the tools
# container (internal network + data volumes): scripts/state.py
state() {
  local out
  out="$(dc run --rm -T --entrypoint python tools /work/scripts/state.py "$@")" || return 1
  printf '%s\n' "$out" | tail -n 1  # the JSON line only (a rebuild of the tools image may print first)
}
