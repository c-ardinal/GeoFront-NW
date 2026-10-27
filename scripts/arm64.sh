#!/usr/bin/env bash
# Raspberry Pi (linux/arm64): (1) every pulled image's pinned digest is a multi-arch index with linux/arm64 (and amd64);
# (2) the self-built images build for linux/arm64 with their build-time selftests (buildx; on amd64 through QEMU, slow:
# by default the three with arch-specific dependencies: tools (argon2 / PyYAML wheels), flowd (maxminddb wheel),
# analyzer (Debian tshark). ARM64_IMAGES="tools mask-api analyzer flowd notify-relay capture demo-gen testbed" for all).
# On the Pi itself `docker compose build` is the same check, natively.
set -u
. "$(dirname "$0")/lib.sh"
rc=0
BASE_IMG="$(grep -o 'docker-image://python:3.12-slim@sha256:[0-9a-f]*' "$ROOT/compose.yaml" | head -1)"
for img in $(grep -oE '(image: |docker-image://)[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' "$ROOT/compose.yaml" | sed -E 's#^(image: |docker-image://)##' | sort -u); do
  plats="$(docker buildx imagetools inspect "$img" 2>/dev/null | awk '/Platform:/ { print $2 }' | tr '\n' ' ')"
  if printf '%s' "$plats" | grep -q 'linux/arm64' && printf '%s' "$plats" | grep -q 'linux/amd64'; then
    printf '[OK] %s  (%s)\n' "${img%@*}" "linux/amd64 linux/arm64"
  else
    printf '[NG] %s  (platforms: %s)\n' "${img%@*}" "${plats:-none}"; rc=1
  fi
done
for name in ${ARM64_IMAGES:-tools flowd analyzer}; do
  ctx=(--build-context "python:3.12-slim=$BASE_IMG")
  case "$name" in
    tools) ctx+=(--build-context "repo=$ROOT") ;;
    analyzer) ctx+=(--build-context "demo=$ROOT/demo") ;;
    demo-gen|testbed) ctx+=(--build-context "drivers=$ROOT/drivers") ;;
  esac
  t0=$(date +%s)
  if docker buildx build --platform linux/arm64 "${ctx[@]}" --output type=cacheonly "$ROOT/$name" > "${TMPDIR:-/tmp}/arm64-$name.log" 2>&1; then
    printf '[OK] build linux/arm64 %s + selftest  (%ss)\n' "$name" $(( $(date +%s) - t0 ))
  else
    printf '[NG] build linux/arm64 %s  (log: %s)\n' "$name" "${TMPDIR:-/tmp}/arm64-$name.log"; tail -n 20 "${TMPDIR:-/tmp}/arm64-$name.log"; rc=1
  fi
done
exit "$rc"
