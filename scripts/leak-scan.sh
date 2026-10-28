#!/usr/bin/env bash
# Leak scan (scripts/leak_scan.py): data that must never be committed - site addresses (non-documentation IPv4 / IPv6,
# burned-in MACs), secrets, keys, certificates, .env, pcap, databases, site config.
#   scripts/leak-scan.sh              the files `git add -A` would commit (tracked + untracked, not ignored)
#   scripts/leak-scan.sh --staged     the index (what the next commit records; the pre-commit hook)
#   scripts/leak-scan.sh --history    every commit of every ref (git log -p --all: added lines, messages, paths)
#   scripts/leak-scan.sh --all        both (before a push / publishing)
# Exit 0 = no NG (WARN only), 1 = NG, 2 = error. Values are printed masked. Test values: scripts/leak-allow.txt.
# Called by: the pre-commit hook (git config core.hooksPath scripts/git-hooks), CI, scripts/doctor.sh.
. "$(dirname "$0")/lib.sh"
command -v git >/dev/null || die "git がありません"
[ -n "$PY" ] || die "python3 がありません"
exec "$PY" "$ROOT/scripts/leak_scan.py" "$@"
