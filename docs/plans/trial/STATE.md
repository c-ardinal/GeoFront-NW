# STATE: YAMAHA Network Observatory — Docker demo trial

- Spec: owner upload `yamaha_network_observability_spec_20261024.html` (baseline v1.0)
- Scope: G1/G2 + G3 (offline Geo) on Docker with synthetic data. No real devices touched.
- Status: stack running (grafana 12.2.0 / prometheus v3.6.0 / loki 3.5.5 / alloy v1.11.0 / demo-gen). All targets up, PM verified wallboard renders.
- Command center (:8080): v6 interactions accepted after 2 review rounds (B1-B3, S1-S2, N1-N7, F1-F2 resolved). Themes default/eva.
- Open: command-center/app.js dead stub (owner to decide deletion); masking is client-side only (needs auth layer, SEC-03); real-GPU kiosk perf unchecked.
- Open: RFC3164 parser eats YAMAHA leading token (TC-003, decide after real log capture); map tiles fetched from Esri online.
- Branch: none (not a git repo)

## R1 (docs/plans/v2/R1-SPEC.md, GeoFront-NW) - items 1-6 implemented, uncommitted on main (HEAD faa7ba6), awaiting PM acceptance
- Item 7 (history scan -> push) is NOT done: `scripts/leak-scan.sh --history` finds 2 NG IPv4 in commit 5e0e6ef
  docs/plans/trial/STATE.md: the host's real LAN address and the Docker gateway (redacted).
  History rewrite = owner's decision; CI (`--all`) and the release workflow fail until then (intended gate).
- Config (item 1): site config in OBS_CONFIG_DIR (.env, inventory/devices.yaml, alerting/receivers.yaml, backups/),
  mounted at /config in the tools services; unset = the repository (legacy layout, gitignored). Examples only in
  config.example/. `./geofront` = docker compose with it (--env-file, default ~/.config/geofront when the repo has no
  .env, <NAME>_FILE secrets for 13 secrets, explicit --env-file respected). tools init pins COMPOSE_PROJECT_NAME +
  OBS_CONFIG_DIR; `tools migrate-config` copies the legacy files (keeps them) and pins the project name; doctor rows:
  config location, legacy .env left behind, leak scan. Authelia users / generated config / CA stay in their volumes.
- Project name: compose.yaml keeps `name: yamaha-observatory-trial` (existing volumes); new installs via ./geofront get
  geofront-nw (legacy volumes present -> legacy name); testbed.env keeps yamaha-observatory-testbed.
- Leak scan (item 2): scripts/leak_scan.py (+ leak-scan.sh, git-hooks/pre-commit --staged, leak-allow.txt for selftest
  vectors, also applied to history); doctor.sh / verify.sh leak-scan / ci.yml. Values printed masked.
- Drivers (item 3): drivers/{yamaha-rtx,yamaha-wlx,generic}/driver.yaml (kinds, snmp_modules, lldp, wan,
  wireless_clients) + demo.json (demo-gen devices, output equal to before: snmp / lldp / flows / normal syslog compared;
  only the logburst error-line pool order changed) + syslog.jsonl (split from testbed/fixtures). lldp job -> lldp.json.
  UI: config.json devices carry `wireless`. docs/drivers.md.
- Name / theme (4, 5): README / screen title / dashboard title GeoFront-NW (dashboard uid, provider and rule group
  names, TOTP issuer, evidence manifest key kept); theme eva-film -> film (aliases eva, eva-film). LICENSE (MIT,
  c-ardinal), THIRD_PARTY_NOTICES.md. No bundled fonts (Google Fonts at run time, OFL); no Evangelion / NERV marks.
- GHCR (6): images ghcr.io/c-ardinal/geofront-nw-<svc>:${GEOFRONT_VERSION:-local} (+ build kept), testbed
  geofront-nw-testbed:local; .github/workflows/ci.yml, release.yml, docker-bake.hcl, dependabot.yml. mask-api
  Dockerfile: SELFTEST_EVIDENCE_BUDGET build arg (900 in the release bake; arm64 under QEMU took ~41 min).
- Verification (after the last code change): verify.sh quick: selftests 8/8 rc=0, compose OK (incl. OBS_CONFIG_DIR
  mount, bake print), leak-scan OK (tree 0 NG), doctor NG only for "no .env" in this tree (expected; run with
  COMPOSE_PROJECT_NAME=obs-e2e-quick); e2e-open E2E_CONFIG=outside OK (nothing written into the tree) and legacy OK;
  `scripts/upgrade.sh faa7ba6` OK (data kept after the update and again after migrate-config + up from OBS_CONFIG_DIR).
  actionlint (container) clean; dry multi-arch bake of mask-api (amd64 + arm64, cacheonly) OK. Codex r1 (1 P1 + 2 P2)
  and r2 (P2 wrapper --env-file fixed; P1 "history gate fails" = intended, needs the owner's history decision).
- Not done / open: e2e-auth, resilience, backup-restore, arm64.sh not re-run; release workflow not run on GitHub;
  docker-compose Dependabot ecosystem not exercised; empty dirs inventory/, alerting/, testbed/fixtures/ left in the
  tree (untracked, removable). Containers: obs-e2e-* removed; main projects stopped, 22 volumes untouched.
- Evidence: scratchpad r1/ (final/*, codex-r1.md, codex-r2.md, bake-mask-api2.log, leak-baseline.txt).
- Follow-up (PM + review NO-GO B1/B2, O1-O8): real-subnet strings gone from the tree (local-only check outside the repo);
  B1 testbed.env OBS_INVENTORY / OBS_RECEIVERS = /work/testbed/... and the wrapper picks no config dir for an
  explicit --env-file (its <NAME>_FILE settings are still read: Codex r3 P2 fixed); verify compose checks the testbed
  inventory with OBS_CONFIG_DIR set. B2 leak_scan: single-word keys, lower-case YAML keys, dotted MACs, IPv4 masked to
  two octets, git core.quotePath=false, allow-list = exact (path, line) entries with the marker (no file-wide skips).
  Wrapper: compose-like comment / quote handling, *_FILE must be a readable file (else exit 2), CR stripped.
  .gitignore /inventory/ /alerting/ /backups/ anchored; workflow actions pinned to commit SHAs.
  Re-run: leak selftest + tree 0 NG; testbed (prod+testbed, OBS_CONFIG_DIR set) tools check all OK (--syslog-wait 0:
  throwaway container names); e2e-open outside OK; e2e-auth (real LAN bind) + resilience + backup-restore OK in the
  legacy layout and in the outside layout. Logs: scratchpad r1/fu2/, codex-r3.md.

## H1 (docs/plans/v2/H1-SPEC.md) - implemented, uncommitted on main (HEAD 5e0e6ef), awaiting PM acceptance
- tools doctor (tools/doctor.py pure assessments + obs.cmd_doctor; host facts from scripts/doctor.sh: engine >= 25,
  compose >= 2.20, arch, NTP (timedatectl), busy ports (ss / netstat), skipped while this stack runs): memory, disk vs
  bounded stores, clock vs repo mtime, .env presence / 0600 / profiles / check_env|validate, users = 0 with login, CA +
  leaf certs (caddy-data now mounted in tools at /vol/caddy), Grafana stored default. OK/WARN/NG + fix, NG -> rc 1.
- Bug fixed: backup/restore did not include caddy-data (the proxy's CA key): a restore on a new host made a new root, so
  every LAN device had to re-register it. Now part `caddy` (owner 0:0); restore also refuses while proxy runs (proxy:80).
  Regression: scripts/backup-restore.sh (ca_key_sha / ca_root_sha equal, archive lists caddy, TLS with the old root).
- compose: testbed container_name from TESTBED_RTX_NAME / TESTBED_WLX_NAME (defaults unchanged) so a second testbed
  (e2e) can run next to the stopped yamaha-observatory-testbed containers.
- scripts/ (bash + stdlib python): lib.sh, doctor.sh, e2e-fresh.sh open|auth (E2E_LAN_IP, E2E_CAPTURE, KEEP),
  resilience.sh (REBOOT_CMD), backup-restore.sh, upgrade.sh [ref], arm64.sh, state.py (data state JSON in tools),
  probe.py (screens / roles / Grafana admin, subset of the P7 lancheck + openprobe), verify.sh quick|full|names.
- README: doctor step, update with --remove-orphans + backup first, caddy-data in backup, proxy in the stop list,
  section 検証 (scripts/verify.sh) + Pi first steps, capture "Pi で最初に確かめること". No real host values in the repo
  (owner: repo will be published; the old P7 line with this PC's LAN IP redacted to <LAN_IP>; it is still in commit 5e0e6ef).
- Results (this PC, Docker Desktop 4.55 / Engine 29.1.3 amd64, auth runs on a real LAN bind <LAN_IP>):
  development runs: e2e open OK (+ E2E_CAPTURE=1 with CAPTURE_ALLOW_VM: ring -> flowd -> Prometheus, flows_configured),
  e2e auth OK (17 probes), resilience 12/12 + Docker Desktop restart (16 containers back, check OK), backup-restore all
  10 state items equal + same root / key + TLS with the old root + login (its comparator then failed to parse JSON
  mixed with build output: fixed in lib.sh state()), upgrade bb2f21d OK (5 items kept, grafana-guard removed, Authelia
  up), arm64: 10/10 pinned images amd64+arm64, arm64 builds + selftests tools 214 s / flowd 168 s / analyzer 537 s.
  Codex r1 (3 P2: e2e.env 0600, doctor per-port ownership, cleanup trap) + r2 (2 P2: PROM/GRAFANA_LOCAL_PORT from the
  shell, upgrade test demo-gen port) fixed, not re-reviewed (2 rounds max).
  Final verify.sh full after the last code change: selftests (8/8 rc=0), compose, e2e-open, e2e-auth OK; resilience
  12/12 service checks OK, then REBOOT_CMD "docker desktop restart" left Docker Desktop crashed (backend: stale AF_UNIX
  socket %LOCALAPPDATA%\Docker\run\dockerInference "cannot be accessed"; same after killing all Docker processes and
  restarting). backup-restore / upgrade / arm64 were not re-run after the r1/r2 script edits. Logs: scratchpad
  h1/verify-final/, earlier runs h1/*.log, codex h1/codex-r1.md, r2.md.
  Review NO-GO fixes (Docker down, static checks only): B1 scripts/*.sh 100755 in the index (add -N + update-index
  --chmod=+x: their content is staged, re-add after edits); O1 pre-clean by name (lib.sh down_project, obs-e2e-* only,
  no compose file needed); O2 resilience.sh [project [tree]] (no COMPOSE_PROJECT_NAME inheritance, needs e2e.env);
  O3 doctor.sh netstat only on MINGW/MSYS/CYGWIN, unread ports -> WARN; O4 read_env_file: export, inline ` #`
  comments, quoted values with trailing comments / escapes (selftest cases); README: REBOOT_CMD systemctl only.
  bash -n, py_compile, doctor selftest, read_env_file cases OK. After Docker came back: the exit traps also use
  down_project (compose-file `down -v` had left obs-e2e-*_geoip volumes of an inactive profile behind).
- FINAL (after the last code change, scripts re-staged 100755): `E2E_LAN_IP=<LAN_IP> scripts/verify.sh full`, no
  REBOOT_CMD: selftests OK 181 s (8/8 + tools build selftest), compose OK, e2e-open OK, e2e-auth OK (27 OK), resilience
  OK (12/12), backup-restore OK (36 OK), upgrade OK, arm64 OK (13 OK, build cache). Logs scratchpad h1/verify-final2/.
  Codex r3 (review fixes): no findings. All obs-e2e-* projects removed (containers, volumes, networks); main projects
  stopped, their 22 volumes untouched.
- Not verifiable here: real LAN capture (Docker Desktop host network = VM), native arm64 run, a real reboot of a Pi
  (Docker Desktop restart used), disk-full behaviour (bounded by config only; doctor estimates), real devices.

## P7 (docs/plans/v2/P7-SPEC.md) - implemented, uncommitted on main (HEAD bb2f21d), awaiting PM acceptance
- Access mode = auth on any LAN bind (no unauthenticated LAN exposure any more) or OBS_AUTH=1; else open (127.0.0.1, no
  login: demo default unchanged). One rule in proxy / authelia / grafana entrypoints, mask-api auth_required, tools/auth.py.
- Authelia 4.39.28 (digest bd97cff4..., amd64 + arm64) behind Caddy forward_auth (subpath /auth on the screens' origin),
  non-root 10091, no caps; idles in open mode; refuses to start without generated config / secrets / a user -> proxy 502.
  Config generated by the setup step (tools/auth.py): file users argon2id (32 MiB, t3, p4; Authelia's own hash verified in
  selftest), access only groups viewer/operator/admin (default deny), regulation user+ip 5 / 10m / 15m, cookie
  obs_session per screen host Secure/HttpOnly/SameSite=Strict, inactivity 30m / expiration 12h, remember-me off, optional
  TOTP (OBS_AUTH_TOTP=1, filesystem notifier, placeholder e-mail per user), refresh_interval always.
- HTTPS: Caddy tls internal on the screens' port (container :8080 in both modes), plain HTTP redirected (http_redirect
  listener wrapper), default_sni = bind address, hostless catch-all 421; caddy/access-{open,auth}[-global].caddy imported by
  OBS_ACCESS. Root cert: docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt (README).
- Identity: proxy strips client X-Obs-*/Remote-*, sets X-Obs-User / X-Obs-Role (highest group) and X-Obs-Auth =
  OBS_AUTH_PROXY_KEY only towards mask-api; mask-api identity() needs the key (compare_digest, >= 32 chars, header once,
  exact role, name rule) else no identity. Writes: verified operator/admin (proxy 403 for others too) or open mode;
  CSRF/Origin/Host checks kept. OBS_OPS_TRUST_ROLE removed. /am/ops adds auth/user/role (menu).
- Real names: ACK createdBy/comment, evidence manifest generated_by, notify-relay record of an expired ACK (receiver ack, by).
- Grafana auth proxy (X-Obs-User, X-Obs-Grafana-Role: viewer/operator -> Viewer, admin -> Admin), no anonymous / login form /
  basic auth with login. grafana-guard service + gate removed (LAN now gated by the login); tools check keeps the hash check.
- tools: user add/passwd/role/remove/list/secrets (argon2-cffi 25.1.0 pinned), init generates OBS_AUTH_* into .env (--auth),
  backup/restore include authelia-data (SQLite consistent copy), check lists Authelia + users.
- UI: ⋯ menu user / role / logout (+ admin hint), no LAN warning with login, reload on 401 / login redirect; snapshot option
  in playback bar and 原因候補 (disabled with the reason when not writable).
- Leftovers: snapshot / pcap caps MiB in Caddy and app; POST /evidence/export judged (permission, CSRF, query, type, size,
  slot, rate) before reading, body read with a total deadline (read1 per socket read) + idle timeout; verification scripts
  record each command's own rc (selftests.sh, no tail pipe; P6's flowd rc=0 was such a case).
- Done (after the last code change): final build + selftests.sh all rc=0 (mask-api incl. identity/spoof/role gating, relay,
  analyzer, flowd clean, demo-gen, capture, tools incl. auth hashing vector), open mode probes + P4 export_check scopes +
  limits (0 raw hits) + browser open (29 OK); real LAN bind <LAN_IP>: lancheck 79/79 (unauth / viewer / operator / admin
  x reads / writes, spoofed + duplicated headers, internal container without key, Authelia down -> 502, HTTP -> HTTPS, 421,
  cookie flags, Grafana roles, logout) + bruteforce 2/2 (bans revoked after), browser lan 81 OK (both themes, 390-2560).
  Codex r1 2 P2 fixed, r2 1 P1 + 1 P2 fixed, r3 clean; argon2 32 MiB + GOMEMLIMIT changed after r3 (measured), re-verified.
  Containers stopped (docker compose stop). Orphan grafana-guard container stopped (remove: up -d --remove-orphans).
- Open / limits: sessions in Authelia memory; Docker Desktop shows every LAN client as its gateway address (ip bans hit all);
  Grafana: admin only, auth proxy trusts the proxy's fixed address only (security review F2/F3).
- Evidence: scratchpad p7/ (logs/final*-*.txt|log, shots/final*, codex-r1..3.md, lancheck.py, check-p7.js, selftests.sh).
- Security review (conditional GO) fixes, same uncommitted set: F1 default GF_ADMIN_PASSWORD is an error with login
  (check_env / init / setup); proxy 403 for /grafana/login*, /grafana/api/login*, /grafana/api/user/password; 127.0.0.1:3000
  403 with login. F2 network grafana-front (internal, ipam 172.31.253.0/29, dynamic ip_range .4/30, proxy fixed .2 =
  GF_AUTH_PROXY_WHITELIST, proxy dials grafana-front:3000; testbed.env own subnet). F3 /grafana/* admin only with login
  (viewer / operator 403), Grafana role Admin; command-center has no Grafana links. F10 one strict loopback rule
  (ipaddress / awk, 5 places). save_users fsync; README notes (interactive password, cookie across ports, 9090 local).
  Backup archives were already 0600 (umask 077 + chmod). Codex r4 1 P2 (testbed subnet) fixed, r5 clean, r6 clean
  (after the ip_range fix). After the last code change: selftests all rc=0, lancheck 86 incl. F1/F2/F3 (one expectation
  corrected: Basic admin:admin with an admin session -> Grafana 401, never its local admin) + grafana part 7/7, bruteforce
  2/2, browser lan / open all OK, open probes OK, export_check scopes + limits 0 raw hits, tools check OK. Test users
  boss / alice / victor removed (tools user remove; no users left). Containers stopped. Evidence: logs/f-*.

## P6 (docs/plans/v2/P6-SPEC.md) - implemented, uncommitted on main (HEAD 09e8cec), awaiting PM acceptance
- N3 notify-record tokens: notify-relay records an exactly-IPv4 instance / ifName as a.b.c.x~<token> (mask-api's
  HMAC-SHA256, 12 hex). No new secret: mask-api's per-process KEY is shared through a tmpfs volume `token-key`
  (mask-api rw, writes /run/obs-key/token.key 0644 at start or reuses a valid one still there; notify-relay ro). No key
  -> a.b.c.x (fail closed); exact IPv6 -> x. Outbound bodies unchanged (no tokens). mask-api masks {job="notify"} lines
  value by value (mask_line / relay_value): a token is kept (and registered) only if it checks out against the current
  key over a.b.c.0-255, else stripped. Evidence notify_keep matches tokens exactly, /24 fallback only for token-less
  records (manifest note). Correlate relates them by instance equality.
- Snapshot: drawer evidence option 「画面の画像」 (off, not stored); command-center/js/snapshot.js (no library:
  DOM clone -> SVG foreignObject, canvases incl. WebGL globe (globe.redrawNow) as backgrounds, text re-masked + tokens
  removed, typed inputs emptied, animations off, vertical scroll by items). POST /evidence/export (PNG body) under the
  silence write rules (127.0.0.1 only / CSRF / same origin; Caddy 403 on LAN + 8 MB body cap); mask-api checks the PNG
  (CRC, IHDR, <= 8192 px, <= 8 MB), keeps IHDR/PLTE/IDAT/IEND only; manifest.snapshot generated_by browser + sha256.
  Fallback (LAN 403 / csrf / bad PNG / 413 / cannot render) -> GET export without PNG, reason in the status line.
- Done (after the last code change): build selftests (mask-api / relay incl. golden token vector + fail closed, analyzer,
  demo-gen, capture, tools; flowd ok in a clean container - under `compose run` its env makes an unrelated IPv6 assert
  fail, untouched by P6), N3 E2E (relay token == HMAC(volume key), correlate 同じ機器 / other token 同時期, key reused
  over a mask-api restart, older-key tokens stripped), export_check scopes + limits + snapshot (0 raw hits, PNG only
  IHDR/IDAT/IEND, sha256 file = manifest, refusals 403/400/405/421), token-scoped device export (exact + /24 note),
  browser p6/check-p6.js (shell) + probe-globe.js (gpu): option off by default, 44 px on touch widths, both themes,
  390-2560 px, POST only when on, LAN-refused / untaintable fallbacks. Codex r1 (2 P2 fixed: X-Obs-Snapshot header,
  truncated flag) r2 clean, r3 clean. Containers stopped (`docker compose stop`).
- Open / limits: Caddy LAN 403 for the POST checked by selftest + route stub, not with a real LAN bind; snapshot has
  system fonts (no web fonts), vertical scroll only; playback bar / 原因候補 「証跡」 have no snapshot option; tokens
  change when mask-api and notify-relay both stop (tmpfs), older records then show a.b.c.x.
- Evidence: scratchpad p6/ (final-*.log / *.txt, shots/, codex-r1..3.md).

## P5 (docs/plans/v2/P5-SPEC.md) - implemented, uncommitted on main (HEAD 6335c68), awaiting PM acceptance
- Network map (command-center/js/topology.js): switch in the globe's controls (#g-view, localStorage cc-globe-view), same
  slot; graph = inventory (new optional parent / parent_if / uplink_if, tools/obs.py validates, config.json `links`) +
  LLDP (snmp/lldp.yml module, Prometheus job `lldp` every 2m, demo-gen and testbed snmpsim answer it); per-link source
  台帳 / LLDP / 台帳+LLDP; deterministic tidy-tree layout recomputed only on graph / size change; globe paused while hidden.
- Surges: setup writes prometheus surge-rules.yml from SURGE_FACTOR / SURGE_MIN_KBPS / SURGE_BASELINE (.env);
  header button 急増 N + modal (correlate.js); demo surge in flowd-demo (FLOWD_DEMO_SURGE = DEMO_AUTO_FAULTS).
- 原因候補: mask-api correlate.py `GET /correlate/events` (read-only, own masked read paths, bounded; Caddy GET/HEAD only);
  drawer view from alert drawer / surge rows / playback bar; rules shown; links to detail / packets (since) / evidence.
- Selftests: correlate.selftest (ordering, relatedness, spans, request checks), tools (links, loops, surge rules,
  lldp.yml), flowd (demo surge), demo-gen (lldp), testbed device (LLDP rows).
- Done: all build selftests (cached analyzer / notify-relay / capture run explicitly), P4 export_check scopes + limits
  (0 raw hits), browser checks (scratchpad p5/check-p5.js: map / faults / playback / gpu; both themes, 390-2560 px),
  testbed (real snmp-exporter lldp module over v3 + v2c, tools check all OK), Codex r1 (3 P2 fixed) + r2 (2 P2 fixed,
  not re-reviewed). Containers stopped (compose down, volumes kept).
- Review NO-GO B1 fixed (round 2): 原因候補 clipped to the playback cursor on every cursor change (main setTime ->
  correlate.clipToCursor), before / without a fetch and after a failed one; cursor before the window -> "窓の外" state
  (no items, no request; re-anchor button); server refuses a window that would end before it starts. Browser check
  p5/check-pbclip.txt (in flight / 429 / outside: 0 items after the cursor, 0 requests with to <= from).
  O1 live refetch 60 s; O3 masked / IPv4 sysNames not split on "."; O4 baseline needs >= 10 samples (demo surge first
  at 20 min); O2 noted in README. Containers: `docker compose stop` from now on (owner).
- Codex r3 (after the B1 fix): 2 P2 fixed (spans end at one missing evaluation point / ongoing = present at the last
  point; packet drill-down picks only ring files closed before the window end); selftests re-run, not re-reviewed.
- Design notes: surge baseline = median (quantile_over_time 0.5) so recurring bursts do not raise it; demo surge every
  32 min from 12 min. Open: RTX/WLX LLDP-MIB support unverified on real devices.

## PERF (docs/plans/v2/PERF-SPEC.md) - implemented, uncommitted on main (HEAD b923d19), awaiting PM acceptance
- Results: docs/plans/v2/PERF-RESULTS.md (targets met; also met before the change by the x4 Pi estimate).
- Baseline: done (client base2, server demo/testbed from a HEAD worktree, since removed).
- Server changes: scrape/eval 30s (+ 2m rate windows in UI / WAN rules / dashboard), self-metric keep lists,
  healthchecks 60s + start_interval, Loki small-host tuning, Prometheus query concurrency 4, Alloy --disable-reporting,
  Grafana optional (OBS_GRAFANA=0, scale) + no Grafana alerting/Live, grafana-guard PBKDF2 memo, flowd tick 5s.
- Client changes: render-mode.js (GPU probe, AUTO/GPU/LITE, menu RENDER button), globe-layers.js (shader pulses,
  canvas eva labels), 30/15 fps pacing + on-demand LITE, hidden points, merged graticule, request timeouts + reuse,
  no overlapping polls, slow queries 1/min, compositor-only DOWN/film animations.
- LITE also makes the page static (reduced-motion presentation); limits: grafana-guard 96m, PROM_MEM 512m.
- Done: after-measurement, README Pi section, selftests (build), tools check, export_check, check.js, Codex r1 (1 P2
  fixed: OBS_GRAFANA=0 in check_env / check) + r2 (no findings). Containers stopped.
