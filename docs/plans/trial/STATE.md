# STATE: YAMAHA Network Observatory — Docker demo trial

- Spec: owner upload `yamaha_network_observability_spec_20261024.html` (baseline v1.0)
- Scope: G1/G2 + G3 (offline Geo) on Docker with synthetic data. No real devices touched.
- Status: stack running (grafana 12.2.0 / prometheus v3.6.0 / loki 3.5.5 / alloy v1.11.0 / demo-gen). All targets up, PM verified wallboard renders.
- Command center (:8080): v6 interactions accepted after 2 review rounds (B1-B3, S1-S2, N1-N7, F1-F2 resolved). Themes default/eva.
- Open: command-center/app.js dead stub (owner to decide deletion); masking is client-side only (needs auth layer, SEC-03); real-GPU kiosk perf unchecked.
- Open: RFC3164 parser eats YAMAHA leading token (TC-003, decide after real log capture); map tiles fetched from Esri online.
- Branch: none (not a git repo)

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
