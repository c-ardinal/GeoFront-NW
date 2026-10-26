# STATE: YAMAHA Network Observatory — Docker demo trial

- Spec: owner upload `yamaha_network_observability_spec_20261024.html` (baseline v1.0)
- Scope: G1/G2 + G3 (offline Geo) on Docker with synthetic data. No real devices touched.
- Status: stack running (grafana 12.2.0 / prometheus v3.6.0 / loki 3.5.5 / alloy v1.11.0 / demo-gen). All targets up, PM verified wallboard renders.
- Command center (:8080): v6 interactions accepted after 2 review rounds (B1-B3, S1-S2, N1-N7, F1-F2 resolved). Themes default/eva.
- Open: command-center/app.js dead stub (owner to decide deletion); masking is client-side only (needs auth layer, SEC-03); real-GPU kiosk perf unchecked.
- Open: RFC3164 parser eats YAMAHA leading token (TC-003, decide after real log capture); map tiles fetched from Esri online.
- Branch: none (not a git repo)

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
