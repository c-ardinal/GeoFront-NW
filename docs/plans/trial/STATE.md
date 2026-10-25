# STATE: YAMAHA Network Observatory — Docker demo trial

- Spec: owner upload `yamaha_network_observability_spec_20261024.html` (baseline v1.0)
- Scope: G1/G2 + G3 (offline Geo) on Docker with synthetic data. No real devices touched.
- Status: stack running (grafana 12.2.0 / prometheus v3.6.0 / loki 3.5.5 / alloy v1.11.0 / demo-gen). All targets up, PM verified wallboard renders.
- Command center (:8080): v6 interactions accepted after 2 review rounds (B1-B3, S1-S2, N1-N7, F1-F2 resolved). Themes default/eva.
- Open: command-center/app.js dead stub (owner to decide deletion); masking is client-side only (needs auth layer, SEC-03); real-GPU kiosk perf unchecked.
- Open: RFC3164 parser eats YAMAHA leading token (TC-003, decide after real log capture); map tiles fetched from Esri online.
- Branch: none (not a git repo)
