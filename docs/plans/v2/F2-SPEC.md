# F2 仕様: Grafana をなくし、コマンドセンターだけで足りるようにする

親計画は `docs/plans/v2/PLAN.md` です。F1 (`F1-SPEC.md`) の続きです。

オーナーの要件 (2026-10-29) は次のとおりです。

> grafanaに頼らず本開発対象ダッシュボードだけで満足できることが要件

F1 では Grafana を任意 (compose の profile `grafana`) にしました。これは要件に合っていませんでした。
F2 では Grafana を製品から外し、Grafana にあったものはすべてコマンドセンターで見られるようにします。

## 受入条件

### 1. 置き換えの表

- Grafana の設定 (`grafana/` と `dashboards/`) にあるパネルと問い合わせを、すべて下の表に載せます。
- 表のどの行にも、コマンドセンターでの置き場所があります。置き場所がなかった項目は、この F2 で作ります。
- 新しく作る項目も、問い合わせは mask-api を通して伏せ字にします。

### 2. 新しく作る項目

- 機器ごとの `Last seen` (最後に SNMP で取れてからの秒数) を出します。
  - DOWN の機器も含めます。15 分のあいだ一度も取れていなければ `> 15 min` と出します。
  - 置き場所は機器状態の一覧 (見出しの ⤢) の列とカード、機器の詳細のタイルです。
- 一覧の先頭のタイルに `Data freshness (worst)` (一番古い機器の `Last seen`) を出します。
  - 45 秒以上で注意、120 秒以上で異常の色にします (Wallboard と同じ閾値です)。
- 問い合わせは既存の画面と同じ `/prom/` の経路 (mask-api の literal の検査と伏せ字) を通します。PLAYBACK 中は再生位置の時刻で求めます。
- 上部バーには項目を足しません。両テーマ、390〜2560 px、44 px のタッチ目標、LITE の規則を守ります。

### 3. Grafana を消す

- compose の `grafana` のサービスと profile、ネットワーク `grafana-front`、ボリューム `grafana-data` の定義、proxy の 3000 番の公開を消します。
- `grafana/` (provisioning) と `dashboards/` を消します。
- Caddy の `/grafana` の経路と「有効になっていません」の 404 のページを消します。`/grafana/` はほかの知らないパスと同じく 404 になります。
- `.env.example` と `testbed/testbed.env` から `GF_*` と Grafana 用の設定を消します。
- tools から Grafana を消します。
  - init の `--grafana` `--grafana-password` `--reset-grafana-admin` と、`grafana-reset-admin` のコマンド
  - check と doctor の Grafana の行、backup の Grafana の部分
  - Grafana の WAN パネルのためだけにあった記録の規則 (`obs_wan:*`)
- 試験の道具 (`e2e-fresh.sh` の `E2E_GRAFANA`、`probe.py`、`state.py`、`verify.sh`、`upgrade.sh`) と文書 (README の図を含む) から Grafana を消します。

### 4. 以前の Grafana の扱い

- Grafana はまだ開発中で、誰も使っていません (オーナーの指示、2026-10-29)。以前のバージョンとの互換のための処理は作りません。
  - doctor の警告、restore での Grafana の部分の読み飛ばし、更新の手順の説明は入れません。
  - ツリーに残る `grafana` の文字は Loki と Alloy のイメージ名 (`grafana/loki` `grafana/alloy`) と、履歴の検査のための leak-allow の行だけにします。

### 5. 試験

- `scripts/verify.sh selftests compose leak-scan` が通ること
- `scripts/verify.sh e2e-open e2e-auth` が通ること (`Last seen` の問い合わせが mask-api を通ること)
- `scripts/ui-check.js` が通ること (機器状態の一覧と機器の詳細の `Last seen`、両テーマ、全画面幅)
- `scripts/upgrade.sh 325ced8` が `DEMO_AUTO_FAULTS=0` で通ること (F1 の前のバージョンのデータが変わらない。`--remove-orphans` の後に、消えたサービスのコンテナが残らない)
- `scripts/verify.sh backup-restore` が通ること
- 変えた文書が yomiyasu の lint を通ること

## Grafana のパネルの置き換え

Grafana の設定にあったダッシュボードは `dashboards/wallboard.json` (DB01 Wallboard) の 1 つです。データソースは Prometheus と Loki でした。

| # | パネル (種類) | 問い合わせの要点 | コマンドセンターでの置き場所 | F2 |
|---|---|---|---|---|
| 1 | WAN Down (stat) | WAN の IF の受信 Mbps (`obs_wan:*`) | 外部回線 (WAN) のパネルの ↓ DOWN と 15 分の線。長い期間は `推移` (WAN の利用率、IF の通信量) | 既存 |
| 2 | WAN Up (stat) | WAN の IF の送信 Mbps | 外部回線 (WAN) のパネルの ↑ UP と 15 分の線、`推移` | 既存 |
| 3 | Devices online (stat) | `sum(up)` / `count(up)` | 機器状態の見出し `n / N online`、一覧の `Online` のタイル | 既存 |
| 4 | Firing alerts (stat) | `count(ALERTS{alertstate="firing"})` | 発報中の見出しの数、警報のタブの数、`ALERT` バナー | 既存 |
| 5 | Syslog events / 5m (stat) | `count_over_time({job="syslog"}[5m])` | 重要度のパネル (15 分の件数と TOTAL)、ログ検索の件数の棒グラフ (任意の期間と刻み) | 既存 |
| 6 | Data freshness (worst) (stat) | 機器ごとの最後に取れた時刻の最大の古さ (15 分まで) | 機器状態の一覧の `Data freshness (worst)` のタイル。上部の鮮度バッジ、収集系統のパネルと一覧 | 新規 |
| 7 | DEMO DATA の注記 (text) | なし | 上部の `DEMO DATA / SYNTHETIC`、広域通信の下の注記 | 既存 |
| 8 | 宛先の地図 (geomap) | 国・都市・緯度経度ごとの bps | 広域通信 (地球儀) のアーク、位置不明のパネル | 既存 |
| 9 | Device status (table) | 機器ごとの Status / Uptime / Last seen | 機器状態のパネル (Status / Uptime)。`Last seen` は一覧の列とカード、機器の詳細のタイル | `Last seen` は新規 |
| 10 | Top destinations by country (table) | 国ごとの bps と割合 (Unknown も分母) | 通信先のパネルと一覧 (国・量・割合) | 既存 |
| 11 | WAN throughput (timeseries) | WAN の IF の受信・送信 Mbps の時系列 | 外部回線 (WAN) のパネルの線、`推移` の WAN の利用率と IF の通信量 (1h〜30d) | 既存 |
| 12 | Alerts (alertlist) | Prometheus の規則の firing と pending | 発報中のパネル (firing)、警報の一覧 (firing と pending)。どちらも mask-api の `/prom/api/v1/alerts` から。PLAYBACK では `ALERTS` から | 既存 |
| 13 | Syslog latest 50 (logs) | `{job="syslog"}` の新しい 50 行 | 記録のパネル、機器の詳細の直近 50 行、ログ検索 | 既存 |
| - | 変数 `device` (複数選択) | `label_values(up, instance)` | 行から開く詳細、推移とログ検索の機器の絞り込み | 既存 |
| - | 時間の範囲 (now-15m、15 秒ごと) | なし | LIVE の 15 秒ごとの更新、履歴再生 (PLAYBACK)、推移とログ検索の期間 | 既存 |
| - | Explore (自由な PromQL / LogQL、伏せ字なし) | なし | 置き換えません。伏せ字の規則のため、問い合わせはサーバー側の決まった型だけです | 対象外 |

## 設計の要点

- `Last seen` の問い合わせは Wallboard の式と同じ形です。
  - `time() - max by (instance) (timestamp(up) and up == 1 or max_over_time((timestamp(up) and up == 1)[900s:30s]))`
  - `timestamp()` は生のセレクタに掛けます (標本の時刻を得るため)。結果のない機器は、Prometheus が知っていれば `> 15 min` にします。
- 試験の後片付け (`scripts/lib.sh` の `down_project`) は、今の compose の定義にないボリュームとネットワーク (更新の試験で古いバージョンが作ったもの) も、プロジェクトのラベルで消します。使い捨ての `obs-e2e-*` だけが対象です。

## 不変条件

- 伏せ字、認証と役割、Host の許可リスト (421)、PLAYBACK、PERF の挙動を変えません。
- 画面の規則 (情報の重複なし、幅固定、STALE と「—」、44 px、両テーマ、全画面幅) を守ります。
- Prometheus・Loki・Alertmanager・Authelia・認証局のボリュームのデータを消しません。

## 検証の制約

- 使うコンテナは使い捨ての `obs-e2e-*` だけにし、終わったら `down_project` で消します。main のプロジェクトには触れません。
- ブラウザは同時に 1 つだけ使います。
