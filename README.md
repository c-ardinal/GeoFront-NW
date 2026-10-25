# YAMAHA Network Observatory - Grafana-first 試行

> **DEMO DATA / synthetic (demo profile)**
> `demo` profile が表示するメトリクス・フロー・ログは、すべて `demo-gen` が生成した**疑似データ**です。
> 実機 (RTX1300 / WLX413 / WLX222) の観測値ではありません。国・都市・座標・ASN は架空の GeoIP 推定値で、
> 宛先 IP はドキュメント用予約範囲 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) のみを使います。

仕様書 (要件定義・設計・試行計画 v1.0) の G1/G2 相当 — 収集 → 保存 → Grafana DB01-Wallboard — の挙動を、
実機なしで確認するためのものです。v2 P1 から、同じ compose 一式を実機につないで常時運用する `prod` profile と、
実機なしで prod の経路を試す `testbed` profile を加えました (計画: `docs/plans/v2/PLAN.md`、`docs/plans/v2/P1-SPEC.md`)。

## 構成

compose の profile で動かし方を選びます (`--profile <名前>`、または `.env` の `COMPOSE_PROFILES`)。共通のサービスはどの profile でも動きます。

| profile | 内容 |
|---|---|
| `demo` | demo-gen の疑似データで動くデモ (これまでと同じ) |
| `prod` | 実機: snmp-exporter (SNMPv3) と LAN からの syslog。対象は機器台帳 `inventory/devices.yaml` |
| `testbed` | `prod` と一緒に使う疑似実機 (SNMPv3 で答える SNMP シミュレータ + syslog 送信器)。`testbed/testbed.env` で起動 |
| `capture` | P3 (パケット取込) 用に名前だけ予約。まだサービスはありません |

| サービス | イメージ | 役割 | ホスト公開 |
|---|---|---|---|
| proxy | caddy:2.11.7-alpine | 前段のリバースプロキシ。command-center を `/`、Grafana を `/grafana/` で配信。認証の差し込み口 | `OBS_BIND:OBS_PORT` (既定 127.0.0.1:8080)、127.0.0.1:9090 (Prometheus 読み取り専用)、127.0.0.1:3000 (旧 Grafana URL の転送) |
| command-center | nginx:1.29.2-alpine | 自作の司令室画面 (静的) と mask-api への中継 | なし (proxy 経由) |
| mask-api | python:3.12-slim (自作, 標準ライブラリのみ) | 読み取り専用プロキシ。Prometheus/Loki/Alertmanager の応答中の IP/MAC をサーバ側で伏せる。書き込みは抑止 (silence) の作成・延長・解除だけ (許可リスト) | なし |
| alertmanager | prom/alertmanager:v0.34.1 | Prometheus の全アラートの通知: 重大度ごとの送り先と再通知、復旧通知、抑止 (silence) / 確認 (ACK) | なし |
| notify-relay | python:3.12-slim (自作, 標準ライブラリのみ) | Alertmanager から受けて、日本語・伏せ字の通知文をメール / Slack / Discord / LINE / Webhook に送り、結果を Loki に記録。ACK の自動解除 | なし |
| prometheus | prom/prometheus:v3.6.0 | SNMP/フロー/自己監視のスクレイプ (15s)、アラートルール | なし (proxy の :9090 経由で読み取りのみ) |
| loki | grafana/loki:3.5.5 | syslog 保存 (single binary, filesystem, tsdb v13) | なし |
| alloy | grafana/alloy:v1.21.2 | syslog UDP/TCP 514 (raw 受信 + 解析) → Loki | `SYSLOG_BIND:SYSLOG_PORT` (既定 127.0.0.1:514、UDP/TCP) |
| grafana | grafana/grafana:12.2.0 | データソース・ダッシュボードをプロビジョニング (`/grafana/` 配下) | なし (proxy 経由) |
| demo-gen (`demo`) | python:3.12-slim (自作) | snmp_exporter 互換 `/snmp`、フロー `/flows`、RFC3164 syslog 送信、異常注入 | 127.0.0.1:9116 |
| snmp-exporter (`prod`) | prom/snmp-exporter:v0.30.1 | 実機への SNMP (IF-MIB ifTable/ifXTable、SNMPv2-MIB system)。SNMPv3 authPriv 既定 | なし |
| testbed-rtx / testbed-wlx (`testbed`) | python:3.12-slim + snmpsim (自作) | 疑似実機。SNMPv3 応答と YAMAHA 形式 syslog の送信を同じアドレスから | なし |
| notifymock (`testbed`) | testbed イメージ | 通知先のモック (SMTP + STARTTLS/TLS、Slack / Discord / LINE / Webhook の HTTP)。受けた内容を記録するだけ | なし |
| demo-setup / prod-setup | tools (自作) | 起動時に 1 回だけ動き、profile に合った scrape 対象を生成して終了 | なし |
| tools | python:3.12-slim + PyYAML (自作) | `docker compose run --rm tools <コマンド>` の初期設定・確認・バックアップ | なし |

既定ではすべて 127.0.0.1 にだけ bind します。host network は使いません。

運用設定 (全サービス): healthcheck、`restart: unless-stopped` (一回だけ動く setup / tools は除く)、メモリ / CPU 上限 (Raspberry Pi 4 4GB を想定した既定値。`.env` の `PROM_MEM` などで変更)、コンテナログのローテーション (json-file、`LOG_MAX_SIZE` 既定 10m × `LOG_MAX_FILE` 既定 3)、イメージはタグ + digest 固定 (どれも linux/amd64 と linux/arm64 の両方がある multi-arch イメージ。自作イメージの元の python:3.12-slim も digest 固定)。

保持期間: syslog (Loki) は `LOKI_RETENTION` (既定 720h = 30 日。`loki/loki-config.yaml` の compactor retention)。期限切れのデータは compactor が 10 分ごとに印を付け、2 時間後に削除します。メトリクス (Prometheus) は `PROM_RETENTION` (既定 30d)。SD カードの容量で抑えたいときは `PROM_RETENTION_SIZE` (例 `8GB`、古いブロックから消える)。

## デモで試す

```sh
docker compose --profile demo up -d --build
```

`.env` は無くても動きます (Grafana admin パスワードは "admin"、初回ログイン時に変更を促される)。`cp .env.example .env` して `COMPOSE_PROFILES=demo` を有効にすると `docker compose up -d` だけで起動できます。

- コマンドセンター: http://127.0.0.1:8080/
- Wallboard (ログイン不要・匿名 Viewer): http://127.0.0.1:8080/grafana/d/yamaha-wallboard?kiosk (以前の http://127.0.0.1:3000/d/yamaha-wallboard?kiosk も転送されます)
- Grafana 管理: http://127.0.0.1:8080/grafana/ (admin / `.env` の `GF_ADMIN_PASSWORD`)
- Prometheus: http://127.0.0.1:9090 (アラート: /alerts。読み取り専用。admin API と書き込みは proxy が 403 にします)

停止: `docker compose --profile demo stop` (コンテナも消すなら `down`、データも消す場合は `down -v`)

## Wallboard (DB01) の見方

1920×1080 の kiosk 表示でスクロールなしに収まるよう配置しています。

- 上段 KPI: WAN Down / Up (Mbps)、Devices online (online / 対象数)、Firing alerts、Syslog events/5m、Data freshness (最も古い機器の最終成功スクレイプからの秒数)
- Geomap: 宛先の GeoIP **推定**位置。マーカーの大きさ・色は bps。物理経路ではありません。Unknown (GeoIP 不明) は地図に描かず、右の Top destinations に計上します (分母にも含める)。
- Device status: UP / DOWN / UNKNOWN を文字で表示 (色だけに頼らない)。取得できない値は `STALE`。
- WAN throughput: rtx1300 lan2、単位 Mbps 固定、800 Mbps (80%) にしきい値線。
- Alerts: Prometheus ルール (DeviceDown / WanHighUtilization / InterfaceErrors / DeviceRebooted)。
- Syslog: Loki から最新 50 行。

欠損は 0 ではなく `NO DATA / STALE` や空白 (グラフの切れ目) で表示します。

地図タイルは Esri World Dark Gray をインターネットから取得します (Grafana 既定の CARTO は API キーが必要になったため)。オフラインでは地図背景だけが表示されません。

## コマンドセンター画面 (自作 UI の早期試作)

- URL: http://127.0.0.1:8080/ (1920×1080 基準。大画面・タブレット・スマートフォンにも対応、下記「画面サイズ」)
- 映画の司令室風の画面。中央は自転する 3D 地球儀で、ホーム地域から各宛先へのアーク (橙 = outbound、水色 = inbound、太さ = bps)、宛先のリング、都市ラベルを描きます。左に機器状態・国別上位宛先、右に WAN Mbps とスパークライン (15 分)・online 台数・発報中アラート、下に syslog フィードを表示します。
- 表示データは Grafana と同じ Prometheus / Loki の**疑似データ**です。画面上部に `DEMO DATA / SYNTHETIC` を常時表示します。
- アークは GeoIP 推定地点との論理的な関係で、物理経路ではありません。起点 (`js/globe.js` の `ORIGIN`、既定は東京付近) は大まかな地域で、実際の住所ではありません。Unknown (GeoIP 不明) は地球儀に描かず、左の一覧と合計には含めます。宛先 IP・syslog 本文中の IP / MAC は末尾を伏せて表示します。
- アラートが 1 件でも発報中だと赤枠と `ALERT` バナー (アラート名つき) を表示し、解消すると戻ります。取得に失敗したときやデータが 2 周期 (20 秒) より古いときは `DEGRADED` / `STALE` を表示し、最後の値を薄く残します (0 にはしません)。`prefers-reduced-motion` の環境では回転・アーク・点滅を止めます。
- ブラウザは Prometheus / Loki に直接つながりません。nginx が GET の `/prom/api/v1/{query,query_range,alerts}` と `/loki/loki/api/v1/query_range` だけを中継し、それ以外の `/prom/`・`/loki/` 配下は 403 を返します。
- **外部依存 (インターネット接続が必要)**: globe.gl 2.46.2 (cdn.jsdelivr.net、SRI 付き)、three-globe 2.45.6 の地球夜景・地形・星空テクスチャ (cdn.jsdelivr.net)、Google Fonts (IBM Plex Sans / IBM Plex Mono / Orbitron)。オフラインでは地球儀が表示されません (他のパネルは動きます)。
- 別テーマ: `http://127.0.0.1:8080/?theme=eva-film` (または上部バー右端の ⋯ 設定メニューの THEME ボタンで STD ↔ FILM を切り替え) で、アニメの指令室ディスプレイ風のデザインになります (黒地に橙、長体の極太明朝の見出し、六角ステータスセル、目盛りスケール、レーダースイープの地球儀、赤帯の「警報 ALERT」)。配置・内容・データは既定テーマと同じで、選択はブラウザに保存されます (`?theme=default` で既定に戻す)。以前の `?theme=eva` や保存済みの `eva` は `eva-film` として開きます。このテーマは追加で Google Fonts の Oswald / Shippori Mincho B1 (予備に Noto Serif JP) を使い、地球儀の陸地ドットに Natural Earth 110m の国境 GeoJSON (cdn.jsdelivr.net の globe.gl@2.46.2 example データ、SRI 検証付き) を読み込みます (取得できない場合は経緯線のみで表示)。
- 画面サイズ: 1280〜2399 px 幅が基準の壁面表示 (スクロールなし)。2400 px 以上の幅または 1400 px 以上の高さの大画面では文字と余白を最大 1.5 倍まで拡大し、一覧と syslog は空いた高さの分だけ行を増やします (横長 21:10 以上では syslog / 重要度 / 収集系統を右端の列に移動)。768〜1279 px のタブレットは、横向きが「地球儀 + 右列 (概要 / 通信 / 機器 / ログ / 警報 のタブ)」、縦向きが「地球儀を上に、パネルを 2 列」でページスクロールあり。768 px 未満のスマートフォンは要約カード・地球儀・タブで切り替えるパネル・下部のタブバーで構成し、詳細はボトムシート、全件表示は全画面で開きます。タッチ操作では地球儀の通信先を 1 回タップで概要、もう 1 回 (または OPEN DETAILS) で詳細を開きます。
- 上部バーは、パネルにない情報だけを表示します: タイトル、アラートバナー (クリック / Enter で発報中アラートの一覧を開く。タブレット/スマホでは警報タブへ移動)、鮮度バッジ (`● LIVE 3s` / `▲ DEGRADED 12s` / `■ STALE 2m`。状態とデータの経過時間。経過時間は最後に取得に成功してからの時間に Prometheus 側で測ったサンプルの経過時間を足したもので、ブラウザとホストの時計のずれの影響を受けません。ツールチップに最終更新時刻と失敗しているソース・DOWN の対象を表示)、JST 時計、`DEMO` 表示、調査中の「✕ BACK TO LIVE」、⋯ (設定: THEME)。対象数・最大経過時間は COLLECTION HEALTH / DEVICE STATUS パネルで確認します。幅が足りないときは文言を短くして (JST の文字、DEMO、タイトル、バナーの前置き、バッジの状態語を DEGR などに) 1 行に収め、項目は隠しません。表示値の桁数や状態語が変わってもバッジ・時計・件数は固定幅で、他の項目の位置は動きません。
- 鮮度の判定: 最後の成功が 1 周期 (10 秒 + 3 秒) 以内なら LIVE、それより遅れるか一部のソースが失敗 (ログ取得失敗・フロー停止・DOWN の対象あり) なら DEGRADED (理由はツールチップと読み上げ)、2 周期 (20 秒) 成功がなければ STALE。画面が固まったりタブが止まったりしても LIVE のまま残らないよう、更新が成功するたびに CSS アニメーションを再始動し、25 秒更新がなければスクリプトが止まっていても STALE 表示に切り替わります。タブを再表示したときは、最初の取得が成功するまで STALE を表示します。
- 発報中アラート名は省略しません: 上部バナーに収まらないときは横スクロール (ティッカー) で全件を流し、マウスを載せる / フォーカスすると止まります。`prefers-reduced-motion` では流さずに折り返して全件表示します。

### コマンドセンターの操作 (調査モード)

- 何も操作していない状態は WALLBOARD (自動更新のみ)。パネルを開く・行を選ぶ・地球儀を動かすと INVESTIGATE になり、上部バーに「✕ BACK TO LIVE」が出ます (これがモード表示を兼ねます)。`Esc` か「✕ BACK TO LIVE」で WALLBOARD に戻ります。5 分間操作がないと自動で戻ります。調査中もデータは 10 秒ごとに更新され、取得できないときは詳細画面にも `STALE` を表示します (欠損を 0 にしない)。
- パネル見出し (または見出し横の ⤢) をクリックすると、そのパネルの省略なしのデータをモーダルで表示します (列見出しクリックで並べ替え)。WAN は 1h/6h/24h のグラフ、SYSLOG はホスト・重要度・文字列・期間で絞り込めるログビューア (古い行の追加読み込みあり) です。
- 行をクリックすると右側に詳細ドロワーが開き、関連データ (機器→インターフェース・1 時間グラフ・関連アラート・syslog、通信先→送信元ホスト・宛先 IP・推移、アラート→ルール式・関連機器・発報時刻前後の syslog、syslog 行→前後 20 行など) をたどれます。ドロワー内は戻る / パンくずで行き来できます。
- 地球儀はホイール / ピンチで拡大縮小、ドラッグで回転、右上の + / − / ⟲ (初期表示に戻して自動回転を再開)。通信先の点・アークにカーソルを合わせると概要、クリックで通信先の詳細を開き、その通信先 (または選んだ送信元ホスト) のアークだけを強調します。
- キーボード操作: Tab で移動、Enter で開く、Esc で閉じる。モーダル内ではフォーカスが外に出ず、閉じると元の位置に戻ります。
- IP / MAC は詳細画面でも常に末尾を伏せています。伏せ字を外す表示は、仕様 SEC-03 の認証層 (未実装) ができるまで提供しません。
  - **サーバ側マスク**: ブラウザが叩く `/prom/` `/loki/` は nginx → `mask-api` → Prometheus/Loki の順に通ります。`mask-api` は GET かつ許可パス (Prometheus `query` / `query_range` / `alerts` / `rules`、Loki `query_range`) だけを中継し、応答 JSON を解析して**全ての文字列** (ラベル名・ラベル値・ログ本文・ルール式) の IPv4 を `a.b.c.x`、MAC を `aa:bb:cc:xx:xx:xx` (区切りが `-` ならそのまま `-`) に置き換えてから返します。値そのものが 1 つの IPv4 であるラベル値 (宛先 IP など) は `203.0.113.x~<トークン>` になります。トークンは IP の HMAC-SHA256 (鍵は mask-api 起動ごとにランダム) の先頭 12 桁で、元の値は分かりませんが宛先ごとに区別できるため、宛先 IP 別の行・集計・ドリルダウンは従来どおり 1 宛先 1 行です。画面では末尾を `x` と表示し、トークンは見せません。クエリ中のトークンは mask-api が元の IP に戻して問い合わせます (発行していない・期限切れのトークンは 400。mask-api の再起動後は画面の再読込が必要)。ブラウザ側の伏せ字は二重の保険として残しています。nginx も従来どおり許可パス・GET 限定・セキュリティヘッダを持ちます。
  - 伏せた値を手掛かりに元の値を確かめられないよう、受け付けるクエリの形を絞っています (どれにも当たらないものは HTTP 400、ログビューアでは「この条件は検索できません…」と表示):
    - **Loki**: コマンドセンターが送る形だけを受け付けます。ラベル `job` / `host` / `severity` / `facility` の `=` だけからなるストリームセレクタに、文字列の `|=` / `!=` 行フィルタを任意個つけた形と、`sum by (severity)` / `sum by (host, severity)` の `count_over_time({…} [期間])` (同じ行フィルタを付けてもよい) の 2 種類です。それ以外 (`|~` `|>` `!>`、パーサ、`line_format` などのステージ、正規表現マッチ、その他の集計) は拒否します。Loki に送るのは**セレクタだけ**で、行フィルタは mask-api が**伏せた後の本文**に適用します。このためフィルタが一致するのは画面に見えている文字列だけで、伏せた桁の推測には使えません (例: `|= "192.0.2.x" |= "10:443"` は伏せた本文に `10:443` が無いので常に 0 件)。フィルタがある場合は、要求された向き (direction) にセレクタの行を 5000 行ずつ読み進め、伏せた本文で一致した行が要求件数 (limit) に達するか、期間の端まで読み終えるまで続けます (ページの継ぎ目は 1 秒重ねて読み、重複は除きます)。読む行は 1 回あたり最大 100,000 行・約 9 秒までで、途中で打ち切った場合は返した行に加えて `data.warnings` と `data.scanned_until` (読み進めた位置の ns 時刻) を返します。続きは backward なら `end=scanned_until`、forward なら `start=scanned_until+1` で要求できます (現在の UI はこの 2 項目を使わず、件数が limit 未満なら終わりとみなします)。行フィルタ付きの件数集計 (ログビューアの件数グラフ) も同じ考え方で、Loki からはセレクタの行だけを新しい順に取得し、伏せた本文にフィルタをかけてから、mask-api が step ごとの件数 (区間は `(t - 期間, t]`) を数えて Loki と同じ matrix 形式で返します。数える行は 1 回あたり最大 100,000 行 (取得は約 9 秒で打ち切り) で、上限に達した場合は `data.warnings` に「新しい側の N 行だけ数えた。古いバケットは少なく出ることがある」旨を入れます (現在の UI はこの警告を表示しません)。アドレスに触れない語 (例 `Rejected`) なら、件数は Loki 自身の集計と一致します。フィルタの無い件数集計は従来どおり Loki がそのまま数えます。ログ一覧で返る件数が limit 未満になるのは、期間内の一致が尽きたときか、上の打ち切りで `data.scanned_until` が付いたときだけです。
    - **Prometheus**: 文字列は `=` / `!=` のラベル一致の値としてだけ使えます。正規表現マッチ (`=~` `!~`) と、ラベルの文字列を読む・写す・並べる関数 (`label_replace` `label_join` `sort_by_label` `count_values` `info` `limitk` `limit_ratio`) は拒否します。パラメータは `query` と時刻 (`time` / `start` / `end` / `step`) だけです。
    - 共通: 文字列の中に完全な IPv4 / MAC、部分 IP (伏せた形とトークンを除いた残りに **数字.数字**。例 `113.50`、`2.4GHz` も該当)、部分 MAC (**4 組以上の 16 進ペア**。例 `5e:20:00:01`)、発行していないトークン、`\x2e` のように文字を隠すエスケープがあれば拒否します。
  - 伏せた形 (`203.0.113.x`、`02:00:5e:xx:xx:xx`) での絞り込みは使えます。ログビューアでは伏せた本文にそのまま一致します。Prometheus のラベル一致では「同じ先頭を持つ任意のアドレス」に書き換えます (例: `dst_ip="203.0.113.x"` は同じ /24 の全宛先)。
  - 残る制限: (1) 受け付ける形は現在の UI に合わせた許可リストです。UI に新しいクエリの形を足すときは mask-api も合わせて更新が必要です。(2) Prometheus は関数とラベル一致の値を制限する方式で、メトリクス名の許可リストは持っていません。(3) IPv6 は伏せません (デモデータに含まれません)。ドット区切りの MAC 表記 (`0200.5e10.0001`) も対象外です。(4) Grafana (`/grafana/`) と Prometheus (127.0.0.1:9090) は管理ツールとして生の値を表示します。マスク対象はコマンドセンター (`/prom/` `/loki/`) 経由の経路だけです。`OBS_BIND` で LAN 公開すると Grafana はログインが必要になります (`OBS_GRAFANA_ANON_ON_LAN=1` で匿名 Viewer に戻すと、LAN から生の値が見えます)。Prometheus の :9090 は常に 127.0.0.1 のみです。
- 読み取り専用のプロキシ許可パスに `/prom/api/v1/rules` (GET のみ、アラートのルール式表示用) を追加しました。

## 異常注入

`DEMO_AUTO_FAULTS=1` (既定) のとき、demo-gen は約 4 分ごとに下記を順番に自動注入します (無人の常設画面でも状態変化が見える)。止めるには `.env` で `DEMO_AUTO_FAULTS=0`。

手動注入:

```sh
curl "http://127.0.0.1:9116/fault/down?target=wlx222&seconds=120"   # スクレイプ 503 → up=0、syslog 停止 → DeviceDown
curl "http://127.0.0.1:9116/fault/wanspike?seconds=120"              # WAN 約 90% → WanHighUtilization
curl "http://127.0.0.1:9116/fault/logburst?seconds=60"               # syslog 10 倍 + エラー、IF エラー増 → InterfaceErrors
curl "http://127.0.0.1:9116/fault/counter_reset?target=rtx1300"      # sysUpTime とカウンタを 0 から → DeviceRebooted (rate にスパイクは出ない)
curl "http://127.0.0.1:9116/fault/status"
```

demo-gen の自己テスト: `docker compose exec demo-gen python demo_gen.py --selftest` (イメージビルド時にも実行)。
mask-api の自己テスト (`python mask-api/mask_api.py --selftest`、イメージビルド時にも実行) は、件数集計の処理時間の絶対値 (1 秒以内) を `OBS_SELFTEST_PERF=1` のときだけ判定します (Pi やエミュレーションでのビルドを時間で落とさないため)。計算量の退行は、範囲の広さを変えたときの処理時間の比でどの環境でも検出します。

## 本番に入れる (Raspberry Pi / 小型 PC)

前提: 64 bit の Linux (Raspberry Pi OS 64-bit / Ubuntu など、arm64 または amd64)、Docker Engine と compose plugin。
ホストに Python などは要りません (設定作業は `tools` コンテナで行います)。Pi 4 (4 GB) で動く既定値にしてあります。
P1 時点で実機での動作確認はまだです (下記「既知の制限」)。

```sh
# 1. 取得 (git clone など) して、そのディレクトリで:
docker compose run --rm tools init          # 対話で .env と inventory/devices.yaml を作り、検証する
#    非対話: docker compose run --rm -e GF_ADMIN_PASSWORD=... -e SNMP_V3_AUTH_PASS=... -e SNMP_V3_PRIV_PASS=... \
#              tools init --yes --snmp-user obs --syslog-bind 192.168.100.10 \
#              --device rtx1300,rtx,192.168.100.1 --device wlx413,wlx,192.168.100.2 --wan rtx1300:lan2
#    (この例は tools --selftest が README と突き合わせて確認しています)
# 2. 機器側に SNMPv3 ユーザーと syslog 送信先を設定する (下記「機器側の設定例」。手作業)
# 3. 起動 (init が .env に COMPOSE_PROFILES=prod を書くので profile 指定は不要)
docker compose up -d --build
# 4. 確認: 設定の検証、各機器への SNMP (sysUpTime・ifHC カウンタ)、syslog の受信待ち (既定 60 秒)、各サービスの health
docker compose run --rm tools check
```

- 秘密値 (SNMP のパスワード・コミュニティ、Grafana 管理者パスワード) は `.env` にだけ入ります (git 管理外、権限 600)。機器台帳 `inventory/devices.yaml` (git 管理外。例は `inventory/devices.example.yaml`) には auth の名前だけを書きます。
- 機器台帳を変えたら `docker compose run --rm tools targets` (Prometheus の scrape 対象と、syslog の送信元 → 機器名の対応表を作り直します。再起動は不要)。`docker compose up` のたびにも `prod-setup` が作り直します。
- SNMP: `snmp/auths.yml` が auth のテンプレートです。`yamaha_v3` (SNMPv3 authPriv、既定 SHA / AES) と `yamaha_v2c` (`SNMP_COMMUNITY` が空なら無効)。方式は `.env` から埋め込み、SNMPv3 のユーザー名とパスワードは snmp_exporter が起動時に環境変数から読みます (生成物にも書きません)。SNMPv2c のコミュニティは snmp_exporter が環境変数を展開しない項目のため、生成物 (generated ボリューム内の auths.yml、権限 600) に値を書きます (リポジトリやログには出しません)。モジュールは snmp_exporter 同梱の `if_mib` + `system` (IF-MIB / SNMPv2-MIB) です。
- syslog: `.env` の `SYSLOG_BIND` をこのホストの LAN 側 IP (または `0.0.0.0`) にすると、UDP/TCP `SYSLOG_PORT` (既定 514) で機器から受けます。既定の 127.0.0.1 では LAN から届きません。送信元は機器台帳の `address` で機器名 (Loki の `host`) に対応付けます (IP なら送信元 IP、DNS 名なら送信元の逆引き名)。`host` は送信元アドレスだけで決め、syslog ヘッダのホスト名は使いません (LAN 上の誰でもヘッダに `rtx1300` と書けるため)。台帳に無い送信元は `host="unknown"` で、送信元 IP を `src_ip` ラベルに入れます (画面では伏せ字)。`.env` の `SYSLOG_DROP_UNKNOWN=1` で台帳に無い送信元の行を捨てます。ヘッダのホスト名が機器名と違うときは本文の先頭に残します (ホスト名を省いた RFC3164 で本文の先頭語が欠けることもありません)。`tools check` の syslog 受信待ちも、この送信元アドレスで決まった `host` で数えます。UDP の送信元アドレス自体は偽装できるので、これは認証ではなく取り違えの防止です。台帳の `address` は IP で書くのを勧めます。DNS 名で書くと逆引き名で照合するため、DHCP でホスト名を名乗れる端末に機器名を騙られる余地があります。インターネットから届くホストで `SYSLOG_BIND=0.0.0.0` にする場合は `SYSLOG_DROP_UNKNOWN=1` にし、FW で送信元を絞ってください。Alloy は送信元の逆引き名をキャッシュするため、機器の `address` は固定 IP (DHCP 予約) で書くのが確実です。DNS 名で書いた機器の IP が変わったら `docker compose restart alloy` してください (testbed の疑似機器を作り直したときも同じ。compose には疑似機器の更新時に Alloy も再起動する指定を入れてあります)。
- WLX の無線クライアント数 (`demo_wlan_clients`) とフロー (`/flows`) はデモ専用です。YAMAHA の独自 MIB の OID は確認できるまで推測で入れません。prod では command-center の WIRELESS CLIENTS は不明 (—)、通信先 (地球儀・TOP DESTINATIONS / SOURCES) はデータなしになります (フロー収集は P3)。
- WAN: 台帳でルーターに `wan_interface: <ifName>` (例 `lan2`、1 台だけ) を書くと、command-center の WAN パネル・スパークライン・詳細画面 (見出し `WAN · <機器名> <ifName>`) とアラート `WanHighUtilization` (生成される `wan-rules.yml`) がそのインターフェースを使います。`tools init` が rtx の機器で尋ね (非対話は `--wan rtx1300:lan2`)、`tools check` はその ifName が実機の IF-MIB にあるかを確かめます。書かなければ WAN パネルは「WAN interface not configured」と表示し、アラートも作りません。デモは従来どおり rtx1300 の lan2 です。Grafana の Wallboard (`dashboards/wallboard.json`) の WAN パネルは rtx1300 lan2 のままです。

### 機器側の設定例 (手作業で投入。ツールからは機器の設定を変更しません)

仕様 08 章の原則どおり、監視側からは読み取りだけです (SNMP は GET/WALK のみ、書き込みビューは作らない)。以下は**例**です。
コマンドの書式は機種・ファームウェアのコマンドリファレンスで確認してから投入してください (実機ではまだ確認していません)。
`192.168.100.10` は監視ホスト、パスワードは `.env` と同じ値にします。

RTX (コンソール / telnet / ssh のコマンド例):

```
# SNMPv3: 読み取り専用ユーザー (認証 SHA、暗号 AES128-CFB -> .env は SNMP_V3_AUTH_PROTO=SHA / SNMP_V3_PRIV_PROTO=AES)
snmpv3 usm user 1 obs group 1 sha <認証パスワード> aes128-cfb <暗号パスワード>
snmpv3 vacm view 1 include 1.3.6.1.2.1
snmpv3 vacm access 1 read 1
snmpv3 host 192.168.100.10 user 1
# syslog の送信先
syslog host 192.168.100.10
syslog notice on
syslog info on
save
```

WLX: Web GUI の SNMP 設定で SNMPv3 の読み取り専用ユーザー (同じ認証・暗号方式とパスワード、アクセスを許すホストに監視ホスト) を作り、syslog の送信先に監視ホストを指定します。

確認: `docker compose run --rm tools check` で SNMP が OK、syslog の受信待ちで該当機器の行が届けば完了です。NG の詳細に原因の目安 (応答なし = IP・ポート・SNMP 有効化・ACL、認証エラー = ユーザー名・パスワード・方式) を出します。

## 疑似実機で prod の経路を試す (testbed)

実機なしで prod 構成をそのまま動かします。SNMP シミュレータ (snmpsim) と syslog 送信器が 2 台分 (`testbed-rtx` = rtx1300 は SNMPv3 authPriv、`testbed-wlx` = wlx413 は SNMPv2c) 立ち、本物の snmp-exporter → Prometheus、Alloy → Loki を通ります。
`testbed/testbed.env` を使うので `.env` には触れず、別プロジェクト名 (別ボリューム) と別ポート (画面 18080、Prometheus 19090、Grafana 13000、syslog 10514) で動きます。資格情報はダミー値です。

```sh
docker compose --env-file testbed/testbed.env up -d --build
docker compose --env-file testbed/testbed.env run --rm tools check          # SNMP・up・syslog・health がすべて OK になる
docker compose --env-file testbed/testbed.env run --rm tools test-syslog    # syslog 解析の回帰テスト
docker compose --env-file testbed/testbed.env down -v                       # 片付け (testbed のボリュームだけ消える)
```

シミュレータは実機のファームウェアを模したものではありません (インターフェース構成はデモと同じ、標準 MIB のみ、syslog は fixtures の YAMAHA 形式の行)。

## syslog の解析 (TC-003)

Alloy は syslog を raw で受け (PRI から重要度・facility だけを取り、残りはそのまま)、`loki.process` で RFC5424 / RFC3164 のヘッダがあれば外します。YAMAHA 形式 (PRI のみ・時刻 / ホスト名 / タグなし) は本文をそのまま残すので、以前の RFC3164 パーサで起きていた先頭語の欠け (`PP[01] Rejected at ...` が `01] Rejected at ...`、`LAN2: link up` が `link up` になる) は起きません。デモの syslog も同じ経路なので、デモのログ表示も先頭語まで出るようになりました。raw 受信は Alloy の experimental 機能のため、alloy は `--stability.level=experimental` で動かしています。

- 回帰テスト: `docker compose run --rm tools test-syslog` (`testbed/fixtures/syslog.jsonl` の各行を UDP と TCP で Alloy に送り、Loki に入った行の host / severity / facility / 本文を期待値と比べる)。テストの送信元 (tools コンテナ) は台帳に無いので、すべて `host="unknown"`・`src_ip`=送信元になり、ヘッダのホスト名は本文の先頭に残ることも確かめます。テストの行は `[obs-test …]` の印つきで実際の Loki に入るので、本番では testbed で実行するのがおすすめです (`SYSLOG_DROP_UNKNOWN=1` のときは届きません)。
- fixtures はデモ生成ログ (demo-gen) の形と、公開仕様 (RFC 3164 / 5424) の例の形から作ったものです。**実機の syslog はまだ採取していません**。実機ログを採取したら fixtures に足して形式を確かめてください。
- 受信時刻でタイムスタンプします (RFC3164 / YAMAHA 形式は時刻やタイムゾーンを持たない / 持たないことがあるため。RFC5424 の時刻も使いません)。

## 公開範囲と認証の差し込み口

- Grafana が作る絶対 URL (共有リンク・`/grafana/goto/...` など) は `.env` の `OBS_PUBLIC_URL` (既定 `http://127.0.0.1:8080`) を元にします。LAN 公開するときは LAN から開く URL にしてください (`tools init` は `--bind` と `--port` から作り、`0.0.0.0` のときは尋ねます。非対話は `--public-url`)。
- 台帳の機器名 `unknown` は使えません (台帳に無い syslog 送信元の host に使う予約語)。`SYSLOG_DROP_UNKNOWN=1` で捨てるのは「台帳との対応付けが無かった行」で、ラベルの値では判断しません。
- 既定は 127.0.0.1 のみ。`.env` の `OBS_BIND` を LAN 側の IP (または `0.0.0.0`) にすると、proxy が command-center と Grafana を LAN に公開します。このとき **認証はありません**。proxy の起動ログに `WARNING: ... WITHOUT authentication (認証なしで LAN 公開中)` を出し、command-center の上部バーに `認証なしで LAN 公開中` (幅が足りないときは `無認証 LAN`) を常に表示します。判定は proxy が返す `/obs/exposure.json` によります (127.x / localhost 以外なら表示)。答えが無いときは `/obs/config.json` に入っている OBS_BIND を使い、どちらも答えないときは前回の値でも 127.x なら信用せず `LAN 公開: 不明` と表示します (前回が LAN なら LAN と表示)。どちらも 60 秒ごとに取り直すので、後から答えが戻ったり OBS_BIND を変えたりしても表示が追従します。
- 画面が答えるホスト名は決まっています (DNS リバインディング対策): `127.0.0.1` / `localhost` / `[::1]`、`OBS_PUBLIC_URL` のホスト、LAN 公開時の `OBS_BIND` のアドレスだけです (proxy の起動ログに一覧)。それ以外の Host で来た要求 (例: 攻撃者の名前を 127.0.0.1 に向けたページ) は、画面・伏せ字済みのデータ・操作のどれも返さず 421 になります。127.0.0.1:9090 (Prometheus) / :3000 も 127.0.0.1 / localhost / [::1] だけです。LAN からは `OBS_PUBLIC_URL` の URL で開いてください (`OBS_BIND=0.0.0.0` のときは特に)。
- Grafana は生の値 (IP / MAC を伏せない) を表示するため、LAN 公開時 (`OBS_BIND` が 127.x 以外) は匿名 Viewer を切り、ログインを必須にします (起動ログに `Grafana anonymous access disabled`)。管理者パスワードは `.env` の `GF_ADMIN_PASSWORD` で、`tools init` は既定値 (空 / admin / change-me) を受け付けず、`tools check` も LAN 公開で既定値なら NG にします (Grafana がこの値を使うのは初回起動時だけ。以降は Grafana の画面で変更)。どうしても LAN でログインなしにしたい場合だけ `OBS_GRAFANA_ANON_ON_LAN=1` (起動ログと check に警告)。command-center (伏せ字あり) はログインなしのままです。
- Grafana の管理者パスワードの確認: `GF_ADMIN_PASSWORD` は Grafana が最初にデータベースを作るときにしか使われないため、デモで作られた `grafana-data` ボリュームは admin/admin (または change-me) のままになります。そこで常駐の `grafana-guard` (tools イメージ) が `OBS_GRAFANA_GUARD_INTERVAL` 秒 (既定 60) ごとに `grafana.db` の一貫したコピー (SQLite の backup API、元は読み取り専用) を取り、すべてのサーバー管理者 (`is_admin`。名前が admin でなくてもよい) と admin という名前のユーザーについて、保存されたパスワードのハッシュ (Grafana 12.2 の方式: PBKDF2-HMAC-SHA256・10000 回・50 バイト・ユーザーごとの salt) を既定値 (admin / change-me / 空) と比べます。ログインは試さないので、ログイン失敗の記録も Grafana のアカウントロックも起きません。LAN 公開時の `/grafana/` は、proxy が毎回 grafana-guard (内部ネットワークのみ、ホストには出さない) に問い合わせ (Caddy の forward_auth)、「直近の確認が成功で、しかも 2 間隔以内」のときだけ通します。確認の成功 = 「データベースを読めて、サーバー管理者が 1 人以上いて、形式が想定どおりで、どの管理者も既定値ではない」です。それ以外 (既定値の管理者がいる、読めない、壊れている、形式が違う) は 403 で閉じ、開いた後でも次の確認 (最長 1 間隔) で閉じます。grafana-guard が止まった・固まった・応答しない場合も、proxy は 2 秒で諦めて通しません (502 / 504)。確認が 2 間隔より古くなった場合も 403 です。理由は `docker compose logs grafana-guard` と check に出し、LAN 公開を閉じている間は grafana-guard が unhealthy になります (127.0.0.1 公開のときは閉じず、check で注意)。ローカルのパスワードを持たない管理者 (OAuth / LDAP / 認証プロキシで作られ、password も salt も空) は、パスワードでログインできないので既定値には数えません。Grafana の画面で変えたパスワードは `.env` の値と違っても問題ありません (既定値でなければ開きます)。既定値のときは `docker compose run --rm tools grafana-reset-admin` (明示的に実行したときだけ、既定値と分かった管理者ごとに、その既定値で 1 回だけログインし、Grafana の API で `.env` の値に変えます。受け付けられなかった管理者には手での変更方法を表示します)。admin は `docker compose exec grafana grafana cli admin reset-admin-password '<値>'` でも変えられます。`tools init` は既定値の管理者がいれば名前を挙げて変更を提案し (非対話は `--reset-grafana-admin`)、`tools check` と `tools targets` も同じハッシュ確認を使います。
- 内部ネットワークについて (SEC-03 で扱う): Prometheus の admin API・`/-/reload` は compose の内部ネットワーク上のどのコンテナからも認証なしで呼べます (ホストや LAN には出していません)。Grafana は command-center と同じオリジン (`/grafana/`) で配信されます (以前は別ポート)。command-center は静的な画面で CSP も厳しくしていますが、分離の度合いは下がっています。
- 認証を後から入れる場所: `caddy/Caddyfile` の forward_auth の例 (コメント)。認証プロキシ (Authelia など) を compose に足して有効にし、役割を `X-Obs-Role` ヘッダで渡します。proxy はクライアントから来た `X-Obs-Role` を必ず消します。mask-api は `X-Obs-Role` を受け取る口 (`request_role`) を持ちますが、今は常に viewer 扱いで伏せ字とクエリ制限は外しません (仕様 SEC-03 の認証層ができるまで)。

## バックアップ / 復元

```sh
docker compose run --rm tools backup                 # backups/obs-backup-<日時 (JST、.env の TZ で変更)>.tar.gz
docker compose run --rm tools backup --include-env   # .env (秘密値) も含める。取り扱い注意
```

1 つのアーカイブに Prometheus のスナップショット (admin API。admin API は内部ネットワークからだけ使え、proxy・nginx・mask-api は中継しません)、Loki のデータ、Grafana のデータ (grafana.db は SQLite の backup API で一貫したコピー)、Alertmanager のデータ (抑止・ACK と通知の記録。Alertmanager は約 15 分ごとにファイルへ書くため、直前の変更は入らないことがあります)、機器台帳と通知先 (receivers.yaml)、`--include-env` なら `.env` を入れます。動かしたままで取れます (Loki は稼働中のコピーなので、厳密に揃えたいときは `docker compose stop loki` してから)。

```sh
docker compose stop prometheus loki grafana alertmanager
docker compose run --rm tools restore backups/obs-backup-XXXXXXXX-XXXXXX.tar.gz        # 確認あり (--yes で省略)
docker compose run --rm tools restore backups/... --with-config                         # 機器台帳・通知先 (と含まれていれば .env) も戻す
docker compose up -d
```

restore は対象のサービスが動いていると止めるよう案内して何もしません。ボリュームの中身を消してアーカイブの内容に置き換え、各サービスの実行ユーザーに所有者を合わせます (空の新しいボリュームにも戻せます)。往復テスト (testbed で backup → ボリューム削除 → restore → 同じ時刻の値と Grafana の印のフォルダが一致) は確認済みです。

## profile を付けずに起動した場合

`docker compose up -d` を profile なし (`.env` に `COMPOSE_PROFILES` も無い) で実行すると、`setup-check` が「profile が指定されていません」と出して失敗し、共有サービスは起動しません (scrape 対象や syslog の対応表が無いまま動かさないため)。`--profile demo` を付けるか、`tools init` で `.env` を作ってください。一度どれかの profile で起動したあとは、最後に生成した設定で動きます。

## 更新

```sh
git pull                              # compose.yaml のイメージ (タグ + digest) や設定が更新される
docker compose run --rm tools backup  # 念のため
docker compose pull                   # 固定された新しいイメージを取得
docker compose up -d --build          # 自作イメージも作り直して入れ替え (prod-setup が scrape 対象を作り直す)
docker compose run --rm tools check
```

イメージを上げるときは、`compose.yaml` のタグと digest を一緒に変え、linux/amd64 と linux/arm64 の両方があることを確かめます:
`docker buildx imagetools inspect <image>:<tag>` (Digest と、Manifests の Platform に linux/amd64・linux/arm64 があること)。

## アラート通知 (P2)

Prometheus のアラートはすべて Alertmanager に送られ、Alertmanager が重大度 (critical / warning / info) ごとの送り先・再通知・復旧通知・抑止を受け持ちます。実際の送信は notify-relay が行い、通知文は日本語で、機器名・対象 (ifName)・値・開始時刻 (JST)・画面へのリンク (`OBS_PUBLIC_URL/?open=alerts`、開くと警報一覧) を含み、IP / MAC は mask-api と同じ規則で伏せます (例 `192.168.100.x`、`00:a0:de:xx:xx:xx`)。復旧 (resolved) も通知します。

- **既定はどこにも送りません。** 通知先は `alerting/receivers.yaml` (git 管理外。書式は `alerting/receivers.example.yaml`) に書き、秘密値 (Webhook URL・トークン・SMTP パスワード) は `.env` だけに置きます。setup (prod-setup / `tools targets`) がこの 2 つから Alertmanager の設定 (秘密値なし) と notify-relay の設定 (秘密値あり、`generated` ボリュームに権限 600) を作ります。ログに秘密値は出しません。
- 通知先の種類: メール (SMTP。`SMTP_TLS=starttls` / `tls` / `none`)、Slack (Incoming Webhook)、Discord (Webhook)、LINE (Messaging API の push。LINE Notify は 2025 年に終了済みのため使いません。チャネルアクセストークンを `.env`、送り先のユーザー ID / グループ ID を receivers.yaml に)、汎用 Webhook (JSON を POST。任意で Bearer トークン)。秘密値は種類ごとに 1 組です (メールの宛先は 1 件に複数書けます)。
- 重大度ごとの送り先と再通知の間隔は `routes:` に書きます。書かない重大度は既定で critical / warning がすべての通知先、info は通知しません。間隔は解消するまで繰り返す間隔です (例 critical 1h)。
- demo profile では receivers.yaml を使わず、外部へ送らない「デモ用受信先」(`demo-sink`) に記録するだけです。DEMO_AUTO_FAULTS の障害で、記録 (Loki `{job="notify"}`) と画面の「通知済」が見えます。 警報の詳細には、送られたはずの通知文 (伏せ字済み) も表示します。

```sh
cp alerting/receivers.example.yaml alerting/receivers.yaml   # 編集し、秘密値は .env へ (または tools init の対話で作る)
docker compose run --rm tools targets       # 設定を生成し Alertmanager に読み込ませる (docker compose up -d でも生成)
docker compose run --rm tools notify-test   # 各通知先にテスト送信 (Alertmanager 経由)。結果と応答 (HTTP / SMTP) を表で出す
docker compose run --rm tools notify-test --receiver mail   # 1 つだけ
docker compose run --rm tools check         # 通知先の設定の検証、Alertmanager が生成した設定で動いているか、Prometheus からの送信
```

画面 (command-center):

- 警報パネルの各行に通知状態の欄 (幅固定): `通知済` (今回の発報について、今の経路の送り先すべてに届いた) / `一部未確認` (まだ記録の無い送り先がある。詳細にその名前) / `通知失敗` (1 つでも失敗、またはメールの一部の宛先が拒否。詳細に「mail OK / slack HTTP 403」のように送り先ごとの結果) / `未通知` (まとめ待ち) / `通知なし` (その重大度は通知しない設定) / `抑止中` / `確認済` / `不明` (Alertmanager か通知の記録に接続できない) / `履歴上限` (記録が上限 5000 件を超え、古い記録を読んでいない)。同じ警報が一度解消して再発した場合は、再発後の通知だけを数えます。大きい画面では詳細行に次回の再通知時刻 (今の経路の送り先について、最後に届いた時刻 + 再通知間隔) も出ます。送り先が無くなった警報は履歴だけを表示し、次回時刻は出しません。
- メールは宛先ごとに結果を見ます。一部の宛先が拒否された場合は残りの宛先に送り、拒否された宛先を記録します (再送はしない: 届いた宛先に二重に届くため)。
- 警報の詳細 (ドロワー) の「Notification & actions」: 通知状態・最後に送った時刻と通知先・次回の再通知・抑止 / 確認の期限と、操作 `確認 (ACK)` (その警報の再通知を解消まで止める) / `抑止する` (この警報・この機器のすべて・この警報名のすべて × 1h / 4h / 24h / 7d) / `抑止を解除`。
- 警報一覧 (モーダル) に通知状態の列と「Silences & ACK」: 一覧・延長 (+1 h / +24 h)・解除、新しい抑止の作成 (機器か警報名のどちらかは必須)。
- ACK は Alertmanager の silence です。作成者は `command-center (<操作者>)`、コメントは `ACK by <操作者>` で始まります (操作者は認証層の利用者名 `X-Obs-User`。`OBS_OPS_TRUST_ROLE=1` のときだけ信用し、それ以外は `local`)。期限は 24 時間 (上限 7 日。延長しても開始から 7 日まで)。警報が解消すると notify-relay が自動で解除するので「解消まで」になり、解除後に復旧通知が送られます。自動解除は、Alertmanager の起動から 150 秒 (Prometheus の再送 1 分 × 2 + 最長の `for:` 30 秒。`RELAY_REAP_MIN_UPTIME_S`) 経ってから、しかも 1 分ごとの確認で 3 回続けて一致する警報が無かったときだけです (Alertmanager の再起動直後に ACK が消えないように)。確認済は検出 (firing) とは別に表示し、警報自体は発報中のまま残ります。

抑止・確認の書き込み (これだけが書き込み):

- **127.0.0.1 公開のときだけ有効**です。LAN 公開 (`OBS_BIND` が 127.x 以外) では proxy と mask-api の両方が拒否し、画面のボタンは理由付きで無効になります (認証が無いため)。将来の認証層が `X-Obs-Role` に operator / admin を入れる構成では、`OBS_OPS_TRUST_ROLE=1` と Caddyfile の `@amLanWrite` の置き換えで開けられます。
- 許可リスト: silence の作成・延長・解除だけ (`POST /am/api/v2/silences`、`DELETE /am/api/v2/silence/<id>`)。一致条件は alertname / instance / ifName / severity の等号だけ (正規表現・否定は不可、alertname か instance は必須)、期間は 7 日まで、コメントは 200 文字まで、作成者は常に `command-center`。延長・解除は command-center が作ったものだけです。
- CSRF 対策: 同一オリジン (Origin が上の許可ホストで、転送元ホストと一致。`Sec-Fetch-Site`) と独自ヘッダ `X-Obs-Csrf: 1`、`Content-Type: application/json` が必須。書き込みは 1 分 30 件まで。
- 読み取り (`GET /am/api/v2/alerts`、`/am/api/v2/silences`、`/am/ops`) は他と同じく伏せ字付きです。Alertmanager 自体はホストにも LAN にも公開しません。

送信の再試行: 宛先が 429 / 5xx / 応答なし (タイムアウト・接続できない) のときは Alertmanager に失敗を返し、Alertmanager が再送します (`Retry-After` が 10 秒以内なら notify-relay がその場で 1 回だけ待って再送)。3xx (転送は追わない: 認証ヘッダを他へ送らない)・その他の 4xx・SMTP の 5xx は再送しません。LINE には `X-Line-Retry-Key` を付け、同じ通知の再送が二重に届かないようにします。notify-relay は専用の uid (10095) で動き、秘密値の入った relay.json はその uid だけが読めます (同じボリュームを読む Prometheus / Alertmanager からは読めません)。画面の「通知済」は notify-relay の記録 (Loki、最大 7 日 + 1 時間・新しい 5000 件まで、1 分ごとに読み直し) によります。記録が読めないときは「通知済」や次回時刻を出さず `不明` にします (抑止・確認の状態は Alertmanager から分かるので表示します)。

testbed (`docker compose --env-file testbed/testbed.env up -d --build`) では `testbed/receivers.yaml` の 5 種類の通知先がすべて `notifymock` に向いています (ダミーの秘密値)。`tools notify-test` で全部 OK になり、notifymock の記録 (`docker compose --env-file testbed/testbed.env exec notifymock python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8080/captures').read().decode())"`) で本文・宛先・伏せ字・復旧通知を確かめられます。

Grafana の wallboard の WAN パネルは、機器台帳の `wan_interface` (デモは rtx1300 lan2) から setup が生成する記録ルール `obs_wan:ifHCInOctets:rate1m` / `obs_wan:ifHCOutOctets:rate1m` を表示します (WAN 未設定ならデータなし)。

## 既知の制限 (P1 時点)

- 実機 (RTX/WLX) では未検証です。SNMPv3 の方式・syslog の形式・機器側コマンドは実機で確かめる必要があります。
- command-center は proxy の `/obs/config.json` (setup が生成: profile・フロー収集の有無・台帳の機器名と種別。アドレスや資格情報は含まない) で動作を切り替えます。60 秒ごとに取り直し、内容が変わっていれば (初回の取得に失敗していた、`tools targets` で台帳を変えた など) 画面を読み込み直します。調査中 (INVESTIGATE) は読み込み直さず、WALLBOARD に戻ったとき (Esc / BACK TO LIVE / 無操作) に読み込み直します。prod では `DEMO DATA / SYNTHETIC` 表示を出さず、機器一覧は台帳の機器、通信先 (地球儀・TOP DESTINATIONS / SOURCES・UNKNOWN GEO と詳細画面) は「no flow source configured (P3)」の表示になり、フロー未設定は鮮度バッジの DEGRADED / STALE の理由に数えません (設定済みのソースが止まった場合の STALE はこれまでどおり)。WIRELESS CLIENTS は prod では見出しが `MIB unconfirmed` になり、WLX ごとの値は不明 (—) で、0 は表示しません (鮮度バッジには影響しません)。
