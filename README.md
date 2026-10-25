# YAMAHA Network Observatory - Grafana-first 試行 (デモ版)

> **DEMO DATA / synthetic**
> このスタックが表示するメトリクス・フロー・ログは、すべて `demo-gen` が生成した**疑似データ**です。
> 実機 (RTX1300 / WLX413 / WLX222) の観測値ではありません。国・都市・座標・ASN は架空の GeoIP 推定値で、
> 宛先 IP はドキュメント用予約範囲 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) のみを使います。

仕様書 (要件定義・設計・試行計画 v1.0) の G1/G2 相当 — 収集 → 保存 → Grafana DB01-Wallboard — の挙動を、
実機なしで確認するためのものです。

## 構成

| サービス | イメージ | 役割 | ホスト公開 |
|---|---|---|---|
| demo-gen | python:3.12-slim (自作, 標準ライブラリのみ) | snmp_exporter 互換 `/snmp`、フロー `/flows`、RFC3164 syslog 送信、異常注入 | 127.0.0.1:9116 |
| prometheus | prom/prometheus:v3.6.0 | SNMP/フロー/自己監視のスクレイプ (15s)、アラートルール | 127.0.0.1:9090 |
| loki | grafana/loki:3.5.5 | syslog 保存 (single binary, filesystem, tsdb v13、保持 30 日) | なし |
| alloy | grafana/alloy:v1.11.0 | syslog UDP 514 (rfc3164) 受信 → Loki | なし |
| grafana | grafana/grafana:12.2.0 | データソース・ダッシュボードをプロビジョニング | 127.0.0.1:3000 |
| mask-api | python:3.12-slim (自作, 標準ライブラリのみ) | コマンドセンター用の読み取り専用プロキシ。Prometheus/Loki の応答中の IP/MAC をサーバ側で伏せる | なし (command-center からのみ) |

ポートはすべて 127.0.0.1 のみに bind します。host network は使いません。

保持期間: syslog (Loki) は 30 日です (`loki/loki-config.yaml` の compactor retention、`retention_period: 720h`)。期限切れのデータは compactor が 10 分ごとに印を付け、2 時間後に削除します。メトリクス (Prometheus) も 30 日です (`--storage.tsdb.retention.time=30d`)。

## 起動

```sh
cp .env.example .env   # 任意。無くても起動する (Grafana admin パスワードは "admin"、初回ログイン時に変更を促される)
docker compose up -d --build
```

- Wallboard (ログイン不要・匿名 Viewer): http://127.0.0.1:3000/d/yamaha-wallboard?kiosk
- Grafana 管理: http://127.0.0.1:3000 (admin / `.env` の `GF_ADMIN_PASSWORD`)
- Prometheus: http://127.0.0.1:9090 (アラート: /alerts)

停止: `docker compose down` (データも消す場合は `docker compose down -v`)

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

- URL: http://127.0.0.1:8080/ (1920×1080 向け、スクロールなし)
- 映画の司令室風の画面。中央は自転する 3D 地球儀で、ホーム地域から各宛先へのアーク (橙 = outbound、水色 = inbound、太さ = bps)、宛先のリング、都市ラベルを描きます。左に機器状態・国別上位宛先、右に WAN Mbps とスパークライン (15 分)・online 台数・発報中アラート、下に syslog フィードを表示します。
- 表示データは Grafana と同じ Prometheus / Loki の**疑似データ**です。画面上部に `DEMO DATA / SYNTHETIC` を常時表示します。
- アークは GeoIP 推定地点との論理的な関係で、物理経路ではありません。起点 (`js/globe.js` の `ORIGIN`、既定は東京付近) は大まかな地域で、実際の住所ではありません。Unknown (GeoIP 不明) は地球儀に描かず、左の一覧と合計には含めます。宛先 IP・syslog 本文中の IP / MAC は末尾を伏せて表示します。
- アラートが 1 件でも発報中だと赤枠と `ALERT` バナー (アラート名つき) を表示し、解消すると戻ります。取得に失敗したときやデータが 2 周期 (20 秒) より古いときは `DEGRADED` / `STALE` を表示し、最後の値を薄く残します (0 にはしません)。`prefers-reduced-motion` の環境では回転・アーク・点滅を止めます。
- ブラウザは Prometheus / Loki に直接つながりません。nginx が GET の `/prom/api/v1/{query,query_range,alerts}` と `/loki/loki/api/v1/query_range` だけを中継し、それ以外の `/prom/`・`/loki/` 配下は 403 を返します。
- **外部依存 (インターネット接続が必要)**: globe.gl 2.46.2 (cdn.jsdelivr.net、SRI 付き)、three-globe 2.45.6 の地球夜景・地形・星空テクスチャ (cdn.jsdelivr.net)、Google Fonts (IBM Plex Sans / IBM Plex Mono / Orbitron)。オフラインでは地球儀が表示されません (他のパネルは動きます)。
- 別テーマ: `http://127.0.0.1:8080/?theme=eva` (または上部バーの THEME ボタン) で黒×橙基調の別デザインに切り替わります。配置・内容・データは同じで、選択はブラウザに保存されます (`?theme=default` で既定に戻す)。このテーマは追加で Google Fonts の Oswald / Noto Serif JP を使い、地球儀の国境ドットに Natural Earth 110m の国境 GeoJSON (cdn.jsdelivr.net の globe.gl@2.46.2 example データ、SRI 検証付き) を読み込みます (取得できない場合は経緯線のみで表示)。
- `?theme=eva-film` — アニメの指令室ディスプレイ風に寄せた第3テーマ（長体の極太明朝の見出し、六角ステータスセル、目盛りスケール、レーダースイープの地球儀、赤帯の警報）。THEME トグルで STD → EVA → FILM の順に切り替わり、レイアウトとデータは同一。

### コマンドセンターの操作 (調査モード)

- 何も操作していない状態は WALLBOARD (自動更新のみ)。パネルを開く・行を選ぶ・地球儀を動かすと INVESTIGATE になり、上部バーに表示されます。`Esc` か「✕ BACK TO LIVE」で WALLBOARD に戻ります。5 分間操作がないと自動で戻ります。調査中もデータは 10 秒ごとに更新され、取得できないときは詳細画面にも `STALE` を表示します (欠損を 0 にしない)。
- パネル見出し (または見出し横の ⤢) をクリックすると、そのパネルの省略なしのデータをモーダルで表示します (列見出しクリックで並べ替え)。WAN は 1h/6h/24h のグラフ、SYSLOG はホスト・重要度・文字列・期間で絞り込めるログビューア (古い行の追加読み込みあり) です。
- 行をクリックすると右側に詳細ドロワーが開き、関連データ (機器→インターフェース・1 時間グラフ・関連アラート・syslog、通信先→送信元ホスト・宛先 IP・推移、アラート→ルール式・関連機器・発報時刻前後の syslog、syslog 行→前後 20 行など) をたどれます。ドロワー内は戻る / パンくずで行き来できます。
- 地球儀はホイール / ピンチで拡大縮小、ドラッグで回転、右上の + / − / ⟲ (初期表示に戻して自動回転を再開)。通信先の点・アークにカーソルを合わせると概要、クリックで通信先の詳細を開き、その通信先 (または選んだ送信元ホスト) のアークだけを強調します。
- キーボード操作: Tab で移動、Enter で開く、Esc で閉じる。モーダル内ではフォーカスが外に出ず、閉じると元の位置に戻ります。
- IP / MAC は詳細画面でも常に末尾を伏せています。伏せ字を外す表示は、仕様 SEC-03 の認証層 (未実装) ができるまで提供しません。
  - **サーバ側マスク**: ブラウザが叩く `/prom/` `/loki/` は nginx → `mask-api` → Prometheus/Loki の順に通ります。`mask-api` は GET かつ許可パス (Prometheus `query` / `query_range` / `alerts` / `rules`、Loki `query_range`) だけを中継し、応答 JSON を解析して**全ての文字列** (ラベル名・ラベル値・ログ本文・ルール式) の IPv4 を `a.b.c.x`、MAC を `aa:bb:cc:xx:xx:xx` (区切りが `-` ならそのまま `-`) に置き換えてから返します。値そのものが 1 つの IPv4 であるラベル値 (宛先 IP など) は `203.0.113.x~<トークン>` になります。トークンは IP の HMAC-SHA256 (鍵は mask-api 起動ごとにランダム) の先頭 12 桁で、元の値は分かりませんが宛先ごとに区別できるため、宛先 IP 別の行・集計・ドリルダウンは従来どおり 1 宛先 1 行です。画面では末尾を `x` と表示し、トークンは見せません。クエリ中のトークンは mask-api が元の IP に戻して問い合わせます (発行していない・期限切れのトークンは 400。mask-api の再起動後は画面の再読込が必要)。ブラウザ側の伏せ字は二重の保険として残しています。nginx も従来どおり許可パス・GET 限定・セキュリティヘッダを持ちます。
  - 伏せた値を手掛かりに元の値を確かめられないよう、受け付けるクエリの形を絞っています (どれにも当たらないものは HTTP 400、ログビューアでは「この条件は検索できません…」と表示):
    - **Loki**: コマンドセンターが送る形だけを受け付けます。ラベル `job` / `host` / `severity` / `facility` の `=` だけからなるストリームセレクタに、文字列の `|=` / `!=` 行フィルタを任意個つけた形と、`sum by (severity)` / `sum by (host, severity)` の `count_over_time({…}[期間])` の 2 種類です。それ以外 (`|~` `|>` `!>`、パーサ、`line_format` などのステージ、正規表現マッチ、その他の集計) は拒否します。Loki に送るのは**セレクタだけ**で、行フィルタは mask-api が**伏せた後の本文**に適用します。このためフィルタが一致するのは画面に見えている文字列だけで、伏せた桁の推測には使えません (例: `|= "192.0.2.x" |= "10:443"` は伏せた本文に `10:443` が無いので常に 0 件)。フィルタがある場合は要求件数の 10 倍 (上限 5000 行) を取得してから絞り込み、件数と並び順 (direction) を合わせて返します。期間が長く条件が厳しいと、期間内に一致する行があっても返る件数が少なくなることがあります。
    - **Prometheus**: 文字列は `=` / `!=` のラベル一致の値としてだけ使えます。正規表現マッチ (`=~` `!~`) と、ラベルの文字列を読む・写す・並べる関数 (`label_replace` `label_join` `sort_by_label` `count_values` `info` `limitk` `limit_ratio`) は拒否します。パラメータは `query` と時刻 (`time` / `start` / `end` / `step`) だけです。
    - 共通: 文字列の中に完全な IPv4 / MAC、部分 IP (伏せた形とトークンを除いた残りに **数字.数字**。例 `113.50`、`2.4GHz` も該当)、部分 MAC (**4 組以上の 16 進ペア**。例 `5e:20:00:01`)、発行していないトークン、`\x2e` のように文字を隠すエスケープがあれば拒否します。
  - 伏せた形 (`203.0.113.x`、`02:00:5e:xx:xx:xx`) での絞り込みは使えます。ログビューアでは伏せた本文にそのまま一致します。Prometheus のラベル一致では「同じ先頭を持つ任意のアドレス」に書き換えます (例: `dst_ip="203.0.113.x"` は同じ /24 の全宛先)。
  - 残る制限: (1) 受け付ける形は現在の UI に合わせた許可リストです。UI に新しいクエリの形を足すときは mask-api も合わせて更新が必要です。(2) Prometheus は関数とラベル一致の値を制限する方式で、メトリクス名の許可リストは持っていません。(3) IPv6 は伏せません (デモデータに含まれません)。ドット区切りの MAC 表記 (`0200.5e10.0001`) も対象外です。(4) Grafana (127.0.0.1:3000) と Prometheus (127.0.0.1:9090) は localhost 限定の管理ツールとして生の値を表示します。マスク対象はコマンドセンター (:8080) 経由の経路だけです。
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

## 実機への切り替え

`demo-gen` は snmp_exporter の HTTP 契約 (`/snmp?target=&module=if_mib`) と if_mib のメトリクス名を模倣しています。
実機を使うときは `prometheus/prometheus.yml` の job `snmp` で

- `replacement: demo-gen:9116` を実 snmp_exporter のアドレスへ
- `targets` を実機の管理 IP へ

変更し、RTX/WLX の syslog 送信先をこのホストの UDP 514 にします (compose で alloy の 514/udp を公開する必要あり)。
`demo_wlan_clients` と `/flows` はデモ専用で、実機の対応 MIB・フロー収集 (P2) は未確定です。

## 既知の観察事項 (実機検証で確認すべき点)

- RFC3164 パーサは、タグ無しで始まる YAMAHA 風メッセージの先頭語をタグとして解釈します。例: `PP[01] Rejected at ...` は本文が `01] Rejected at ...`、`LAN2: link up` は `link up` になります。実機ログの形式を採取してパーサを調整する必要があります (仕様 08 / TC-003)。
- syslog は受信時刻でタイムスタンプされます (RFC3164 はタイムゾーンを持たないため)。
