# 設定

## 設定ディレクトリ

現場ごとの設定はリポジトリの外にある設定ディレクトリ `OBS_CONFIG_DIR` に置きます。リポジトリには例 (`config.example/`) だけがあります。

```
$OBS_CONFIG_DIR/               例 /etc/geofront。既定は ~/.config/geofront
  .env                         設定と秘密値 (権限 600)。例: config.example/.env.example
  inventory/devices.yaml       機器台帳。例: config.example/inventory/devices.example.yaml
  alerting/receivers.yaml      通知先 (任意)。例: config.example/alerting/receivers.example.yaml
  backups/                     tools backup の出力先
```

- `./geofront` は `docker compose` と同じ引数で使えるラッパーです。設定ディレクトリの `.env` を読み込み、tools コンテナには設定ディレクトリを `/config` としてマウントします。
- `OBS_CONFIG_DIR` は絶対パスで指定してください。ディレクトリがなければ権限 700 で作られます。
- ラッパーを使わずに動かすこともできます (`OBS_CONFIG_DIR=/etc/geofront docker compose --env-file /etc/geofront/.env ...`)。
- どの設定値も環境変数で上書きできます。環境変数は `.env` より優先されます。
- 設定・アドレス・秘密値・pcap・DB は決してコミットしないでください。コミット前の確認には `scripts/leak-scan.sh` を使います ([operations.md](operations.md))。

## 古い配置からの移行

リポジトリの中に `.env` を置く古い配置もそのまま動きます。設定をリポジトリの外へ移すには、次のように実行します。

```sh
./geofront run --rm tools backup --include-env
OBS_CONFIG_DIR=/etc/geofront ./geofront run --rm tools migrate-config
export OBS_CONFIG_DIR=/etc/geofront
./geofront up -d --build --remove-orphans && ./geofront run --rm tools check
```

`migrate-config` は設定をコピーするだけで、元のファイルは残します。移す先に同じファイルがあると止まります (`--force` を付けると上書きし、元のファイルを `.bak-*` として残します)。
動作を確かめたら、migrate-config が表示したリポジトリ内の古いファイルを消してください。データボリュームは移行の前と同じものが使われます。

## .env の主な項目

全項目と既定値は `config.example/.env.example` に載っています。必要な項目は `tools init` が書き込みます。

| 項目 | 既定 | 内容 |
|---|---|---|
| `COMPOSE_PROFILES` | なし | `prod` (実機)、`demo`、`prod,capture` (パケット取込あり) |
| `COMPOSE_PROJECT_NAME` | `yamaha-observatory-trial` | コンテナとボリュームの名前。古いボリュームがないホストで `./geofront` から新しく導入すると `geofront-nw` になります。`tools init` が値を固定します。変えると今までのデータが見えなくなります |
| `OBS_BIND` / `OBS_PORT` | `127.0.0.1` / `8080` | 画面を公開するアドレス。LAN 側の IP か `0.0.0.0` にすると LAN に公開します (ログインと HTTPS が必須) |
| `OBS_PUBLIC_URL` | `http://127.0.0.1:8080` | 画面・ログイン・通知のリンクに使う URL |
| `OBS_AUTH` | `0` | `1` にすると 127.0.0.1 でもログインが必須になります |
| `OBS_AUTH_*` | なし | ログインの秘密値と、セッション・締め出しの設定 ([security.md](security.md)) |
| `SYSLOG_BIND` / `SYSLOG_PORT` | `127.0.0.1` / `514` | syslog の受信先 (UDP / TCP)。機器から受けるにはホストの LAN 側 IP にします |
| `PROM_LOCAL_PORT` | `9090` | このホストだけで開ける Prometheus (読み取り専用) |
| `SYSLOG_DROP_UNKNOWN` | `0` | `1` にすると、台帳にない送信元からの syslog を捨てます |
| `SNMP_V3_USER` `SNMP_V3_AUTH_PROTO` `SNMP_V3_AUTH_PASS` `SNMP_V3_PRIV_PROTO` `SNMP_V3_PRIV_PASS` | 方式は `SHA` / `AES` | SNMPv3 authPriv のユーザーと方式とパスワード |
| `SNMP_COMMUNITY` | 空 | SNMPv2c のコミュニティ。v3 を使えない機器があるときだけ設定します |
| `OBS_INVENTORY` / `OBS_RECEIVERS` | `inventory/devices.yaml` / `alerting/receivers.yaml` | 台帳と通知先のパス |
| `SMTP_*` `SLACK_WEBHOOK_URL` `DISCORD_WEBHOOK_URL` `LINE_CHANNEL_ACCESS_TOKEN` `WEBHOOK_*` | なし | 通知先の秘密値 ([notifications.md](notifications.md)) |
| `OBS_CAPTURE` `CAPTURE_*` `OBS_LAN_CIDRS` `PCAP_*` | なし | パケットの取込と解析 ([capture.md](capture.md)) |
| `SURGE_FACTOR` / `SURGE_MIN_KBPS` / `SURGE_BASELINE` | `3` / `200` / `1h` | 通信の急増の判定 ([ui.md](ui.md)) |
| `PROM_RETENTION` / `PROM_RETENTION_SIZE` | `30d` / `0` | メトリクスの保存期間と容量の上限 (例 `8GB`。古いものから消えます) |
| `LOKI_RETENTION` | `720h` | syslog の保存期間 |
| `*_MEM` / `*_CPUS`、`LOG_MAX_SIZE` / `LOG_MAX_FILE` | Pi 4 向け | リソースの上限と、コンテナログのローテーション ([operations.md](operations.md)) |
| `GEOFRONT_VERSION` | `local` | `local` は手元でビルドします。リリースのタグ (例 `v1.0.0`) を指定すると配布イメージを使います |
| `DEMO_AUTO_FAULTS` | `1` | デモで、一定の間隔で異常を自動的に起こします |
| `TZ` | `Asia/Tokyo` | tools のタイムゾーン。バックアップのファイル名に使われます |

## 秘密値のファイル指定

`./geofront` を使う場合は、秘密値を `.env` に書く代わりにファイルから渡せます。
環境変数か `.env` に `<名前>_FILE=/path` と書くと、そのファイルの中身が値になります。`tools init` はこの値を `.env` に書きません。

ファイルで渡せる値: `SNMP_V3_AUTH_PASS` `SNMP_V3_PRIV_PASS` `SNMP_COMMUNITY` `SMTP_PASSWORD` `SLACK_WEBHOOK_URL`
`DISCORD_WEBHOOK_URL` `LINE_CHANNEL_ACCESS_TOKEN` `WEBHOOK_URL` `WEBHOOK_BEARER_TOKEN` `OBS_AUTH_SESSION_SECRET`
`OBS_AUTH_STORAGE_KEY` `OBS_AUTH_PROXY_KEY`

## 機器台帳

機器台帳は設定ディレクトリの `inventory/devices.yaml` です。

```yaml
devices:
  - name: rtx1300          # 表示名 (英小文字・数字・- _)。unknown は予約語なので使えません
    kind: rtx              # rtx | wlx | other (ドライバを選びます)
    address: 192.168.100.1 # 管理 IP (推奨) か DNS 名。host:port も書けます
    snmp_auth: yamaha_v3   # yamaha_v3 (SNMPv3、推奨) | yamaha_v2c
    syslog: true
    wan_interface: lan2    # 任意。1 台だけに書きます。WAN の表示と WanHighUtilization アラートに使います
  - name: wlx413
    kind: wlx
    address: 192.168.100.2
    snmp_auth: yamaha_v3
    syslog: true
    parent: rtx1300        # 任意。ネットワーク図で上位につながる機器
    parent_if: lan1        # 任意。上位の機器側の ifName
    uplink_if: lan1        # 任意。この機器側の ifName
```

- 台帳には秘密値を書かず、`.env` に置いてください。
- 台帳を変えたら `./geofront run --rm tools targets` を実行します。再起動は要りません。
- syslog の送信元は `address` で照合します。`address` には DHCP の予約などで固定した IP を書いてください。
- DNS 名で書いた機器の IP が変わったら、`./geofront restart alloy` を実行します。
- 台帳にない送信元からの syslog は `host="unknown"` として保存されます。

## 通知先

通知先は設定ディレクトリの `alerting/receivers.yaml` に書きます。書式は `config.example/alerting/receivers.example.yaml` を、手順は [notifications.md](notifications.md) を見てください。
