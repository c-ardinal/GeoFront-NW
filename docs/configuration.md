# 設定

## 設定ディレクトリ

現場単位の設定はリポジトリ外部の設定ディレクトリ `OBS_CONFIG_DIR` に配置します。リポジトリには例 (`config.example/`) のみ存在します。

```
$OBS_CONFIG_DIR/               例 /etc/geofront。既定は ~/.config/geofront
  .env                         設定と秘密値 (権限 600)。例: config.example/.env.example
  inventory/devices.yaml       機器台帳。例: config.example/inventory/devices.example.yaml
  alerting/receivers.yaml      送信先 (任意)。例: config.example/alerting/receivers.example.yaml
  backups/                     tools backup の出力先
```

- `./geofront` は `docker compose` と同一の引数で利用可能なラッパーです。設定ディレクトリの `.env` を読み込み、tools コンテナには設定ディレクトリを `/config` としてマウントします。
- `OBS_CONFIG_DIR` は絶対パスで指定してください。ディレクトリ不在の場合は権限 700 で作成します。
- ラッパーなしでの稼働も可能です (`OBS_CONFIG_DIR=/etc/geofront docker compose --env-file /etc/geofront/.env ...`)。
- 全設定値は環境変数で上書き可能です。環境変数は `.env` より優先します。
- 設定・アドレス・秘密値・pcap・DB のコミットは厳禁です。コミット前の確認には `scripts/leak-scan.sh` を利用します ([operations.md](operations.md))。

## 旧配置からの移行

リポジトリ内部に `.env` を配置する旧配置も引続き動作します。設定のリポジトリ外部への移動手順は以下のとおりです。

```sh
./geofront run --rm tools backup --include-env
OBS_CONFIG_DIR=/etc/geofront ./geofront run --rm tools migrate-config
export OBS_CONFIG_DIR=/etc/geofront
./geofront up -d --build --remove-orphans && ./geofront run --rm tools check
```

`migrate-config` は設定のコピーのみ実施し、元ファイルは保持します。移動先に同一ファイルが存在する場合は停止します (`--force` 指定時は上書きし、元ファイルを `.bak-*` として保持します)。
動作確認後、migrate-config が表示したリポジトリ内の旧ファイルを削除してください。データボリュームは移行前と同一のものを使用します。

## .env の主な項目

全項目と既定値は `config.example/.env.example` に記載しています。必須項目は `tools init` が出力します。

| 項目 | 既定 | 内容 |
|---|---|---|
| `COMPOSE_PROFILES` | なし | `prod` (実機)、`demo`、`prod,capture` (パケットキャプチャあり) |
| `COMPOSE_PROJECT_NAME` | `yamaha-observatory-trial` | コンテナとボリュームの名称。旧ボリュームのないホストで `./geofront` から新規導入した場合は `geofront-nw` です。`tools init` が設定値を固定します。変更すると既存データが参照不可になります |
| `OBS_BIND` / `OBS_PORT` | `127.0.0.1` / `8080` | 画面の公開アドレス。LAN 側の IP か `0.0.0.0` の指定で LAN に公開します (ログインと HTTPS が必須) |
| `OBS_PUBLIC_URL` | `http://127.0.0.1:8080` | 画面・ログイン・通知のリンク用 URL |
| `OBS_AUTH` | `0` | `1` の場合は 127.0.0.1 でもログインが必須です |
| `OBS_AUTH_*` | なし | ログインの秘密値と、セッション・ロックアウトの設定 ([security.md](security.md)) |
| `SYSLOG_BIND` / `SYSLOG_PORT` | `127.0.0.1` / `514` | syslog の受信先 (UDP / TCP)。機器からの受信にはホストの LAN 側 IP を指定します |
| `PROM_LOCAL_PORT` | `9090` | 本ホスト限定で参照可能な Prometheus (読取専用) |
| `SYSLOG_DROP_UNKNOWN` | `0` | `1` の場合、台帳にない送信元からの syslog を破棄します |
| `SNMP_V3_USER` `SNMP_V3_AUTH_PROTO` `SNMP_V3_AUTH_PASS` `SNMP_V3_PRIV_PROTO` `SNMP_V3_PRIV_PASS` | 方式は `SHA` / `AES` | SNMPv3 authPriv のユーザーと方式とパスワード |
| `SNMP_COMMUNITY` | 空 | SNMPv2c のコミュニティ。v3 非対応の機器がある場合のみ設定します |
| `OBS_INVENTORY` / `OBS_RECEIVERS` | `inventory/devices.yaml` / `alerting/receivers.yaml` | 台帳と送信先のパス |
| `SMTP_*` `SLACK_WEBHOOK_URL` `DISCORD_WEBHOOK_URL` `LINE_CHANNEL_ACCESS_TOKEN` `WEBHOOK_*` | なし | 送信先の秘密値 ([notifications.md](notifications.md)) |
| `OBS_CAPTURE` `CAPTURE_*` `OBS_LAN_CIDRS` `PCAP_*` | なし | パケットのキャプチャと解析 ([capture.md](capture.md)) |
| `SURGE_FACTOR` / `SURGE_MIN_KBPS` / `SURGE_BASELINE` | `3` / `200` / `1h` | 通信の急増の判定 ([ui.md](ui.md)) |
| `PROM_RETENTION` / `PROM_RETENTION_SIZE` | `30d` / `0` | メトリクスの保存期間と容量の上限 (例 `8GB`。古い順に削除) |
| `LOKI_RETENTION` | `720h` | syslog の保存期間 |
| `*_MEM` / `*_CPUS`、`LOG_MAX_SIZE` / `LOG_MAX_FILE` | Pi 4 向け | リソースの上限と、コンテナログのローテーション ([operations.md](operations.md)) |
| `GEOFRONT_VERSION` | `local` | `local` はローカルでビルドします。リリースのタグ (例 `v1.0.0`) の指定で配布イメージを使用します |
| `DEMO_AUTO_FAULTS` | `1` | デモで、一定間隔で異常を自動発生させます |
| `TZ` | `Asia/Tokyo` | tools のタイムゾーン。バックアップのファイル名に使用します |

## 秘密値のファイル指定

`./geofront` の利用時は、秘密値を `.env` への記載の代替としてファイルから指定可能です。
環境変数か `.env` に `<名称>_FILE=/path` を記載すると、該当ファイルの内容が設定値になります。`tools init` はこの設定値を `.env` に出力しません。

ファイル指定が可能な設定値: `SNMP_V3_AUTH_PASS` `SNMP_V3_PRIV_PASS` `SNMP_COMMUNITY` `SMTP_PASSWORD` `SLACK_WEBHOOK_URL`
`DISCORD_WEBHOOK_URL` `LINE_CHANNEL_ACCESS_TOKEN` `WEBHOOK_URL` `WEBHOOK_BEARER_TOKEN` `OBS_AUTH_SESSION_SECRET`
`OBS_AUTH_STORAGE_KEY` `OBS_AUTH_PROXY_KEY`

## 機器台帳

機器台帳は設定ディレクトリの `inventory/devices.yaml` です。

```yaml
devices:
  - name: rtx1300          # 表示名 (英小文字・数字・- _)。unknown は予約語のため使用不可
    kind: rtx              # rtx | wlx | other (ドライバの選択)
    address: 192.168.100.1 # 管理 IP (推奨) か DNS 名。host:port も記載可能
    snmp_auth: yamaha_v3   # yamaha_v3 (SNMPv3、推奨) | yamaha_v2c
    syslog: true
    wan_interface: lan2    # 任意。1 台のみに記載。WAN の表示と WanHighUtilization アラートに使用
  - name: wlx413
    kind: wlx
    address: 192.168.100.2
    snmp_auth: yamaha_v3
    syslog: true
    parent: rtx1300        # 任意。ネットワーク図で上位の接続先機器
    parent_if: lan1        # 任意。上位機器側の ifName
    uplink_if: lan1        # 任意。本機器側の ifName
```

- 台帳には秘密値を記載せず、`.env` に配置してください。
- 台帳の変更後は `./geofront run --rm tools targets` を実行します。再起動は不要です。
- syslog の送信元は `address` で照合します。`address` には DHCP の予約などで固定済みの IP を記載してください。
- DNS 名で記載した機器の IP の変更時は、`./geofront restart alloy` を実行します。
- 台帳にない送信元からの syslog は `host="unknown"` として保存します。

## 送信先

送信先は設定ディレクトリの `alerting/receivers.yaml` に記載します。書式は `config.example/alerting/receivers.example.yaml` を、手順は [notifications.md](notifications.md) を参照してください。
