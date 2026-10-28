# GeoFront-NW

GeoFront-NW は宅内ネットワークを観測するための docker compose 一式です。ルーターやアクセスポイントから
SNMP・syslog・パケットを集め、Grafana と専用の司令室画面 (コマンドセンター) に表示します。
YAMAHA RTX / WLX 用のドライバが付属しています。他社の機器にはドライバを追加して対応します ([docs/drivers.md](docs/drivers.md))。

## 機能

- 機器の状態・WAN の速度・インターフェースのエラーを SNMPv3 で集めます
- syslog を受信して保存し、画面から検索できます
- 通信先を 3D の地球儀に表示します (パケット取込と GeoIP)
- アラートをメール / Slack / Discord / LINE / Webhook に通知し、画面から抑止や ACK ができます
- パケットをブラウザで解析できます (IP / MAC は伏せ字で表示します)
- 過去の時刻を再生し、証跡を zip で出力できます
- ネットワーク図を表示し、通信の急増と原因候補を一覧にします
- LAN に公開するときは、ログインと HTTPS が必須になります

## 必要なもの

- Linux (arm64 / amd64) または Raspberry Pi 4 (4 GB、64 bit OS)
- Docker Engine 25 以上と compose v2 (plugin)

ホストに Python などを入れる必要はありません。設定の作業は `tools` コンテナで行います。

## デモで試す

デモは疑似データで動くので、実機も設定ファイルも要りません。

```sh
git clone https://github.com/c-ardinal/GeoFront-NW.git && cd GeoFront-NW
docker compose --profile demo up -d --build
```

コマンドセンターは http://127.0.0.1:8080/ で、Grafana は http://127.0.0.1:8080/grafana/ (admin / admin) で開きます。
止めるときは `docker compose --profile demo stop` を実行します。データごと消すときは `down -v` を使います。

## 本番への導入

設定はリポジトリの外にある設定ディレクトリ `OBS_CONFIG_DIR` に置きます。既定の場所は `~/.config/geofront` です。
以下の手順では `docker compose` の代わりにラッパーの `./geofront` を使います。

1. リポジトリを取得します。
   ```sh
   git clone https://github.com/c-ardinal/GeoFront-NW.git && cd GeoFront-NW
   export OBS_CONFIG_DIR=/etc/geofront      # 任意
   ```
2. 初期設定を行います。対話形式で `.env` と機器台帳が作られます。
   ```sh
   ./geofront run --rm tools init
   ```
   対話なしで実行するときの例です。
   ```sh
   ./geofront run --rm -e GF_ADMIN_PASSWORD=... -e SNMP_V3_AUTH_PASS=... -e SNMP_V3_PRIV_PASS=... \
     tools init --yes --snmp-user obs --syslog-bind 192.168.100.10 \
     --device rtx1300,rtx,192.168.100.1 --device wlx413,wlx,192.168.100.2 --wan rtx1300:lan2
   ```
3. 機器側で SNMPv3 のユーザーと syslog の送信先を設定します ([docs/devices.md](docs/devices.md))。
   `--bind` に LAN 側の IP を指定して LAN に公開する場合は、ログインする利用者も作ってください。
   ```sh
   ./geofront run --rm tools user add yamada --role admin
   ```
4. 導入前の自己診断を実行します。NG の項目があれば、表に出る直し方に従って直してください。
   ```sh
   scripts/doctor.sh
   ```
5. 起動します。
   ```sh
   ./geofront up -d --build
   ```
6. 動作を確認します。SNMP・syslog の受信・各サービスの health がすべて OK になれば完了です。
   ```sh
   ./geofront run --rm tools check
   ```

画面は `.env` の `OBS_PUBLIC_URL` (例 `https://192.168.100.10:8080`) で開きます。
LAN に公開した場合は、各端末にルート証明書を登録してください ([docs/security.md](docs/security.md))。

## 更新

```sh
./geofront run --rm tools backup --include-env
git pull && scripts/doctor.sh
OBS_COMMIT=$(git rev-parse --short HEAD) ./geofront up -d --build --remove-orphans && ./geofront run --rm tools check
```

## バックアップと復元

```sh
./geofront run --rm tools backup
./geofront run --rm tools restore backups/obs-backup-XXXXXXXX-XXXXXX.tar.gz
```

バックアップは `<設定ディレクトリ>/backups/` に作られます。復元する前には対象のサービスを止めてください。
止めるサービスと各オプションは [docs/operations.md](docs/operations.md#バックアップと復元) に載っています。

## ドキュメント

| ドキュメント | 内容 |
|---|---|
| [docs/configuration.md](docs/configuration.md) | 設定ディレクトリ、`.env` の項目、`*_FILE`、機器台帳、通知先 |
| [docs/devices.md](docs/devices.md) | 機器側の設定例 (RTX / WLX の SNMPv3 と syslog、LLDP) |
| [docs/notifications.md](docs/notifications.md) | アラートの通知、抑止と ACK |
| [docs/security.md](docs/security.md) | LAN への公開とログイン、役割、証明書、利用者の管理、伏せ字 |
| [docs/capture.md](docs/capture.md) | パケットの取込と解析、GeoIP、プライバシー |
| [docs/operations.md](docs/operations.md) | 検証、自己診断、トラブルの対処、Raspberry Pi、リソース |
| [docs/ui.md](docs/ui.md) | 画面の使い方 (Wallboard、コマンドセンター、履歴再生、証跡、ネットワーク図、原因候補) |
| [docs/drivers.md](docs/drivers.md) | 機種ドライバと他社の機器の追加 |

## ライセンス

本体は MIT License ([LICENSE](LICENSE)) です。利用している OSS とデータは [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) に載せています
(GeoIP: IP Geolocation by [DB-IP](https://db-ip.com)、CC BY 4.0)。YAMAHA / RTX / WLX は Yamaha Corporation の商標で、本プロジェクトは同社とは関係ありません。
