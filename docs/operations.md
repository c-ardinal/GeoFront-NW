# 運用

## 自己診断

```sh
scripts/doctor.sh                      # ホストの項目も含めた診断
./geofront run --rm tools doctor       # ホストの項目を除いた診断
```

doctor.sh は以下の項目を調査します。機器には接続しません。

- Docker 25 以上と compose
- CPU (arm64 / amd64)、メモリ、ディスク
- 時刻 (NTP)
- ポートの衝突
- `.env` と台帳
- 利用者不在の LAN 公開
- 証明書
- コミット禁止のデータ

結果は OK / WARN / NG と対処方法の表で出力し、NG がある場合は終了コード 1 で終了します。

## 動作の確認

```sh
./geofront run --rm tools check
```

設定、各機器への SNMP、syslog の受信 (既定で 60 秒待機)、送信先、各サービスの health を確認します。

## バックアップと復元

```sh
./geofront run --rm tools backup                      # <設定ディレクトリ>/backups/obs-backup-<日時>.tar.gz
./geofront run --rm tools backup --include-env        # .env (秘密値) も格納
./geofront run --rm tools backup --include-captures   # キャプチャとアップロード済み pcap も格納
```

バックアップにはメトリクス・syslog・抑止と ACK・ログインの利用者・認証局の証明書と鍵・機器台帳・送信先を格納します。
稼働中でも取得可能です。鍵と秘密値を含むため、アーカイブの管理に注意してください。
他ホストへの復元時は `--include-env` を指定して `.env` も格納してください。TOTP の鍵は `.env` の `OBS_AUTH_STORAGE_KEY` なしでは読込不可です。

restore は各ボリュームの現在の内容を削除し、アーカイブの内容に置換します。

```sh
./geofront stop prometheus loki alertmanager authelia proxy
./geofront run --rm tools restore backups/obs-backup-XXXXXXXX-XXXXXX.tar.gz                  # --yes で確認を省略
./geofront run --rm tools restore backups/obs-backup-XXXXXXXX-XXXXXX.tar.gz --with-config    # 台帳・送信先・.env も復元
./geofront up -d
```

`--include-captures` で取得したアーカイブの復元時は、`./geofront stop capture flowd flowd-demo mask-api` も事前に実行してください。
対象サービスの稼働中は、restore は何も変更せず停止します。

## 更新

```sh
./geofront run --rm tools backup --include-env
git pull
./geofront pull --ignore-buildable
scripts/doctor.sh
OBS_COMMIT=$(git rev-parse --short HEAD) ./geofront up -d --build --remove-orphans
./geofront run --rm tools check
```

- `--remove-orphans` の指定で、不使用になったサービスのコンテナを削除します。
- `OBS_COMMIT` は証跡に記録するバージョンの情報です。未指定の場合は `unknown` です。
- LAN 公開中の構成では、旧バージョンからの更新でログインが必須になります。事前に `tools user secrets` と `tools user add <名称> --role admin` を実行してください。

配布イメージの利用時は、`.env` に `GEOFRONT_VERSION=v1.0.0` のようにタグを記載し、`./geofront pull` と `./geofront up -d` を実行します。

## 検証

```sh
scripts/verify.sh                          # quick: selftests compose leak-scan doctor (数分)
scripts/verify.sh full                     # selftests compose leak-scan e2e-open e2e-auth resilience backup-restore upgrade arm64 (doctor は含まない)
scripts/verify.sh e2e-auth backup-restore  # 名称の列挙で一部のみ実行
```

GitHub Actions の `full-verify` ワークフローでも同一の検証を実行可能です (手動実行と、develop から main へのリリース PR で起動)。amd64 のランナーで e2e-open・ui-check・e2e-auth・resilience・backup-restore・upgrade を、arm64 のランナー (Raspberry Pi と同一アーキテクチャ) で selftests と e2e-open を実行し、結果の表を実行のサマリーに出力します。

verify.sh の実行には、ホストに bash・docker・python3 が必要です。検証は別プロジェクト (`obs-e2e-*`) で実施し、終了後に削除します。運用中のプロジェクトには影響しません。
他の検証との同時実行時は、`E2E_TAG=<名称>` と `E2E_SLOT=1`〜`5` で、プロジェクト名とポートを分離してください。

推移とログ検索の画面は `scripts/ui-check.js` でブラウザから確認可能です (Node.js と playwright-core が必要。e2e-open を `KEEP=1` で保持したプロジェクトに使用)。

```sh
PW_CORE=<playwright-core のディレクトリ> CHROME=<Chromium の実行ファイル> node scripts/ui-check.js http://127.0.0.1:28080
```

| 検査 | 内容 |
|---|---|
| selftests | 自作イメージをビルドし、各 selftest を実行 |
| compose | 各構成で compose の設定を解決可能 |
| leak-scan | コミット禁止のデータが不在 |
| doctor | `scripts/doctor.sh` |
| e2e-open / e2e-auth | 新規コピーで init から check まで通過 (ログインなし / ログインあり)。`E2E_LAN_IP=<LAN の IP>` で LAN 公開を試験 |
| resilience | サービスを 1 件ずつ停止し、画面のエラー表示と起動後の復旧を確認。`REBOOT_CMD="sudo systemctl restart docker"` でホスト再起動の近似状態も試験 |
| backup-restore | バックアップを別プロジェクトに復元し、内容の一致を確認 |
| upgrade | 旧バージョンのデータボリュームを現行バージョンで起動可能 |
| arm64 | イメージが linux/arm64 と linux/amd64 を含み、arm64 でビルド可能 |

Raspberry Pi への導入後は、以下の順に確認してください。

1. `scripts/verify.sh quick` を実行します。
2. `E2E_LAN_IP=<Pi の LAN の IP> scripts/verify.sh e2e-open e2e-auth resilience backup-restore` を実行します。
3. `sudo reboot` で再起動し、`./geofront ps` で全件 healthy (loki はヘルスチェックなしで Up)、`tools check` が OK となることを確認します。

## コミット禁止データの検査

```sh
scripts/leak-scan.sh              # コミット対象になり得るファイル
scripts/leak-scan.sh --staged     # 次回コミットの内容
scripts/leak-scan.sh --history    # 全履歴
git config core.hooksPath scripts/git-hooks   # コミット時に毎回検査 (任意)
```

ドキュメント用以外のアドレス、機器固有の MAC、秘密鍵、トークン、パスワードなどの検出時は NG です。
テスト用の数値を例外とする場合は、`scripts/leak-allow.txt` に 1 行単位で記載するか、行に `leak-scan: allow` を付与します。

## 疑似実機での試験

testbed は実機の代替として疑似機器 (SNMP シミュレータと syslog の送信器) で prod の構成を稼働させます。
`.env` には影響せず、別プロジェクトと別ポート (画面 18080、Prometheus 19090、syslog 10514) で動作します。

```sh
docker compose --env-file testbed/testbed.env up -d --build
docker compose --env-file testbed/testbed.env run --rm tools check
docker compose --env-file testbed/testbed.env run --rm tools test-syslog    # syslog 解析の回帰テスト
docker compose --env-file testbed/testbed.env run --rm tools notify-test    # 通知はモックに到達
docker compose --env-file testbed/testbed.env down -v
```

Linux ホストではパケットキャプチャの経路も試験可能です (`COMPOSE_PROFILES=prod,testbed,capture OBS_CAPTURE=1 CAPTURE_IFACE=br-<testbed のネットワーク ID の先頭 12 文字>` を指定して起動)。

## デモの異常

デモでは `DEMO_AUTO_FAULTS=1` (既定) の場合、約 4 分間隔で異常が発生します。停止には `.env` に `DEMO_AUTO_FAULTS=0` を設定し、手動での発生には以下のコマンドを使用します。

```sh
curl "http://127.0.0.1:9116/fault/down?target=wlx222&seconds=120"   # DeviceDown
curl "http://127.0.0.1:9116/fault/wanspike?seconds=120"              # WanHighUtilization
curl "http://127.0.0.1:9116/fault/logburst?seconds=60"               # InterfaceErrors
curl "http://127.0.0.1:9116/fault/counter_reset?target=rtx1300"      # DeviceRebooted
curl "http://127.0.0.1:9116/fault/status"
```

## トラブルの対処

| 症状 | 対処 |
|---|---|
| `up -d` で「profile の設定が存在しません」と表示して停止 | `--profile demo` を指定するか、`tools init` で `.env` を生成 |
| 画面を表示できない (LAN 公開中) | 利用者の有無を確認 (`tools user list`)。`./geofront logs authelia` を参照 |
| ブラウザが証明書の警告を表示 | 端末にルート証明書を登録 ([security.md](security.md)) |
| ログイン不可 | ロックアウトの有無を確認し、必要に応じて解除 ([security.md](security.md)) |
| `tools check` で SNMP が NG | 表示された原因の目安を確認 ([devices.md](devices.md)) |
| syslog が未着 | `SYSLOG_BIND` が LAN 側の IP か、台帳の `address` と送信元の一致を確認。DNS 名で記載した機器の IP の変更時は `./geofront restart alloy` |
| 検索で「unknown or expired address token」と表示 | ページを再読込 |
| パケットキャプチャが動作しない | [capture.md](capture.md) の確認手順に従って調査 |

## Raspberry Pi での推奨設定

既定値は Raspberry Pi 4 (4 GB) 向けに設定済みです。

- SD カードの容量が少ない場合は、`PROM_RETENTION_SIZE` (例 `8GB`) で容量の上限を設定してください。

## 表示端末の描画モード

地球儀は WebGL で描画します。⋯ メニューの `RENDER:` で描画モードを選択可能です (AUTO → GPU → LITE)。URL への `?render=lite` の付与は、該当表示のみに適用されます。

| モード | 内容 |
|---|---|
| `GPU` | 地球儀のアニメーション表示 (アークの流れ、パルス、自転) |
| `LITE` | 同一情報を静止表示で描画します。データ更新時と操作時のみ描画するため、CPU の負荷が軽減します |
| `AUTO` (既定) | WebGL 非対応時やソフトウェア描画時は LITE、それ以外は GPU |

Raspberry Pi の Chromium を表示端末にする場合は、以下の点を確認してください。

- `chrome://gpu` で「WebGL: Hardware accelerated」と表示され、WebGL のレンダラが `V3D` であれば GPU を使用中です。`llvmpipe` や「Software only」はソフトウェア描画です。
- Raspberry Pi OS (Bookworm) では `/boot/firmware/config.txt` の `dtoverlay=vc4-kms-v3d` で GPU が有効になります。Chromium が GPU を不使用の場合は、起動オプションに `--ignore-gpu-blocklist` を追加してください。
- 4K の画面や、Pi で収集サーバを兼用する場合は LITE を推奨します。

```sh
chromium-browser --kiosk --noerrdialogs --disable-infobars http://<host>:8080/?render=lite
```

## リソースと保存期間

メモリと CPU の上限は `.env` の `*_MEM` / `*_CPUS` で変更可能です (一覧は `config.example/.env.example`)。
コンテナのログは `LOG_MAX_SIZE` (既定 10m) × `LOG_MAX_FILE` (既定 3) でローテーションします。

| 項目 | 既定 | 内容 |
|---|---|---|
| `PROM_RETENTION` | `30d` | メトリクスの保存期間 |
| `PROM_RETENTION_SIZE` | `0` (上限なし) | メトリクスの容量の上限。古いブロックから削除 |
| `LOKI_RETENTION` | `720h` | syslog の保存期間 |
| `ALERTMANAGER_RETENTION` | `168h` | 抑止と通知の記録の保存期間 |
| `AUTHELIA_MEM` | `256m` | ログインのメモリの上限 |
| `ANALYZER_MEM` | `896m` | パケット解析のメモリの上限 ([capture.md](capture.md)) |
