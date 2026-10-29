# 運用

## 自己診断

```sh
scripts/doctor.sh                      # ホストの項目も含めた診断
./geofront run --rm tools doctor       # ホストの項目を除いた診断
```

doctor.sh は次の項目を調べます。機器には接続しません。

- Docker 25 以上と compose
- CPU (arm64 / amd64)、メモリ、ディスク
- 時刻 (NTP)
- ポートの衝突
- `.env` と台帳
- 利用者のいない LAN 公開
- 証明書
- コミットしてはいけないデータ

結果は OK / WARN / NG と直し方の表で出て、NG があると終了コード 1 で終わります。

## 動作の確認

```sh
./geofront run --rm tools check
```

設定、各機器への SNMP、syslog の受信 (既定で 60 秒待ちます)、通知先、各サービスの health を確かめます。

## バックアップと復元

```sh
./geofront run --rm tools backup                      # <設定ディレクトリ>/backups/obs-backup-<日時>.tar.gz
./geofront run --rm tools backup --include-env        # .env (秘密値) も含める
./geofront run --rm tools backup --include-captures   # キャプチャとアップロードした pcap も含める
```

バックアップにはメトリクス・syslog・Grafana (データがあるときだけ)・抑止と ACK・ログインの利用者・認証局の証明書と鍵・機器台帳・通知先が入ります。
動かしたままでも取れます。鍵と秘密値が入るので、アーカイブの扱いに注意してください。
別のホストに戻すときは `--include-env` を付けて `.env` も含めてください。TOTP の鍵は `.env` の `OBS_AUTH_STORAGE_KEY` がないと読めません。

restore は各ボリュームの今の中身を消して、アーカイブの内容に置き換えます。

```sh
./geofront stop prometheus loki grafana alertmanager authelia proxy
./geofront run --rm tools restore backups/obs-backup-XXXXXXXX-XXXXXX.tar.gz                  # --yes で確認を省く
./geofront run --rm tools restore backups/obs-backup-XXXXXXXX-XXXXXX.tar.gz --with-config    # 台帳・通知先・.env も戻す
./geofront up -d
```

`--include-captures` で取ったアーカイブを戻すときは、`./geofront stop capture flowd flowd-demo mask-api` も先に実行してください。
対象のサービスが動いていると、restore は何も変えずに止まります。

## 更新

```sh
./geofront run --rm tools backup --include-env
git pull
./geofront pull --ignore-buildable
scripts/doctor.sh
OBS_COMMIT=$(git rev-parse --short HEAD) ./geofront up -d --build --remove-orphans
./geofront run --rm tools check
```

- `--remove-orphans` を付けると、使われなくなったサービスのコンテナが消えます。
- `OBS_COMMIT` は証跡に記録されるバージョンの情報です。渡さないと `unknown` になります。
- LAN に公開している構成では、以前のバージョンから更新するとログインが必須になります。先に `tools user secrets` と `tools user add <名前> --role admin` を実行してください。

配布イメージを使うときは、`.env` に `GEOFRONT_VERSION=v1.0.0` のようにタグを書き、`./geofront pull` と `./geofront up -d` を実行します。

## 検証

```sh
scripts/verify.sh                          # quick: selftests compose leak-scan doctor (数分)
scripts/verify.sh full                     # selftests compose leak-scan e2e-open e2e-auth resilience backup-restore upgrade arm64 (doctor は含まない)
scripts/verify.sh e2e-auth backup-restore  # 名前を並べて一部だけ
```

verify.sh を動かすには、ホストに bash・docker・python3 が要ります。検証は別のプロジェクト (`obs-e2e-*`) で行い、終わると消します。運用中のプロジェクトには触れません。
e2e-open / e2e-auth は既定で Grafana なしで試します。`E2E_GRAFANA=1` を付けると Grafana も動かして試します。
ほかの検証と同時に動かすときは、`E2E_TAG=<名前>` と `E2E_SLOT=1`〜`5` で、プロジェクト名とポートを分けてください。

推移とログ検索の画面は `scripts/ui-check.js` でブラウザから確かめられます (Node.js と playwright-core が要ります。e2e-open を `KEEP=1` で残したプロジェクトに使います)。

```sh
PW_CORE=<playwright-core のディレクトリ> CHROME=<Chromium の実行ファイル> node scripts/ui-check.js http://127.0.0.1:28080
```

| 検査 | 内容 |
|---|---|
| selftests | 自作イメージをビルドし、各 selftest を実行する |
| compose | 各構成で compose の設定を解決できる |
| leak-scan | コミットしてはいけないデータがない |
| doctor | `scripts/doctor.sh` |
| e2e-open / e2e-auth | 新しいコピーで init から check まで通す (ログインなし / ログインあり)。`E2E_LAN_IP=<LAN の IP>` で LAN に公開して試す |
| resilience | サービスを 1 つずつ止めて、画面がエラーを示し、起動すると戻る。`REBOOT_CMD="sudo systemctl restart docker"` でホストの再起動に近い状態も試す |
| backup-restore | バックアップを別のプロジェクトに戻して、内容が一致する |
| upgrade | 前のバージョンのデータボリュームを今のバージョンで起動できる |
| arm64 | イメージが linux/arm64 と linux/amd64 を含み、arm64 でビルドできる |

Raspberry Pi に導入したら、次の順に確かめてください。

1. `scripts/verify.sh quick` を実行します。
2. `E2E_LAN_IP=<Pi の LAN の IP> scripts/verify.sh e2e-open e2e-auth resilience backup-restore` を実行します。
3. `sudo reboot` で再起動し、`./geofront ps` ですべて healthy (loki はヘルスチェックなしで Up)、`tools check` が OK になることを確かめます。

## コミットしてはいけないデータの検査

```sh
scripts/leak-scan.sh              # コミットされうるファイル
scripts/leak-scan.sh --staged     # 次のコミットの中身
scripts/leak-scan.sh --history    # 全履歴
git config core.hooksPath scripts/git-hooks   # コミットのたびに検査する (任意)
```

ドキュメント用以外のアドレス、機器固有の MAC、秘密鍵、トークン、パスワードなどが見つかると NG になります。
テストの値を例外にするときは、`scripts/leak-allow.txt` に 1 行ずつ書くか、行に `leak-scan: allow` を付けます。

## 疑似実機での試験

testbed は実機の代わりに疑似の機器 (SNMP シミュレータと syslog の送信器) で prod の構成を動かします。
`.env` には触れず、別のプロジェクトと別のポート (画面 18080、Prometheus 19090、Grafana 13000、syslog 10514) で動きます。

```sh
docker compose --env-file testbed/testbed.env up -d --build
docker compose --env-file testbed/testbed.env run --rm tools check
docker compose --env-file testbed/testbed.env run --rm tools test-syslog    # syslog の解析の回帰テスト
docker compose --env-file testbed/testbed.env run --rm tools notify-test    # 通知はモックに届く
docker compose --env-file testbed/testbed.env down -v
```

Linux ホストではパケット取込の経路も試せます (`COMPOSE_PROFILES=prod,testbed,capture OBS_CAPTURE=1 CAPTURE_IFACE=br-<testbed のネットワーク ID の先頭 12 文字>` を付けて起動します)。

## デモの異常

デモでは `DEMO_AUTO_FAULTS=1` (既定) のとき、約 4 分ごとに異常が起こります。止めるときは `.env` を `DEMO_AUTO_FAULTS=0` にし、手で起こすときは次のコマンドを使います。

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
| `up -d` で「profile が指定されていません」と出て止まる | `--profile demo` を付けるか、`tools init` で `.env` を作る |
| 画面が開かない (LAN に公開している) | 利用者がいるか確かめる (`tools user list`)。`./geofront logs authelia` を見る |
| ブラウザが証明書の警告を出す | 端末にルート証明書を登録する ([security.md](security.md)) |
| ログインできない | 締め出されていないか確かめ、必要なら解除する ([security.md](security.md)) |
| `tools check` で SNMP が NG | 表示された原因の目安を確かめる ([devices.md](devices.md)) |
| syslog が届かない | `SYSLOG_BIND` が LAN 側の IP か、台帳の `address` が送信元と一致するかを確かめる。DNS 名で書いた機器の IP が変わったら `./geofront restart alloy` |
| 検索で「期限切れ」と出る | ページを読み込み直す |
| `/grafana/` が「有効になっていません」と返す | Grafana は既定で動きません。使うときは下の「Grafana を使う」の手順で有効にする |
| パケット取込が動かない | [capture.md](capture.md) の確認の順に調べる |

## Raspberry Pi での推奨設定

既定値は Raspberry Pi 4 (4 GB) に合わせてあります。

- Grafana は既定で動きません。コマンドセンターの「推移」と「ログ検索」で用が足ります。Pi では Grafana を有効にしないことを勧めます。
- SD カードの容量が少ないときは、`PROM_RETENTION_SIZE` (例 `8GB`) で容量の上限を決めてください。

## Grafana を使う

Grafana は任意の追加機能です。既定では動かさず、コマンドセンターの「推移」と「ログ検索」で同じ情報を伏せ字のまま見られます ([ui.md](ui.md))。
動かすときは、`.env` の `COMPOSE_PROFILES` に `grafana` を加えて起動します。

```sh
# .env: COMPOSE_PROFILES=prod,grafana   (デモなら demo,grafana)
./geofront up -d
./geofront run --rm tools check      # Grafana の health と管理者パスワードも確かめます
```

新しく導入するときは `tools init --grafana` でも同じ設定になります。`GF_ADMIN_PASSWORD` には既定値以外を入れてください。
有効にしたときの扱い (ログインありの構成では admin だけが開ける、など) は [security.md](security.md) のとおりです。

止めるときは `COMPOSE_PROFILES` から `grafana` を外し、Grafana のコンテナを止めて消します。データのボリューム (grafana-data) は消えません。

```sh
./geofront rm -s -f grafana
```

動いていない間、`/grafana/` は「有効になっていません」というページ (404) を返します。`tools doctor` と `tools check` は Grafana を求めません。

以前のバージョンから更新すると、Grafana は動かなくなります。ダッシュボードや利用者のデータ (grafana-data) は残っているので、
`COMPOSE_PROFILES` に `grafana` を加えれば元のまま使えます。`tools doctor` が、データが残っていることと、`.env` に残った `OBS_GRAFANA=1` を知らせます。
更新の前から動いていた Grafana のコンテナは、`up -d` では止まりません。止めるときは上の `rm -s -f grafana` を実行してください。

## 表示端末の描画モード

地球儀は WebGL で描きます。⋯ メニューの `RENDER:` で描画モードを選べます (AUTO → GPU → LITE)。URL に `?render=lite` を付けると、その表示だけに効きます。

| モード | 内容 |
|---|---|
| `GPU` | 地球儀が動きます (アークの流れ、パルス、自転) |
| `LITE` | 同じ情報を静止した表示で描きます。データが更新されたときと操作したときだけ描くので、CPU の負荷が小さくなります |
| `AUTO` (既定) | WebGL がないときやソフトウェア描画のときは LITE、それ以外は GPU になります |

Raspberry Pi の Chromium を表示端末にするときは、次の点を確かめてください。

- `chrome://gpu` で「WebGL: Hardware accelerated」と表示され、WebGL のレンダラが `V3D` になっていれば GPU が使われています。`llvmpipe` や「Software only」はソフトウェア描画です。
- Raspberry Pi OS (Bookworm) では `/boot/firmware/config.txt` の `dtoverlay=vc4-kms-v3d` で GPU が有効になります。Chromium が GPU を使わないときは、起動オプションに `--ignore-gpu-blocklist` を加えてください。
- 4K の画面や、Pi で収集サーバも兼ねるときは LITE を勧めます。

```sh
chromium-browser --kiosk --noerrdialogs --disable-infobars http://<host>:8080/?render=lite
```

## リソースと保存期間

メモリと CPU の上限は `.env` の `*_MEM` / `*_CPUS` で変えられます (一覧は `config.example/.env.example`)。
コンテナのログは `LOG_MAX_SIZE` (既定 10m) × `LOG_MAX_FILE` (既定 3) でローテーションされます。

| 項目 | 既定 | 内容 |
|---|---|---|
| `PROM_RETENTION` | `30d` | メトリクスの保存期間 |
| `PROM_RETENTION_SIZE` | `0` (上限なし) | メトリクスの容量の上限。古いブロックから消えます |
| `LOKI_RETENTION` | `720h` | syslog の保存期間 |
| `ALERTMANAGER_RETENTION` | `168h` | 抑止と通知の記録の保存期間 |
| `AUTHELIA_MEM` | `256m` | ログインのメモリの上限 |
| `ANALYZER_MEM` | `896m` | パケット解析のメモリの上限 ([capture.md](capture.md)) |
