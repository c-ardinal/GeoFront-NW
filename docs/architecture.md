# 構成

コンテナ間の接続は [README の図](../README.md#構成) に記載しています。本文書はコンテナ単位の役割の一覧です。

## 常時稼働のコンテナ

| コンテナ | 役割 | 接続先 |
|---|---|---|
| proxy | 入口です (Caddy)。許可済みのホスト名にのみ応答します。LAN への公開時は HTTPS 化し、Authelia でログインを確認します | command-center、mask-api (`/trend/`・`/logsearch/` など)、authelia。127.0.0.1:9090 で Prometheus を読取専用で公開します |
| authelia | ログインと役割 (viewer / operator / admin) を管理します。ログイン不要の場合は待機のみです | proxy から呼出 |
| command-center | 画面の静的ファイルを応答します (nginx) | `/prom/` と `/loki/` を mask-api へ転送 |
| mask-api | 画面用の API です。IP や MAC をマスク処理してから応答します。抑止と ACK、pcap の解析とアップロード、証跡、原因候補、推移 (`/trend/`)、ログ検索 (`/logsearch/`) も担当します | prometheus、loki、alertmanager、analyzer |
| analyzer | pcap を tshark で解析します。ネットワーク非接続で、Unix ソケット経由でのみ呼出可能です | mask-api と flowd から呼出。pcap を読取専用で参照 |
| prometheus | メトリクスを保存し、アラートを判定します | snmp-exporter、flowd、demo-gen から取得し、alertmanager へ送信 |
| loki | syslog と通知の記録を保存します | alloy と notify-relay から受信 |
| alloy | syslog を受信し、送信元を台帳の機器名称に変換します | loki へ送信 |
| alertmanager | 通知を集約し、重要度別に振り分けます。抑止と ACK を保存します | notify-relay へ送信 |
| notify-relay | 通知の本文を生成し、各送信先へ送信します。デモでは外部送信せず、デモ用の受信先に記録します | 外部の送信先、loki (記録)、alertmanager (完了済み ACK の解除) |

## プロファイル指定で追加されるコンテナ

| コンテナ | プロファイル | 役割 |
|---|---|---|
| demo-gen | demo | 疑似の SNMP・syslog・通信量を出力します。疑似の異常を約 4 分間隔で発生させます |
| flowd-demo | demo | 付属の疑似 pcap を反復再生し、通信先を地球儀に表示します |
| snmp-exporter | prod | 台帳の機器に SNMP で問合せします (読取のみ) |
| capture | capture | LAN のパケットを dumpcap でキャプチャし、pcap を順次上書きして保存します (Linux ホスト限定) |
| flowd | capture | キャプチャ済みの pcap を analyzer で解析し、通信先単位の量と GeoIP を Prometheus に出力します |
| testbed-rtx / testbed-wlx | testbed | 疑似の RTX / WLX です (SNMPv3 と syslog) |
| testbed-traffic | testbed | キャプチャ試験用の疑似通信を出力します |
| notifymock | testbed | 疑似の送信先です。外部送信は一切ありません |

## 起動時に一度のみ稼働するコンテナ

| コンテナ | 役割 |
|---|---|
| demo-setup / prod-setup | プロファイルに応じて、取得先・アラート・通知・ログインの設定を生成します |
| capture-setup | キャプチャ設定と `.env`・プロファイルの整合性を確認します |
| setup-check | プロファイルの選択有無を確認し、pcap などの保存先の所有者を修正します |
| tools | 手動操作 (`./geofront run --rm tools ...`) 用です |
