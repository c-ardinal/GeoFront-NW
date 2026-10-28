# 構成

コンテナのつながりは [README の図](../README.md#構成) に載っています。この文書はコンテナごとの役割をまとめます。

## 常に動くコンテナ

| コンテナ | 役割 | つながる先 |
|---|---|---|
| proxy | 入口です (Caddy)。許可したホスト名だけに答えます。LAN に公開したときは HTTPS にして、Authelia でログインを確かめます | command-center、mask-api、grafana、authelia。127.0.0.1:9090 で Prometheus を読み取り専用で見せます |
| authelia | ログインと役割 (viewer / operator / admin) を扱います。ログインが要らないときは待機だけします | proxy から呼ばれます |
| command-center | 画面の静的ファイルを返します (nginx) | `/prom/` と `/loki/` を mask-api へ渡します |
| mask-api | 画面が使う API です。IP や MAC を伏せ字にしてから返します。抑止と ACK、pcap の解析とアップロード、証跡、原因候補もここで扱います | prometheus、loki、alertmanager、analyzer、grafana (証跡に書くバージョンだけ) |
| analyzer | pcap を tshark で解析します。ネットワークを持たず、Unix ソケットだけで呼ばれます | mask-api と flowd から呼ばれます。pcap を読み取り専用で読みます |
| prometheus | メトリクスを保存し、アラートを判定します | snmp-exporter、flowd、demo-gen から取得し、alertmanager へ送ります |
| loki | syslog と通知の記録を保存します | alloy と notify-relay から受け取ります |
| alloy | syslog を受信し、送信元を台帳の機器名に読み替えます | loki へ送ります |
| alertmanager | 通知をまとめ、重要度ごとに振り分けます。抑止と ACK を保存します | notify-relay へ送ります |
| notify-relay | 通知の本文を作り、各通知先へ送ります。デモでは外部に送らず、デモ用の受信先に記録します | 外部の通知先、loki (記録)、alertmanager (済んだ ACK の解除) |
| grafana | ダッシュボードです。ログインがあるときは admin だけが開けます。`OBS_GRAFANA=0` で止められます | prometheus、loki |

## プロファイルで加わるコンテナ

| コンテナ | プロファイル | 役割 |
|---|---|---|
| demo-gen | demo | 疑似の SNMP・syslog・通信量を出します。疑似の異常を約 4 分ごとに起こします |
| flowd-demo | demo | 付属の疑似 pcap を繰り返し再生し、通信先を地球儀に出します |
| snmp-exporter | prod | 台帳の機器に SNMP で問い合わせます (読み取りだけ) |
| capture | capture | LAN のパケットを dumpcap で取り込み、pcap を順に上書きして保存します (Linux ホストだけ) |
| flowd | capture | 取り込んだ pcap を analyzer で解析し、通信先ごとの量と GeoIP を Prometheus に出します |
| testbed-rtx / testbed-wlx | testbed | 疑似の RTX / WLX です (SNMPv3 と syslog) |
| testbed-traffic | testbed | 取込を試すための疑似の通信を出します |
| notifymock | testbed | 疑似の通知先です。外部には何も送りません |

## 起動のたびに一度だけ動くコンテナ

| コンテナ | 役割 |
|---|---|
| demo-setup / prod-setup | プロファイルに合わせて、取得先・アラート・通知・ログインの設定を作ります |
| capture-setup | 取込の設定が `.env` とプロファイルで合っているかを確かめます |
| setup-check | プロファイルを選んだかを確かめ、pcap などの保存先の所有者を直します |
| tools | 手作業の操作 (`./geofront run --rm tools ...`) に使います |
