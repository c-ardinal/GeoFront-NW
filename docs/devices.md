# 機器側の設定

監視側から機器へは読取 (SNMP の GET / WALK) のみ実施し、機器の設定は変更しません。機器の設定は手動で投入してください。
以下は設定例です。投入前に、機種とファームウェアのコマンドリファレンスで書式を確認してください。
本設定例は実機で未検証です。例中の `192.168.100.10` は監視ホストのアドレスです。パスワードには `.env` と同一の設定値を使用します。

## RTX の SNMPv3 と syslog

```
# SNMPv3: 読取専用ユーザー (認証 SHA、暗号 AES128-CFB → .env は SNMP_V3_AUTH_PROTO=SHA / SNMP_V3_PRIV_PROTO=AES)
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

## WLX の SNMPv3 と syslog

Web GUI の SNMP 設定で、SNMPv3 の読取専用ユーザーを作成します。認証・暗号の方式とパスワードは RTX と同一にし、アクセス許可ホストには監視ホストを指定してください。
syslog の送信先にも監視ホストを指定します。

## 監視ホスト側の受信

`.env` の `SYSLOG_BIND` に監視ホストの LAN 側 IP を設定してください。既定の 127.0.0.1 のままでは LAN から受信不可です。
syslog の時刻には受信時刻を使用します。
インターネットから到達可能なホストで `0.0.0.0` を指定する場合は、`SYSLOG_DROP_UNKNOWN=1` を設定し、ファイアウォールで送信元を制限してください。

## LLDP

機器が LLDP-MIB に応答すると、ネットワーク図に隣接機器が追加されます。RTX / WLX の応答可否は未確認です。非応答の機器でも、ネットワーク図は台帳の情報のみで描画可能です。
SNMPv3 のビューが `1.3.6.1.2.1` のみの場合、LLDP-MIB は読込不可です。読込には、読取ビューへの LLDP-MIB の追加が必要です (例)。

```
snmpv3 vacm view 1 include 1.3.6.1.2.1 1.0.8802.1.1.2
```

## 設定の確認

```sh
./geofront run --rm tools check
```

SNMP が OK となり、syslog の受信待機で該当機器の行が到着すれば完了です。NG の場合は原因の目安を表示します。
応答なしの場合は IP・ポート・SNMP の有効化・ACL を、認証エラーの場合はユーザー名・パスワード・方式を確認してください。
