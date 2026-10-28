# 機器側の設定

監視側から機器へは読み取り (SNMP の GET / WALK) しか行わず、機器の設定は変えません。機器の設定は手作業で投入してください。
以下は設定の例です。投入する前に、機種とファームウェアのコマンドリファレンスで書式を確かめてください。
この設定例はまだ実機では確かめていません。例の `192.168.100.10` は監視ホストのアドレスです。パスワードには `.env` と同じ値を使います。

## RTX の SNMPv3 と syslog

```
# SNMPv3: 読み取り専用ユーザー (認証 SHA、暗号 AES128-CFB → .env は SNMP_V3_AUTH_PROTO=SHA / SNMP_V3_PRIV_PROTO=AES)
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

Web GUI の SNMP 設定で、SNMPv3 の読み取り専用ユーザーを作ります。認証と暗号の方式とパスワードは RTX と同じにし、アクセスを許すホストには監視ホストを指定してください。
syslog の送信先にも監視ホストを指定します。

## 監視ホスト側の受信

`.env` の `SYSLOG_BIND` に監視ホストの LAN 側 IP を設定してください。既定の 127.0.0.1 のままでは LAN から受信できません。
syslog の時刻には受信した時刻を使います。
インターネットから届くホストで `0.0.0.0` を指定するときは、`SYSLOG_DROP_UNKNOWN=1` にし、ファイアウォールで送信元を絞ってください。

## LLDP

機器が LLDP-MIB に応答すると、ネットワーク図に隣接の機器が加わります。RTX / WLX が応答するかは確かめていません。応答しない機器でも、ネットワーク図は台帳の情報だけで描けます。
SNMPv3 のビューが `1.3.6.1.2.1` だけだと LLDP-MIB は読めません。読めるようにするには、読み取りビューに LLDP-MIB を加えます (例)。

```
snmpv3 vacm view 1 include 1.3.6.1.2.1 1.0.8802.1.1.2
```

## 設定の確認

```sh
./geofront run --rm tools check
```

SNMP が OK になり、syslog の受信待ちで該当の機器の行が届けば完了です。NG のときは原因の目安が表示されます。
応答がないときは IP・ポート・SNMP の有効化・ACL を、認証エラーのときはユーザー名・パスワード・方式を確かめてください。
