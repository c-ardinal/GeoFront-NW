# 機種ドライバ (drivers/)

機種に固有のもの (SNMP の取得モジュール、LLDP を読むか、syslog の形式の回帰用 fixture、デモの機器) は
`drivers/<vendor-model>/` にまとめ、本体 (tools・Prometheus・Alloy・mask-api・画面) は機種に依存しません。
機器台帳の `kind` がドライバを選びます (ドライバの `kinds` に書いた値)。

| ドライバ | kind | 内容 |
|---|---|---|
| `drivers/yamaha-rtx` | `rtx` | YAMAHA RTX ルーター。WAN の IF を `tools init` が尋ねる。デモの rtx1300 |
| `drivers/yamaha-wlx` | `wlx` | YAMAHA WLX アクセスポイント。画面に無線クライアント数の欄 (prod では不明 —)。デモの wlx413 / wlx222 |
| `drivers/generic` | `other` | 標準 MIB (MIB-II / IF-MIB) だけの機器。RFC 3164 / 5424 の syslog fixture |

## ドライバのファイル

| ファイル | 必須 | 使うもの | 内容 |
|---|---|---|---|
| `driver.yaml` | ○ | tools (`targets` / `check` / `init`) | `name`、`label`、`kinds` (台帳の kind の値)、`snmp_modules` (snmp_exporter のモジュール。Prometheus の `snmp` ジョブの module)、`lldp` (true なら `lldp` ジョブの対象 = LLDP-MIB の隣接をネットワーク図に)、`wan` (true なら `tools init` が WAN の IF を尋ねる)、`wireless_clients` (true なら画面に無線クライアント数の欄) |
| `syslog.jsonl` | 任意 | `tools test-syslog`、testbed の疑似機器 | この機種の syslog の行と、Alloy → Loki で期待される host / severity / facility / 本文 (`id`, `model` (= kind), `form` (`yamaha` は PRI だけの形式、`rfc3164` / `rfc5424`), `raw`, `host`, `severity`, `facility`, `line`) |
| `demo.json` | 任意 | demo-gen (イメージに同梱)、tools (demo profile の対象・台帳の代わり) | demo profile の機器 (インターフェース表、ルーターは `wan_if`、AP は `ap` の配分、`ssids`、`lldp` の隣接、`link` = ネットワーク図の親、`logs` / `error_logs` = syslog の文面)。疑似データ |

SNMP の資格情報 (`snmp/auths.yml`) と LLDP のモジュール (`snmp/lldp.yml`) は標準 MIB なので全機種共通です
(auth の名前 `yamaha_v3` / `yamaha_v2c` は R1 より前の台帳と互換のための名前で、中身は SNMPv3 authPriv / v2c の汎用設定です)。
syslog の解析 (`alloy/config.alloy`) は形式で判定し (RFC 5424 / RFC 3164 のヘッダがあれば外し、PRI だけの行はそのまま)、
機種名では分けていません。

## 他社機を足す手順

1. `drivers/generic` を `drivers/<vendor-model>` (例 `drivers/acme-sw`) に写し、`driver.yaml` の `name` / `label` / `kinds`
   (例 `[acmesw]`、既存の kind と重ねない) を書き換えます。
2. 標準 MIB (IF-MIB / SNMPv2-MIB) で足りるなら `snmp_modules: [if_mib, system]` のまま。独自 MIB が要るなら snmp_exporter の
   generator でモジュールを作って `snmp/` に置き、`compose.yaml` の snmp-exporter の `--config.file` に足して、そのモジュール名を
   `snmp_modules` に書きます (読み取りの GET / WALK だけ。OID は機種の資料で確かめてから。推測で入れない)。
3. LLDP-MIB に答えない機種は `lldp: false`。
4. 実機の syslog を採取したら、伏せ字にしたうえで (アドレスはドキュメント用 192.0.2.x などに置き換え) `syslog.jsonl` に行を足し、
   testbed で `tools test-syslog` を通します。PRI だけ・RFC 3164・RFC 5424 のどれでもない形式なら `alloy/config.alloy` の扱いを先に確認します。
5. デモに出したいときだけ `demo.json` を足します (`drivers/yamaha-wlx/demo.json` が例)。
6. 台帳に `kind: <新しい kind>` の機器を書いて `tools targets` (または `up`)、`tools check` で SNMP が OK になること。
   `scripts/verify.sh quick` (tools の selftest は既存のドライバとデモの機器を確かめます。デモの機器を足した場合は tools/obs.py の selftest の期待値も直します)。
7. コミット前に `scripts/leak-scan.sh` (採取したログ・アドレス・MAC が残っていないこと)。
