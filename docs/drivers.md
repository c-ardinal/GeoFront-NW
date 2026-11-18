# 機種ドライバ

機種固有の要素 (SNMP の取得モジュール、LLDP の読込有無、syslog 形式の回帰用 fixture、デモの機器) は
`drivers/<vendor-model>/` に集約し、本体 (tools・Prometheus・Alloy・mask-api・画面) は機種非依存です。
機器台帳の `kind` でドライバを選択します (ドライバの `kinds` に記載の設定値)。

| ドライバ | kind | 内容 |
|---|---|---|
| `drivers/yamaha-rtx` | `rtx` | YAMAHA RTX ルーター。WAN の IF を `tools init` で質問。デモの rtx1300 |
| `drivers/yamaha-wlx` | `wlx` | YAMAHA WLX アクセスポイント。画面に無線クライアント数の欄 (prod では数値不明)。デモの wlx413 / wlx222 |
| `drivers/generic` | `other` | 標準 MIB (MIB-II / IF-MIB) のみの機器。RFC 3164 / 5424 の syslog fixture |

## ドライバのファイル

| ファイル | 必須 | 利用元 | 内容 |
|---|---|---|---|
| `driver.yaml` | ○ | tools (`targets` / `check` / `init`) | `name`、`label`、`kinds` (台帳の kind の設定値)、`snmp_modules` (snmp_exporter のモジュール。Prometheus の `snmp` ジョブの module)、`lldp` (true の場合は `lldp` ジョブの対象 = LLDP-MIB の隣接をネットワーク図に反映)、`wan` (true の場合は `tools init` で WAN の IF を質問)、`wireless_clients` (true の場合は画面に無線クライアント数の欄) |
| `syslog.jsonl` | 任意 | `tools test-syslog`、testbed の疑似機器 | 本機種の syslog の行と、Alloy → Loki での期待値 host / severity / facility / 本文 (`id`, `model` (= kind), `form` (`yamaha` は PRI のみの形式、`rfc3164` / `rfc5424`), `raw`, `host`, `severity`, `facility`, `line`) |
| `demo.json` | 任意 | demo-gen (イメージに同梱)、tools (demo profile の対象・台帳の代替) | demo profile の機器 (インターフェース表、ルーターは `wan_if`、AP は `ap` の配分、`ssids`、`lldp` の隣接、`link` = ネットワーク図の親、`logs` / `error_logs` = syslog の文面)。疑似データ |

SNMP の資格情報 (`snmp/auths.yml`) と LLDP のモジュール (`snmp/lldp.yml`) は標準 MIB のため全機種共通です
(auth の名称 `yamaha_v3` / `yamaha_v2c` は旧台帳との互換用の名称であり、内容は SNMPv3 authPriv / v2c の汎用設定です)。
syslog の解析 (`alloy/config.alloy`) は形式で判定し (RFC 5424 / RFC 3164 のヘッダは除去、PRI のみの行は無加工)、
機種名による分岐はありません。

## 他社機の追加手順

1. `drivers/generic` を `drivers/<vendor-model>` (例 `drivers/acme-sw`) に複製し、`driver.yaml` の `name` / `label` / `kinds`
   (例 `[acmesw]`、既存の kind との重複は不可) を変更します。
2. 標準 MIB (IF-MIB / SNMPv2-MIB) で充足する場合は `snmp_modules: [if_mib, system]` のまま。独自 MIB が必要な場合は snmp_exporter の
   generator でモジュールを生成して `snmp/` に配置し、`compose.yaml` の snmp-exporter の `--config.file` に追加して、該当モジュール名を
   `snmp_modules` に記載します (読取の GET / WALK のみ。OID は機種の資料で確認後に記載。推測での記載は禁止)。
3. LLDP-MIB 非対応の機種は `lldp: false`。
4. 実機の syslog の採取後、マスク処理を施して (アドレスはドキュメント用 192.0.2.x などに置換) `syslog.jsonl` に行を追加し、
   testbed で `tools test-syslog` を通過させます。PRI のみ・RFC 3164・RFC 5424 のいずれにも該当しない形式の場合は、`alloy/config.alloy` の処理を事前に確認します。
5. デモへの表示が必要な場合のみ `demo.json` を追加します (`drivers/yamaha-wlx/demo.json` が例)。
6. 台帳に `kind: <新規 kind>` の機器を記載して `tools targets` (または `up`)、`tools check` で SNMP が OK となることを確認。
   `scripts/verify.sh quick` (tools の selftest は既存ドライバとデモの機器を確認します。デモの機器を追加した場合は tools/obs.py の selftest の期待値も修正します)。
7. コミット前に `scripts/leak-scan.sh` (採取したログ・アドレス・MAC の残存がないこと)。
