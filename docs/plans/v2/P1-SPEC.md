# P1 仕様: 本番構成と導入の手軽さ

親計画: `docs/plans/v2/PLAN.md`（オーナー承認済み: 本番ホストは Linux / Pi、認証は当面なし・差し込み口だけ用意）

## 受入条件（観察可能な結果）
1. **profile 分け**: `docker compose --profile demo up -d` で現在と同じデモが動く。`--profile prod` で demo-gen を使わず、実機向けの収集（snmp_exporter / syslog 受信）で動く。`capture` は P3 用に名前だけ予約（中身は P3）。
2. **実機収集の経路**: 本物の `prom/snmp-exporter`（SNMPv3 authPriv、資格情報は `.env` から。`snmp.yml` の auth はテンプレートから生成）→ Prometheus。syslog は Alloy が LAN 側の UDP/TCP 514（ポートと待受アドレスは設定可能、既定は無効または 127.0.0.1）で受信。
3. **疑似実機での検証**: 実機がなくても prod 経路を試せる `testbed` profile。SNMPv3 で応答する SNMP シミュレータ（例: snmpsim）と syslog 送信器を立て、prod 構成をそのまま向けて、Prometheus の `up`・IF カウンタ・Loki のログが取れることを自動確認できる。
4. **初期設定**: ホストに Python 等を入れずに使える `tools` コンテナ。
   - `init`: 対話または引数で `.env` と `inventory/devices.yaml`（機器名・種別・管理 IP・SNMP 認証の参照名）を生成。秘密値は `.env` のみ（git 管理外）。生成後に設定の検証を行う。
   - `check`: 各機器へ SNMP の疎通（sysUpTime・ifHC カウンタ取得）、syslog の受信待ち（指定時間内に該当ホストからの行が届くか）、各サービスの health を表で出す。
   - `backup` / `restore`: 設定（`.env` を除く／含めるを選択）と Prometheus スナップショット・Loki データ・Grafana を 1 アーカイブに。復元手順の往復テストが通る。
   - 機器台帳から Prometheus の scrape 対象を生成（file_sd）。台帳を変えて `check`／再読込で反映。
5. **運用設定**: 全サービスに healthcheck・`restart: unless-stopped`・メモリ/CPU 上限（Pi 4 4GB を想定した既定値、`.env` で調整）・ログローテーション（json-file の max-size/max-file）・イメージはタグ＋digest 固定（amd64/arm64 の両方が存在することを確認）。保持期間（Prometheus 30d、Loki 30d）は `.env` で調整可能。
6. **公開範囲と認証の差し込み口**: 前段にリバースプロキシ（Caddy など）を 1 つ置き、command-center と Grafana をそこから配信。既定は 127.0.0.1 のみ。`.env` で LAN 公開にすると、認証が無い旨の警告をログと画面（小さな常設表示）に出す。プロキシに forward-auth を差し込める設定の場所と、mask-api が将来の役割ヘッダ（例 `X-Obs-Role`）を受け取る口（今は常に viewer 扱い・伏せ字は外さない）を用意。
7. **YAMAHA syslog の解析**: RFC3164 として読むと先頭語が欠ける問題（TC-003）を解消。raw 受信＋ `loki.process` で、YAMAHA 形式（PRI のみ・タグなし）と RFC3164/5424 の両方を扱える。機種ごとの回帰テスト用 fixtures（デモ生成ログ＋公開資料から作った例。実機ログ未採取であることを README に明記）。
8. **ドキュメント**: README に「デモで試す」「本番に入れる（Pi 手順）」「機器側の設定例（SNMPv3・syslog 転送の設定コマンド例。投入は手作業、仕様 08 章の原則どおり読み取り専用）」「バックアップ/復元」「更新」を追加。

## 不変条件
- demo profile の見た目・挙動は変えない（command-center / Grafana の現機能）
- ルーター等の機器設定をツールから変更しない
- 既定は 127.0.0.1 公開のみ。秘密値はリポジトリに入れない
- mask-api の伏せ字とクエリ制限は維持（prod でも同じ経路）

## 検証の制約（オーナー指示）
- PC 負荷が高い: コンテナは検証時だけ起動し、終わったら停止。ブラウザは同時 1 つ（browser.lock）、P1 では原則ブラウザ不要
