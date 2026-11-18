# アラートの通知

Prometheus のアラートは Alertmanager で集約し、notify-relay が各送信先に送信します。
通知文は日本語で、機器名・対象・数値・開始時刻 (JST)・画面へのリンクを含み、IP / MAC はマスク表示です。アラートの解消時も通知します。

既定では送信しません。送信先の設定時のみ送信します。

## 送信先の設定

```sh
mkdir -p "$OBS_CONFIG_DIR/alerting"
cp config.example/alerting/receivers.example.yaml "$OBS_CONFIG_DIR/alerting/receivers.yaml"
./geofront run --rm tools targets
./geofront run --rm tools notify-test
./geofront run --rm tools check
```

1. `receivers.yaml` を編集して、送信先と振分ルールを記載します。秘密値 (Webhook の URL・トークン・SMTP のパスワード) は `.env` のみに記載してください ([configuration.md](configuration.md))。
2. `tools targets` で設定を生成し、Alertmanager に反映します。`./geofront up -d` でも生成します。
3. `tools notify-test` で各送信先にテストを送信し、結果を表で確認します。単独の試験には `--receiver mail` のように名称を指定します。

| 種類 (`type`) | `.env` の記載項目 | `receivers.yaml` の記載項目 |
|---|---|---|
| `email` | `SMTP_HOST` `SMTP_PORT` `SMTP_FROM` `SMTP_USER` `SMTP_PASSWORD` `SMTP_TLS` (`starttls` / `tls` / `none`) | `to` |
| `slack` | `SLACK_WEBHOOK_URL` (Incoming Webhook) | なし |
| `discord` | `DISCORD_WEBHOOK_URL` | なし |
| `line` | `LINE_CHANNEL_ACCESS_TOKEN` (Messaging API) | `to` (ユーザー ID かグループ ID) |
| `webhook` | `WEBHOOK_URL`、任意で `WEBHOOK_BEARER_TOKEN` | なし |

秘密値は送信先の種類単位で 1 組です。メールの送信先 (`to`) は複数指定可能です。

`routes:` には重大度 (critical / warning / info) 別の送信先と再通知の間隔を記載します。
未記載の重大度は、critical と warning が全送信先に送信され、info は通知対象外です。

demo profile では外部送信せず、デモ用の受信先への記録のみです。

## 通知の状態

警報パネルの各行に通知の状態を表示します。

| 表示 | 意味 |
|---|---|
| `通知完了` | 今回の発報が現行経路の全送信先に到達 |
| `一部未確認` | 記録未着の送信先が存在 |
| `通知失敗` | 送信失敗の送信先が存在 (メールの一部送信先の拒否を含む) |
| `未通知` | 一括送信の待機中 |
| `通知なし` | 該当の重大度は通知対象外の設定 |
| `抑止中` / `確認完了` | 抑止中、または ACK 完了 |
| `不明` | Alertmanager か通知の記録に接続不可 |
| `履歴上限` | 記録が 5000 件を超過し、旧記録は未読込 |

警報の詳細画面で、送信先別の結果と次回の再通知時刻を確認可能です。送信結果は Loki の `{job="notify"}` にも記録します。

## 抑止と ACK

警報の詳細画面では以下の操作が可能です。

- `確認 (ACK)` の押下で、該当警報の再通知を解消まで停止します。期限は 24 時間で、延長時も最長 7 日です。警報の解消時は自動解除します。
- `抑止する` では範囲 (本警報 / 本機器の全警報 / 同一警報名の全件) と期間 (1h / 4h / 24h / 7d) を選択します。
- `抑止を解除` の押下で抑止を終了します。

警報一覧の「Silences & ACK」では抑止の一覧・延長 (+1 h / +24 h)・解除と、新規抑止の作成が可能です。

ログインありの構成では、抑止と ACK の操作は operator と admin のみ可能です。ログインなしの構成 (127.0.0.1) では、本ホストの全利用者が操作可能です。

## 送信の再試行

送信先が 429・5xx を応答した場合や無応答の場合は、Alertmanager が再送します。3xx・その他の 4xx・SMTP の 5xx は再送しません。
