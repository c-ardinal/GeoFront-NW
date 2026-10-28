# アラートの通知

Prometheus のアラートは Alertmanager に集められ、notify-relay が各通知先に送ります。
通知文は日本語で、機器名・対象・値・開始時刻 (JST)・画面へのリンクが入ります。IP / MAC は伏せ字になります。アラートが解消したときも通知します。

既定ではどこにも送りません。通知先を設定したときだけ送ります。

## 通知先の設定

```sh
mkdir -p "$OBS_CONFIG_DIR/alerting"
cp config.example/alerting/receivers.example.yaml "$OBS_CONFIG_DIR/alerting/receivers.yaml"
./geofront run --rm tools targets
./geofront run --rm tools notify-test
./geofront run --rm tools check
```

1. `receivers.yaml` を編集して、通知先と送り先のルールを書きます。秘密値 (Webhook の URL・トークン・SMTP のパスワード) は `.env` だけに書いてください ([configuration.md](configuration.md))。
2. `tools targets` で設定を生成し、Alertmanager に読み込ませます。`./geofront up -d` でも生成されます。
3. `tools notify-test` で各通知先にテストを送り、結果を表で確かめます。1 つだけ試すときは `--receiver mail` のように名前を付けます。

| 種類 (`type`) | `.env` に書く値 | `receivers.yaml` に書く値 |
|---|---|---|
| `email` | `SMTP_HOST` `SMTP_PORT` `SMTP_FROM` `SMTP_USER` `SMTP_PASSWORD` `SMTP_TLS` (`starttls` / `tls` / `none`) | `to` |
| `slack` | `SLACK_WEBHOOK_URL` (Incoming Webhook) | なし |
| `discord` | `DISCORD_WEBHOOK_URL` | なし |
| `line` | `LINE_CHANNEL_ACCESS_TOKEN` (Messaging API) | `to` (ユーザー ID かグループ ID) |
| `webhook` | `WEBHOOK_URL`、任意で `WEBHOOK_BEARER_TOKEN` | なし |

秘密値は通知先の種類ごとに 1 組です。メールの宛先 (`to`) は複数書けます。

`routes:` には重大度 (critical / warning / info) ごとの送り先と再通知の間隔を書きます。
書かなかった重大度は、critical と warning がすべての通知先に送られ、info は通知されません。

demo profile では外部に送らず、デモ用の受信先に記録するだけです。

## 通知の状態

警報パネルの各行に通知の状態が出ます。

| 表示 | 意味 |
|---|---|
| `通知済` | 今回の発報が今の経路の送り先すべてに届いた |
| `一部未確認` | まだ記録のない送り先がある |
| `通知失敗` | 失敗した送り先がある (メールの一部の宛先が拒否された場合を含む) |
| `未通知` | まとめて送るのを待っている |
| `通知なし` | その重大度は通知しない設定になっている |
| `抑止中` / `確認済` | 抑止中、または ACK 済み |
| `不明` | Alertmanager か通知の記録に接続できない |
| `履歴上限` | 記録が 5000 件を超え、古い記録を読んでいない |

警報の詳細を開くと、送り先ごとの結果と次の再通知の時刻を確かめられます。送った結果は Loki の `{job="notify"}` にも記録されます。

## 抑止と ACK

警報の詳細では次の操作ができます。

- `確認 (ACK)` を押すと、その警報の再通知が解消まで止まります。期限は 24 時間で、延長しても最長 7 日です。警報が解消すると自動で解除されます。
- `抑止する` では範囲 (この警報 / この機器のすべて / この警報名のすべて) と期間 (1h / 4h / 24h / 7d) を選びます。
- `抑止を解除` を押すと抑止が終わります。

警報一覧の「Silences & ACK」では抑止の一覧・延長 (+1 h / +24 h)・解除と、新しい抑止の作成ができます。

ログインありの構成では、抑止と ACK を操作できるのは operator と admin だけです。ログインなしの構成 (127.0.0.1) では、このホストの誰でも操作できます。

## 送信の再試行

送り先が 429・5xx を返したときや応答がないときは、Alertmanager が送り直します。3xx・ほかの 4xx・SMTP の 5xx は送り直しません。
