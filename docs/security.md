# セキュリティ

## 公開範囲とログイン

既定では画面を 127.0.0.1 のみに公開し、ログインはありません。
`.env` の `OBS_BIND` に LAN 側の IP (か `0.0.0.0`) を指定すると LAN に公開します。この場合はログイン (Authelia) と HTTPS が必ず有効になり、ログインなしでの LAN 公開は不可能です。
127.0.0.1 でもログインを必須にする場合は、`.env` に `OBS_AUTH=1` を記載します (`tools init --auth` でも設定可能)。

想定脅威は同一 LAN 上の他端末からの不正アクセスです (パスワードの総当たり、セッションの盗用、CSRF、DNS リバインディング、盗聴)。
インターネットへの公開と、本ホスト自体の侵害は想定外です。

Authelia の停止時や、設定・秘密値・利用者の不在時は、画面は何も表示しません。

## 画面の URL

画面は `OBS_PUBLIC_URL` (例 `https://192.168.100.10:8080`) で表示します。`tools init` が `--bind` と `--port` から生成します。

- 画面の応答対象は、本ホスト名と `OBS_BIND` のアドレスへの要求のみです。
- 名称で表示する場合は、ドットを含む名称 (例 `obs.home.arpa`) を使用してください。`localhost` や `raspberrypi` のような 1 語の名称ではログインの cookie を設定できません。
- ログインありの構成では、`127.0.0.1` や `localhost` での表示は不可です。本ホストからも LAN の URL で表示してください。
- 同一 IP の他ポートで、信頼できないサービスを公開しないでください。cookie はポートを区別しないため、該当サービスにも送信されます。

## ルート証明書

HTTPS には proxy 独自の認証局の証明書を使用し、HTTP での要求は HTTPS に転送します。
端末へのルート証明書の登録で、警告なしでの表示が可能になります。

```sh
./geofront cp proxy:/data/caddy/pki/authorities/local/root.crt ./obs-root.crt
```

証明書は `caddy-data` ボリュームに存在し、ボリュームを削除しない限り不変です。`down -v` での削除時は再生成されるため、端末への再登録が必要です。

| 端末 | 登録方法 |
|---|---|
| Windows | ファイルを開いて「証明書のインストール」→「ローカル コンピューター」→「信頼されたルート証明機関」 |
| macOS | キーチェーンアクセスの「システム」に追加し、「常に信頼」に設定 |
| iPhone / iPad | ファイルを送信してプロファイルをインストールし、「設定 > 一般 > 情報 > 証明書信頼設定」で有効化 |
| Android | 「設定 > セキュリティ > 暗号化と認証情報 > 証明書のインストール > CA 証明書」 |
| Linux (Debian 系) | `/usr/local/share/ca-certificates/obs-root.crt` に配置して `sudo update-ca-certificates` を実行。Firefox は独自の証明書ストアに読込 |

## 利用者の管理

```sh
./geofront run --rm tools user add yamada --role admin          # 役割は viewer / operator / admin (既定は viewer)
./geofront run --rm tools user add sato --role operator --display '佐藤'
./geofront run --rm tools user passwd sato                      # パスワードの変更
./geofront run --rm tools user role sato --role viewer          # 役割の変更 (次回操作から有効)
./geofront run --rm tools user remove sato                      # 削除 (次回操作からログアウト扱い)
./geofront run --rm tools user list
```

- パスワードは対話形式で 2 回入力してください。TTY 不在時のみ `-e OBS_USER_PASSWORD=...` で指定可能です。本設定値はシェルの履歴やプロセスの一覧に残存する場合があるため、使用後は履歴を削除してください。
- 保存対象はパスワードの argon2id ハッシュのみです。
- 利用者の名称は英小文字・数字・`. _ -` で最大 32 文字です。`admin` `root` `local` は予約語のため使用不可です。
- パスワードは 12 文字以上とし、名称を含まない文字列にしてください。
- 利用者が 0 人の間は画面を表示しません。`./geofront logs authelia` に案内を表示します。

## 役割

| 役割 | 権限 |
|---|---|
| viewer | 読取のみ (画面、詳細、履歴再生、解析、原因候補、画面の画像なしの証跡出力)。操作ボタンは理由付きで無効化 |
| operator | viewer の権限に加えて、抑止・ACK、pcap のアップロードと削除、画面の画像付きの証跡出力 |
| admin | operator の権限に加えて、⋯ メニューに利用者管理の案内を表示 (管理は `tools user` で実施) |

ACK・証跡・通知の記録にはログイン利用者の名称を記録します。ログインなしの構成では `local` です。

## ログインの秘密値

`OBS_AUTH_SESSION_SECRET` `OBS_AUTH_STORAGE_KEY` `OBS_AUTH_PROXY_KEY` は `tools init` が生成して `.env` に出力します。
既存の `.env` への追加には `./geofront run --rm tools user secrets` を実行します。既存の設定値は不変です。
`OBS_AUTH_STORAGE_KEY` の変更で Authelia は保存データ (TOTP の鍵) を読込できず起動不可になります。本設定値は `.env` と併せて保管してください。

## セッション

| 項目 | 既定 | 内容 |
|---|---|---|
| `OBS_AUTH_INACTIVITY` | `30m` | 無操作時のセッション失効までの時間 |
| `OBS_AUTH_EXPIRATION` | `12h` | セッションの最長時間 |
| `OBS_AUTH_REMEMBER_ME` | `0` | 「ログインしたままにする」の期間 (例 `7d`)。`0` では非表示 |

セッションはメモリ上のみに存在するため、Authelia の再起動で全員がログアウトします。設定の変更後は `./geofront up -d` を実行してください。
ログアウトは ⋯ メニューから実行します。

## 総当たりへのロックアウト

ログインの失敗が `OBS_AUTH_FIND_TIME` (既定 10 分) の間に `OBS_AUTH_MAX_RETRIES` (既定 5) 回に到達すると、ロックアウトを開始します。
ロックアウトの対象は該当の利用者名と送信元のアドレスで、期間は `OBS_AUTH_BAN_TIME` (既定 15 分) です。
ロックアウト中は正規のパスワードでもログイン不可です。

```sh
cfg=/etc/obs-generated/authelia/configuration.yml
./geofront exec authelia authelia storage bans user list --config $cfg
./geofront exec authelia authelia storage bans user revoke <名称> --config $cfg
./geofront exec authelia authelia storage bans ip list --config $cfg
./geofront exec authelia authelia storage bans ip revoke <アドレス> --config $cfg
```

Docker Desktop (Windows / macOS) では LAN の送信元が全件同一アドレスとして観測されるため、アドレスのロックアウトが全員に適用されます。

## 二要素認証

TOTP は任意で、既定では無効です。有効化には `.env` に `OBS_AUTH_TOTP=1` を記載し、`./geofront up -d` を実行します。
全員がログイン後に TOTP の登録を要求され、登録の確認コードはメールではなくファイルに出力されます。
管理者が以下のコマンドで参照し、本人に伝達してください。

```sh
./geofront exec authelia cat /config/notification.txt
```

## マスク

コマンドセンターと通知と証跡では IP / MAC の末尾をマスク表示します (例 `192.168.100.x`、`00:a0:de:xx:xx:xx`)。全役割でマスクは解除不可です。
送信先単位の識別には元の数値を推測不可能なトークンを使用します。マスク済みの数値を手掛かりに元の数値を推測する検索は不可能です。

以下の画面は管理用で、元の数値を無加工で表示します。

- Prometheus (http://127.0.0.1:9090、読取専用)。本ホストからのみ表示可能
- `tools capture status` と `tools check` の出力
