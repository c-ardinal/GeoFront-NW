# セキュリティ

## 公開範囲とログイン

既定では画面を 127.0.0.1 だけに公開し、ログインはありません。
`.env` の `OBS_BIND` を LAN 側の IP (か `0.0.0.0`) にすると LAN に公開します。このときはログイン (Authelia) と HTTPS が必ず有効になり、ログインなしで LAN に公開することはできません。
127.0.0.1 でもログインを必須にしたいときは、`.env` に `OBS_AUTH=1` を書きます (`tools init --auth` でも設定できます)。

想定している脅威は同じ LAN にある別の端末からの不正なアクセスです (パスワードの総当たり、セッションの盗用、CSRF、DNS リバインディング、盗聴)。
インターネットへの公開と、このホスト自体が侵害されることは想定していません。

ログインの仕組みが止まっているときや、設定・秘密値・利用者がないときは、画面は何も表示しません。

## 画面を開く URL

画面は `OBS_PUBLIC_URL` (例 `https://192.168.100.10:8080`) で開きます。`tools init` が `--bind` と `--port` から作ります。

- 画面が応答するのはこのホスト名と `OBS_BIND` のアドレスへの要求だけです。
- 名前で開くときは、ドットを含む名前 (例 `obs.home.arpa`) にしてください。`localhost` や `raspberrypi` のような 1 語の名前では、ログインの cookie を置けません。
- ログインありの構成では、`127.0.0.1` や `localhost` では開けません。このホストからも LAN の URL で開いてください。
- 同じ IP の別のポートで、信用できないサービスを公開しないでください。cookie はポートを区別しないので、そのサービスにも送られます。

## ルート証明書

HTTPS には proxy が持つ独自の認証局の証明書を使います。HTTP で来た要求は HTTPS に転送されます。
端末にルート証明書を登録すると、警告なしで開けるようになります。

```sh
./geofront cp proxy:/data/caddy/pki/authorities/local/root.crt ./obs-root.crt
```

証明書は `caddy-data` ボリュームにあり、ボリュームを消さない限り変わりません。`down -v` で消すと作り直されるので、端末への登録もやり直しになります。

| 端末 | 登録の方法 |
|---|---|
| Windows | ファイルを開いて「証明書のインストール」→「ローカル コンピューター」→「信頼されたルート証明機関」 |
| macOS | キーチェーンアクセスの「システム」に追加し、「常に信頼」にする |
| iPhone / iPad | ファイルを送ってプロファイルをインストールし、「設定 > 一般 > 情報 > 証明書信頼設定」で有効にする |
| Android | 「設定 > セキュリティ > 暗号化と認証情報 > 証明書のインストール > CA 証明書」 |
| Linux (Debian 系) | `/usr/local/share/ca-certificates/obs-root.crt` に置いて `sudo update-ca-certificates` を実行する。Firefox は独自の証明書ストアに読み込む |

## 利用者の管理

```sh
./geofront run --rm tools user add yamada --role admin          # 役割は viewer / operator / admin (既定は viewer)
./geofront run --rm tools user add sato --role operator --display '佐藤'
./geofront run --rm tools user passwd sato                      # パスワードを変える
./geofront run --rm tools user role sato --role viewer          # 役割を変える (次の操作から有効)
./geofront run --rm tools user remove sato                      # 削除する (次の操作からログアウト扱い)
./geofront run --rm tools user list
```

- パスワードは対話で 2 回入力してください。TTY がないときだけ `-e OBS_USER_PASSWORD=...` で渡せます。この値はシェルの履歴やプロセスの一覧に残ることがあるので、使ったら履歴を消してください。
- 保存されるのはパスワードの argon2id ハッシュだけです。
- 利用者の名前は英小文字・数字・`. _ -` で 32 文字までです。`admin` `root` `local` は予約語なので使えません。
- パスワードは 12 文字以上で、名前を含まないものにしてください。
- 利用者が 1 人もいないあいだは画面が開きません。`./geofront logs authelia` に案内が出ます。

## 役割

| 役割 | できること |
|---|---|
| viewer | 読み取りだけ (画面、詳細、履歴再生、解析、原因候補、画面の画像なしの証跡出力)。操作のボタンは理由付きで無効になります。Grafana は開けません |
| operator | viewer の操作に加えて、抑止・ACK、pcap のアップロードと削除、画面の画像付きの証跡出力 |
| admin | operator の操作に加えて、Grafana (`/grafana/`)。⋯ メニューに利用者の管理の案内が出ます (管理は `tools user` で行います) |

ACK・証跡・通知の記録にはログインした利用者の名前が残ります。ログインなしの構成では `local` になります。

## ログインの秘密値

`OBS_AUTH_SESSION_SECRET` `OBS_AUTH_STORAGE_KEY` `OBS_AUTH_PROXY_KEY` は `tools init` が作って `.env` に書きます。
既存の `.env` に足すときは `./geofront run --rm tools user secrets` を実行します。すでにある値は変わりません。
`OBS_AUTH_STORAGE_KEY` を変えると Authelia が保存データ (TOTP の鍵) を読めずに起動しなくなります。この値は `.env` と一緒に保管してください。

## セッション

| 項目 | 既定 | 内容 |
|---|---|---|
| `OBS_AUTH_INACTIVITY` | `30m` | 操作がないとセッションが切れるまでの時間 |
| `OBS_AUTH_EXPIRATION` | `12h` | セッションの最長の時間 |
| `OBS_AUTH_REMEMBER_ME` | `0` | 「ログインしたままにする」の期間 (例 `7d`)。`0` では表示しません |

セッションはメモリにだけあるので、Authelia を再起動すると全員がログアウトします。設定を変えたら `./geofront up -d` を実行してください。
ログアウトは ⋯ メニューから行います。

## 総当たりの締め出し

`OBS_AUTH_FIND_TIME` (既定 10 分) のあいだに `OBS_AUTH_MAX_RETRIES` (既定 5) 回ログインに失敗すると、その利用者名と送信元のアドレスが `OBS_AUTH_BAN_TIME` (既定 15 分) のあいだ締め出されます。
締め出し中は正しいパスワードでもログインできません。

```sh
cfg=/etc/obs-generated/authelia/configuration.yml
./geofront exec authelia authelia storage bans user list --config $cfg
./geofront exec authelia authelia storage bans user revoke <名前> --config $cfg
./geofront exec authelia authelia storage bans ip list --config $cfg
./geofront exec authelia authelia storage bans ip revoke <アドレス> --config $cfg
```

Docker Desktop (Windows / macOS) では LAN の送信元がすべて同じアドレスに見えるので、アドレスの締め出しが全員にかかります。

## 二要素認証

TOTP は任意で、既定では無効です。有効にするには `.env` に `OBS_AUTH_TOTP=1` を書き、`./geofront up -d` を実行します。
全員がログインのあとに TOTP の登録を求められます。登録の確認コードはメールでは送られず、ファイルに書かれます。
管理者が次のコマンドで読み、本人に伝えてください。

```sh
./geofront exec authelia cat /config/notification.txt
```

## Grafana

Grafana は IP / MAC を伏せずに表示するので、ログインありの構成で `/grafana/` を開けるのは admin だけです。
Grafana の管理者 `admin` のパスワードを既定の値のままにしないでください。変えるには次を実行します。

```sh
./geofront exec grafana grafana cli admin reset-admin-password '<値>'
```

Grafana は proxy の固定アドレスから来た利用者の情報だけを受け付けます。
このホストで `172.31.253.0/29` がすでに使われているときは、`OBS_GRAFANA_NET` `OBS_GRAFANA_NET_DYNAMIC` `OBS_GRAFANA_PROXY_IP` の 3 つを変えてください。

## 伏せ字

コマンドセンターと通知と証跡では IP / MAC の末尾を伏せて表示します (例 `192.168.100.x`、`00:a0:de:xx:xx:xx`)。どの役割でも伏せ字は外れません。
宛先ごとの区別には元の値が分からないトークンを使います。伏せた値を手がかりに元の値を探るような検索はできません。

次の画面は管理用で、元の値をそのまま表示します。

- Grafana (`/grafana/`)。ログインありの構成では admin だけが開けます
- Prometheus (http://127.0.0.1:9090、読み取り専用)。このホストからだけ開けます
- `tools capture status` と `tools check` の出力
