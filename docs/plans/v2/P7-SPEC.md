# P7 仕様: 認証（LAN 向け）と残課題

親計画: `docs/plans/v2/PLAN.md`（P1〜P6・PERF 完了、HEAD bb2f21d）。オーナー指示 2026-10-27:
「課題対応と認証実装に進んで。認証は LAN で動かすこともあるので OSS などを活用して適度な堅牢性に。外部露出は考えない。LAN 内からの攻撃（不正アクセス含む）に耐えればよい」

## 脅威モデル
- 想定: 同じ LAN 上の他端末からの不正アクセス（総当たり・セッション窃取・CSRF・DNS リバインディング・平文の盗聴）
- 想定しない: インターネット公開、標的型の高度な攻撃、ホスト自体の侵害

## 受入条件
1. **認証基盤（OSS）**: Authelia（Caddy の forward_auth と組合せ。Pi で軽い・arm64 あり）を採用。版固定＋digest、healthcheck・上限・ログローテーション、データは volume、backup/restore の対象
   - 利用者はファイル定義（argon2id ハッシュ）。`tools user add / passwd / remove / list` で管理（ホストに道具を入れない）
   - 総当たり対策（失敗回数・期間・締め出し）、セッションの有効期限と無操作期限、cookie は Secure / HttpOnly / SameSite
   - 二要素（TOTP）は任意で有効化可能（既定は無効、README に手順）
   - 秘密値（セッション・保存用暗号鍵など）は `tools init` が生成し `.env` 側にのみ置く
2. **HTTPS（LAN）**: LAN 公開時は Caddy の内部 CA（`tls internal`）で HTTPS を既定にし、HTTP は HTTPS へ転送。ルート証明書の取り出しと端末への登録手順を README に。127.0.0.1 公開時は従来どおり（認証なしで使える既定を残すか、`.env` で認証必須にできる）
3. **役割**: viewer / operator / admin（Authelia のグループ）。Caddy が検証済みの利用者名と役割だけを `X-Obs-User` / `X-Obs-Role` として後段へ渡し、クライアントから来た同名ヘッダは必ず消す。mask-api はこのヘッダを内部ネットワーク経由のときだけ信用する
   - operator 以上: 抑止・確認（ack）・pcap アップロード・スナップショット付き証跡出力を LAN でも可能にする（今は 127.0.0.1 のみ）。CSRF / Origin / Host の検査は維持
   - viewer: 読み取りのみ（今の LAN 公開時と同じ）
   - admin: 上記＋利用者管理の案内。**伏せ字の解除は今回も行わない**（将来の口のみ）
   - 操作者欄（ack のコメント、証跡 manifest の出力者、通知記録）に実際の利用者名を入れる
4. **Grafana**: auth proxy（Remote-User）で同じ利用者として入れる。役割の対応（viewer→Viewer、admin→Admin）。既存の grafana-guard は認証有効時に置き換えるか整合させ、fail-closed を維持
5. **画面**: 上部バーは増やさない。設定メニュー（⋯）に利用者名・役割・ログアウト。権限のない操作は理由付きで無効表示（既存の規則どおり）。ログイン画面は Authelia のもの（テーマ調整は任意）
6. **残課題**
   - スナップショットの大きさ上限の単位を Caddy とアプリで揃える（MiB に統一）
   - `POST /evidence/export` は本文を読む前に書き込み可否・同時 1 件の検査を行う。本文の読み取りにタイムアウト
   - 再生バーと原因候補からの証跡出力にもスナップショットの選択肢
   - LAN に実際に bind して、未認証・viewer・operator それぞれで書き込み経路が期待どおり拒否／許可されることを確認（この PC 上の LAN アドレスまたは Docker ネットワーク経由で可）
   - 検証スクリプトの終了コードの拾い方（`tail` の rc を見ている問題）

## 不変条件
- 伏せ字・Host 許可リスト（421）・PLAYBACK・PERF・P5/P6 の挙動、画面規則（重複なし・幅固定・STALE と —・44px・両テーマ・全画面サイズ）を維持
- demo profile はログインなしで試せる既定を残す（`.env` で認証必須にできる）

## 検証の制約（オーナー指示）
- コンテナは確認時のみ起動し `docker compose stop`。ブラウザは同時 1 つ（browser.lock）。短時間・逐次
