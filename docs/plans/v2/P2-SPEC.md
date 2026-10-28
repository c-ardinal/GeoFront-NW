# P2 仕様: アラート通知

親計画: `docs/plans/v2/PLAN.md`（承認済み。P1 は 481163a で完了）

## 受入条件
1. **Alertmanager**: 全 profile で動く（版固定・digest・amd64/arm64、healthcheck、上限、ログローテーション、データは volume、backup/restore の対象）。Prometheus のアラートはすべて Alertmanager を経由する。外部には公開しない（Caddy 経由の読み取りと、下記の操作だけ）。
2. **通知先**: `.env`（秘密値）と `alerting/receivers.yaml`（宛先と経路、git 管理外の実ファイル＋例）から設定を生成する。対応する通知先:
   - メール（SMTP、STARTTLS/TLS）
   - Slack（Incoming Webhook）
   - Discord（Webhook）
   - LINE（Messaging API の push。LINE Notify は 2025 年に終了済みのため使わない）
   - 汎用 Webhook
   重大度（critical / warning / info）ごとに送り先と再通知間隔を変えられる。info は既定で通知しない。復旧（resolved）も通知する。通知文は日本語で、機器名・対象・値・開始時刻（JST）・画面へのリンク（OBS_PUBLIC_URL）を含み、IP/MAC は伏せ字。
3. **通知テスト**: `tools notify-test [--receiver 名前]` で各通知先にテスト送信し、成功/失敗（HTTP 応答・SMTP 応答）を表で出す。`tools check` に Alertmanager の健全性と、設定済み通知先の検証結果を加える。
4. **抑止と確認（ack）**: command-center の警報モーダル/ドロワーから、
   - 確認（ack）: そのアラートの再通知を止める（Alertmanager の silence で実装、期限は「解消まで」相当＋上限、コメントに ACK と操作者欄）。画面では「確認済み」を表示し、検出（firing）とは別に扱う。
   - 抑止（silence）: 機器/アラート名/期間を指定。一覧・延長・解除。
   - 操作は書き込みなので、認証が無い現状では **127.0.0.1 公開時のみ有効**。LAN 公開時は既定で無効（ボタンは理由付きで無効表示）。将来の認証層（`X-Obs-Role` operator 以上）で開放できる口を mask-api（または専用の小さな API）に用意。書き込みは許可リスト方式で、silence の作成・延長・削除だけ。
5. **画面**: 警報パネル/モーダル/ドロワーに、通知状態（通知済み・抑止中・確認済み）と次回の再通知時刻を表示。既存の幅固定・重複なし・STALE の規則を守る。
6. **デモ**: demo profile では、外部へ送らない「デモ用受信先」（受信した通知を Loki / 画面で見られる webhook シンク）を既定にし、DEMO_AUTO_FAULTS の障害で通知の流れが見える。
7. **P1 からの持ち越し**: Grafana の wallboard の WAN パネルを機器台帳の WAN 設定に合わせる（固定の rtx1300 lan2 をやめる）。

## 不変条件
- 既定は外部送信なし（通知先を設定しない限りどこにも送らない）。秘密値は `.env` のみ
- mask-api の伏せ字・クエリ制限は維持。書き込みは上記の許可リストに限定
- P1 の規則（公開範囲、Grafana のガード、上部バーの規則）を壊さない

## 検証の制約（オーナー指示）
- コンテナは確認時のみ起動し終わったら停止、ブラウザは同時 1 つ（browser.lock）
- 外部サービスへの実送信はしない（各通知先はローカルのモック受信器で検証）
