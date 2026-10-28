# H1 仕様: 本番一発起動のための強化（テスト未実施・薄い箇所）

親計画: `docs/plans/v2/PLAN.md`（P1〜P7 完了、HEAD 5e0e6ef）。オーナー指示 2026-10-27:
「テスト未実施・薄い箇所などを強化して、本番環境に載せた時に 1 発で動けるように構えて」

## 受入条件
1. **導入前の自己診断 `tools doctor`**（`tools check` の前段。機器への疎通は不要）: Docker Engine ≥25・compose 版、CPU アーキテクチャ（arm64/amd64）、空きディスク・メモリ、使用ポートの衝突（443/80/514 など）、時刻同期（NTP、RTC のない Pi で時刻が大きくずれていないか）、`.env` の必須値と形式、Grafana 既定パスワード、利用者 0 人で LAN 公開していないか、証明書の状態。各項目を OK/WARN/NG と直し方で表示し、NG があれば非 0 で終了
2. **新規導入の通し試験**（まっさらな状態から）: 別の compose プロジェクト名・空の volume で、`git clone` 相当のツリーから `tools init`（非対話・引数指定）→ `tools doctor` → `--profile prod`（＋testbed を実機の代わりに）起動 → `tools check` 全 OK → command-center と Grafana（admin）表示、までを 1 本のスクリプト `scripts/e2e-fresh.sh`（または tools のサブコマンド）で自動実行。認証あり（LAN bind）と認証なし（127.0.0.1）の両方
3. **更新の通し試験**: 1 つ前の版（P6 の bb2f21d など）で作ったデータ volume を、現在の版で起動して壊れないこと（rate2m への改名、grafana-guard 廃止、Authelia 追加、ネットワーク追加）。孤立コンテナの扱い（`--remove-orphans` を手順に）。README の「更新」手順をこの結果に合わせる
4. **backup / restore の往復**（認証あり構成）: 利用者・Authelia の保存データ・Caddy の CA 鍵（`caddy-data`）・Grafana・Prometheus・Loki・Alertmanager の抑止を含めて、別プロジェクトへ復元して同じ状態になること
5. **障害・再起動への耐性**: ホスト再起動相当（全コンテナ停止→起動、`restart: unless-stopped`）、各サービスの単独停止（Loki・Prometheus・Authelia・mask-api・notify-relay）で画面が正しく DEGRADED/STALE になり、復帰後に自動で戻ること。ディスク逼迫（キャプチャ・Loki の上限）で全体が止まらないこと
6. **arm64**: 自前イメージ（tools / mask-api / analyzer / flowd / notify-relay / capture / demo-gen など）が arm64 でビルドでき、ビルド時の selftest が通ること（buildx＋QEMU。重ければ代表 2〜3 個で、その旨を記録）。取得イメージは digest が arm64 を含むことを全件確認
7. **一括の検証コマンド**: これまで散らばっている検証（各 selftest・export_check・LAN 確認・open 確認・topo_test など）を、リポジトリに入れて `scripts/verify.sh`（または `tools verify`）から呼べるようにする。Pi 上でも動き、結果を表で出す。scratchpad にしかない検証スクリプトのうち再利用価値のあるものはリポジトリへ移す
8. **Linux 固有の経路**: capture profile（host network・NET_RAW）を WSL2 か Linux VM で短時間確認できればする。できなければ理由を記録し、README の Pi 手順で必要な確認手順を明記

## 不変条件
- 既存の機能・画面規則・伏せ字・認証の挙動を変えない（直すのは不具合と導入手順のみ。不具合を見つけたら直して記録）
- 秘密値をリポジトリに入れない

## 検証の制約（オーナー指示）
- コンテナは確認時のみ起動し `docker compose stop`（試験用の別プロジェクトは終わったら down -v で片付けてよい）。ブラウザは同時 1 つ。この PC の負荷に配慮し逐次・短時間
