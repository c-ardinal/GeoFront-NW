# R1 仕様: 公開に向けた構成整理と配布（GeoFront-NW）

親計画: `docs/plans/v2/PLAN.md`。H1 の後に実施。オーナー指示 2026-10-27:
- プライベートリポジトリ `https://github.com/c-ardinal/GeoFront-NW.git` を作成済み。諸々対応を進める
- いずれ外部公開する。設定はコミットせず保持、または環境変数で設定できるように
- 名前に YAMAHA を入れない（他機種も将来サポート）。エヴァ用語を絡める → GeoFront-NW
- ライセンスは MIT
- **コミットしてはいけないデータは絶対にコミットしない**

## 受入条件
1. **設定の外出し**: 現場固有の設定（`.env`、機器台帳、通知先、Authelia の利用者、生成物）は `OBS_CONFIG_DIR`（既定はリポジトリ外。例 `/etc/geofront` か `~/.config/geofront`、無指定時は後方互換で従来の場所）にまとめる。リポジトリには `config.example/` のみ。全設定値は環境変数で上書き可能、秘密値は `*_FILE` でも受け取れる。`tools init/doctor/check/backup` を対応させる。既存の配置からの移行コマンド（`tools migrate-config`）
2. **漏洩防止の仕組み**: `.gitignore` の強化に加え、`scripts/leak-scan.sh`（git の追跡対象と**全履歴**を対象に、ドキュメント用以外の IPv4・MAC・秘密値らしい文字列・`.env`・鍵・証明書・pcap・DB ファイルを検出）。pre-commit フック（任意導入）と CI と `tools doctor` から呼ぶ。許可リスト（RFC 5737/3849 のドキュメント用アドレス、テスト用と明記された値）
3. **機種ドライバの分離**: 機種固有（SNMP の取得モジュール、syslog の解析、LLDP の扱い、デモの機器）を `drivers/<vendor-model>/` に寄せ、本体は機種に依存しない。今は `drivers/yamaha-rtx`・`drivers/yamaha-wlx`。機器台帳の `type` からドライバを選ぶ。他社機の追加手順を README（または docs/drivers.md）に
4. **名称**: プロジェクト名を GeoFront-NW に（README・画面のタイトル・compose のプロジェクト名既定・イメージ名）。compose のプロジェクト名変更で既存 volume が見えなくなる問題は、既定のプロジェクト名を据え置くか移行手順を用意して避ける（データを失わない）
5. **商標・ライセンス**: `LICENSE`（MIT、著作者 c-ardinal）、`THIRD_PARTY_NOTICES.md`（同梱 JS・Python 依存・イメージに含む OSS・DB-IP の CC BY 4.0・tshark の GPLv2 とソース入手先）。テーマ名 `eva-film` を中立名（例 `film`）へ（設定の後方互換あり）。「Evangelion」「NERV」等の商標・公式ロゴ・キャラクターを使っていないことを確認。同梱フォントのライセンス確認（再配布不可なら同梱をやめる）
6. **配布（GHCR）**: GitHub Actions: push/PR で selftest・leak-scan・verify の軽量版、タグ `v*` で自前イメージを amd64/arm64 でビルドし selftest 後に `ghcr.io/c-ardinal/geofront-nw-<svc>` へ登録。compose は `image: ghcr.io/...:${GEOFRONT_VERSION}` を既定にしつつ `build:` を残す（手元ビルド可）。外部イメージの更新提案に Dependabot（docker・github-actions）
7. **リポジトリへの登録**: 全履歴を leak-scan で検査し、問題がなければ `origin` を設定して main を push（プライベート）。履歴に問題があれば push せず報告（履歴の書き換えはオーナー判断）

## 不変条件
- 機能・画面規則・伏せ字・認証の挙動を変えない
- 既存の main プロジェクトのデータ（volume）を失わない
