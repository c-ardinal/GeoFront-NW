# P3 仕様: パケット取込と解析

親計画: `docs/plans/v2/PLAN.md`（承認済み: キャプチャ（任意有効化）と保存済み pcap 解析の両対応、本番ホストは Linux）

## 受入条件
1. **capture profile**: `--profile capture` で有効化（既定は無効）。キャプチャ用コンテナは host network ＋ 必要最小の capability（NET_RAW / NET_ADMIN のみ）、指定インターフェース・BPF フィルタ・snaplen を `.env` で設定。dumpcap のリングバッファ（ファイルサイズ・本数・合計容量の上限）。容量超過・停止・パケット欠落（dumpcap の drop 統計）を Prometheus 指標として出し、COLLECTION HEALTH と鮮度判定に反映。Windows / Docker Desktop では使えない旨を検出して起動時に明示的に失敗する。
2. **フロー生成と GeoIP**: キャプチャ（またはアップロードした pcap）から 5-tuple のフロー集計を作り、`demo_flow_bytes_total` と同じ形（src_host, dst_ip, dst_country, dst_city, lat, lon, asn, direction）で Prometheus に出す。src_host は DHCP/ARP・機器台帳・逆引きで名前付け（取れなければ IP の伏せ字）。方向（outbound/inbound）は LAN 側アドレス範囲（`.env`）で判定。GeoIP は DB-IP Lite（City + ASN、CC BY 4.0、表示義務を UI と README に記載）を tools でダウンロード・更新（版と更新日を画面に表示、期限切れは DEGRADED）。プライベート・ドキュメント用アドレスは Unknown 扱い。本番の通信先パネル・地球儀はこの実フローで動き、`flows_configured` が true になる。
3. **pcap 解析画面**（command-center に新しい「解析」ビュー。既存の画面規則に従う）:
   - 取り込み: キャプチャ中のリングファイルの選択、または pcap/pcapng のアップロード（サイズ上限、拡張子とマジックバイト検証）
   - パケット一覧（時刻・送信元・宛先・プロトコル・長さ・情報）。仮想スクロール、ページング
   - 表示フィルタ（Wireshark の display filter 文法。サーバ側で tshark に渡す。長さ・文字種・実行時間の上限）
   - パケット詳細（プロトコル階層ツリー）と 16 進＋ASCII 表示、選択箇所の相互ハイライト
   - 統計: プロトコル階層、会話（IP/TCP/UDP）、端点、I/O グラフ（時間ごとのパケット/バイト）、DNS・TLS SNI・HTTP Host の一覧
   - フローや通信先から「この通信のパケットを見る」で解析画面へ遷移（期間とフィルタを引き継ぐ）
   - 伏せ字: 一覧・詳細・16 進・統計・エクスポートのすべてで IP/MAC を伏せる（16 進中の生バイトも伏せる）。伏せ字を外す操作は認証層待ちで不可
4. **解析の隔離**: tshark は専用の analyzer コンテナで実行（ネットワークなし、読み取り専用ファイルシステム、非 root、CPU/メモリ/時間の上限、1 リクエスト 1 プロセス、同時実行数の上限）。キャプチャファイルは analyzer に読み取り専用で渡す。書き込み・シェル展開は一切させない（引数は配列で渡す）。
5. **保存と削除**: キャプチャとアップロードの保存期間・合計容量の上限（既定は小さめ、Pi の SD を想定）。tools に `capture status / list / prune` を追加。backup の対象外を既定にする（含めるオプションあり）。
6. **デモ／テスト**: demo profile では合成 pcap（ドキュメント用アドレス、典型的な DNS/HTTPS/NTP/ARP/DHCP を含む）を同梱し、解析画面とフロー生成が動く。testbed では合成トラフィックを流すコンテナを置き、capture profile の経路（Linux 上で）を検証できる。Windows 上の検証は pcap 取り込みと解析まで。
7. **安全と説明**: README に、ミラーポート設定は手作業・仕様 G4 の承認が前提であること、捕捉データの扱い（暗号化された中身は見えない・見ない、保存期間）、プライバシー注意を記載。

## 不変条件
- capture は既定で無効。ルーター設定を変更しない。完全 PCAP の長期保存はしない（上限付きリング）
- 伏せ字と書き込み制限（P1/P2）を維持。解析 API は読み取りのみ
- 既存の画面規則（重複なし・幅固定・STALE と — の扱い・44px・両テーマ）

## 検証の制約（オーナー指示）
- コンテナは確認時のみ起動・終了後停止、ブラウザは同時 1 つ（browser.lock）
- この PC は Windows のため、host network のキャプチャ経路は「Linux 前提の構成として compose 検証＋可能なら Linux VM/WSL 上で短時間」まで。できない場合はその旨を明記
