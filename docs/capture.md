# パケットのキャプチャと解析

`capture` profile の有効化で、LAN のパケットをキャプチャし、通信先 (地球儀・通信先のパネル) を実際のフローで表示します。
キャプチャ済みのパケットと、アップロード済みの pcap / pcapng は、コマンドセンターの解析画面で調査可能です。既定では無効です。

## 有効化の手順

パケットキャプチャは Linux ホスト限定です。Docker Desktop (Windows / macOS) と WSL では LAN のパケットを参照できないため利用不可です。

1. LAN の通信を観測可能な位置にホストの NIC を接続します (スイッチやルーターのミラーポートなど)。ミラーポートの設定は機器の管理画面で手動実施してください。本ツールは機器の設定を変更しません。
2. `tools init` の実行後、`.env` に以下を追記します。
   ```sh
   COMPOSE_PROFILES=prod,capture
   OBS_CAPTURE=1
   CAPTURE_IFACE=eth0                # LAN の通信を観測可能なインターフェース
   CAPTURE_BPF="not port 22"         # 任意 (tcpdump の書式)
   OBS_LAN_CIDRS=192.168.100.0/24
   ```
   `OBS_LAN_CIDRS` は LAN 側のアドレス範囲 (カンマ区切り) で、通信の方向 (outbound / inbound) の判定に使用します。未指定の場合は、全プライベートアドレスの範囲を LAN として処理します。
3. 起動後に GeoIP のデータベースを取得し、状態を確認します。
   ```sh
   ./geofront up -d
   ./geofront run --rm tools geoip update      # DB-IP Lite City + ASN (約 65 MB)。月 1 回更新
   ./geofront run --rm tools capture status    # 稼働状況、インターフェース、リング、受信数と欠落
   ./geofront run --rm tools check
   ```

動作不良の場合は、以下の順に確認してください。

1. `ip -br link` で `CAPTURE_IFACE` の名称が存在し、UP 状態である。
2. `./geofront ps capture` が running (healthy) で、`./geofront logs capture` に dumpcap の開始記録がある。
3. `tools capture status` で受信数が増加し、リングのファイルが `CAPTURE_FILE_SECONDS` 間隔で増加している。
4. 2〜3 分後に、`tools check` の「パケットキャプチャとフロー」が OK となり、地球儀に通信先が表示されている。

キャプチャの停止や欠落はアラート (CaptureDown / CaptureNicDrops / CaptureDumpcapDrops / GeoIPStale / FlowSourceStale / FlowFilesSkipped) で通知します。

profile と `.env` の不整合時 (`capture` profile で `OBS_CAPTURE=1` や `CAPTURE_IFACE` が未設定、`prod` が未指定) は、起動時の確認処理が理由を表示して停止します。

## 解析画面

解析画面は GLOBAL TRAFFIC 見出しの「解析」、または通信先 / 送信元の詳細の「本通信のパケット」から表示します。

- 表示対象のファイルはキャプチャのリングファイル、アップロード済みの pcap / pcapng、デモの合成 pcap です。
- パケットの一覧、Wireshark の表示フィルタ、プロトコルの階層ツリー、16 進と ASCII の表示が利用可能です。
- 統計ではプロトコル階層、会話、端点、I/O グラフ、DNS の問合せ名 / TLS SNI / HTTP Host を参照可能です。一覧と統計は CSV で保存可能です。
- 表示フィルタでは規定のフィールドと演算子のみ利用可能です。非対応の記法はエラーです。
- ログインありの構成では、アップロードと削除は operator と admin のみ可能です。

## プライバシー

キャプチャ対象はパケットそのものです。HTTPS などで暗号化済みの内容は参照不可で、復号も実施しません。
HTTP や DNS のような平文のプロトコルは内容が残存します。家族や同居人など、LAN の利用者への周知後に有効化してください。
キャプチャ量は `CAPTURE_BPF` で制限可能です。`CAPTURE_SNAPLEN` の縮小で、TLS SNI や HTTP Host が欠落する場合があります。

解析画面では全 IP / MAC をマスク表示します。ただし、DNS の問合せ名・TLS SNI・HTTP Host の一覧からは、各端末の閲覧サイトが判明します。
LAN への公開時は、viewer を含む全ログイン利用者が本情報を参照可能なため、利用者は必要最小限としてください。

## 保存期間と容量

| 項目 | 既定 | 内容 |
|---|---|---|
| `CAPTURE_FILES` × `CAPTURE_FILE_MB` | 20 × 20 MB | リングの容量。古い順に上書き |
| `CAPTURE_FILE_SECONDS` | 60 秒 | 次ファイルへの切替の最長間隔 |
| `CAPTURE_KEEP_HOURS` | 24 時間 | 本時間を超過したリングファイルは削除 |
| `CAPTURE_SNAPLEN` | 1514 バイト | 1 パケットあたりの保存バイト数 |
| `PCAP_UPLOAD_MAX_MB` | 50 MB | アップロード 1 件の上限 |
| `PCAP_UPLOADS_TOTAL_MB` | 200 MB | アップロードの合計の上限。超過時は古い順に削除 |
| `PCAP_KEEP_HOURS` | 24 時間 | アップロードの保存時間 |
| `FLOWD_RDNS` | `0` | `1` の場合、台帳と DHCP で名称不明の端末を逆引きで命名 |

Prometheus に残存するのはフロー単位のバイト数のみです。フローの系列数の上限は `FLOWD_MAX_SERIES` (既定 3000) で、超過分は `other` に集約します。

```sh
./geofront run --rm tools capture list
./geofront run --rm tools capture prune               # 保存期間と合計の上限の超過分を削除
./geofront run --rm tools capture prune --dry-run     # 削除対象の確認のみ
./geofront run --rm tools capture prune --keep-hours 6
```

バックアップには既定でキャプチャを含めません。含める場合は `tools backup --include-captures` を使用し、通信内容を含むファイルとして管理してください。

## 解析の上限

| 項目 | 既定 | 内容 |
|---|---|---|
| `PCAP_ANALYZE_TIMEOUT` | 60 秒 | tshark 1 回の実行時間 |
| `PCAP_VALIDATE_TIMEOUT` | 180 秒 | アップロードの全量読込の時間。超過時は受付拒否 |
| `PCAP_ANALYZE_CONCURRENCY` | 1 | 解析の同時実行数 |
| `PCAP_ANALYZE_PROC_MB` | 384 | 解析 1 回のメモリ |
| `PCAP_READS_PER_MIN` | 120 | 利用者単位の 1 分あたりの解析回数 |

`ANALYZER_MEM` (既定 896m) は (`PCAP_ANALYZE_CONCURRENCY` + 1) × `PCAP_ANALYZE_PROC_MB` + 約 60 MB 以上の設定値にしてください。

## GeoIP

国・都市・緯度経度には DB-IP の IP to City Lite を、ASN には IP to ASN Lite を使用します。ライセンスは CC BY 4.0 です (IP Geolocation by [DB-IP](https://db-ip.com))。

```sh
./geofront run --rm tools geoip update    # 当月か前月の版を取得。失敗時も前の版は保持
./geofront run --rm tools geoip status    # 版と経過日数
```

月 1 回 (cron など) 更新してください。45 日を超過すると、`tools check` が注意を表示し、画面の鮮度表示が DEGRADED になります。
プライベートアドレスやドキュメント用アドレス、データベース未登録のアドレスは `Unknown` となり、データベースが不在でもフローは国が `Unknown` のまま動作します。
