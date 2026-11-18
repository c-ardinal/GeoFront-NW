# パケットの取込と解析

`capture` profile を有効にすると、LAN のパケットを取り込んで通信先 (地球儀・通信先のパネル) を実際のフローで表示します。
取り込んだパケットと、アップロードした pcap / pcapng は、コマンドセンターの解析画面で調べられます。既定では無効です。

## 有効にする手順

パケットの取込は Linux ホストでだけ使えます。Docker Desktop (Windows / macOS) と WSL では LAN のパケットが見えないので使えません。

1. LAN の通信が見える位置にホストの NIC をつなぎます (スイッチやルーターのミラーポートなど)。ミラーポートの設定は機器の管理画面で手作業で行ってください。このツールは機器の設定を変えません。
2. `tools init` のあとで、`.env` に次を書き足します。
   ```sh
   COMPOSE_PROFILES=prod,capture
   OBS_CAPTURE=1
   CAPTURE_IFACE=eth0                # LAN の通信が見えるインターフェース
   CAPTURE_BPF="not port 22"         # 任意 (tcpdump の書式)
   OBS_LAN_CIDRS=192.168.100.0/24
   ```
   `OBS_LAN_CIDRS` は LAN 側のアドレス範囲 (カンマ区切り) で、通信の向き (outbound / inbound) の判定に使います。書かなければ、すべてのプライベートアドレスの範囲を LAN として扱います。
3. 起動して GeoIP のデータベースを取得し、状態を確かめます。
   ```sh
   ./geofront up -d
   ./geofront run --rm tools geoip update      # DB-IP Lite City + ASN (約 65 MB)。月に 1 回更新します
   ./geofront run --rm tools capture status    # 動作中か、インターフェース、リング、受信数と欠落
   ./geofront run --rm tools check
   ```

うまく動かないときは、次の順に確かめてください。

1. `ip -br link` で `CAPTURE_IFACE` の名前があり、UP になっている。
2. `./geofront ps capture` が running (healthy) で、`./geofront logs capture` に dumpcap の開始が出ている。
3. `tools capture status` で受信数が増え、リングのファイルが `CAPTURE_FILE_SECONDS` ごとに増えている。
4. 2〜3 分後に、`tools check` の「パケット取込とフロー」が OK になり、地球儀に通信先が出ている。

取込の停止や取りこぼしはアラート (CaptureDown / CaptureNicDrops / CaptureDumpcapDrops / GeoIPStale / FlowSourceStale / FlowFilesSkipped) で通知されます。

profile と `.env` が合っていないとき (`capture` profile なのに `OBS_CAPTURE=1` や `CAPTURE_IFACE` がない、`prod` がない) は、起動時の確認が理由を出して止まります。

## 解析画面

解析画面は GLOBAL TRAFFIC 見出しの「解析」、または通信先 / 送信元の詳細の「本通信のパケット」から表示します。

- 開けるファイルはキャプチャのリングファイル、アップロードした pcap / pcapng、デモの合成 pcap です。
- パケットの一覧、Wireshark の表示フィルタ、プロトコルの階層ツリー、16 進と ASCII の表示を使えます。
- 統計ではプロトコル階層、会話、端点、I/O グラフ、DNS の問い合わせ名 / TLS SNI / HTTP Host を見られます。一覧と統計は CSV で保存できます。
- 表示フィルタでは決められたフィールドと演算子だけを使えます。使えない書き方はエラーになります。
- ログインありの構成では、アップロードと削除ができるのは operator と admin だけです。

## プライバシー

取り込むのはパケットそのものです。HTTPS などで暗号化された中身は見えず、復号もしません。
HTTP や DNS のような平文のプロトコルは中身が残ります。家族や同居人など、LAN の利用者に知らせてから有効にしてください。
取り込む量は `CAPTURE_BPF` で絞れます。`CAPTURE_SNAPLEN` を小さくすると、TLS SNI や HTTP Host が欠けることがあります。

解析画面ではすべての IP / MAC を伏せます。それでも、DNS の問い合わせ名・TLS SNI・HTTP Host の一覧からは、どの端末がどのサイトを見たかが分かります。
LAN に公開すると、ログインできる利用者は viewer を含めてこれを見られるので、利用者は必要な人だけにしてください。

## 保存期間と容量

| 項目 | 既定 | 内容 |
|---|---|---|
| `CAPTURE_FILES` × `CAPTURE_FILE_MB` | 20 × 20 MB | リングの大きさ。古いファイルから上書きされます |
| `CAPTURE_FILE_SECONDS` | 60 秒 | 次のファイルに切り替える最長の間隔 |
| `CAPTURE_KEEP_HOURS` | 24 時間 | これより古いリングファイルは消されます |
| `CAPTURE_SNAPLEN` | 1514 バイト | 1 パケットあたりに残すバイト数 |
| `PCAP_UPLOAD_MAX_MB` | 50 MB | アップロード 1 件の上限 |
| `PCAP_UPLOADS_TOTAL_MB` | 200 MB | アップロードの合計の上限。超えると古いものから消えます |
| `PCAP_KEEP_HOURS` | 24 時間 | アップロードを残す時間 |
| `FLOWD_RDNS` | `0` | `1` にすると、台帳と DHCP で名前が分からない端末を逆引きで名付けます |

Prometheus に残るのはフローごとのバイト数だけです。フローの系列数の上限は `FLOWD_MAX_SERIES` (既定 3000) で、超えた分は `other` にまとめられます。

```sh
./geofront run --rm tools capture list
./geofront run --rm tools capture prune               # 保存期間と合計の上限を超えたものを消す
./geofront run --rm tools capture prune --dry-run     # 消す対象を確かめるだけ
./geofront run --rm tools capture prune --keep-hours 6
```

バックアップには既定でキャプチャを含めません。含めるときは `tools backup --include-captures` を使い、通信の中身が入ったファイルとして扱ってください。

## 解析の上限

| 項目 | 既定 | 内容 |
|---|---|---|
| `PCAP_ANALYZE_TIMEOUT` | 60 秒 | tshark 1 回の実行時間 |
| `PCAP_VALIDATE_TIMEOUT` | 180 秒 | アップロードを最後まで読む時間。超えると受け付けません |
| `PCAP_ANALYZE_CONCURRENCY` | 1 | 同時に動かす解析の数 |
| `PCAP_ANALYZE_PROC_MB` | 384 | 解析 1 回のメモリ |
| `PCAP_READS_PER_MIN` | 120 | 利用者ごとの 1 分あたりの解析の回数 |

`ANALYZER_MEM` (既定 896m) は (`PCAP_ANALYZE_CONCURRENCY` + 1) × `PCAP_ANALYZE_PROC_MB` + 約 60 MB が収まる値にしてください。

## GeoIP

国・都市・緯度経度には DB-IP の IP to City Lite を、ASN には IP to ASN Lite を使います。ライセンスは CC BY 4.0 です (IP Geolocation by [DB-IP](https://db-ip.com))。

```sh
./geofront run --rm tools geoip update    # 今月か先月の版を取得します。失敗しても前の版はそのまま残ります
./geofront run --rm tools geoip status    # 版と経過日数
```

月に 1 回 (cron など) 更新してください。45 日より古くなると、`tools check` が注意を出し、画面の鮮度の表示が DEGRADED になります。
プライベートアドレスやドキュメント用のアドレス、データベースにないアドレスは `Unknown` になり、データベースがなくてもフローは国が `Unknown` のまま動きます。
