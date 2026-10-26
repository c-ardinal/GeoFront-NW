# PERF 計測結果: Raspberry Pi 向け軽量化と表示側 GPU 活用

仕様: `docs/plans/v2/PERF-SPEC.md`。変更前 = HEAD `b923d19` (P4)、変更後 = 本作業の未コミット変更。計測日 2026-10-26。

## 条件

- 計測ホスト: Intel Core i5-8400 (6 コア 2.8〜4.0 GHz) / Docker Desktop 29.1 (VM 6 CPU, 32 GB) / NVIDIA RTX 4080。
- Pi 相当の制限: 計測用の override (scratchpad の `pi.yaml`、リポジトリには入れていない) で常駐サービスをすべて VM の 4 コアに固定 (`cpuset: "0-3"`)。メモリ / CPU 上限は compose の既定値 (Pi 4 4GB 想定) のまま。Docker ではコアを遅くできないため、**CPU 値はこの PC のコア 1 個 = 100 %**。Pi 4 (Cortex-A72 1.5 GHz) への換算は **×4** と仮定 (単一スレッド性能の比。実機での確認は未了)。
- 時間 (この PC の負荷を抑えるため仕様の 10 分より短縮): `up` 後 3 分待ってから、**待機 4 分** (ブラウザなし) と **WALLBOARD 1 画面 4 分** (GPU 有りのヘッドレス Chromium 1 つで command-center を表示) を続けて計測。`docker stats` をストリームで読み (1 コンテナあたり約 1 秒ごと、各 948 点)、平均と最大 (約 1 秒の最大値) を取った。
  - 最初に試した `docker stats --no-stream` の 10 秒間隔の採取は、起動直後 (Grafana・Loki の起動処理) を含み、SwiftShader のブラウザと同時に動かすと VM が飢えて値が壊れたため不採用 (下の「捨てた計測」)。
- 構成: demo (`--profile demo`、合成の 3 台) と prod + testbed (`--env-file testbed/testbed.env`、疑似機器 2 台: rtx1300 / wlx413。仕様の「機器 3 台」より 1 台少ない)。testbed の疑似機器 (testbed-rtx / testbed-wlx / testbed-traffic / notifymock) は本番には無いので、合計は「全コンテナ」と「疑似機器を除く」の両方を出す。
- 表示側: WALLBOARD 1920×1080 を 2 分。GPU 無し = Playwright の chrome-headless-shell + SwiftShader、GPU 有り = Chromium (headless=new, ANGLE D3D11, RTX 4080)。fps = WebGL の `clear()` 回数 / 秒 (globe の描画回数)、描画呼び出し = `draw*()` 回数 / フレーム、メインスレッド = CDP `Performance.getMetrics` の TaskDuration、長いタスク = `longtask` (50 ms 超)、ブラウザ CPU = CDP `SystemInfo.getProcessInfo` の全プロセス (GPU プロセス含む。SwiftShader はここで CPU を使う) の CPU 時間 / 経過時間。
- ヘッド付き (画面のある) GPU 実行はしていない (ヘッドレスでも RTX 4080 の D3D11 で WebGL が動くことを WebGL レンダラ名で確認したため)。Raspberry Pi の Chromium (V3D) では計測していない。

## 判定 (サーバ側の目標: prod + testbed、Pi 4 相当)

| 項目 | 目標 | 変更前 | 変更後 (Grafana あり) | 変更後 (`OBS_GRAFANA=0`) |
|---|---|---|---|---|
| 平均 CPU (WALLBOARD 表示中、疑似機器を除く) | 1 コア換算 25 % 未満 (厳しい読み) / 4 コア合計の 1/4 未満 (括弧書き) | 7.27 % (この PC) → Pi 換算 約 29 % / 1 コア = **4 コア合計の約 7 %** | 4.70 % → Pi 換算 約 19 % / 1 コア = **約 4.7 %** | 4.12 % → 約 16 % / 1 コア = **約 4.1 %** |
| 同 (全コンテナ、疑似機器込み) | 同上 | 9.39 % → 4 コア合計の約 9 % | 5.86 % → 約 5.9 % | 5.39 % → 約 5.4 % |
| 合計 RAM (平均 / 最大、疑似機器を除く) | 2.5 GB 未満 | 462 / 534 MiB | 451 / 523 MiB | 355 / 421 MiB |
| 合計 RAM (全コンテナ) | 同上 | 595 / 684 MiB | 572 / 650 MiB | 474 / 557 MiB |

**変更後はどちらの目標も満たす。** 変更前が満たしていたかは目標の読み方で変わる: 仕様の「1 コア換算で 25 % 未満」を厳しく (Pi のコア 1 個の 25 % 未満 = この PC で約 6.25 % 未満) 読むと、変更前は Pi 換算で約 29 % / 1 コアで**未達**、変更後は約 19 % (Grafana なし約 16 %) で達成。括弧書きの「4 コア合計の 1/4 未満」と読めば変更前も達成していた。変更による削減は CPU で約 35〜45 %。RAM はほぼ同じで、Grafana を外すと約 100 MB 減る。換算係数 ×4 は仮定で、Pi 実機ではまだ測っていない。Pi では 1 コアあたりの処理が重く、各サービスの CPU 上限 (`*_CPUS`、多くは 0.25〜1.0 コア) に当たりやすいので、上の最大値 (起動直後・圧縮・詳細画面を開いたとき) は実機で確かめる必要がある。

## サーバ側: prod + testbed

### WALLBOARD 1 画面表示中 (4 分)

| service | CPU avg % before | after | CPU max % before | after | RAM avg MiB before | after |
|---|---:|---:|---:|---:|---:|---:|
| loki-1 | 1.97 | 1.41 | 62.3 | 41.9 | 112 | 115 |
| mask-api-1 | 1.32 | 1.03 | 12.6 | 10.1 | 25 | 24 |
| testbed-rtx (sim) | 0.79 | 0.40 | 9.2 | 7.1 | 47 | 46 |
| testbed-wlx (sim) | 0.71 | 0.36 | 12.0 | 6.5 | 58 | 46 |
| grafana-guard-1 | 0.70 | 0.31 | 17.1 | 16.1 | 22 | 22 |
| grafana-1 | 0.56 | 0.34 | 7.2 | 3.2 | 91 | 87 |
| prometheus-1 | 0.50 | 0.31 | 6.5 | 5.0 | 49 | 45 |
| alloy-1 | 0.50 | 0.33 | 5.7 | 3.3 | 51 | 49 |
| notifymock-1 (sim) | 0.45 | 0.24 | 14.5 | 11.6 | 19 | 20 |
| notify-relay-1 | 0.43 | 0.21 | 20.3 | 11.9 | 19 | 19 |
| proxy-1 | 0.36 | 0.28 | 8.4 | 3.1 | 17 | 18 |
| analyzer-1 | 0.34 | 0.14 | 15.2 | 8.2 | 9 | 9 |
| command-center-1 | 0.29 | 0.19 | 5.2 | 3.0 | 5 | 5 |
| testbed-traffic-1 (sim) | 0.18 | 0.16 | 0.9 | 0.6 | 9 | 9 |
| snmp-exporter-1 | 0.16 | 0.06 | 5.0 | 2.5 | 45 | 42 |
| alertmanager-1 | 0.12 | 0.07 | 3.1 | 3.2 | 16 | 13 |
| **TOTAL (all containers)** | **9.39** | **5.86** | | | **595** (max 684) | **572** (max 650) |
| **TOTAL without simulators** | **7.27** | **4.70** | | | **462** (max 534) | **451** (max 523) |

### 待機 (ブラウザなし、4 分)

| service | CPU avg % before | after | CPU max % before | after | RAM avg MiB before | after |
|---|---:|---:|---:|---:|---:|---:|
| loki-1 | 1.00 | 0.75 | 9.5 | 3.5 | 81 | 69 |
| testbed-rtx (sim) | 0.82 | 0.37 | 15.6 | 6.6 | 47 | 46 |
| grafana-guard-1 | 0.71 | 0.29 | 25.3 | 15.2 | 22 | 22 |
| testbed-wlx (sim) | 0.69 | 0.37 | 11.2 | 7.1 | 58 | 45 |
| notify-relay-1 | 0.57 | 0.20 | 17.9 | 11.8 | 19 | 19 |
| grafana-1 | 0.54 | 0.33 | 7.2 | 3.6 | 92 | 88 |
| alloy-1 | 0.50 | 0.33 | 6.2 | 4.1 | 51 | 49 |
| notifymock-1 (sim) | 0.44 | 0.22 | 15.8 | 13.5 | 19 | 20 |
| analyzer-1 | 0.43 | 0.17 | 17.4 | 8.1 | 9 | 9 |
| mask-api-1 | 0.38 | 0.12 | 16.2 | 6.0 | 21 | 21 |
| prometheus-1 | 0.21 | 0.10 | 4.4 | 4.2 | 38 | 39 |
| snmp-exporter-1 | 0.20 | 0.07 | 8.8 | 2.7 | 45 | 42 |
| testbed-traffic-1 (sim) | 0.17 | 0.16 | 1.2 | 0.6 | 9 | 9 |
| alertmanager-1 | 0.12 | 0.05 | 4.5 | 3.2 | 16 | 13 |
| proxy-1 | 0.11 | 0.04 | 4.0 | 3.0 | 14 | 14 |
| command-center-1 | 0.11 | 0.04 | 3.3 | 2.7 | 5 | 5 |
| **TOTAL (all containers)** | **7.00** | **3.63** | | | **546** (max 618) | **512** (max 571) |
| **TOTAL without simulators** | **4.89** | **2.50** | | | **412** (max 468) | **391** (max 437) |

### Grafana なし (`OBS_GRAFANA=0`、変更後どうしの比較)

| 条件 | CPU avg % (Grafana あり → なし) | 疑似機器を除く | RAM avg MiB (あり → なし) | 疑似機器を除く |
|---|---|---|---|---|
| 待機 | 3.63 → 3.52 | 2.50 → 2.16 | 512 → 406 | 391 → 286 |
| WALLBOARD | 5.86 → 5.39 | 4.70 → 4.12 | 572 → 474 | 451 → 355 |

## サーバ側: demo

### WALLBOARD 1 画面表示中 (4 分)

| service | CPU avg % before | after | CPU max % before | after | RAM avg MiB before | after |
|---|---:|---:|---:|---:|---:|---:|
| loki-1 | 2.98 | 1.70 | 62.3 | 37.5 | 108 | 121 |
| mask-api-1 | 1.88 | 1.46 | 24.6 | 19.8 | 25 | 29 |
| grafana-guard-1 | 0.94 | 0.31 | 24.3 | 13.9 | 22 | 22 |
| demo-gen-1 | 0.91 | 0.34 | 24.5 | 13.5 | 14 | 16 |
| alloy-1 | 0.73 | 0.43 | 7.3 | 3.6 | 56 | 67 |
| prometheus-1 | 0.66 | 0.41 | 10.2 | 6.5 | 70 | 65 |
| grafana-1 | 0.62 | 0.35 | 9.3 | 4.2 | 96 | 85 |
| flowd-demo-1 | 0.60 | 0.19 | 22.2 | 10.5 | 19 | 19 |
| notify-relay-1 | 0.58 | 0.20 | 23.4 | 11.0 | 19 | 20 |
| analyzer-1 | 0.45 | 0.16 | 17.4 | 11.2 | 12 | 12 |
| proxy-1 | 0.39 | 0.33 | 5.4 | 5.7 | 19 | 22 |
| command-center-1 | 0.27 | 0.22 | 3.3 | 5.3 | 5 | 5 |
| alertmanager-1 | 0.17 | 0.07 | 5.8 | 2.8 | 14 | 19 |
| **TOTAL** | **11.18** | **6.17** | | | **480** (max 571) | **501** (max 556) |

### 待機 (4 分)

| service | CPU avg % before | after | CPU max % before | after | RAM avg MiB before | after |
|---|---:|---:|---:|---:|---:|---:|
| loki-1 | 1.81 | 1.10 | 78.2 | 30.5 | 100 | 117 |
| demo-gen-1 | 0.82 | 0.36 | 25.6 | 21.2 | 14 | 16 |
| grafana-guard-1 | 0.79 | 0.29 | 23.1 | 16.5 | 22 | 22 |
| grafana-1 | 0.64 | 0.32 | 8.4 | 3.0 | 96 | 84 |
| alloy-1 | 0.62 | 0.41 | 9.9 | 3.3 | 56 | 68 |
| flowd-demo-1 | 0.62 | 0.19 | 22.3 | 10.2 | 19 | 19 |
| mask-api-1 | 0.58 | 0.36 | 19.4 | 13.5 | 23 | 31 |
| analyzer-1 | 0.53 | 0.17 | 20.0 | 9.5 | 12 | 12 |
| notify-relay-1 | 0.52 | 0.21 | 18.3 | 11.8 | 19 | 20 |
| prometheus-1 | 0.33 | 0.15 | 10.8 | 4.1 | 62 | 65 |
| proxy-1 | 0.19 | 0.10 | 8.3 | 3.7 | 15 | 20 |
| command-center-1 | 0.15 | 0.07 | 4.7 | 2.6 | 5 | 5 |
| alertmanager-1 | 0.12 | 0.06 | 5.1 | 2.9 | 14 | 19 |
| **TOTAL** | **7.71** | **3.79** | | | **457** (max 552) | **497** (max 521) |

読み方:
- 待機時の CPU の多くは healthcheck (Python サービスは 30 秒ごとに Python を 1 プロセス起動していた) と自己 scrape だった。60 秒間隔 (起動直後のみ 5 秒) と scrape 30 秒で半分前後になった。CPU max の 10〜25 % はこの healthcheck の瞬間。
- WALLBOARD 表示中の増分は主に Loki (ログの範囲取得) と mask-api (伏せ字処理)。1 画面・10 秒ごとの取得で、変更後は 1 周期の Prometheus の瞬時問い合わせを 29 → 24 件に減らした (`up{job="snmp"}` を `up` から作り、変化の遅い 4 件は 1 分ごと)。
- Loki の RAM はやや増えた (`chunk_idle_period` 1h で少量のログを長くメモリに置き、チャンクの書き出しと索引を減らすため)。上限 512 MiB に対して最大 170 MiB。

## 表示側 (WALLBOARD 1920×1080、2 分、demo)

| 条件 | 描画モード | fps | 描画呼び出し / フレーム | メインスレッド % | うち script % | 長いタスク (件 / 合計 ms) | ブラウザ CPU % (全プロセス) |
|---|---|---:|---:|---:|---:|---:|---:|
| GPU 無し (SwiftShader)・既定テーマ before | (なし: 常にアニメ) | 10.3 | 88 | 11.5 | 9.0 | 37 / 7759 | **481** |
| 同 after (AUTO → LITE) | LITE | 0.3 | 74 | 3.6 | 1.6 | 12 / 804 | **23** |
| GPU 無し・eva-film before | | 12.2 | 92 | 8.4 | 3.5 | 18 / 1992 | **458** |
| 同 after (AUTO → LITE) | LITE | 0.4 | 46 | 3.1 | 1.0 | 7 / 585 | **29** |
| GPU 無しで GPU モードを強制 (`?render=gpu`) after | GPU | 11.2 | 67 | 10.5 | 8.2 | 43 / 6107 | 484 |
| GPU 有り (RTX 4080)・既定テーマ before | | 57.6 | 88 | 19.0 | 15.7 | 0 | **41** |
| 同 after (AUTO → GPU) | GPU | 19.0 * | 66 | 9.7 | 7.2 | 0 | **23** |
| GPU 有り・eva-film before | | 57.7 | 93 | 19.5 | 11.4 | 0 | **45** |
| 同 after | GPU | 19.0 * | 39 | 8.1 | 5.1 | 0 | **22** |

\* 最大 30 fps、操作が 1 分ないと 15 fps (計測は無操作なので 2 分の平均で 19)。操作中は 28〜30 fps (機能確認で 28.4 fps)。

- GPU 無しのブラウザは、変更前は地球儀の描画 (SwiftShader) と CSS アニメーションの合成でこの PC の約 5 コアを使い続けていた (fps はホストの空き具合で 10〜36 と大きくぶれる)。LITE では静止表示で、データ更新・操作のときだけ描く (12 秒で 5〜14 フレーム)。LITE で画面全体を静止表示にする前の計測 (地球儀だけ静止) は 89 % / 107 % で、残りは合成だけで済む CSS アニメーション (DOWN の点滅・警報の枠・dead-man など) をソフトウェアで毎フレーム合成するコストだった。
- GPU 有りでは描画回数が半分になり (60 → 30 / 15 fps)、描画呼び出しは既定テーマ 88 → 66 (当たり判定用の透明な点を描かない、パルスを 1 回の描画に)、eva-film 93 → 39 (さらに経緯線 35 本を 2 本の線に、HTML ラベルを 1 枚のキャンバスに)。メインスレッドは約半分。

## 変更内容 (要約)

サーバ側
- Prometheus: scrape / 評価 30 秒、同時評価 4、Loki / Alloy / Prometheus 自身のメトリクスは画面が使うものだけ保存。画面・WAN の記録ルール (`obs_wan:*:rate2m` に改名)・Grafana の rate 窓は 2 分 (4 間隔)、Grafana データソースの `timeInterval` 30s。
- Loki: 照会の並列 2、結果 / チャンクキャッシュ 32 MB、WAL 再生上限 128 MB・チェックポイント 15 分、チャンクの idle 1h、ring の heartbeat 30s、ruler の評価・ポーリング 10 分。
- Alloy: `--disable-reporting`。Grafana: 任意 (`OBS_GRAFANA=0` で grafana と grafana-guard を起動しない。`tools check` / `check_env` もそれに従う)、Grafana 自身のアラート評価と Live を無効、ログ warn。
- 全サービスの healthcheck: 60 秒 (起動直後 60 秒間は 5 秒)。grafana-guard: 保存された管理者のハッシュが同じなら PBKDF2 を再計算しない。flowd: 5 秒ごとの tick、系列の期限切れ走査は 1 分ごと。
- 上限の見直し: grafana-guard のメモリ 64 → 96 MiB (最大 41 MiB を測定)、`PROM_MEM` 既定 768 → 512 MiB (最大約 80 MiB)。他は最大値の 2 倍以上の余裕があり据え置き。

表示側
- `render-mode.js`: WebGL の有無・ソフトウェア描画 (SwiftShader / llvmpipe など、`failIfMajorPerformanceCaveat`) の判定、AUTO / GPU / LITE を設定メニューの `RENDER:` で表示・切替 (localStorage、例外は握りつぶして既定値)。
- `globe-layers.js`: 都市のパルスをシェーダで描く 1 メッシュ (時間の uniform だけ更新、周期で折り返して精度を保つ)、eva-film のラベルを 1 枚のキャンバスに (以前の HTML ラベルと同じ位置・見た目をスタイルシートから読む。カメラが動いたときだけ描き直し、重なりの間引きも同時に計算)。
- `globe.js`: 30 fps 上限 / 無操作 1 分で 15 fps / タブ非表示で停止、LITE と reduced-motion は変化時だけ描画、当たり判定の点を描かない、eva の経緯線を 2 本に。
- 取得: 要求ごとの期限 (8 秒 / 範囲・ログ 16 秒) → 超過は DEGRADED (理由 `timeout`)、続けば STALE。同じ URL の 4 秒以内の要求は共有、定期取得は Prometheus / Loki それぞれ前回の応答が来るまで重ねない (鮮度もそれぞれ独立: Loki が遅くても metrics の鮮度は変わらない)、変化の遅い 4 問い合わせは LIVE で 1 分ごと、`up{job="snmp"}` は `up` から作る。
- CSS: DOWN の点滅・eva の暗転・eva の警報帯を opacity だけのアニメーションに (見た目は同じ: 黒 30 % の重ね = brightness 0.7、帯は 69 %)。LITE は reduced-motion と同じ静止表示 (ticker は折り返し、dead-man は動く)。

## 確認したこと (変更後)

- ビルド時の自己テスト: mask-api / analyzer / flowd / notify-relay / demo-gen / tools (`tools --selftest`、Grafana 無効時の検証を追加) すべて ok。
- `tools check` (demo): すべて OK。
- P4 の証跡出力チェック (`export_check.py` scopes / limits): 7 範囲の zip すべてで生の IPv4 / IPv6 / MAC / トークン 0 件、不正な要求はすべて 400 / 405。
- ブラウザ (scratchpad `check.js`): GPU 有りは AUTO → GPU・28.4 fps、メニューで AUTO → GPU → LITE と切り替わり localStorage に保存、LITE は 12 秒で 10〜14 フレーム。GPU 無しは AUTO → LITE、ツールチップは LITE でも出る。reduced-motion は GPU モードでも静止。両テーマ・390 / 1024 / 1920 / 2560 px でエラーなし、メニューのボタンはタッチ幅で 44 px。PLAYBACK: バッジ PLAYBACK (幅 147 px 固定)、停止中の取得 0 件、シーク後の 34 要求すべてがカーソル時刻、時刻なしの LIVE 問い合わせ 0、LIVE に戻る。要求の遅延 (9.5 秒) で LIVE → DEGRADED (理由 timeout) → STALE、バッジ幅は 147 px のまま。

## 既知の制限

- CPU の Pi 換算 (×4) は仮定。Pi 4 実機・Pi の Chromium (V3D) では未計測。
- `PROM_MEM` の既定 512 MiB は、短時間の計測 (最大約 80 MiB) からの見直しで、30 日分のデータの圧縮や 7 日分の証跡出力・PLAYBACK の範囲問い合わせでは確かめていない (Pi 実機での確認項目)。
- 変更前の SwiftShader 計測 (表示側) では、ブラウザがこの PC の約 5 コアを使ったため Docker の VM が飢え、command-center の取得に 502 / 504 が出ていた (各条件 5 件程度)。変更前の GPU 無しの数値はこの状態のもの。変更後の LITE ではエラーなし。
- 計測は 4 分 (表示側 2 分) で、仕様の 10 分より短い。Loki の圧縮 (10 分ごと)・Prometheus の head 圧縮 (2 時間ごと) は含まない。
- testbed の疑似機器は 2 台 (仕様は 3 台)。機器の数に比例する部分 (snmp-exporter 全体で 0.06 %、Prometheus 0.31 %) は小さく、3 台でも判定は変わらない見込み (未計測)。
- scrape 30 秒にしたため、起動直後や停止明けは値が出るまで約 1 分かかる (rate の窓 2 分に 2 点必要。以前は 15〜30 秒)。PLAYBACK のコマ送り (15 秒) は変えていないので、1 コマおきに同じ値になる。
- アーク (最大 30 本) は 1 本ずつの描画のまま (three-globe のアーク層の作り直しが必要なため)。複数画面で同時に見る場合の mask-api 側の応答共有は入れていない。

## 捨てた計測

- `docker stats --no-stream` を 10 秒ごとに採った最初の基準値 (demo 待機 19.75 %): 起動 90 秒後からの 4 分で Grafana・Loki の起動処理を含み、1 秒窓の抜き取りでもあるため不採用。SwiftShader のブラウザと同時に採った値 (合計 160 %、上限 0.5 コアのサービスが 145 %) は VM の飢えで計算が壊れていたため不採用。
- 最初の表示側計測の「ブラウザ CPU」(PowerShell の Get-Process): PowerShell 自体が数十秒かかり、その間も計測が続いて 600 % を超える値になったため不採用 (CDP の SystemInfo に変更)。

証跡 (scratchpad `perf/`): `base2-client.json` / `after-client.json` / `after2-client.json` (表示側)、`base-*-{idle,wall}.json` / `after-*-{idle,wall}.json` (サーバ側)、`check2.txt` (機能確認)、`shots/` (画面)、`export_check-*.log`、`codex-r*.md`。
