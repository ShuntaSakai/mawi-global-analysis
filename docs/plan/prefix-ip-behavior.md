# MAWI プレフィックス別・送信観測IP通信挙動分析：実装計画書

- 状態: **実装前（Codex作業指示用）**
- 対象リポジトリ: `ShuntaSakai/mawi-global-analysis`
- 対象実験: `dataset_id=202604081400`, `run_name=scan_source_driven_removal`
- 前提: 実験runが成功し、研究室PCの `flows.csv`（`flows-v3`）, `flow_labels.csv`, `flow_prefix_membership.csv`, `prefixes.csv`, `run_manifest.json` が存在する。PCAPは再読込しない。
- 完成目標: **全18 native プレフィックスの Raw 送信観測IP**について、通信挙動を3群で集計し、再現可能なCSVと、既存のオフライン単体HTMLダッシュボードに安全に表示する。

## 0. 開始前に守ること

`AGENTS.md` → `docs/agent/README.md` → `docs/agent/research-contract.md` → `docs/agent/repository-architecture.md` → `docs/agent/development-workflow.md` → 対象config → 既存実装・テストの順に確認する。

`AGENTS.md` の指定に従い、作業中の `main` と未コミットの人手変更を確認。既存変更を維持し、別branch / worktreeの作成、`git add/commit/push`、PR作成は指示がない限り行わない。差分を確認し、作業終了時は追加・変更・削除ファイル、テスト結果、実データ未検証事項、提案commit messageを報告する。

既存の `src/mawi_global_analysis/host_counts.py`、`src/mawi_global_analysis/flow_length.py`、`src/mawi_global_analysis/prefix_dashboard.py`、`src/mawi_global_analysis/prefix_dashboard.html`、`scripts/export_prefix_dashboard.py`、`scripts/enrich_prefix_dashboard.py` と既存のホスト数の定義ID・CSP・メモ保存機構を再利用し、重複実装や既存契約の破壊を避ける。

## 1. 研究質問と分析境界

1. 各プレフィックスの送信観測IPは、TCP接続試行（plain SYN）、TCP応答（SYN-ACK/RST）、UDPのいずれを主に送信しているか。
2. 送信挙動は `Raw` / `removed` / `retained` でどう変化するか。除外対象の通信に依存する送信IPはどれか。
3. IPごとの通信相手・ポートの広がりはどう異なるか。`/32`、`/28`、`/24` で特徴は変わるか。
4. 後続調査として `202.3.204.0/24` の retained送信未観測IP（現状216アドレス）の受信・宛先側通信を別コホートとして分析する。**今回は送信観測IPの分析を主スコープとし、216件を送信観測IPと混ぜない。**

「送信観測IP」は当該IPがフロー端点であり、その端点からの `packets_from_* > 0` が Raw群の少なくとも1フローで成り立つ IPv4 アドレス。IP数は物理端末数、ホストの正常性、悪意を証明しない。

**Rawの送信IP集合を母集団として固定**し、各IPの `Raw`、`removed`、`retained` を必ず3行出力する。片方の群で送信実績が0となっても行を省かない。

## 2. 入力、再現性、成果物

### 入力

`inspect_run(root, dataset, run)` を入口に、run manifest、manifestハッシュ、flow schema、選定18プレフィックス、各成果物の存在・対応を検証。必ず `analysis_scope=native` の membershipを使用し、normalized `/24` と混同しない。所属条件は `src_ip in prefix OR dst_ip in prefix`。`flow_labels.csv` の `broad_removed` で厳密に群分割。欠損・重複・型不正・存在しないflow ID・異なるrunはエラーとして止める。

**データ構造の注意**: `flows.csv` の `src_ip/dst_ip` は最初に観測されたパケット方向であり、通信開始/応答やクライアント/サーバを意味しない。`initial_syn_sender_ip/initial_syn_receiver_ip` は観測された通常SYNに基づくので、TCPの場合だけ「観測された接続試行側/応答側」と表現する。UDPの「開始者」は断定しない。

### 成果物（run固有の新規ディレクトリ）

推奨出力先: `results/202604081400/scan_source_driven_removal/ip_behavior/`（既存run成果物を上書きしない）。

1. `prefix_ip_behavior.csv`: 各 `prefix × ip × group` で一意、少なくとも以下を格納。
   - ID: `dataset_id`, `run_name`, `prefix`, `ip`, `group`
   - 基本: `flow_count`, `sent_packets`, `received_packets`, `sent_frame_bytes`, `received_frame_bytes`, `tcp_flow_count`, `udp_flow_count`, `tcp_sent_packets`, `udp_sent_packets`, `tcp_received_packets`, `udp_received_packets`
   - TCP観測事実: `plain_syn_sent_count_observed_post_init`, `synack_sent_count_observed_post_init`, `rst_sent_count_observed_post_init`, `tcp_syn_attempt_flows`, `tcp_syn_receiver_flows`, `tcp_synack_response_flows`, `tcp_rst_response_flows`, `tcp_payload_observed_flows` 等（各列の厳密な定義はschema docで確定）。
   - 通信相手: `unique_peer_ips`（同じIPは重複除去）, `unique_tcp_peer_ips`, `unique_udp_peer_ips`, 必要に応じ送受信両方向フロー比率。
   - すべて非負整数。未定義は0と混同せず必要に応じ明示する。
2. `prefix_ip_ports.csv`: `prefix, ip, group, protocol, port_side, observed_role, port, flow_count, sent_packets` など。
   - `port_side=local|peer`。**各行のportは対象IPから見たローカルポートか通信相手側ポートかを明示**。
   - `observed_role` はTCPなら観測通常SYNの `syn_sender|syn_receiver|unknown`、UDPなら `first_packet_sender|first_packet_receiver`。UDPを client/server と呼ばない。
   - 同一フローが `local` と `peer` の双方に1件ずつ寄与する設計なら、それらを合算してフロー数2倍の誤集計をしない。
   - 全ポート記録はCSVに保持する。HTML側は見やすさ・ファイルサイズのため上位10程度に限定可能（切捨て件数・全件合計を明示）。
3. `ip_behavior_manifest.json`: 定義・schema version（例 `prefix-ip-behavior-v1`）、dataset/run、run manifest SHA-256、入力パスと識別情報、出力のハッシュ・行数、生成時のツール情報。適切なチェックサム取得方法を性能と併せて定義する。
4. `ip_behavior_validation.json`: 期待対象数、sender IP数、各群の検証結果、欠損・不正レコード数、集計対象フロー数を明記。検証失敗時は不完全な成果物を正式配置しない。

既存の `unique_endpoint_ips` / `unique_sender_ips`・フロー長キャッシュの定義IDは変更しない。新しい集計は**run固有の派生成果物**とする。

## 3. 方向別TCPフラグとパケットの厳密な意味

`flow.py` を再確認し以下を守る。

- `packets_from_src/dst`, `bytes_from_src/dst` はcanonicalなsrc/dst端点からの送信。対象IP側に対応づける。送受信量は相手側端点のカウンターで説明できる。ただし両端が同一IPの場合はIPごとのフロー数を1とし、方向とポートに関する定義を別途明示・テスト。
- `initial_syn_sender_ip` が当該IPなら観測TCP SYN送信側、`initial_syn_receiver_ip` なら観測TCP SYN受信側。
- `syn_from_initiator/responder`・`synack_from_initiator/responder`・`rst_from_initiator/responder` は**最初のplain SYNを観測して開始者が決定された後**の記録。これらを使って当該IP側からの送信フラグ数を求められるが、キャプチャ中の全TCPパケットの完全なフラグ別送信数ではない。列名/注記にこの条件を反映する。
- `ack_count`, `syn_count`, `rst_count` はフロー全体。IPごとの送信フラグ数と誤認して加算しない。
- FIN、PSH、全ACK、複合フラグの厳密な送信元別分布、パケット順序の全復元、UDP通信開始側は `flows-v3` 単独では得られない。PCAPを再解析して補完したかのような表示は禁止。
- `tcp_payload_observed_flows` はフロー全体のペイロード観測であり当該IPが送ったペイロードとは限らない。送信者別ペイロードと誤認しない。

## 4. 処理アルゴリズム・性能

- 数千万行の元CSV全体を `pandas.read_csv` でメモリ展開しない。標準ライブラリ `csv` のストリーミングと一時SQLite（必要なflow ID・membership・ラベルのディスク索引）で構築。flowsは原則1回シーケンシャル走査。対象IDとIPの集合だけであっても膨大になり得るため、SQLiteによるspill-to-diskを優先。
- 取り込み順序に依存せず、`flow_id` と `prefix` の多重membershipを重複正規化。`native` 以外のmembershipは除外。フロー内部の両IPが同一プレフィックスに属すときもプレフィックス単位のフロー数は1、IP別ではそれぞれ1（2つの異なるIPの場合）。
- Raw sendersの特定とgroup別IP集計は一時SQLiteテーブル/集計を用い、2パスが必要な場合も**既存CSVを再処理するだけ**であることを明示。ディスク使用量、checkpoint、進捗、失敗時のtemporary cleanup、既存ファイル非破壊に配慮。
- 原データを改変せず、atomic staging → 検証 → 新規ファイル配置。事前にscratch容量を確認。手作業の `rm -rf` を含めない。

## 5. 検証（必須）

1. 対象 = `inspect_run.selected_prefixes` の**18件だけ**で、各Raw sender IPに3行。総件数は実測値で判断し、93件と決め打ちしない。
2. 各IPの加算量: `Raw = removed + retained`（フロー数・送受信パケット/バイト・方向別TCP観測フラグ数・ポート別の同一キー加算量）。IP数/peer集合/portユニーク数には足し算を適用せず集合和を使う。
3. Raw群の `sent_packets > 0` なdistinct IP数は、既存 `host_counts` の各native prefix `unique_sender_ips` と一致。removed/retainedも同じRaw固定集合で整合すること。
4. 対象prefixのフロー数は独立した既存 `flow_length_summary`/HTMLと一致。ただしIP別 `flow_count` を全IP合計してもprefix総フロー数とは限らない（非送信IPが省かれ、両端が対象に含まれることもある）。この誤った総和検証は禁止。
5. source/run identity・manifest SHA・schema・boolean label・整数・IPv4所属、重複・欠損の検査。
6. テストケース: /32、/28、/24、TCP SYN送信側/応答側、SYN-ACK/RST、plain SYN未観測、UDPの一方向/双方向、同一IP同一flowの両端、両端が同一prefix、重複membership、0フロー、未送信group、Raw group和、peer重複、ポートのsource/destinationとlocal/peerの取り違え、巨大ID、ソートの決定性、malformed rows、manifest不一致、既存出力保護。
7. フィクスチャ/合成データのテストと、**研究室PCで実測CSVを実行・確認した事実**を厳密に区別する。

## 6. HTMLダッシュボード統合

- 入力は検証済み新規2 CSV + manifest。独立した `scripts/enrich_prefix_dashboard.py` の拡張、または新CLI `scripts/enrich_prefix_ip_behavior.py` で、**既存信頼HTMLを読み取り、新しい単体HTMLを別パスへ生成**。生成時の「export from exact cache」経路とも再利用可能なattach機構を設計。
- `src/mawi_global_analysis/prefix_dashboard.py` 内の既存JSON検証を拡張し、対象prefix、Raw sender集合、3群、加算量・IP数照合、manifest一致、上限、不正値/欠落で停止。参照集計（`selected_union`, `overall_ipv4`）にはIP個別データがないため **未集計** と明示し、数字を推定しない。
- UIは `プレフィックスを選択 → 送信観測IP一覧 → IP詳細`。一覧にはRaw送信IP数、群切替とIP検索/ソート、送受信量とTCP/UDP比率。IP詳細に接続試行/応答の観測指標、peer数、プロトコル別Top portsを表示。
- 送信実績がremovedでしかないIPはretainedで0行を表示。現時点ではRaw sender以外のIPを詳細対象に追加せず、`202.3.204.0/24` のretained送信未観測216 IPは**次段階の受信コホート分析**とする。
- 無通信群、0フロー、空ポート、TCP SYN未観測などは曖昧な0/ダッシュ表示にせず定義に沿ったempty stateを表示。
- `textContent` / DOM生成で安全に表示。HTML・JSONは `<\/script>` 等の無害化、既存メモJSON保存/読込/HTML再保存、グラフ・サムネイル・Raw/removed/retained切替、全選定18件、参照2件、オフライン閲覧・CSPハッシュを維持。スクリプトを変更したら生成時にSHA-256を再計算し、CSPは `unsafe-inline` に緩めない。
- 埋め込み容量を抑えるため生フローや全portクロス積を埋め込まず、検証済み集約データのみをJSONへ保存。TopK件数以外に総件数を記録して切捨て表示を明示。

## 7. フェーズ・完了条件

**Phase A — 集計実装**: schema doc、CLI、CSV2種、manifest/validation、合成フィクスチャテスト、性能上限配慮。HTML非変更で一度完了確認。

**Phase B — HTML統合**: データ入力と整合性バリデーション、UI、CSP、保存/再生成、既存テスト回帰。プレビューデモで挙動確認。

**Phase C — 研究室PCで実データ実行**: 自動再計算ではなく、ユーザー管理下の結果ファイルからCSV作成→検証→HTML別名出力。全18対象のRaw sender実測件数、群別総計、パケット方向/ポートTopK、生成ファイルのmanifest一致を報告。`202.3.204.0/24`、2つの`157.53.116.x/28`、`150.217.140.38/32` を重点確認。**実データに未アクセスなら実測結果の完了を主張しない。**

完了報告には、作成/変更ファイル、実行コマンド、テスト結果、実データ検証の有無、未対応（全ACK/FIN/PSH、宛先のみIPの深掘り）、既存ダッシュボードの回帰結果を記載。エラー時は既存ファイルを変更しない。

## 8. Codexから提示してほしい実行例

次のようなユーザー向けCLIが使えるようにする（名称は既存CLI慣例に合わせ、実装後の正確な名前を案内すること）。

```bash
cd ~/mawi-global-analysis
PYTHONPATH=src uv run --no-sync python scripts/aggregate_prefix_ip_behavior.py \
  --root "$PWD" \
  --dataset 202604081400 \
  --run scan_source_driven_removal \
  --output-dir "$PWD/results/202604081400/scan_source_driven_removal/ip_behavior"

PYTHONPATH=src uv run --no-sync python scripts/enrich_prefix_ip_behavior.py \
  --input /path/to/prefix-dashboard-202604081400-hosts-v2.html \
  --behavior-csv "$PWD/results/202604081400/scan_source_driven_removal/ip_behavior/prefix_ip_behavior.csv" \
  --ports-csv "$PWD/results/202604081400/scan_source_driven_removal/ip_behavior/prefix_ip_ports.csv" \
  --manifest "$PWD/results/202604081400/scan_source_driven_removal/ip_behavior/ip_behavior_manifest.json" \
  --output "$PWD/reports/prefix-dashboard-202604081400-ip-behavior.html"
```

コマンドを実行していない段階でこれらのパスの存在・実測結果を断定しない。既存の `prefix_host_summary.csv` と新成果物は別物である。
