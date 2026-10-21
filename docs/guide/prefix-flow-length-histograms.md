# 選定nativeプレフィックスごとのフロー長ヒストグラム

入口は `notebooks/06_prefix_flow_length_histograms.ipynb`。
flow lengthはcanonicalな双方向5タプルあたりの`packet_count`であり、バイト数ではない。
Raw / Broad removed / Broad retainedを同じ区間で比較する。

このMacには実MAWIフローCSV一式がない。研究室PCに接続・転送せず、既存runを
読み込む実装と合成データ検証だけを行った。実データ再現の成功は主張しない。

## 実装調査の記録

確認したbaseは`a0aa4f74a2f64c3d394afaa2ece3947604c4d4ad`。
添付の「貼り付けたMarkdown.md」は参考資料とし、以下の実コードで再確認した。

| 参照先 | 確認した契約 |
| --- | --- |
| `README.md`, `docs/agent/*` | dataset共通観測とrun固有解釈を分離。実装検証と実データ検証を区別 |
| `configs/scan_source_driven_removal.yaml` | timeoutなし、IPv4、src/dst候補、/24以上、src_or_dst、60秒/10秒、Strict閾値3/2、Broad有効 |
| `src/mawi_global_analysis/pipeline.py` (`_run_paths`, `run_manifest_path`) | runごとのlabels、prefixes、membershipとmanifestの標準保存位置 |
| `src/mawi_global_analysis/flow_stage.py` (`run_flow_stage`) | `flows-v3`、flow cacheのprofile/fingerprintと隣接flow manifest |
| `src/mawi_global_analysis/io.py` (`load_run`, `_artifact_entry`, `_read_csv`) | manifest指定パスのみ。相対はroot基準、絶対はそのまま。`flows_csv`互換名。成功run・正規列・記録行数を検査。ただし全行をRAMに読む |
| `src/mawi_global_analysis/prefix.py` (`build_corrected_prefix_ledger`) | 両側Aguri候補を統合しIPv4 /24以上を選定。親優先。フロー数・tiny率・top-kによる選別なし |
| `src/mawi_global_analysis/membership.py` (`build_membership`) | src OR dst、nativeとnormalized_24は別集合。normalizedは/24全体から再計算 |
| `src/mawi_global_analysis/scan_labels.py` (`build_flow_labels`) | Strict送信元の許可パターンのみ除外。Broadはsyn_only_observedを拡張。Strict⊆Broad |
| `notebooks/02_main_prefix_comparison.ipynb` | native個別と一意な統合の区別、保存された対象件数 |
| `notebooks/03_prefix_deep_dive.ipynb` | 単一nativeのRaw/removed/remaining分割、フロー数・分位点・1パケット率 |

02および`notebooks/archive/society-2026/02_main_prefix_comparison_3_2.ipynb`の保存出力は、
native選定18、所属550,289行、一意549,990フロー、IPv4 Raw33,295,132。
保存出力の参照であり、今回CSVから再現した件数ではない。新規Notebookは実行前に
台帳の選定数を表示し、対象日なら18との件数比較を示す。件数一致だけでは歴史的な集合一致の証明にはならない。
不足分を埋めるために選定条件を変更したり、30個に水増ししたりしない。

## 研究室PCで探す成果物

想定rootは保存Notebook由来の`/home/s-sakai/mawi-global-analysis`。
その存在は未確認。`D=202604081400`, `run=scan_source_driven_removal`を初期調査候補とする。
以下のテンプレートに一致するファイルを勝手に選ぶのではなく、**run manifestの記録を優先**する。

| ファイル | 標準位置 | 処理に使用する列・フィールド |
| --- | --- | --- |
| `run_manifest.json` | `results/<D>/<run>/` | status=success、dataset_id、config.text/hash、input.sha256、artifacts各path/row_count、cache.flows |
| `flows.csv` | `data/<D>/processed/flows/tcp-udp-no-timeout-<fingerprint[:10]>/` | flow_id、ip_version、packet_count、src_ip、dst_ip、protocol、initial_syn_sender_ip、observed_tcp_pattern |
| `flow_manifest.json` | 上のflowsと同じディレクトリ（run.cacheに参照があればその参照を使用） | input_sha256、fingerprint、schema_version、flow_config、row_count |
| `flow_labels.csv` | `results/<D>/<run>/` | flow_id、strict_scan_like、broad_scan_like、strict_removed、broad_removed |
| `prefixes.csv` | 同上 | prefix、selected_for_analysis |
| `flow_prefix_membership.csv` | 同上 | flow_id、analysis_scope、analysis_prefix、src_match、dst_match |

使用列だけをチャンクで読み込むが、各CSVには既存定数`FLOW_COLUMNS`、
`FLOW_LABEL_COLUMNS`、`CORRECTED_LEDGER_COLUMNS`、`MEMBERSHIP_COLUMNS`の全正規列が
存在する必要がある。列欠落・古い非互換スキーマは明示停止する。CSVの手作業変更で合わせない。
`row_count`のないmanifestも停止し、成功済みrunの記録を確認する。

Aguriのraw出力・候補CSV、source_scan_windows、source_scan_summary、PCAPは今回の描画には不要。
時間窓集計と送信元要約しか残っていない場合、個々のflow length分布は復元できない。

## 実行設定

既存環境はrepo rootで`uv sync`を済ませ、Python 3.12のカーネルを使用する。
PCAP解析・Aguriのビルドは不要。今回の変更で依存ライブラリは追加していない。

研究室PC上で環境変数を設定してJupyterを起動する例:

```bash
export MAWI_ANALYSIS_ROOT=/home/s-sakai/mawi-global-analysis
export MAWI_DATASET_ID=202604081400
export MAWI_RUN_NAME=scan_source_driven_removal
export MAWI_FLOW_LENGTH_SCRATCH_DIR=/path/to/existing/large/local/scratch
export MAWI_FLOW_LENGTH_CHUNK_SIZE=100000
uv run jupyter lab notebooks/06_prefix_flow_length_histograms.ipynb
```

`SCRATCH_DIR`の例は実在するディレクトリに置き換える。Notebookの最初の設定セルでも
同じパラメータを直接設定できる。コードをこのrepoから起動し、データrootは別指定できる。
絶対artifact pathはDATA_ROOT変更では付け替わらない。移動済みファイルを黙って拾わず停止する。

デモは`MAWI_FLOW_LENGTH_DEMO=1`か`DEMO=True`でのみ有効。隔離された一時rootに
少数の合成CSV/manifestを作り、同じ検査・集計経路を通す。パターンラベルは合成の既知ラベルであり、
Scan検出器自体やMAWIデータの検証にはならない。入力欠落時の自動フォールバックはない。

保存が必要なら`MAWI_FLOW_LENGTH_OUTPUT_DIR`か`OUTPUT_DIR`に**まだ存在しない**フォルダを指定する。
CSV2表、ページごとのPNG、入力manifest参照・hash・ビン境界・監査結果のJSONを新規保存する。
既存フォルダなら停止する。元run成果物、既存Notebookの上書きはしない。

## 集計と検査

- flows/labelsの全IDをディスク上で照合する。ファイル順序に依存せず、チャンク境界を跨ぐ
  重複ID、ラベル欠落、余計なラベル、孤立所属を拒否する。
- Strict⊆Broad、scan_likeとremovedの一致、除外対象の許可パターン・TCP・観測SYN送信元の存在を検査する。
  送信元を選んだ窓閾値の判定そのものは再実行しない。設定を照合した既存ラベルを使用する。
- 所属の(scope,prefix,flow_id)は一意。端点とsrc_match/dst_matchを照合し、全フローから
  計算したnative/normalized各範囲の期待所属数と比較して欠落も拒否する。
- native個別では1フローが2prefixに現れる場合がある。同一prefixに両端が入っても1回だけ。
  `selected_union`はflow_idの和集合で1回だけ。`overall_ipv4`は全IPv4フロー。
- Raw=removed+retained。除外率はremoved/Raw。各群の1パケット率と図の構成比は各群のNが分母。
- ビンは`[1,2),[2,3),[3,4),[4,8),[8,16),...`。全図共通の上端を最大値まで延長する。
  等幅カテゴリ表示の度数・構成比であり、確率密度ではない。
- 中央値/p95は整数packet_count別の正確な度数から線形補間する。ヒストグラム区間による近似や
  サンプリングはしない。空群はNaN、フローが0件の選定先も消さない。

RAMはチャンクサイズ、パース中の列、SQLiteの32MiBキャッシュ等に依存する。
一時SQLiteには全flow IDと必要観測・ラベル・所属を保持するため、ディスクはデータ量に比例する。
3,330万フローでは数GB以上の余裕が必要になる。実データの所要時間・最大使用量は未計測。
SQLiteのsort/group-byはOSの一時ディスクも使うので、その空き容量も確認する。
正常終了・例外終了で作業用DBを削除する（強制終了時には残る可能性がある）。

manifestにCSV内容SHA-256があれば検査する。古いrunには通常それがないため、設定hash、
cache fingerprint、schema、行数、IDと所属整合性の検査だけで過去のバイト単位同一性は証明できない。
記録済みproducerのflow fingerprint、flow cache manifestのパス/hash、membershipが参照する
prefix CSVのhashがあれば、その矛盾も拒否する。producer記録自体のない古いrunは許容する。
同一ID・行数を保った意味的な値の置換をすべて検出できるとは主張しない。
実データを用いた件数・図の再現は研究室PCで別途確認する。

## 検証方法

```bash
uv run pytest -q tests/unit/test_flow_length.py
uv run pytest -q
```

新規テストは既知の合成CSVを独立に作成し、NumPyの中央値・p95と比較する。
チャンクサイズ1/2/100、二重所属、0件prefix、空群、順序が逆のlabels、不正manifest/設定/値、
重複ID、孤立ID、所属欠落を検査する。デモモードの全コードセル実行と、実データ欠落時の停止も検査する。
集計に失敗した再実行では古い結果を無効化し、入力を変更したままの表示・保存も拒否する。
合成テストは実装検証であり、実データ再現の証拠ではない。
