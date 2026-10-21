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

## 追加: 独立した線形・整数ビンのグラフ

既存の比較グラフ、`flow_length_summary.csv`、`flow_length_histogram.csv`、
`flow_length_page_*.png`は従来どおり。追加の線形グラフは既存の`figures`リストや
比較PNGの出力に混ぜない。Scan-like判定とnative/normalizedの所属定義も変更していない。

06 Notebookのセクション7で、台帳から取得した各nativeに加えselected_union、overall_ipv4について、
それぞれ独立したMarkdown見出しとコードセルを持つ**新しい表示用Notebook**を生成する。
18個なら20対象、別日で選定数が異なれば自動で増減する。元の06自身を実行中に書き換えず、
元の解析成果物も上書きしない。06には統合群の3枚を確認するセルも追加している。

生成先のパスは06の出力に表示される。そのNotebookを開き、最初の設定セルと目的の対象セルを実行する。
対象名は実際のプレフィックスをMarkdown見出しに使うため、Notebookの目次や検索から見つけられる。
各対象セルはRaw / Broad removed / Broad retainedの**3枚の別々の図**と、統計表を表示する。

```python
X_MAX = None   # 最初は全範囲
# X_MAX = 100  # 1〜100パケットを表示
# X_MAX = 200
Y_AXIS = 'count'  # 'percent'なら各群の全フロー数に対する割合[%]
INDIVIDUAL_OUTPUT_DIR = None  # 保存する場合は個別PNG用の新しいフォルダ
```

横軸・縦軸とも線形、整数パケット数の幅1のビン。存在しない整数値の度数は0であり、
巨大な最大値まで空の棒を確保せず、非ゼロの整数ビンだけを描く。間の整数をまとめる処理ではない。
非常に長いtailがある全範囲表示では1〜3の棒が画面上で小さくなるため、そのときはX_MAXで拡大する。
同一対象の3群はRawの最大値（または指定X_MAX）を共通の横軸上限に使う。
範囲外フロー数・群内割合、Raw件数・除外率、各群の中央値・p95・1パケット率を必ず付記する。
%表示の分母は範囲外を含む各群の全件数。範囲内だけで再正規化しない。空群はn=0、率はNA。

### 整数度数の保存と再利用

旧`flow_length_histogram.csv`のビンは4–7、8–15…なので、正確な整数別度数には戻せない。
summaryからも復元できない。推測や補間は行わない。

そのため**初回だけ、保存済みrunのフローCSVから追加集計が必要**になる。PCAP再処理は不要。
従来の一時SQLiteで作られていた整数度数を、新しい小さい`exact_counts.sqlite`に保存する。
フロー全行の作業用DBを永続化するものではない。cache内には既存形式のsummary/histogram CSVと
`cache_manifest.json`も保存し、2回目以降は既存比較グラフの集計も再利用する。

06では既定で`<DATA_ROOT>/results/flow_length_exact_cache/<dataset>/<run>/`以下に、
入力識別子ごとの新規ディレクトリを作る。研究室PCの保存先を変える場合:

```bash
export MAWI_FLOW_LENGTH_EXACT_CACHE_DIR=/large-disk/mawi-integer-counts
export MAWI_FLOW_LENGTH_X_MAX=100
export MAWI_FLOW_LENGTH_Y_AXIS=count
export MAWI_FLOW_LENGTH_INDIVIDUAL_NOTEBOOK=/path/to/new/06_individual.ipynb
export MAWI_FLOW_LENGTH_INDIVIDUAL_OUTPUT_DIR=/path/to/new/individual-png
```

X_MAX未指定時は全範囲。Notebook内のパラメータで変更してもよい。PNGは対象・群・X_MAX・縦軸を
含む`individual_...png`という別名で保存し、同名の既存PNGがあれば停止する。
表示用Notebookも既存同名ファイルを上書きしない。自動生成したNotebookのINDIVIDUAL_OUTPUT_DIRは
既定Noneなので、全対象の保存が必要ならその設定セルで保存先を指定する。

cache再利用はrun manifestのSHA-256、flow manifest、各入力CSVのpath/size/mtime_nsを照合する。
cache内のSQLite・summary・histogramのSHA-256も検査する。元CSVが更新されていたら別cacheの
新規集計となる。cacheが破損していたら停止し、黙って巨大CSVを再読込したり既存cacheを上書きしたりしない。
path/size/mtimeを意図的に同じにした内容置換まで検出するものではない。この高速照合では元の巨大CSVを
再ハッシュしない。cacheのない初回は従来の全行検証を行う。

生成した実データ表示用Notebookはcache読込専用で、cache欠落・入力不一致では診断停止する。
06に戻って明示的に追加集計する。生成Notebookは生成時のrootとコードの場所を参照するので、
別PCへ移すより、研究室PC上で06から生成する。デモ版は単独実行できる小さい合成入力を作る。

プログラムからは`analyze_run(..., exact_cache_dir=Path(...))`で保存・再利用を有効にできる。
引数を省略した既存呼び出しは従来どおり。`integer_distribution`や`plot_individual_target`へ
古い粗い集計だけを渡した場合は、整数度数の追加集計が必要と明示して停止する。

実データで確認する点は、初回追加集計の時間・ディスク量、再利用が表示されること、台帳に応じた
対象数と見出し、全範囲/100/200でのtail件数、既存比較図・件数の一致。Macでの検証は合成データのみ。
