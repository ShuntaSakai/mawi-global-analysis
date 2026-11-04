# RLS選定指標の比較とオフラインHTML

成功済みのpacket・byte・flow runを条件検証してから、集合・統計・正確なECDFと
対話的HTMLを生成する。PCAP処理・RLS選定は実行せず、既存data/results/run/cacheを変更しない。
主実験は同一canonical IPv4 TCP/UDP、同じ改変版RLS、閾値1%、`-D -D`、corrected選定、
full normalized /24、Raw、src OR dst、unionのflow_id重複排除を使う。
選定数を揃える処理やtop-kはない。

## 生成コマンド

```sh
cd /Users/shunta/mawi-global-analysis
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.rls_weight_comparison \
  --root /path/to/analysis-root \
  --dataset 202604081400 \
  --packet-run canonical-packet-t1-h2 \
  --byte-run canonical-byte-t1-h2 \
  --flow-run canonical-flow-t1-h2 \
  --output-dir /path/to/new-exports/rls-comparison \
  --scratch-dir /path/to/existing-scratch \
  --chunksize 100000
```

root/run/pathは例であり、既存の実runへ置き換える。出力先は新しいディレクトリが必要。
既存の空ディレクトリも上書きしない。data/results/notebooks/sourcesやmanifestのある
既存run/cache配下には出力できない。

`--scratch-dir`は任意。SQLite作業領域に十分なdisk容量のある既存ディレクトリを指定する。
`--max-ecdf-points`は曲線ごとのHTML表示点数の上限で、既定2000、範囲2〜50000。
正確なCSV・統計・KSには影響しない。`--json`は成功時のmanifest/HTML pathを標準出力へ返す。
不一致・失敗時は終了コード2、成功時は0。

従来の`--validate-only`は保存を行わず、`--output-dir`とは排他的。
条件不一致なら出力ディレクトリ・親・一時出力を作る前に失敗する。

Python API：

```python
from pathlib import Path
from mawi_global_analysis.rls_weight_comparison import generate_comparison, verify_comparison_manifest

manifest = generate_comparison(
    Path('/path/to/analysis-root'), '202604081400',
    packet_run='canonical-packet-t1-h2', byte_run='canonical-byte-t1-h2',
    flow_run='canonical-flow-t1-h2', output_dir=Path('/path/to/new-comparison'),
    chunksize=100000, max_ecdf_points=2000,
)
verified = verify_comparison_manifest(manifest)  # hash/schema/行数の読み取り専用再確認
```

## 開き方と操作

生成先の`dashboard.html`を通常のブラウザで開く。サーバー、ネットワーク、CDN、
外部JavaScript/CSSは不要。解析値と表示用の制限されたデータをHTML内に埋め込み、
ブラウザはflow抽出・membership・統計の再集計を行わない。

1. **Overview**：実験条件、run名、3モードの自然な選定数・union統計・coverage、
   /24集合とflow_id集合のJaccardヒートマップ。セルに正確な集合個数も表示する。
2. **Flow Size Distribution**：Overall/packet/byte/flowの右連続ECDF。横軸対数、縦軸0〜1。
   凡例でON/OFF、ホバーで観測点のpacket_count・累積数/分母・CDF、ボタン/ホイール/ドラッグで
   拡大縮小、リセット、表示図のSVG保存。統計表と記述的KS型最大ECDF差も表示する。
3. **Prefix Analysis**：検索、mode/重複modeフィルタ、全列ソート、ページング。
   同じ/24は1行にまとめ、mode一覧とnative prefix対応を示す。正確なcanonical統計を共有し、
   HHH残余を実populationとして使わない。散布図はflow_count対mean_packet_countの対数軸。
   複数modeは分割円で示し、ホバーで統計、クリックで該当/24へ絞り込める。
4. **Experiment Details**：入力・run・manifest・RLS binary/変換条件・hash・比較検証結果、
   集計/CSV/export schemaと実装identity、出力hash、指標定義と注意点。

統計やJaccardの表示は読みやすく丸めるが、セルのtitle/元CSVには元値が残る。
大きな整数はブラウザ用に十進文字列を使い、BigIntで正確にソートする。
研究JSON/CSVは整数値を保持する。

## 正確なECDFと表示点数の分離

`ecdf_counts.csv`は全ての異なるpacket_countの正確な整数度数と累積数を持つ。
median/p95/平均/coverage/KSはこの元データまたは共通の正確な統計から計算し、
ヒストグラムbinの累積や表示点から計算しない。

HTMLの表示点が上限を超える場合、観測されたpacket_countの順序に基づいて点を間引き、
先頭・末尾を必ず保持する。選択点そのものは真のECDF値である。
選択点を通る右階段は下界とし、次の選択点の累積値を上界とする帯を描く。
省略区間の正確な形状を示しているとは主張しない。最大帯幅、元の点数、表示点数、
削減有無を画面と生成条件に記録する。ホバーは最も近い実際の選択点の値を示す。
正確な曲線はCSVの累積数/総フロー数から再現できる。

## 指標とnull規約

- flow/packet/byte coverageは、それぞれselected_unionの値を共通Overallの値で割る。
  個別/24の合計を分子に使わない。分母が非0で選定が空なら0、分母0ならnull。
- Jaccardは積集合数/和集合数。両集合空はnull、片方のみ空なら0。
- KS型距離は両ECDFの最大絶対差であり、p値ではない。空分布を含む場合はnull。
  比較は整数の交差積で行い、最終値と既約の整数分子/分母を保存する。
- 空統計のmean/median/p95/one_packet_rateは段階2と同じnull。
- CSVではnullを空セル、JSONではnull、HTMLでは「—」で示す。未定義値を0や1に置き換えない。
- /24統計には同じflowが複数/24に属し得るが、unionはflow_idで一意化する。
  ECDFは一意なflowを重み1として統合した分布であり、/24 ECDFの均等平均ではない。
- 散布図は選定結果の特徴を見る補助図で、選定バイアスやネットワーク固有性の因果効果を断定しない。

## 保存schema v1

| 成果物 | 内容 |
| --- | --- |
| dashboard.html | `rls-weight-comparison-dashboard-v1`の表示payloadを持つ単一HTML |
| selected_native_prefixes.csv | mode,native_prefix,prefix_length,normalized_prefix_24 |
| selected_normalized24.csv | mode,prefix_24 |
| selection_summary.csv | mode,選定native数,/24数、段階2の全stats、3coverage、KS値と正確な分子/分母 |
| pairwise_jaccard.csv | mode_a,mode_b,set_kind,intersection_count,union_count,jaccard。3ペア×2集合 |
| prefix24_stats.csv | mode,prefix_24,native_prefixes（JSON list）、段階2の全stats |
| ecdf_counts.csv | distribution,packet_count,frequency,cumulative_count,total_flow_count,cumulative_fraction |
| modes/<mode>/summary.json,frequencies.csv | 段階2export_raw_statisticsをそのまま再利用した各runの統計・度数 |
| comparison_manifest.json | `rls-weight-comparison-v1`、success状態、前後の比較検証、入力・出典・実装・各生成物hash/行数・表示条件 |

`cumulative_fraction`は表示可能な浮動小数値であり、正確な比は整数cumulative_countと
total_flow_countに保持する。CSV内のdistributionはoverall_ipv4/packet/byte/flow。
個別/24の全度数は各modeのfrequencies.csvにも残る。

HTMLとmanifestの自己hashは再帰参照になるため埋め込まない。HTMLは他成果物のhashと
「自身のhashは外部comparison_manifest.jsonにある」旨を表示する。manifestは自身以外の
全生成物をhashで結合し、最後に公開する完了記録である。

## 検証と性能上の境界

合成301フローの例では、選定/24数2/4/2、union数1/301/300という異なる自然な選定を
作り、手計算のJaccard・coverage・KS、重複排除、全Overall一致、度数保存則を確認する。
これらは検証fixtureの性質であり、実MAWIの観測結果ではない。

flow_id集合はPython setへ全件展開せず、一意IDと3modeのbitmaskをSQLiteに保持する。
度数もdisk-backed処理。prefix集合・小さな統計と、上限付きECDF点だけをHTMLへ持ち込む。
prefix tableのDOMはページ単位、散布図はCanvasと空間bucketを用いる。

検証・hash照合、3回の共通解析、membershipの再走査、一時SQLiteと各mode度数保存に
時間・disk I/Oが必要。大規模MAWIの時間/RAM/diskは実測しておらず、性能を保証しない。
入力は生成中に変更しない。通常の永続的な変更は前後検証で検出するが、immutableな
ファイルシステムsnapshotを作る機能ではない。

テスト：

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_rls_weight_comparison_generation.py tests/test_rls_weight_comparison_dashboard.py \
  tests/test_rls_weight_comparison.py tests/test_normalized24.py
```

ブラウザ再現用の`scripts/test_rls_weight_dashboard_browser.js`は任意のPlaywright環境で
実行できる。PlaywrightはHTML閲覧の依存ではない。

```sh
node scripts/test_rls_weight_dashboard_browser.js /absolute/path/to/dashboard.html
```

ブラウザツールがfile://を許可しない環境では一時localhostで読み込み、その後offlineにして
操作を確認できる。通常のローカル閲覧にサーバーは不要。ランダム抽出・層化・scan除去・
複数日比較・実MAWI本実験は今回の範囲外。
