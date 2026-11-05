# 固定したRLS選定集合のNative Prefix評価

成功済みpacket/byte/flow runの選定台帳と`analysis_scope=native` membershipを読み、
canonical IPv4 TCP/UDPフローのnative分布と親normalized /24分布を比較する。
PCAP・RLS・選定・membership生成は実行しない。native範囲は/24へ拡張しない。
既存bundleやdata/results/cacheは変更せず、新しいbundleを生成する。

## コマンド

```sh
cd /Users/shunta/mawi-global-analysis
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.rls_weight_comparison \
  --include-native \
  --root /absolute/path/analysis-root --dataset DATASET \
  --packet-run PACKET_RUN --byte-run BYTE_RUN --flow-run FLOW_RUN \
  --from-comparison /absolute/path/normalized-comparison/comparison_manifest.json \
  --output-dir /absolute/path/new-native-comparison \
  --scratch-dir /absolute/path/existing-scratch --chunksize 100000
```

root/dataset/runは同じcanonical・RLS binary・1%・heuristics2・corrected条件の成功runを指定する。
通常の比較検証と同じく、保存されたRLS binary/build manifestは検証のために必要だが実行しない。
`--from-comparison`は任意。指定すれば照合済みnormalized成果物と`dashboard.html`を
バイト単位でそのままコピーする。省略時は既存normalized生成処理を一時領域で呼び出す。
どちらもPCAPは読まない。後者はcanonical CSVからnormalized統計も集計するため時間がかかる。

`--output-dir`は新規ディレクトリ。既存の空フォルダも上書きしない。
元のbundleがnative拡張済みなら、元normalized bundleから新規生成する。
native拡張済みbundleへの通常の`--from-comparison` HTML更新も拒否する。
これは片方のHTMLだけを更新して他方のhash来歴を古くすることを防ぐためである。
`--validate-only`は従来どおり読み取り専用で、`--include-native`と併用できない。

Python API：

```python
from pathlib import Path
from mawi_global_analysis.rls_weight_comparison import generate_native_comparison

manifest = generate_native_comparison(
    Path('/absolute/path/analysis-root'), 'DATASET',
    packet_run='PACKET_RUN', byte_run='BYTE_RUN', flow_run='FLOW_RUN',
    comparison_manifest=Path('/absolute/path/normalized-comparison/comparison_manifest.json'),
    output_dir=Path('/absolute/path/new-native-comparison'),
    chunksize=100000, scratch_dir=Path('/absolute/path/scratch'), max_ecdf_points=2000,
)
```

## 集計と検証

- canonicalを一度SQLite factsへ読み込む。packet_count/byte_countはcanonical値。
  byte_countはEthernetフレーム総量。IPv4 TCP/UDPをOverallとしIPv6は含めない。
- 保存済みnativeとnormalized_24の両scopeを検証する。定義は変更しない。
  prefix+flow_idの一意性、ID存在、src/dst所属flagの正しさ、各prefixの完全性を確認する。
  native長24..32の辞書照合で期待所属数を計算し、flow数×prefix数の全探索を避ける。
  重複membership行は不正artifactとして失敗させ、黙って修復しない。
- src OR dstは1つのOR条件。両端が同じprefixでも1回。異なるprefixには同じflowが入り得る。
  unionはflow_idで一意化する。HHH discounted countは母集団の大きさに使わない。
- nativeと親/24の対応は実際の選定台帳から独立に再構成する。
  保存されたnormalized summaryの全card・native対応・参照統計と全整数度数を
  canonical/membershipからの再集計と照合する。summaryのrun/config/入力hashも照合する。
- 統計の計算本体は既存`normalized24.analysis._summarize`を再利用する。
  分位点はlinear `(n-1)*q`、1パケット率の分母は分布の全Raw flow。
  総packet/byteは正確な整数、空分布はcount/total=0、平均・分位点・率=null。
- native union ⊆ normalized24 unionをflow_idで検証し、flow/packet/byteの総量も以下であることを確認。
  同じnative prefixの各modeの全統計とpacket_countごとの全度数を一致検証する。
  Overallは共通factsから計算し、全modeの保存済みOverall統計・度数と一致させる。
- KSは全整数度数の累積を整数交差積で比較する。native-vs-Overallと
  同一modeのnative-vs-normalized24を保存する。分子/分母も正確に記録する。p値ではない。
- 入力とrun/cacheのhash・比較条件を前後に検証する。保存済みbundleは全体を独立コピーし、
  コピーのhash照合後に読む。成果物の正規相対パス、入力/出力/一時領域の保護を適用し、
  manifestを最後に公開する。解析中は元run/canonicalファイルを変更しないこと。
  canonical自体のimmutableなファイルシステムsnapshotを作る機能ではない。

## HTML操作

`dashboard.html`は従来のnormalized /24。追加の`dashboard_native.html`を通常のブラウザで開く。
どちらも単一HTML、オフライン、外部CDN・サーバー不要。

- **Overview**：自然なnative選定数、native union統計・3coverage、native prefix集合および
  union flow_id集合のJaccard。完全一致のCIDR文字列集合を比較し、IP空間面積のJaccardではない。
- **Flow Size Distribution**：Overallと3mode native unionの4曲線。対数横軸、凡例ON/OFF、
  ホバー、ボタン/ホイール/ドラッグによる拡大縮小、リセット、SVG保存、正確なKS型距離。
- **Prefix Analysis**：native CIDRの部分一致検索、mode/重複modeフィルタ、統計ソート・ページ表示、
  補助散布図。行をクリックするとそのprefixの個別ECDFへ進む。
- **Per-Prefix Flow Size Distribution**：mode切替、検索、最大5つの独立したnative ECDF。
  Overall/現在mode native unionの参照ON/OFF、7指標の表、ホバー・拡大縮小・SVG保存。
- **Scope Comparison**：modeを切り替えてOverall＋同じmodeのnative/normalized24 unionを
  重ねる。7統計・flow coverage・正確なKS分子/分母を比較できる。選定集合は固定される。
- **Experiment Details**：nativeの定義、入力/実装/出力hash、検証結果、来歴と不変条件、表示制限。

表示曲線だけを簡略化しても、統計・KS・CSV度数は変わらない。
unionの表示上限は`--max-ecdf-points`（既定2000、2..50000）。個別prefixは既存の予算
`min(200,max(2,200000//max(1,N)))`を再利用する。先頭・末尾を保持し、
選択点は真値、間の階段は下界、帯は上界。元の正確な形状と区別する。
点配列は選択した最大5件だけ展開する。未選択prefix分も上限付き文字列としてHTMLに必要なので、
prefix数や整数桁数に応じてHTMLサイズは増える。全正確度数はCSVに保持する。

## 追加成果物と互換性

既存の13成果物は保持し、13成果物を追加する。旧manifest v1は引き続き読める。
比較manifestのschemaは`rls-weight-comparison-v1`を維持し、`native_extension`を追加する。
拡張schemaは`rls-native-comparison-v1`。

| 成果物 | 内容 |
| --- | --- |
| dashboard_native.html | `rls-native-comparison-dashboard-v1`表示payload |
| native_selection_summary.csv | mode,native選定数、7統計、flow/packet/byte coverage、KS vs Overall（値/分子/分母） |
| native_prefix_stats.csv | mode,prefix、7統計 |
| native_ecdf_counts.csv | Overallと3native unionの全整数度数・累積数・CDF |
| native_pairwise_jaccard.csv | 3modeペア×native_prefix/flow_id集合。intersection/union個数も保持 |
| scope_comparison.csv | mode、selection_fixed、subset判定、native/normalized24の7統計・flow coverage、両scopeのKS |
| scope_ecdf_counts.csv | Overall＋native3mode＋normalized3modeの正確な7分布。描画点制限に非依存 |
| native/modes/&lt;mode&gt;/summary.json | `rls-native-statistics-v1`、個別/union/Overall統計、実際に読んだrun/inputの来歴 |
| native/modes/&lt;mode&gt;/frequencies.csv | 既存と同じdistribution,packet_count,frequency。全native prefix/union/Overall整数度数 |

prefix列はnative CIDRをそのまま記録する。native payloadは`prefix`、normalized payloadは
`prefix_24`を使い、両者を区別する。個別表示schemaは`rls-native-prefix-ecdf-v1`。
JSON null、CSV空セル、HTML「—」の規約は従来と同じ。両方空のJaccardや空を含むKSはnull。
整数比の浮動小数表示とは別に、正確な累積数・分母・KS分子/分母を保持する。

`native_extension`には元normalized manifestのhash（指定時）、実際に使用した入力path/hash、
比較検証の前後結果、評価定義、固定選定・部分集合などの不変条件、表示設定、実装hash、必須成果物を記録。
sourceの古い入力pathを新規nativeの実入力来歴として転記しない。元normalized来歴は元のまま保持する。
`verify_comparison_manifest()`はnative拡張の定義・validation binding・不変条件・入力hashの結合と
追加成果物の完全性を検証する。native成果物だけ残して拡張宣言を削除するdowngradeも拒否する。
HTML自身のhashは外部manifestに保存し、HTML内へ自己hashを再帰的に埋め込まない。

## 性能と証拠の境界

SQLiteはディスク上の作業領域、page cache32MiB。RAMはchunk・prefix統計・有界表示点に依存する。
canonical facts、3mode×2scopeのmembership、ID集合・度数・索引・ソートに大きな一時diskが必要。
入力hash検証、baseline照合、各scopeのGROUP BY、コピーとCSV出力でI/Oが増える。
大規模MAWIの実行時間/RAM/diskは未実測。十分な空き容量のあるscratchを指定し、既存run/cache内は使わない。

テストは合成の/32・/28に対して親/24の追加フローが存在するケースを含む。
例のnative `[1,4,10]` とnormalized `[1,2,4,10]` ではflow数3対4、packet総数15対17、
記述的KS=1/6を確認する。これはfixtureの性質であり実MAWIの観測結果ではない。
実データの差が小さい/大きいことをこの実装検証から結論しない。
