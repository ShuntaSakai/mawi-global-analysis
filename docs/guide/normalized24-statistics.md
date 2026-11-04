# normalized24：正確な総量とフローサイズ度数

段階2では既存SQLite集計を拡張し、各normalized /24、`selected_union`、
`overall_ipv4`について総量と平均を追加した。正確な整数度数は任意の単一run出力へ
ストリーミング保存できる。3モードのJaccard・coverage・ECDF図・比較manifestは含まない。

## 公開API

従来の`analyze_agurim_run`は同じ引数で使用でき、ファイルを保存せずschema 2の
payloadを返す。正確な度数配列を返したり、HTMLへ埋め込んだりはしない。

```python
from pathlib import Path
from mawi_global_analysis.normalized24 import analyze_agurim_run, export_raw_statistics

data = analyze_agurim_run(
    Path('/path/to/analysis-root'), '202604081400', 'canonical-packet-t1-h2',
    chunksize=100_000, scratch_dir=Path('/path/to/existing-scratch'),
)

summary = export_raw_statistics(
    Path('/path/to/analysis-root'), '202604081400', 'canonical-packet-t1-h2',
    Path('/path/to/new-exports/packet-statistics'),
    chunksize=100_000, scratch_dir=Path('/path/to/existing-scratch'),
)
```

上記は使い方の例。実際のroot/runへ置き換える。byte/flowや従来の成功済みcorrected runも
同じAPIを利用する。exportは一度の解析で度数と統計を生成し、`summary.json`のPathを返す。
出力ディレクトリは新規である必要があり、既存の空ディレクトリも上書きしない。
data/results/notebooks/sourcesやmanifestのある既存run/cache配下には出力できない。
元CSV・run・cacheを変更せず、入力変更検出・解析失敗・公開失敗では成功bundleを残さない。

既存HTML用CLIとexporterは従来の使い方を維持している。度数保存は上のPython APIを使う。

## schemaと意味

分析payload/summaryの`schema_version`は **2**、provenanceの集計versionは
`normalized24-raw-v2`。従来の`prefixes`、`references`、`stats`、`counts`の構造を維持し、
各targetのstatsに次を追加する。

| 項目 | 型と定義 |
| --- | --- |
| `flow_count` | 従来どおり、分布内の一意なcanonical flow数 |
| `packet_total` | 整数。各flowのpacket_count合計 |
| `byte_total` | 整数。各flowのcanonical byte_count合計 |
| `mean_packet_count` | packet_total / flow_count。空集合ならnull |
| `median`, `p95` | 従来のlinear `(n-1)q`補間。変更なし |
| `one_packet_rate` | 従来どおり分布の全Raw flowを分母にする。変更なし |

空集合はflow_count/packet_total/byte_totalが0、平均・分位点・1packet率はnull。
nativeが/24より狭い場合も、その親/24全域の所属を再計算する。src OR dst所属を維持し、
両端が同じ/24のflowはその/24で1回、別の選定/24間のflowは個別統計では両方に属するが、
selected_unionではflow_idで1回だけ数える。個別/24の総和をunion総量には使わない。

Overallは従来どおりcanonicalの全IPv4。packet/byte/flow主比較では、段階1の検証器で
canonicalがIPv4 TCP/UDPという対象条件を満たすことを先に確認する。

`byte_count`は保存されたcanonicalの値を使い、PCAPから再計算しない。入力byte_countは
非負のint64、packet_countは正のint64として検証する。総量はPythonの任意精度整数と、
SQLite内の正確な十進文字列集計により、int64の総和を超えても丸めない。
平均は浮動小数値で、正確な分子・分母はpacket_total/flow_countに残る。

公開`summarize_frequencies`の既存3列dist adapter契約も維持する。
新しい任意引数`byte_total`を渡さない外部
adapterの非空分布は、根拠のない0を返さずbyte_total=nullとする。通常の共通解析は常に
canonical由来のbyte_totalを供給する。

## 単一runの保存物

出力bundleは次の2ファイル。比較用manifestではない。

- `frequencies.csv`：schema `normalized24-exact-frequencies-v1`。
  headerは`distribution,packet_count,frequency`。各正のpacket_countについて正確な整数度数。
  `(distribution,packet_count)`は一意で、distributionの文字列順→packet_count数値順。
  distributionは各/24、`selected_union`、`overall_ipv4`。空分布は行を作らずsummaryで表現。
- `summary.json`：分析schema 2に`status: success`、
  `export_schema_version: normalized24-statistics-v1`、CSVのschema/列/順序/行数/SHA-256を追加。
  provenanceは入力run/CSV/manifestのhash、選定条件、集計意味、実装hashとCSVのidentityを結合する。

度数はSQLite cursorからCSVへ1行ずつ出力する。度数ごと・flowごとの巨大リストや配列を
作らない。SQLiteの一時DBは解析後に削除し、公開前のCSV/JSONも失敗時に清掃する。
summaryは既存の小さなヒストグラムとtarget単位の統計だけを持つ。

JSONの総量は整数tokenで保存し、CSVも十進整数を使う。JavaScriptなどの読取り側は、
2**53を超える整数に対応するparserまたはCSVのBigInt処理を使う。
既存HTMLでは、新しいpacket_total/byte_totalが2**53-1を超える場合のみ十進文字列へ
変換して埋め込む。元のPython payloadは変更せず、既存の表示・統計field型を維持する。
HTMLの`presentation.large_total_encoding`にもこの規則を記録する。

schema 1だけを受理する外部consumerはschema 2への対応が必要。
既存HTMLテンプレート、検索・ソート・詳細、bin/軸の意味は変更していない。
既存の生成済みHTML・CSV・cacheの書換えや再生成は行わない。

## 検証の境界

合成fixtureで手計算の総量、union重複排除、度数保存則、同bin内の異なるpacket_count、
chunksize不変性、巨大整数、空集合、出力保護・失敗時清掃、既存HTML回帰を検証する。
実MAWIでの統計結果・大規模性能検証とは区別する。
