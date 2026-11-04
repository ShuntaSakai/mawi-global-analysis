# RLS重み比較：条件検証とオフラインダッシュボード

同じcanonical IPv4 TCP/UDPを使ったpacket / byte / flowの成功済み3 runについて、
主実験の条件と保存ファイルの整合性を検証します。`--validate-only`は従来どおり
検証だけを行います。`--output-dir`による比較・HTML生成は
[ダッシュボードガイド](rls-weight-comparison-dashboard.md)を参照してください。
どちらのモードもPCAP処理やRLSを自動再実行しません。

## 実行

先に既存`mawi_global_analysis.agurim_prime`で3 runを生成します。各runは同じ
flows.csvと実行ファイルを指定し、`--threshold 1 --disable-heuristics 2`を明示します。
`--disable-heuristics`の既定値0のrunは、この主実験では受理しません。

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.rls_weight_comparison \
  --validate-only \
  --root /Users/shunta/mawi-global-analysis \
  --dataset 202604081400 \
  --packet-run canonical-packet-t1-h2 \
  --byte-run canonical-byte-t1-h2 \
  --flow-run canonical-flow-t1-h2
```

run名は例です。既存の実run名へ置き換えてください。`--json`は検証metadataを標準出力に
表示します。`--chunksize`は正整数で既定100000。
`--validate-only`と`--output-dir`のどちらかが必須で、両者の併用はできません。
検証専用モードの入力不変・保存なしという契約は維持しています。

終了コードは成功0、不一致・破損・不足・引数エラー2です。不一致は最初に検出した
mode/runと項目を表示します。例：

```text
比較条件を検証できません: byte run 'canonical-byte-t1-h0': rls.options: expected ...; got ...
```

Python API：

```python
from pathlib import Path
from mawi_global_analysis.rls_weight_comparison import validate_comparison

validation = validate_comparison(
    Path('/Users/shunta/mawi-global-analysis'), '202604081400',
    packet_run='canonical-packet-t1-h2',
    byte_run='canonical-byte-t1-h2',
    flow_run='canonical-flow-t1-h2',
)
```

失敗は`ComparisonValidationError(ValueError)`です。戻り値は`status: valid`、各runの
config hash・prime fingerprint、共通入力・RLS・fork・評価契約のmetadataです。
選定集合やECDF、coverageを含む実験結果ではありません。

## 検証する条件

- packet / byte / flowの対応、prime run schema、成功状態、first-observed方向、
  additional_filtersなし・top_kなし。
- 完全canonical schema、CSV/flow manifest/captureのSHA-256、flow fingerprint、行数、
  TCP+UDP、inactive timeoutなし。CSV/manifestの所在pathは異なっても同じ内容なら比較可能。
- RLSの閾値1%、実options `-F -m <mode> -t 1 -n 0 -D -D`、成功した実commandとの一致。
- 保存された実行ファイルのchecksumと隣接build_manifestの整合性、同じbuild bundle、
  対応build schema、upstreamとpatchから再計算したfork_identity、明示されたfork_commit、
  compiler/source metadata、pinned upstream、現在の管理patch、converter version、関連実装hash。
- baselineと同じcorrected prefix設定・Raw設定・IPv4 Overall設定。両側候補、/24以上、
  prefer_broader、normalized24有効、src_or_dstを維持。
- 既存のrun/cache/producer/artifactのhashと行数。HHH候補からcorrected ledgerを再生成し、
  追加の隠れた選別がないこと、native→normalized /24列の一致を確認。
- 3条件のbinary入力checksumが同じこと。共通canonicalのIPv4行はTCP/UDPであること。
  IPv6は除外として監査。選定器とOverall評価でprotocol範囲がずれる手製入力は拒否。
- 共通canonical行数・対象flow数・除外数と各変換auditの一致。検証前後の入力hashの一致。
  auditはobjectであり、unit_packets=false・IPv4 TCP/UDP・first-observed方向を必須とする。

config hash全体、prime cache fingerprint、basis、実験名・説明、run名、選定結果の集合は
モードごとに異なり得ます。各run内のhash/fingerprintは検証しますが、3条件間で単純一致
させません。共通の意味的条件と生成実装のidentityを比較します。

## 読み取り専用の範囲と限界

APIはファイルを読み取るだけで、run/cache/data/results、実行ファイル、manifestを
書き換えず、一時DBや解析成果物も作りません。Python自身のbytecode生成も避けたい場合は、
上記のように`PYTHONDONTWRITEBYTECODE=1`を指定してください。ファイルのaccess time等の
OS管理情報までは固定しません。

記録された実行ファイルと隣接build_manifestが現存することが必要です。見つからない場合、
別binaryへの置換や自動rebuildは行いません。fork_commitがnullであることは正常です。

この段階は保存契約・hash・行数・選定台帳の検証です。全membership辺の端点・重複・完全性を
canonicalから再構成する検証や、実際のunion重複排除の集計は行いません。後続の共通
normalized24解析で既存のmembership完全性検証とflow_idによるunion集計を使います。
`valid`は実データ検証済みや研究仮説が正しいという意味ではありません。

CSVやbinaryのhash照合には全ファイルの読取りが必要で、一部は複数回走査します。
大規模データでの実行時間・メモリ・disk性能は未検証です。

## 検証

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_rls_weight_comparison.py
```

テストは実際にビルドした改変版RLSと合成PCAPから生成する3 runを使用します。
正常受理、真正なt/h違い、共通入力・build/実装identity・設定の不一致、artifact破損、
行数不一致、処理中の入力変更、CLI診断、成功・失敗時の入力tree不変性を確認します。
合成fixtureの検証を実MAWIの研究結果として扱いません。
