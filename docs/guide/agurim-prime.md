# 実験1: Agurim'（フロー数ベースRLS）

## 実装と研究上の定義

Agurim' は canonical `flows.csv` の双方向フロー1行を重み1として、既存
Agurim の Recursive Lattice Search (RLS) / HHH を実行するローカルforkです。
`vendor/agurim` の固定commit
`ab5c5cc80e9e1229bb66ec83bb25f186898d5e49` は変更していません。
`vendor/agurim-prime/flow-mode.patch` を親リポジトリで管理し、独立した
ビルドへ適用します。byte/packetを転用せずuint64の独立したflowカウンタを
hash、加算、root、閾値、抽出、ancestorへの割引伝播へ追加しています。
探索順序、label heuristics、`ceil(total * threshold / 100)`、wildcardの保持、
subattributeの閾値倍率は既存構造を維持します。

対象はIPv4 TCP/UDPです。IPv6と他protocolの除外数をmanifestに記録します。
canonicalの`src_*`/`dst_*`は最初に観測されたパケットの方向であり、
initiator/responderやclient/serverではありません。双方向のパケット数を
合計したフローを一方向の1レコードとして渡し、逆方向コピーは作りません。
5タプルにはprotocol、両IP、両portが含まれます。IDは一意である必要があり、
timeoutなしの入力では逆向きを含む同一5タプルの重複も拒否します。
明示的なinactive timeout付きcanonical入力は、元のmanifestの設定に従って
各canonical segmentを1フローとして扱います。今回のbaselineはtimeoutなしです。

`-F -m packet`に各行のpacket重み1を与える試作を`unit-packet`として残しています。
正式`flow`では本当のpacket/byteカウンタを保持し、各入力レコードのflowだけを
1増やします。試作に本物のpacket数があると誤認しないよう、run名・method・basisを分離します。

`discounted_flow_count`はHHHの割引済み残余数です。元のprefix内の実フロー数とは
異なります。たとえば100フローを含む親から80フローの子を抽出すると、親の
割引済み数は20です。テストはこの差を検証します。選定後の統計量はこの値を
使わず、元のcanonicalフローから所属を再計算します。

## 選択と共通ダッシュボード

1. HHHの`src_prefix`と`dst_prefix`の両方から候補を作ります。
2. IPv4の/24〜/32を対象に、既存の`prefer_broader` containmentを適用します。
3. 選定native prefixを含む/24へ正規化し、同一/24を重複排除します。
4. 全/24を採用します。top-k、件数、中央値、scan-likeなどによる追加選別はありません。
5. 全canonical CSVを再走査し、`src_ip OR dst_ip`でnativeとfull-/24所属を記録します。
6. 共通`normalized24`が所属の完全性を検証し、統合分布を`flow_id`で一意にします。

全てRawです。既存の`HistogramSpec`、整数度数による中央値・p95の線形補間、
1パケット率の分母、log(1+n)の件数軸、0〜100%の割合軸を再利用します。
検索、ソート、カード、詳細、統合分布と全IPv4参照分布のHTMLテンプレートは
変更していません。`analyze_agurim_run`という既存の公開関数名も互換性のため維持します。
methodはrunから判定され、primeではproducer・cache・canonical入力のbindingも検証します。

## 実データでの実行

リポジトリのPython 3.12環境、C compiler、`patch`、初期化済みsubmoduleが必要です。
この作業では`build/agurim-prime/agurim`を生成済みです。新規cloneなどでのビルドは:

```sh
cd /Users/shunta/mawi-global-analysis
.venv/bin/python scripts/build_agurim_prime.py --output-dir build/agurim-prime
```

ビルド先が存在する場合は上書きしません。ソース変更後は、別の新しいビルド先を
指定し、そのバイナリを次のコマンドへ渡してください。build bundleにはsource、
LICENSE、実行ファイルと`build_manifest.json`を保存します。

既存のcanonicalキャッシュを指定します。隣接する`flow_manifest.json`が必須です。
以下の`/absolute/path/to/canonical/flows.csv`は実際のファイルへ置き換えてください。
`--root`は既存データ・resultsを持つ分析rootです。

```sh
.venv/bin/python -m mawi_global_analysis.agurim_prime \
  --root /Users/shunta/mawi-global-analysis \
  --dataset 202604081400 \
  --run agurim-prime-flow-t1 \
  --flows /absolute/path/to/canonical/flows.csv \
  --agurim /Users/shunta/mawi-global-analysis/build/agurim-prime/agurim \
  --mode flow --threshold 1 \
  --output /absolute/path/to/new-exports/agurim-prime-24-raw.html \
  --scratch-dir /absolute/path/to/existing-scratch
```

`--threshold`は既存の整数percent仕様の1〜100です。0.1などの小数は受け付けません。
`--disable-heuristics 0`が既存の通常設定で、1と2はそれぞれ`-D`、`-D -D`です。
任意の時刻・入力フィルタ、protocol view、plot、top-kなどの意味を変えるオプションは
正式flowモードでは拒否します。常に`-n 0`です。

対照は**同じflows.csv、同じthresholdとheuristics**を使い、新しいrun名で実行します:

```sh
.venv/bin/python -m mawi_global_analysis.agurim_prime \
  --root /Users/shunta/mawi-global-analysis --dataset 202604081400 \
  --run canonical-byte-t1 --flows /absolute/path/to/canonical/flows.csv \
  --agurim /Users/shunta/mawi-global-analysis/build/agurim-prime/agurim \
  --mode byte --threshold 1 \
  --output /absolute/path/to/new-exports/canonical-byte-24-raw.html
```

`--mode packet`は本当のpacket重み、`--mode unit-packet`は試作用の重み1です。
4条件でrun名と出力名を分けてください。共通のIPv4母集団なら既定軸も一致します。
明示的に固定する場合は、既存HTMLのpayloadから取り出した`histogram_spec` JSONを
`--histogram-spec spec.json`で渡せます。

保存済みprime runの再描画には従来と同じexporterを使います:

```sh
.venv/bin/python -m mawi_global_analysis.normalized24 \
  --root /Users/shunta/mawi-global-analysis --dataset 202604081400 \
  --run agurim-prime-flow-t1 \
  --output /absolute/path/to/new-exports/another-prime-24-raw.html
```

既存run・HTML・ビルド先は同一identityでも上書きしません。CLIで`--output`の生成だけ
失敗した場合、成功済みrunは残ります。別の新規HTML名で上記exporterを実行してください。

## 成果物と来歴

- `data/<dataset>/processed/agurim-prime/<fingerprint>/`: `canonical.bin`、
  `raw.txt`、`prime_candidates.csv`、`prime_manifest.json`。
- `results/<dataset>/<new-run>/`: `prefixes.csv`、`flow_prefix_membership.csv`、
  `run_manifest.json`。元のcanonical `flows.csv`は参照し、コピー・書換えをしません。
- `build/<new-build>/`: upstream固定ソースにパッチを適用した独立bundle。

cache identityには集約basis、canonical flow fingerprint、CSV/flow manifest checksum、
元capture hash、upstream commit、patch checksum、fork identity/commit、binary checksum、
build manifest/source/compiler情報、閾値、全オプション、変換versionと変換/stageコードhashを
含めます。runはconfig本文とhash、親Git commit、dirty状態でも識別できる関連ソースhash、
生成・再利用stage、成果物hash、producerを記録します。cache再利用時は全保存成果物の
checksumと行数を検証し、不完全・改変済みcacheはエラーにします。入力は処理前後でhashを
比較します。HTMLにも入力・選択・fork lineageと共通集計仕様が埋め込まれます。

commit/push禁止の依頼に従い、remote forkやfork commitは作っていません。
`fork_commit: null`はその事実を示し、架空のcommitを保存しません。現段階の厳密なソース
識別子は固定upstream commitと親管理patchのSHA-256です。将来のfork URL/gitlink固定は
[管理手順](../../vendor/agurim-prime/README.md#future-committed-forksubmodule-migration)を参照してください。
親側のpatchを含めてレビュー・保存すれば、dirty submoduleだけに差分が残る問題を避けられます。

## PCAP入力とcanonical入力の比較

PCAP版Agurimとの差を、そのまま「重みの効果」と解釈してはいけません。

| 条件 | 入力表現 | 集約重み |
| --- | --- | --- |
| 従来Agurim | 生PCAP → aguri3の方向別・時間集約 → agurim | 元のbyte/packet（既定はcombination） |
| canonical-byte | 双方向canonical 1行 → 1 binary record | Ethernet frame byte_count合計 |
| canonical-packet | 上と同じ | packet_count合計 |
| unit-packet試作 | 上と同じ（packetフィールドだけ1） | packet重み1 |
| 正式Agurim' | 上と同じ（packet/byteは実値） | 独立flow重み1 |

canonical-byte/packetとflowを同じCSVで比較すれば、入力方向・対象・流量の表現を固定し、
重みの変更を検査できます。従来PCAP版との比較には次の要因も含まれます:

- canonicalは双方向を最初の観測方向へまとめる一方、PCAP版は各パケットのsrc/dstを保持します。
  RLSのsrc/dst格子上での質量配置が変わり、候補が変わる可能性があります。
- canonical条件はIPv4 TCP/UDPだけです。従来版の対象にはIPv6や他protocolも入り得ます。
  canonical parserのfragment・capture truncation等の除外も同じではありません。
- 従来経路はaguri3とagurimの二段集約で、canonical binary経路は直接RLSです。
  途中集約、interval、時間の扱いが一致するとは限りません。
- byteの単位自体はcanonicalの`byte_count == frame_byte_count`と、PCAP parserの
  `agflow_bytes = htonl(h->len)`で共にEthernet frame長です。ただし保持対象の違いは残ります。

この作業で実行した合成fixture `tcp_patterns.pcap` の1%結果:

| 条件 | HHH候補 | HHHのpacket合計 | frame byte合計 | flow合計 |
| --- | ---: | ---: | ---: | ---: |
| 従来PCAP | 12 | 15 | 846 | — |
| canonical-packet / byte | 6 | 13 | 711 | — |
| 正式flow | 6 | 13 | 711 | 6 |
| unit-packet試作 | 6 | 6（試作用） | 711 | — |

canonicalはIPv4の6フローとIPv6の1フローを持ちます。今回の集約対象はIPv4の6フローです。
この小さなfixtureでは全条件が`192.0.2.0/24`と`198.51.100.0/24`を選び、統合分布は
6フロー、median 2、p95 3.75、1packet率1/3で一致しました。両/24の個別件数は各6ですが、
統合は12でなく6です。この一致を一般化しません。

また別の合成101フロー（1000packetの1フローと、1packetの100フロー）を同じ入力表現で
20%集約するテストでは、packet/byteは大きい1フロー側の/24を選び、flow/unit-packetは
多数の小フロー側の/24を選ぶことを検証します。これが重みだけを変えた対照です。

生成例は`examples/agurim-prime-synthetic-20261030/`にあり、
`agurim-prime-24-raw.html`、従来版、byte/packet/probe版、および`comparison.json`を保存しています。
元データとrun/cacheは`synthetic-agurim-prime-20261030`という別dataset名です。

## 検証と制約

2026-10-30、Python 3.12のリポジトリ環境で:

```sh
.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_agurim_prime.py tests/test_agurim_prime_fork.py tests/test_normalized24.py
.venv/bin/python -m pytest -q -p no:cacheprovider
git diff --check
```

結果は関連 **84 passed**、全体 **686 passed / 3 failed**、`git diff --check`は成功です。
変更前の全体は637 passed / 同じ3 failedでした。既存Notebook 06の以下の失敗は変更していません:

- `tests/unit/test_flow_length.py::test_failed_notebook_rerun_cannot_display_or_export_previous_results`
- `tests/unit/test_flow_length_individual.py::test_main_notebook_reruns_analysis_from_cache_and_keeps_legacy_exports`
- `tests/unit/test_flow_length_individual.py::test_eighteen_ledger_prefixes_display_twenty_inline_targets_without_files`

単体・compiled C・結合・合成PCAP end-to-end・cache破損・同一入力再現・既存byte/packet
回帰・割引残余と実分布の区別・完全schema・実行/再利用来歴を検証しています。
独立レビューの2指摘（全canonical schema検証、stage実行/再利用記録）は失敗テストで
再現して修正し、再レビューで解消を確認しました。

ブラウザではnative prefix検索、p95ソート、詳細の開閉、統合参照、22区間のbin表、
通信をofflineにした後の検索/カード操作、390px画面の横overflowなしを確認しました。
console errorは0で、読み込み時のリクエストはHTML自身の1件だけでした。
自動ブラウザは`file://`を許可しないため、ローカルHTTPで初回読み込み後のoffline操作検証です。

実MAWIデータでの実行・検証は未実施です。大規模データの時間・メモリ・diskの性能検証も
未実施です。変換とID検証はSQLite/streaming、membershipはchunk単位ですが、既存
`build_membership`の実行時間は概ねフロー数×選定prefix数です。C本体もOD/protocol表を
メモリに保持します。大きい実験では十分なdisk/RAMと実測が必要です。

upstream binary ABIはpacket/byte/timestampがuint32です。超過フローを分割するとflow数を
壊すため、値の超過は明示エラーにします。timestampの小数秒はbinary入力で切り捨てますが、
時間選別・時間分割を使わずcapture全体を集約する今回の条件では選択重みに使いません。
原canonical CSVのtimestampは変更しません。別時間窓・IPv6・非TCP/UDPの正式flow対応は
今回の対象外です。元parserの未観測/除外や非対称観測から通信の全体像や意図は推定しません。

## 変更ファイル

追加:

- `src/mawi_global_analysis/agurim_prime/`: `__init__.py`, `__main__.py`, `input.py`,
  `stage.py`, `cli.py`（変換、実験run/cache、CLI）。
- `vendor/agurim-prime/flow-mode.patch`, `vendor/agurim-prime/README.md`（独立flow counterとfork管理）。
- `scripts/build_agurim_prime.py`（固定ソースの独立ビルド）。
- `tests/test_agurim_prime.py`, `tests/test_agurim_prime_fork.py`（Python/C/PCAPの検証）。
- `docs/guide/agurim-prime.md`, `docs/superpowers/plans/2026-10-30-agurim-prime.md`。
- `examples/agurim-prime-synthetic-20261030/`: `agurim-24-raw.html`,
  `agurim-prime-24-raw.html`, `canonical-byte-24-raw.html`, `canonical-packet-24-raw.html`,
  `canonical-unit-packet-24-raw.html`, `comparison.json`（合成例）。

変更:

- `src/mawi_global_analysis/normalized24/analysis.py`（共通の集計へのmethod/lineage adapter）。
- `docs/guide/normalized24-dashboard.md`（対応methodの説明）。
- `docs/agent/README.md`, `docs/agent/current-state.md`, `docs/agent/research-contract.md`。
- `.gitignore`（独立ビルド出力`/build/`を除外）。

削除なし。`vendor/agurim`、既存Notebook、既存成果物は変更していません。
生成した合成datasetのdata/resultsおよびbuild bundleは既存の除外規則に従いGit対象外です。
