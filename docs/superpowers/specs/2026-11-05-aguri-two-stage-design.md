# Canonical Aguri3 → Agurim 2段階・3重み実験設計（承認済み）

## 状態・目的

2026-11-05の実装依頼に対するPhase 1のコード調査と実装前設計。
main HEAD `85f8de87c27d248fcd44a0871c0337db4c0ae0db`、開始時差分なし。
Phase 1時点では、この文書の追加以外、製品コード・submodule・cache・runは変更していなかった。
その後、ユーザーがこの設計でのPhase 2以降の実装を承認した。
実MAWIデータはこのMacにないため、C実行・合成データ・手動用CLIまでを実装検証範囲とする。

同一canonical IPv4 TCP/UDP双方向フローを同一順序・初観測src/dstで入力し、
Aguri3による一次RLSとAgurimによる再RLSの両方で同じpacket/byte/flow基準を使う。
既存直接Agurim′、旧PCAP解析、3種類の比較ダッシュボード・成果物は保存する。

## Phase 1で確認した事実

参照は固定upstream `ab5c5cc80e9e1229bb66ec83bb25f186898d5e49`。

1. `vendor/agurim/src/aguri3.c:main/read_flow/check_flowtime/do_agflow`：
   PCAP指定がなければstdinの56byte `aguri_flow`を読む。IP対は上位odflow、
   protocol/両portは下位odprotoへ渡す。元packet/byteはuint32、内部加算はuint64。
   一次集約は共有`hhh_run`。既存canonical converterの1行1recordを再利用可能。
2. `aguri3.c:query_init/option_parse/check_flowtime/aggregator`：
   criteria=COMBINATION、threshold=1%、interval=0、output_interval=0、heuristics=0が既定。
   `max_hashentries=1000000`。heuristics=0では現在のIP対hashが上限を超えると
   次のrecordの前にsummaryを出す。intervalを指定しなくても複数blockになり得る。
   `-i interval,output_interval`は別の時間区間型2-stageで、今回の方式では使わない。
3. `agurim.c:read_file`：AGRのIP対とprotocol分解を再びhashへ入れて共有`hhh_run`を実行する。
   AGRは単なるcanonicalレコードの列ではない。prefix長・割引済みカウンタ・protocol分解を持つ。
   再集約は既定REAGGREGATIONで1%、COMBINATION、heuristics=0、interval=0、nflows=0。
   `-d`/`-p`はcriteriaをBYTEへ変更し、非REAGGREGATIONでは既定threshold=3%、top7になる。
   新方式では表示用のこれらoptionを使わない。
4. `agurim_plot.c:aguri_odflow_print`/`agurim.c:proto_parse`：
   AGRの上位packet/byteは整数。しかしprotocol内訳は小数2桁の割合だけを出力し、
   読み手は`(uint64_t)(割合 * 上位整数 / 100)`で切り捨て復元する。
   例：上位3packet、protocol内訳1packetは33.33%となり、読み戻すと0packet。
   flow用の独立カウンタは存在しない。旧AGRをそのままflow実験に使えない。
5. `hhh.c`：同一RLS関数でIPv4/IPv6・protocolを集約する。
   root、lattice再帰、抽出時のparent subtraction、再帰からの差分伝播を持つ。
   addressの0/0 wildcardは閾値未満でも保持する。一方protocol探索には0/0への最後の探索がなく、
   非抽出protocol残余は末尾で解放される。両者の保存則を同一視しない。
   address閾値は`(total * threshold + 99) / 100`、subattribute閾値は
   heuristics<2で4倍。上位HHH残余はnative membershipの実所属数ではない。
6. `odflow.c:odproto_lookup/odproto_quickmerge`：heuristics=0では下位リスト1000件でquickmerge。
   wildcardの選択はBYTEモードでも実packet数を参照する。これは旧コードの固定補助heuristic。
7. 現行`vendor/agurim-prime/flow-mode.patch`：独立flowをhash/record/root/閾値/抽出/伝播に追加済み。
   ただしAguri3入力時のflow加算は0で、Agurim flow出力は直接binary入力専用。
   Aguri3のsaved_results/restore等はflow対応しておらず、2段階flow経路として流用できない。
   またquickmergeはFLOWの場合だけflowでwildcardを選ぶ。新方式でそのまま適用すると、
   HHH重み以外の補助heuristicも変わる。
8. 現行`aguri.py`の旧PCAPパイプラインはAguri3にだけcfg.aguri.optionsを渡し、
   Agurimへは出力先とAGRファイルしか渡さない。今回の3モードには新しい明示的な両段設定が必要。
9. `agurim_prime.input.convert_flows`は逐次CSV＋SQLiteでID/双方向5タプル重複とABI範囲を検証し、
   protocol/IPv4の除外をauditする。packet/byteを分割せず保持できる。
10. `prefix.build_corrected_prefix_ledger`、`membership.build_membership`、
    `normalized24.analysis._summarize`、`rls_weight_comparison`のSQLite native ingest・
    exact-frequency/ECDF/KS・個別ECDFとHTML rendererを再利用できる。
    直接版の比較validatorは1%/heuristics2/prime lineage固定なので無効化・迂回しない。

## 採用を提案する方式と代替

**提案：upstream + 既存flowパッチ + 2段階差分パッチの独立build。**
既存flowカウンタのRLS拡張を再利用し、Aguri3入力、厳密な中間wire、Agurim読込を追加する。
既存パッチは編集せず、2枚のhash・適用順を固定する。旧形式のpacket/byte/複合経路は残し、
固定upstreamとの回帰の対照にする。

直接Agurim′を2回呼ぶ案はAguri3の前段・中間分解・hash制御を再現しないため依頼に不適合。
旧AGR＋flowだけのsidecar案は、丸め済みprotocol内訳とflowの結合や再ソートに曖昧さを生み、
3カウンタの保存則を保証しづらいため採用しない。
中間形式をexact整数へ変える差は隠さず、旧wire互換経路と新wire経路を別々に検証する。

## 固定する主実験条件（設計上の提案）

| 項目 | 値 |
| --- | --- |
| input | 同一canonical CSV、同一hash、同一行順、IPv4 TCP/UDP、timeout=null |
| orientation | first_observed、逆方向コピーなし、1canonical行=1flow |
| stage1 | Aguri3 read_flow/do_agflow/共有RLS |
| stage2 | Agurimへstage1のprefix残余とprotocol分解を渡して共有RLS |
| basis | packet / byte / flow。両段一致を必須検証 |
| threshold | 両段整数1%。別閾値は別条件 |
| disable_heuristics | 主実験0、両段一致。1/2は別条件でrun/cacheを分離 |
| interval / output_interval | 両段0 / stage1 0、時刻による追加集約なし |
| stage1 max_hashentries | 1000000、明示指定・記録、hash駆動blockは許容 |
| stage2 top-k / proto_view / filters | 0 / false / なし |
| quickmerge | 全3モードでupstreamと同じ実packet比較を固定（補助heuristicも固定する） |
| selection | 両prefix側、IPv4 /24..32、prefer_broader、追加top-kなし |
| evaluation | Raw、native src OR dst、prefix内/unionともflow_id一意 |
| references | 共通Overall。normalized24は追加評価で、nativeと混同しない |

このquickmergeの方針は現行直接prime FLOWの方針とは異なるため、直接版と同一アルゴリズムの比較とは呼ばない。
主実験内で固定される補助packet依存を文書とmanifestへ記録する。
heuristics2はquickmergeを無効化できる別感度条件だが、主実験0を勝手に置換しない。

## 中間データ契約（案：AGURI-WEIGHTS-v1）

旧AGRではなく明示的なmagic/versionを持つ逐次形式。別optionでのみ読書きし、旧readerへの誤入力を拒否する。
具体的なtext/binary符号化は実装者裁量だが、次の論理内容・検証を必須とする。

- file header：magic/version、basis、stage=1、threshold、heuristics、interval/output_interval、hash limit。
- block header：連番、start/end、input/residualのpacket/byte/flow総量、上位/下位record数。
- 上位record：IPv4src/dstのnetwork bitsとprefix長、uint64 residual packets/bytes/flows。
- 下位record：所属上位record ID、protocol/portのlabel bits・prefix長、3つのuint64 residual。
  旧表記の'*'/port rangeを文字列再解釈せず、Cのodflow_specの意味を保持する。
- `protocol_unattributed`監査record：上位残余−実際に出力する下位sumの3counter。
  **新しい検出候補wildcardとしては挿入しない。** 旧RLSが捨てるprotocol残余を監査metadataとして保存する。
  旧AGRが元から行う「具体的な下位出力0件ならwildcard100%」fallbackは、同じ場合だけ3整数を持つ
  通常のwire下位recordとして再現する。このfallback以外に不足分wildcardを作らない。
  実際の0/0下位recordの識別とfallback適用条件は、旧writerの具体的protocol出力条件と一致させる。
- block trailer：各counter合計、record数、完結marker。欠損・負値・overflow・重複ID・親なし下位・
  retained下位sum+unattributedと親の不一致・mode不一致・別version・trailing garbageは失敗。
- file trailer：全block総量、完結marker。Python側manifestは中間全体SHA-256を保持。

上位sumはcanonical入力総量と一致し、各親の下位sum+protocol_unattributedもその親と一致することを検証する。
上位と下位は同じ通信量の別表現であり、file totalに両方を加算しない。
flow総量は入力件数、上位/下位record件数とは独立。
S2は上位と実際の下位recordだけをodflow_addcount/odproto_addcountへ渡し、再度RLSを実施。
protocol_unattributedは候補リストに渡さず、auditへ引き継ぐ。
S2のprotocol RLSでも新たな非抽出分をauditへ保存し、upper/lower/unattributedを別々に照合する。
読み込んだflow数をrecord件数で置き換えない。

## 不可避の差と回帰を判定する基準

1. 旧wireのprotocol割合丸めを新wireでは除く。これはRLS探索変更ではなく伝送精度の変更。
   非抽出protocol残余をRLSへ戻さず監査保存する。上位全量と下位候補全量は別の意味である。
   synthetic deficit wildcardを追加するとodproto_lookupのsuperset一致で後続blockのlabelを吸収し得るため禁止。
   旧fallback wildcardの影響は保存し、別block由来の具体的protocolを含むfixtureで照合する。
   旧wire経路は元の丸めもそのまま維持して旧出力と照合し、新wireはexact値と照合する。
   S1 address residual、S2 address/native選定、protocol出力を別々に比較する。
   旧wireと新wireでprotocolの再集約差が生じても、差を隠して完全一致と報告しない。
2. 既存flowパッチのquickmerge FLOW分岐は新差分で戻し、旧packet比較を3モード共通にする。
3. Aguri3の終了処理はsleep(1)後のexitingフラグでaggregatorを止める。
   全block flushを保証するか合成large/block境界テストで確認する。
   欠落が再現すれば新versioned経路に限定して最終epochまでdrainする最小修正を行い、
   旧互換経路は保存する。カウンタ不一致を黙って補完しない。
4. 閾値算術の形は維持する。uint64乗算/加算/減算の表現範囲を検査し、
   overflow/underflowを拒否する。整数切り上げの規約は変更しない。
5. 1recordのpacket/byteは旧56byte ABIのuint32上限。超えるcanonical行は分割せず拒否する。
   timestampの整数秒化も既存converterと同じ。全canonical CSVのhashを保存する。

## ファイル構成と責務

追加予定：

- `vendor/agurim-two-stage/two-stage.patch`：既存flowパッチ適用後のC差分。
- `scripts/build_agurim_two_stage.py`：固定git object抽出、2枚patch、両binaryの独立build、LICENSE、
  compiler/commands/source/patch/binary hash付きbuild_manifest。既存buildを置換しない。
- `src/mawi_global_analysis/aguri_two_stage/{__init__,__main__,cli}.py`：API/CLI。
- 同`stage.py`：canonical provenance検証、変換、S1/S2実行、immutable cache/run、prefix/membership作成。
- 同`wire.py`：逐次中間検証・record/counter audit。Cと同じschema契約。
- 同`validation.py`：3保存runの専用検証、実行両段・同条件・lineage・中間hash・保存則を確認。
- 同`comparison.py`：共通exact統計・CSV・native/normalized比較・既存rendererへのadapter。
- `tests/test_aguri_two_stage_{c,pipeline,comparison}.py`：下記証拠。
- `docs/guide/aguri-two-stage.md`：手動実行、schema、既定値・差分・性能・解釈。

既存ファイルへの変更は必要なmethod dispatch/adapterとdocs index/research contractの追加のみを想定。
`normalized24._summarize`やmembership/prefixの意味を変更しない。
既存validatorに検証skipや偽prime identityを追加しない。

## 実行・保存API案

```text
scripts/build_agurim_two_stage.py --output-dir build/agurim-two-stage-<new>
python -m mawi_global_analysis.aguri_two_stage run
  --root ROOT --dataset DATASET --flows /canonical/flows.csv
  --build-dir /new-build --mode packet|byte|flow|combination
  --threshold 1 --disable-heuristics 0 --max-hashentries 1000000
  --run canonical-2stage-<mode>-t1-h0
python -m mawi_global_analysis.aguri_two_stage compare
  --root ROOT --dataset DATASET --packet-run ... --byte-run ... --flow-run ...
  --output-dir /new-bundle [--validate-only]
```

combinationは旧対照専用で主3モードvalidatorへ混ぜない。
API/CLIのmodeには1つのbasisだけ指定し、S1/S2別basisの主実験経路を提供しない。
runはsingle-use、cacheは内容identity一致時だけ読取り再利用。
canonical input/flow manifest、両binary、両patch、compiler/source、converter、
両段全option、wire version、prefix/evaluation条件がcache/run identityに含まれる。
中間/出力/auditを含めhash検証済み完了manifestを最後に公開する。

## 検証の順序と受入条件

### Phase 2：旧packet/byte/combination互換

固定upstreamの両binaryと新fork両binaryを独立buildし、同一の合成56byte列をstdinへ渡す。
まずheuristics0でS1旧AGRの数値/ラベル/順序とS2の結果を比較。
processing_time等の実行時間だけを除き、統計を任意に正規化して差を消さない。
threshold1のほか境界値、port1000超、hash低上限で複数block、末尾block、空入力を試す。
旧回帰の不一致があれば原因解決/記録までflow完了と判定しない。
新wireでは各上位残余と総量を旧wireと照合し、protocol roundingの差は専用fixtureで説明する。

### Phase 3：flow・中間保存則

同一IP対・異なる5tuple100flow、巨大packet1flow、双方向を1recordとするcase、
親100−子80=残余20のcase、quickmerge/label/subattribute閾値/複数blockを検証。
S1→wire→S2で上位3counter合計を全段照合。下位は保持counter+unattributed=上位の別保存則。
「保持protocolがあるが残余もある親」「全protocol非抽出で旧fallbackを使う親」を別fixtureとする。
同じ上位prefixが複数blockで再登場する場合に、追加不足分wildcardが後続labelを吸収していないこと、
旧fallbackが存在する場合は旧wireと同じlookup挙動となることをテストする。
重複/破損/別mode/version/不完全trailerを拒否。
S2の子抽出後にflow減算がparentと全ancestorへ伝播することを手計算fixtureで確認。

### Phase 4：run/cache/再現性

同一CSV/hash・build・optionの3modeを実行し、両段commandの成功と中間消費を検証。
同一条件を新runで再実行して中間/出力/candidates一致、cache再利用を確認。
既存run/build/output拒否、入力変更・中間改変拒否、失敗cleanup、元入力不変をテスト。
packet/byte巨大flow群と大量1packet群を持つfixtureでmode差と想定HHHを検証。
直接RLSと2段階が異なるfixtureを固定し、2回直接版を呼んだだけの実装を受理しない。

### Phase 5：評価/HTML/回帰

既存共通集計の整数度数、packet/byte合計、重複排除、coverage/Jaccard/KS、
shared-prefix分布一致、Overall一致、空/null、chunk不変性、表示簡略化不変性をテスト。
既存native UIを再利用し、個別prefix ECDFも含めofflineで操作確認。
旧3ダッシュボード・旧run/canonical cacheを変更しないことを確認する。
既存全テストと比較し、既知Notebook関連失敗と新規回帰を分離する。

## 独立設計レビュー

設計レビューはprotocol未抽出残余、synthetic wildcardの後続block吸収、受入oracleの3点を指摘。
いずれも上記の「実下位record/旧fallbackを維持し、新しい不足分はauditだけへ保存」で設計上解決する案。
RLS候補の完全保存と監査上の完全記録を混同しない。製品実装・C回帰検証はまだ未実施。

## 実装前の検証基準

既存テスト全体を変更前に実行：874成功、3失敗、64.71秒。
失敗は既知のNotebook06再実行/inline表示3件：

- `tests/unit/test_flow_length.py::test_failed_notebook_rerun_cannot_display_or_export_previous_results`
- `tests/unit/test_flow_length_individual.py::test_main_notebook_reruns_analysis_from_cache_and_keeps_legacy_exports`
- `tests/unit/test_flow_length_individual.py::test_eighteen_ledger_prefixes_display_twenty_inline_targets_without_files`

これは新2段階方式の検証結果ではなく、実装前の回帰比較基準である。
既存direct-prime binaryへの70/25/5件の合成flow入力（threshold20）では70/25/wildcard5が出力され、
閾値未満wildcard保持を確認。新S1/S2や旧upstreamとの一致を証明する実験ではない。

## 性能と解釈の制約

converterと評価は逐次CSV/SQLite。C RLSのhashと探索は既存どおりメモリ内であり、
全処理が一定RAMとは主張しない。heuristics0のS1早期summaryは保持する。
S2は全中間prefix/protocolを再集約するため、大きな中間でRAMが増える。
wireは逐次読書き、exact度数はdisk保存、HTML表示点は上限付き。
実MAWIの時間/RAM/diskは未測定として手動計測手順を示す。

この3mode間では新しい共通2段階方式内の重み差を比較する。
旧PCAP対新canonicalでは母集団・方向・入力単位、新wire対旧wireではprotocol伝送精度、
新2段階対直接primeでは一次集約と補助heuristic方針も異なる。
これらを単独の重み効果・純粋RLS実装差として解釈しない。
