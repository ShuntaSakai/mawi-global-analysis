# Canonical Aguri3 → Agurim：2段階のpacket / byte / flow比較

## 範囲

固定Aguri upstream `ab5c5cc80e9e1229bb66ec83bb25f186898d5e49`のAguri3とAgurimを、
canonical双方向フローを入力とする新条件として再利用する。直接Agurim′を2回呼ぶ方式ではない。
元submoduleも既存flow-mode.patchも編集せず、そのパッチの後に独立した
`vendor/agurim-two-stage/two-stage.patch`を適用して両プログラムをbuildする。

```text
保存済みcanonical flows.csv
  → 既存converter：IPv4 TCP/UDPの1行=56byteの1record（packet/byteは元値、逆向き複製なし）
  → 拡張Aguri3：IP対＋protocol/port、一次RLS、flowはrecordごとに独立に+1
  → stage1.agw：割引済みprefix残余・protocol分解・3整数カウンタ
  → 拡張Agurim：中間prefixをhashへ再挿入、再RLS、flowは中間件数でなく保存値を加算
  → stage2.agw → candidates.csv → 既存corrected選定 → 既存src OR dst membership
  → 共通canonicalでnative / normalized24評価、exact度数・ECDF・KS・coverage・Jaccard
```

旧PCAP baseline、BPF版、直接prime3重み、A/B/C・native・normalizedダッシュボードは変更しない。
PCAP再解析・canonical再生成はこのCLIの処理に含まれない。canonicalキャッシュとflow_manifestが必要。

## ビルド

初期化済みsubmoduleの固定git object、C compiler、patch、libpcapとpthreadが必要。
ネットワーク取得は行わない。出力先は新規ディレクトリのみ。

```sh
cd /Users/shunta/mawi-global-analysis
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/build_agurim_two_stage.py \
  --output-dir build/agurim-two-stage-v1
```

両binary、適用後src、LICENSE、build_manifest.jsonを保存する。
upstream、順序付きpatch hash、fork identity、未公開fork_commit=null、source/binary hash、compilerと
実際のcompile argvを記録する。argvに含まれる一時build pathは実行記録であり、公開後のsource参照ではない。
buildの検証は公開後src/hashとbinary/hashを照合する。パッチ変更後は別build先を使う。
既存build・ファイル・symlinkを上書きしない。

## 実行：保存canonicalから3つのrunを新規作成

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.aguri_two_stage run \
  --root /analysis-root --dataset 202604081400 --flows /canonical-cache/flows.csv \
  --build-dir /Users/shunta/mawi-global-analysis/build/agurim-two-stage-v1 \
  --mode packet --run canonical-2stage-packet-t1-h0

PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.aguri_two_stage run \
  --root /analysis-root --dataset 202604081400 --flows /canonical-cache/flows.csv \
  --build-dir /Users/shunta/mawi-global-analysis/build/agurim-two-stage-v1 \
  --mode byte --run canonical-2stage-byte-t1-h0

PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.aguri_two_stage run \
  --root /analysis-root --dataset 202604081400 --flows /canonical-cache/flows.csv \
  --build-dir /Users/shunta/mawi-global-analysis/build/agurim-two-stage-v1 \
  --mode flow --run canonical-2stage-flow-t1-h0
```

`--run`を省略すると上記の既定名になる。非既定hash上限には`-H<上限>`も付く。
同じrun名は再利用しない。runは`results/<dataset>/<run>/`、新cacheは
`data/<dataset>/processed/aguri-two-stage/<fingerprint>/`へ保存。
既存canonical/旧cacheを更新しない。適合する新方式cacheは別run名から読取り再利用できる。

主設定は両段1%、disable_heuristics=0、時間interval=0、追加output_interval=0、top-kなし、
Aguri3 max_hashentries=1000000。CLIに両段を別basisにするoptionはない。
`--threshold`、`--disable-heuristics`、`--max-hashentries`は両段の共通設定としてidentityに記録する。
heuristics1/2は別条件。3mode比較はthreshold1を要求し、他設定は3run間で厳密一致させる。
`combination`は旧packet/byte複合基準の対照専用で、主3mode validatorへ混ぜない。

## 比較・検証

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.aguri_two_stage compare \
  --root /analysis-root --dataset 202604081400 \
  --packet-run canonical-2stage-packet-t1-h0 \
  --byte-run canonical-2stage-byte-t1-h0 \
  --flow-run canonical-2stage-flow-t1-h0 \
  --validate-only --json

PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.aguri_two_stage compare \
  --root /analysis-root --dataset 202604081400 \
  --packet-run canonical-2stage-packet-t1-h0 \
  --byte-run canonical-2stage-byte-t1-h0 \
  --flow-run canonical-2stage-flow-t1-h0 \
  --output-dir /new-exports/canonical-two-stage \
  --scratch-dir /existing-scratch --chunksize 100000 --max-ecdf-points 2000

PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.aguri_two_stage verify \
  /new-exports/canonical-two-stage/comparison_manifest.json --json
```

出力先は空フォルダも含め既存なら拒否。既存run/cache/data/results等の中へ比較出力を作らない。
scratchは入力data/results/notebooks/sourcesの外にある既存フォルダを使う。
`--validate-only`はread-only。PCAPもCも実行せず、binaryの全recordをcanonicalと逐次照合し、
中間全体のhash・3counter・命令の入出力結合・候補/台帳を検証する。
各membership edgeの正しさ・完全性・重複は、その後の共通集計で検証する。
比較時にRLSを再実行する機能はない。エラーは項目/モード名付き、終了code2。成功は0。

## 中間形式：aguri-weight-wire-v1

ネットワークbyte order。magic=`AGWGT001`。固定長要素を数に従って逐次読む。
Pythonの定義は`aguri_two_stage/wire.py`、Cはパッチ内`weights.c`。

| 要素 | wire struct | 意味 |
| --- | --- | --- |
| header | `!8s6I` | magic, basis, threshold, heuristics, stage, hash_limit, reserved=0 |
| block | `BLK1` + `!8Q` | sequence, start, end, packets, bytes, flows, address数, protocol数 |
| address | `!16s16sBB3QI3Q` | src/dst padded label, prefix長, p/b/f, 下位数, unattributed p/b/f |
| protocol | `!16s16sBB3Q` | protocol/port label bits, prefix長, residual p/b/f |
| block trailer | `SUM1` + `!5Q` | p/b/f,address数,protocol数 |
| file trailer | `END1` + `!4Q` | block数,全p/b/f。後続byte禁止 |

basisは1=packet、2=byte、3=combination、4=flow。stage1だけがS2入力。
IPはIPv4の先頭4byte＋zero padding、protocol/portは先頭3byte＋zero padding。
label長/host bits・version・setting・block順・欠損/余分なbyte・trailer・総量・overflowを検証。
親子関係は各addressの直後にその下位数だけprotocol recordが続く構造で保持する。

上位HHH residualの合計は入力全量と一致する。下位sum+protocol_unattributed=上位を検証する。
上位と下位は同じ重みの別表現で、両方をfile totalへ加算しない。
flow residualは中間record件数でもnative内の実所属flow数でもない。

旧protocol探索が抽出しない残余はunattributed metadataへ保存し、RLS候補に戻さない。
不足分wildcardを新たに足すと、後続blockのlabelがsuperset lookupへ吸収されるため禁止。
ただし旧writer自身の「label出力が0件ならwildcard100%」fallbackは同条件で保持する。
そのfallbackが後続blockのlabelを吸収する元の挙動も保存する。
下位RLSでの脱落・fallbackは上位総flow数の保存とは別にauditする。
各stageのunattributed/fallbackは非加算の監査指標であり、stage1+stage2を単純合計しない。

## 旧実装と維持した部分・相違点

- Aguri3のread_flow/do_agflow、IP対/port構造、共有hhh.cの探索順序・格子・label heuristics・
  残余抽出と祖先減算・wildcard保持を再利用する。RLSをPython等で再実装していない。
- 既存flowパッチのhash/record/root/閾値/伝播カウンタを再利用。
  Aguri3で+1、S2で保存flow値を加算する。packet/byteカウンタをflowに流用しない。
- old packet/byte/combinationのAGR経路を残す。新`-W`だけがexact wireを使う。
  新形式をforkの旧AGR readerへ渡した場合も拒否する。
- 旧AGRはprotocol割合を小数2桁で書き、整数に切り捨て復元する。
  新wireはRLSの整数残余とlabel bitsを保持するため、その丸めや文字列表現の曖昧さを持ち込まない。
  protocolの細分結果まで旧wireと完全一致するとは主張しない。上位結果と下位結果を別検証する。
- 旧quickmergeはBYTEでも実packet比較を使う。この補助heuristicを全3modeで固定。
  現行direct-prime FLOWがflow比較へ変更している部分は、この新forkだけで旧packet比較へ戻す。
  主3modeに固定packet依存が残ることを条件として明示する。
- **実装中に再現した旧スケジューリング問題**：低hash上限ではproducerが未処理bufferを再取得でき、
  同じ入力でもblock境界が変わる。新`-W`だけにready/empty待合せと最終epoch drainを追加。
  旧AGR互換経路は元の挙動を保持する。新方式のblock境界は入力に対して決定的で、
  旧方式の特定のスケジューリング結果と一致するとは限らない。RLS探索は変更していない。
- 新経路のcounter加減算と閾値表現範囲を検査し、wrapを失敗とする。旧丸め規約は保持する。
  56byte入力の1行packet/byte uint32上限を超える場合は分割せず拒否する。

## 比較bundleとHTML

新schema=`aguri-two-stage-comparison-v1`、run=`aguri-two-stage-run-v1`、
cache=`aguri-two-stage-cache-v1`、validation=`aguri-two-stage-validation-v1`。
直接版のvalidatorを無効化して受理させることはしない。

- `dashboard.html`：既存native UIを再利用。Overall+3mode ECDF、表・検索・個別prefix複数ECDF、
  同じ選定集合のnative/normalized24 Scope Comparison、来歴、SVG保存。
  両段thresholdと実際のheuristicsを表示し、直接版の`-D -D`固定表示を継承しない。
- `summary.json`：全体/各prefix/各modeの正確な統計・coverage・KS・Jaccard・scope比較。
- `native_selection_summary.csv`、`native_prefix_stats.csv`、`native_pairwise_jaccard.csv`。
- `native_ecdf_counts.csv`：native Overall/3mode全整数度数と正確な累積数。
- `ecdf_counts.csv`：normalized24 Overall/3modeの全度数。
- `scope_comparison.csv`、`scope_ecdf_counts.csv`：固定選定集合の粒度比較と全度数。
- `modes/<mode>/{summary.json,frequencies.csv}`：normalized24共通集計。
- `native/modes/<mode>/{summary.json,frequencies.csv}`：native共通集計。
- `comparison_manifest.json`：全21成果物のhash/schema/件数、前後validation、実装hash。最後に公開。

HTMLは単一・offline・CDN非依存。個別prefixは最大5個、選択時に表示点をdecode。
元度数は全保存し、表示上限/簡略化はexact統計とKSに影響しない。
簡略化時は真の保存点・下界階段・上界帯・誤差上限を示す。
各native・unionともcanonical src OR dst、flow_id一意。別prefix間には共有flowがあり得る。
統計/分位点の規約は既存normalized24と同じ。空集合mean/median/p95/率とゼロ分母はnull。

## 検証の範囲と手動MAWI実行

合成データと固定upstreamのcompiled回帰を実施する。実MAWIがない環境では実行済みと扱わない。
実装前の全体基準は874成功/既知Notebook06失敗3。最新の結果は完了報告のログを参照する。

本番実行では、まず保存canonicalとbuildの検証、各modeのrun、compare --validate-only、
新出力先へのcompare、verifyの順に実行する。3modeのsource hash、両段command、stage1/2総量、
protocol audit、選定集合と統計を確認する。旧PCAP対canonical、旧wire対exact wire、
直接版対2段階は重み以外の差を含むため、それぞれ別対照として解釈する。

canonical converter・評価はchunk/SQLite。wireは逐次。CのRLSはhash/探索用のRAMを要し、
一定メモリを保証しない。S1の100万hash上限はheuristics0で作用するがprotocol listや探索メモリを含む
総RAM上限ではない。heuristics1/2ではその早期summary条件も無効になる。
S2は全中間prefix/下位候補を再集約するため、特にRAMに注意する。
SQLite用disk、canonical.bin、両wire、CSVの容量と、前後hash/逐次binary照合によるI/Oを見込む。
実MAWI規模の性能は未測定。初回は各commandの時間・最大RSS・scratch空き容量を人間が計測する。
