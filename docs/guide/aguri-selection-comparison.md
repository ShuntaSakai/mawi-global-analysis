# 旧Aguri BPF条件とcanonical packet選定のA/B/C比較

保存済みrunのみを読み、同じcanonical IPv4 TCP/UDP・Raw・native src OR dst・
flow_id一意unionで評価する。PCAP解析、canonical生成、Aguri3/Agurim/Agurim′実行はしない。
既存normalized/nativeダッシュボードは変更せず、専用の新規bundleへ出力する。

| 条件 | 既定run | 選定入力 |
| --- | --- | --- |
| A | baseline | 旧PCAP→Aguri3→Agurim、BPFなし |
| B | agurim-ipv4-tcp-udp | 同じ旧経路、`-f 'ip and (tcp or udp)'` |
| C（互換既定） | canonical-packet-t1-h2 | canonical→改変版Agurim′、packet、1%、heuristics=2 (`-D -D`) |
| C（2段階指定） | canonical-2stage-packet-t1-h0 | canonical→拡張Aguri3→拡張Agurim、packet、両段1%、heuristics=0 |

Cはrun名ではなくrun manifestのschemaから方式を判定する。旧Cの既定値は互換性のため維持する。
2段階Cは`--run-c canonical-2stage-packet-t1-h0`で明示する。

## 手動実行

解析rootがリポジトリと同じ場合の例。run/cache/CSVのmanifest記録先を保持すること。
絶対パスを自動置換しない。

```sh
cd /Users/shunta/mawi-global-analysis
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.aguri_selection_comparison \
  --root "$PWD" --dataset 202604081400 \
  --run-a baseline --run-b agurim-ipv4-tcp-udp --run-c canonical-2stage-packet-t1-h0 \
  --validate-only --json
```

`--validate-only`は書き込みなし。native edgeの正しさ・完全性や分布は次の生成時に確認する。

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m mawi_global_analysis.aguri_selection_comparison \
  --root /Users/shunta/mawi-global-analysis --dataset 202604081400 \
  --run-a baseline --run-b agurim-ipv4-tcp-udp --run-c canonical-2stage-packet-t1-h0 \
  --output-dir /absolute/path/new-abc-comparison \
  --scratch-dir /absolute/path/existing-scratch \
  --chunksize 100000 --max-ecdf-points 2000
```

出力先は新規ディレクトリのみ。既存の空フォルダも上書きしない。
data/results/notebooks/sources、既存run/cache内は出力先にできない。
scratchは十分な空き容量のある既存ディレクトリとし、入力data/results等の中には置かない。
失敗時は終了2、成功は0。`--json`は出力manifest/HTML pathを返す。
対象を変える場合は`--target 93.139.29.123/32`（既定値）。除外は指定CIDR完全一致であり、
包含prefixを分割したり、対象IPを含むすべてのflowを取り除いたりしない。

Python API：

```python
from pathlib import Path
from mawi_global_analysis.aguri_selection_comparison import validate_inputs, generate, verify_manifest

validation = validate_inputs(Path('/analysis-root'), '202604081400',
                             run_c='canonical-2stage-packet-t1-h0')
manifest = generate(Path('/analysis-root'), '202604081400', Path('/new-output'),
                    run_c='canonical-2stage-packet-t1-h0',
                    chunksize=100000, scratch_dir=Path('/scratch'))
verify_manifest(manifest)  # 保存済み出力hash/schema/行数/検証記録の再確認、再解析なし
```

## 検証すること・不足情報の扱い

既存`rls_weight_comparison.validate_comparison`をA/B/Cへ適用しない。専用検証を使う。

- 3runのcanonical CSV/flow manifest/PCAP由来hash・flow fingerprint・row count・flow設定を照合。
  PCAP自体は開かない。評価はIPv4 TCP/UDP、Raw、corrected native src OR dst。
  同じcanonicalでもsource/cache/runのhash矛盾があれば項目名付きで失敗する。
- A/BのAguri cache fingerprint、実行ファイルhash、保存configと2段の実行引数を照合。
  getoptでattached/clustered引数も解析し、Aはfilterゼロ、Bは指定filter1つだけを要求する。
  BPF以外のAguri3 option、Agurim option、flow/prefix/analysis/scan/legacy設定が異なれば拒否する。
- A/B・旧Cは実行ファイルが存在すれば実hashを照合する。存在しなければrecorded_hash_onlyと明示する。
  バージョン確認を含め、実行ファイルを呼び出すことはない。
- Aguri-v1はraw AGR/renderedのhistorical hashを記録しない。
  現在のhashと、保存renderedから再parseした候補CSV、記録producer・corrected台帳を照合するが、
  過去のraw bytesを独立に認証したとは扱わない。
- 非gzipはAguri3の`-r`をrunのdeclared PCAP pathへ結合する。
  gzipでは元gzip path・一時PCAP path・完全なargvを保存するが、失われた一時PCAPの内容は検証不能。
  この場合`ab_config_bpf_only=true`、`ab_bpf_only=false`、
  `ab_contrast_verification`で「設定上のBPF差だけ確認、展開内容は独立未確認」と記録・表示する。
  非gzipで`ab_bpf_only=true`でも、それは保存manifest上の入力/引数の結合であり、過去実行の認証ではない。
- 旧C（`agurim-prime-run-v1`）はcanonical入力lineage、packet basis、1%、heuristics=2、converter実装、fork metadataを検証。
  fork_identity・明示的fork_commit（未公開ならnull）・compiler・source hash・build hashを必要とする。
  build_manifestがあれば実hash/内容を照合し、なければ記録のみの限界を示す。
- 新C（`aguri-two-stage-run-v1`）は`aguri_two_stage.validation.inspect_lineage()`を再利用。
  packet basis・両段1%・heuristics=0を必須にし、両段argv、wire設定・整数カウンタ・候補、
  canonical入力、cache/producer/manifest/fingerprint/hash、corrected台帳を厳密に照合する。
  build_manifestとsource・両実行ファイルが実在し、現在のpatch/実装と一致することが必要。
  欠損時に旧Cのrecorded-only経路へフォールバックしない。
  未知schemaや両方式のcache/artifactを混在させたmanifestも拒否する。
- 両方式Cの保存済みcanonical.binの全56byte recordを、converter ABI/スカラー規約を再利用して
  canonical行と順序・src/dst・port・protocol・packet/byte重み・timestampまで逐次照合する。
  binaryを作成し直す処理ではない。packet/byte総量を含むauditも照合する。
- 3runとも候補からcorrected prefix ledgerを再構成して保存台帳と一致検証。
  native/normalized membershipは生成時に一意性、ID存在、src/dst flags、完全性を検証する。
  `*`や`*::`は具体的なprefix候補に数えず、既存corrected parserと同じ扱いにする。
- 入力を前後にhash検証し、全成果物を検証して完了manifestを最後に公開する。
  元ファイルを解析中に変更しないこと。immutable filesystem snapshotを作る機能ではない。

A→Bは上記で確認できた範囲のBPF対照。旧Cとの比較は一次集約の有無・入力形式・heuristicsも異なる。
新Cは同じ2段階構成だが、PCAPパケットとcanonicalフローの入力単位、endpointの向き、
重み付きwire、決定的な段間buffer受渡しも異なる。いずれも純粋なRLS実装差とは解釈しない。
HTMLのヘッダー・条件表・B→C説明は検証済み方式に追従する。

## 集計・寄与の定義

既存SQLite ingestと`normalized24.analysis._summarize`、正確なECDF/KS処理を再利用する。
canonicalを一括DataFrameへ読み込まない。nativeを親/24へ拡張しない。
1つのnative内ではflow_idを一意にし、複数nativeに所属するflowもunionでは1回。
HHH discounted countを実所属flow数として使わない。

- median/p95はlinear `(n-1)*q`。packet_total/byte_totalは正確な整数。
  byte_countはcanonical Ethernetフレーム総量。空集合は総量0、mean/quantile/rateはnull。
- coverageは共通Overallの対応総量を分母とする。分母0はnull。
- KSは全整数度数を整数交差積で比較し、正確な既約分子/分母を保存。p値ではない。
- Jaccardはnative完全一致CIDR集合、親/24へ写像した集合、union ID集合を別々に比較する。
  両方空はnull。CIDR集合のJaccardはIP空間面積のJaccardではない。
- 対象prefixのstandalone所属数は未選定でも共通canonical上で調べる。
  union shareは`対象所属∩条件union / 条件union`。未選定prefixの所属数をそのまま割って
  1を超える「割合」を出さない。候補exact、具体的包含候補、選定の有無も別に記録する。
- B/Cの対象除外は残りのedgeからunionを再構築。共有flowは残す。
  `exclusive_union_flow_count`は当該prefixだけを除外した時に失うID数。
- Bで新規選定されたCIDRのunionは、Aにも所属するflowを含み得る。
  B_only_union、A_only_union、AB_common_unionを別途保存し、IP空間差と混同しない。

## 画面

生成先`dashboard.html`をブラウザで開く。単一HTML・オフライン・CDN不要。

1. Overview：A/B/C条件、7統計・3coverage・KS、3種類のJaccard。
2. Flow Size Distribution：Overall+A/B/Cの4曲線。右連続・対数横軸、凡例、ホバー、
   ボタン/ホイール/ドラッグ拡大縮小、リセット、SVG保存。旧Notebook照合状態も表示。
3. Selection Changes：A/Bの共通/追加/消失CIDR、flow差分component、検索・条件絞り込み・ページング。
4. Prefix Contribution：対象の候補/選定/所属/union寄与、B/Cの除外前後ECDF・7統計・KS、
   他prefixの規模とexclusive ID数の表。表の他prefixの除外後分位点を推測してはいない。
5. Experiment Details：入力・実行ファイル・BPF・fork・検証限界・実装/成果物hash・統計定義。

描画のみ上限付き。選択点は真のECDF値、間引いた階段は下界、帯は次の選択点の上界。
各曲線の元点数・表示点数・最大帯幅を表示する。ホバーは最も近い保存点であり、
カーソル位置のexact値を補間したと主張しない。全exact度数はCSVに保存する。

## 出力schema

manifest=`aguri-selection-comparison-v1`、validation=`aguri-selection-validation-v1`。
旧2種類の比較bundle/manifestとは別契約。17成果物と完了manifestを生成する。

| 成果物 | 内容 |
| --- | --- |
| dashboard.html | 5画面・全表示データ・inlined CSS/JS |
| summary.json | 条件統計、prefix/寄与、focus、感度分析、参照照合。表示曲線配列は除く |
| selection_summary.csv | 条件、native数、7統計、3coverage、KS値と正確な分子/分母 |
| prefix_stats.csv | 条件・native CIDR、7統計、1packet数、union share、exclusive ID/1packet数 |
| pairwise_prefixes.csv | 各ペア、native/親24写像集合、common/A_only等の所属 |
| jaccard.csv | 3ペア×3集合の交差・和・Jaccard |
| ecdf_counts.csv | Overall、A/B/C、B/C_without_target、4component、targetの全度数・累積数・分母・CDF |
| focus_prefix.csv | 各条件の選定/candidate exact/包含候補、target統計、target∩union、union share |
| sensitivity_summary.csv | B/Cのbefore/after、選定有無、7統計とOverallへのKS |
| component_stats.csv | B_added_prefix_union、B_only_union、A_only_union、AB_common_unionの7統計 |
| legacy_comparison.json | 提供参照との照合状態、差分サンプル、静的Notebook監査とhash、歴史的再現の限界 |
| modes/A,B,C/summary.json | 各prefix・union・Overallの正確な統計、入力hash・histogram規約 |
| modes/A,B,C/frequencies.csv | distribution,packet_count,frequency。各native/union/Overallの全整数度数 |
| comparison_manifest.json | 前後validation、入力・実装・出力hash/件数、表示設定、証拠範囲。最後に公開 |

`summary.json`と`comparison_manifest.json`に加算フィールド`selection_conditions`を保存する。
Cのmethod・basis・threshold_percent・heuristics・各stageと条件表示をvalidationに結合し、
`verify_manifest()`で不整合を拒否する。schema v1の既存成果物はこのフィールドがなくても検証できる。
CSVの形式・統計規約・A/Bの集計は変更しない。過去bundleの自動更新もしない。

CSV nullは空セル、JSONはnull、HTMLは「—」。研究用整数値を維持し、ブラウザで安全な範囲を超える
整数は十進文字列にする。正確な比は累積数/分母やKS分子/分母、CDF表示は浮動小数点。

## 旧大会Notebookの参照export（任意）

現行アーカイブにはnative membershipのunique IDsでunionを作る式と、
`np.sort(np.asarray(values, dtype=float))`によるECDFがある。個別prefix中央値分布は別の図。
この静的監査をhash付きで記録するが、当時のrun・中央値・公表図の再現とは扱わない。
浮動小数への変換は巨大整数で値をまとめる可能性がある。現在のexact度数ではまとめない。

**実際に旧図を作ったNotebook/runの状態**からexportする。新CLIの出力を参照へ転記して
一致させても、旧大会結果の証明にはならない。以下は既にNotebookにある
`selected_scope_flows`、`selected_prefixes`、`run`を用いる例で、Notebookを自動実行しない。
入力pathとNotebook pathは実際に照合したものを指定する。

```python
from pathlib import Path
import hashlib, json

ref = Path('/absolute/path/new-society-reference')
ref.mkdir(exist_ok=False)
# 旧packet CDFと同じRaw/TCP/UDP条件を明示する。既にnative unionとして一意な表を使う。
old = selected_scope_flows.loc[
    selected_scope_flows['raw_included'] &
    selected_scope_flows['protocol'].astype(str).isin(['6', '6.0', 'tcp', '17', '17.0', 'udp'])
].copy()
if old['flow_id'].duplicated().any():
    raise ValueError('reference table is not a unique-flow union')
old[['flow_id']].to_csv(ref/'union_flow_ids.csv', index=False)
counts = old['packet_count'].value_counts().sort_index()
counts.rename_axis('packet_count').reset_index(name='frequency').to_csv(ref/'frequencies.csv', index=False)

def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

flows_path = Path('/actual/path/from/the-old-run/flows.csv')
notebook_path = Path('/actual/path/used-for-the-old-figure.ipynb')
record = {
    'schema_version': 'society-union-reference-v1',
    'canonical_csv_sha256': sha256(flows_path),
    'input_capture_sha256': run.manifest['input']['sha256'],
    'selected_native_prefixes': sorted(selected_prefixes['prefix'].tolist()),
    'quantile_rule': 'pandas default linear',
    'statistics': {
        'flow_count': len(old),
        'median': float(old['packet_count'].median()) if len(old) else None,
        'p95': float(old['packet_count'].quantile(.95, interpolation='linear')) if len(old) else None,
        'one_packet_rate': float((old['packet_count'] == 1).mean()) if len(old) else None,
    },
    'reference_source': {'notebook_path': str(notebook_path), 'notebook_sha256': sha256(notebook_path)},
    'artifacts': {key: {'path': name, 'sha256': sha256(ref/name)} for key, name in
                  [('flow_ids', 'union_flow_ids.csv'), ('frequencies', 'frequencies.csv')]},
}
(ref/'legacy_manifest.json').write_text(json.dumps(record, indent=2, allow_nan=False)+'\n')
```

生成コマンドに`--legacy-reference /absolute/path/new-society-reference/legacy_manifest.json`を追加する。
canonical/PCAP由来hashが異なる参照は混ぜず拒否する。参照がない場合は`reference_not_provided`。
提供exportとの一致は`supplied_reference_matches`、ID/度数/提供統計を別々に記録する。
整数・ID・度数は完全一致で照合する。median/p95/mean/1packet率のみ最大4 ULPの丸め差を許容し、
`statistics_rounding_differences`へ差を保持する。それを超える差は統計不一致となる。
不一致ならreference/currentだけのID・度数のサンプル（各最大20件）と件数を残す。
`historical_reproduction_verified`は常にfalse。提供exportの一致だけで、当時の実行・公表値の
真正性まで独立に認証したとは主張しない。Notebook/run/旧成果物の対応は人間が確認する。

## 性能・実データでの残確認

実MAWIは人間が手動実行する。合成テストは研究結果ではない。
Cの逐次binary照合、3runのhash検証を前後に行うため、大きなCSV/cacheを複数回読み込む。
SQLiteのfacts・3条件×2scopeのedges・ID集合・索引・GROUP BYに十分な一時diskが必要。
page cacheは32MiBだが全RAMはchunk、prefix統計、最大表示点数にも依存する。
`max_ecdf_points`は表示のみの上限で、CSV/statistics/KSには影響しない。
本番規模の時間・RAM・diskは未測定。初回は空き容量と進捗を人間が確認すること。

実行後は、(1)A/Bの検証レベル、(2)93.139.29.123/32のcandidate/選定、
(3)B_only_unionと追加prefix unionの重なり、(4)B/C除外時に実際に失うID数、
(5)旧Notebook参照のID/度数・統計の差を確認する。
分布差の大きさが観測されても、それだけで主体の性質やRLS実装だけを原因と確定しない。
