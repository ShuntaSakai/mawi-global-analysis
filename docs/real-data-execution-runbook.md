# Post-M7 real-data execution runbook

このRunbookは、M0〜M7まで実装済みのパイプラインを、十分なローカルストレージを持つ研究室PCで実データ検証するための実行順序を記録する。ここでの実行は再現性とE2E健全性の検証であり、結果の科学的解釈を自動的に確定するものではない。

> **Real MAWI E2E: Deferred due to local storage constraint.**
>
> `202604081400` はこのMacでダウンロード可能だが、canonical `flows.csv` の生成中にローカル容量を超える。これは実装失敗ではなく、実行環境のストレージ制約である。本Runbookでは、十分な容量を持つ研究室PCでのみ実データ処理を開始する。

## 1. 現在の実装状況（M0〜M7）

現在、以下の能力は実装済みである。

- PCAPからTCP/UDP双方向5-tupleのcanonical flowを生成し、`flows.csv` をデータセット共有キャッシュとして保存する。
- Aguriからprefix候補を抽出する。
- corrected IPv4 prefix選択（`src_prefix` と `dst_prefix` の候補和集合、より広いprefix優先、`/24`以上、top-kなし）と、`src_ip OR dst_ip` membershipを生成する。native prefixと真に再計算したnormalized `/24` の両方を保持する。
- 閾値なしのsource-window scan統計とsource summaryを生成する。
- Strict evidenceによるscan-like source検出を行う。
- 同定したsourceについてのみ、capture-wideのStrict / Broad evidence removalラベルを生成する。
- flow/Aguri fingerprint、入力checksum、config内容・hash、code/git identity、stage実行・再利用、artifact行数をmanifestに記録し、意味的に一致するキャッシュを再利用する。
- fixed Raw-derived prefix setを使うRaw / Strict / Broad比較をNotebookで集計・可視化する。
- dataset × config batchの計画・逐次実行、batch manifest/log、成功run provenanceへのlinkを扱う。
- `load_batch` はbatch provenanceのみを先に読み、各run CSVは必要時に遅延ロードする。
- multi-dataset validation Notebookを備える。

上記は実装済み能力である。一方、**実MAWIデータのfull E2Eはまだ完了していない**。Deferredの理由は前述のローカルストレージ制約である。

## 2. 実行時に守る科学的意味論

### Prefix

main comparisonでは、Raw trafficから一度だけ選んだprefix setを固定する。

```text
one Raw-derived selected prefix set
    ↓
Raw / Strict / Broad の全条件で同じsetを使用
```

条件ごとにAguri実行やprefix選択をやり直してはならない。`02_main_prefix_comparison.ipynb` はrun-localのRaw-derived `prefixes.csv` と `flow_prefix_membership.csv` を固定し、同じflow集合へRaw / Strict / Broad inclusionを適用する。

### Scan

scan-like source detectionはStrict evidenceのみを使う。

- Strict evidence: `syn_to_rst`、`syn_synack_rst`
- Broad evidence: `syn_only_observed`

Broad evidenceは独立したdetectorではない。

### Removal

- **Strict:** scan-likeと同定されたsourceのStrict evidence flowだけをcapture-wideに除外する。
- **Broad:** 同じsourceのStrict evidence flowに加え、`syn_only_observed` flowをcapture-wideに除外する。

scan-like sourceの全trafficを削除するものではない。観測されたestablished payload traffic、UDP、mid-connection等はデフォルトで残す。必ず `strict_removed_flow_ids ⊆ broad_removed_flow_ids` を確認する。

### Threshold

`configs/scan_source_driven_removal.yaml` の現在の値、`N_strict = 20` と `M_strict = 10` は**暫定のhuman-approved値**である。最終的または科学的に最適な値として表現してはならない。

## 3. 新しい研究室PCのセットアップ

リポジトリはPython 3.12（`.python-version` と `pyproject.toml`）を対象とし、`uv` を依存関係管理の標準経路にしている。容量の大きいfilesystem上でcloneし、そのcloneをanalysis rootとして実行する。

```bash
git clone --recurse-submodules https://github.com/ShuntaSakai/mawi-global-analysis.git <analysis-root>/mawi-global-analysis
cd <analysis-root>/mawi-global-analysis
uv --version
uv sync
```

`uv --version` が失敗する場合は、先に公式のuv installer等でuvを導入する。OS/package manager別の手順はこのRunbookの対象外である。submoduleを含めずにcloneした場合は、次を実行する。

```bash
git submodule update --init --recursive
```

AguriはPython依存関係とは別に、repository-pinned submodule `vendor/agurim/` で管理される。実行前にsubmoduleの存在を確認し、必要なら実行ファイルをbuildする。

```bash
test -d vendor/agurim
make -C vendor/agurim/src
```

configで実行ファイルを明示しない場合の解決順序は、pinned repository binary、次いでPATH fallbackである。PATH fallbackが使われる場合は警告と実行ファイルpath/version/checksumがprovenanceに記録される。研究再現ではpinned submoduleを優先する。

## 4. ストレージpreflight（必須）

実データ処理の前に、analysis rootが置かれたfilesystemの空き容量を必ず確認する。

```bash
df -h .
```

raw PCAP、canonical flow cache、run-specific artifacts、さらに複数データセットのcache/artifactsは同時に容量を消費する。特に`flows.csv`生成中の容量を見込むこと。**exact storage requirement is not yet established** のため、本Runbookは具体的なGB数を規定しない。容量に余裕がない場合は実行を始めず、より大きいfilesystemをanalysis rootに選ぶ。

## 5. Analysis root

pipelineとbatchのanalysis rootは、現在は環境変数ではなく**実行時のカレントディレクトリ**である。以下の場所をそのrootの下に作る。

```text
data/<dataset>/raw/
data/<dataset>/processed/
results/<dataset>/<run-name>/
results/batches/<batch-name>/
```

したがって、十分な容量を持つ場所にcloneしてからそのディレクトリでcommandを実行する。

```bash
cd <analysis-root>/mawi-global-analysis
```

`MAWI_ANALYSIS_ROOT` はpipeline/batchのroot指定ではない。これは `02_main_prefix_comparison.ipynb` がrunをロードする際に使うNotebook環境変数であり、Notebook実行時には次のように設定する。

```bash
export MAWI_ANALYSIS_ROOT="$PWD"
```

## 6. single-dataset preflight

最初の対象は `202604081400` だけに限定する。実行前に以下を順に確認する。

```bash
cd <analysis-root>/mawi-global-analysis
git rev-parse HEAD
git submodule status --recursive
uv --version
df -h .
test -d vendor/agurim
```

config validationはpipelineによるconfig load時に行われる。実データ取得もartifact書込みもしない計画確認には、以下のdry-runを使える。

```bash
uv run python run_pipeline.py \
  --dataset 202604081400 \
  --config configs/baseline.yaml \
  --dry-run
```

`--dry-run` はstageのexecute/reuse判断だけを表示し、fileを変更しない。未キャッシュの入力に対してもdownloadは行わない。実行する研究室PCで入力済みPCAPを使用したい場合は、pipelineが期待する `data/202604081400/raw/202604081400.pcap.gz` に配置してから同じdataset commandを使う。未配置の場合、通常実行はMAWI input retrievalを行う。

## 7. Raw baseline実行

preflight完了後、corrected Raw baselineを実行する。

```bash
uv run python run_pipeline.py \
  --dataset 202604081400 \
  --config configs/baseline.yaml
```

configのexperiment nameは`baseline`なので、run-local出力は `results/202604081400/baseline/` である。実行後、`run_manifest.json` の`status`が`success`であることを確認する。manifestが記録するartifact pathに従い、少なくとも次を確認する。

- shared canonical flow cache: `data/202604081400/processed/flows/.../flows.csv`
- run-local: `flow_labels.csv`
- run-local: `prefixes.csv`
- run-local: `flow_prefix_membership.csv`
- run-local: `source_scan_windows.csv`
- run-local: `source_scan_summary.csv`
- run-local: `run_manifest.json`

artifactの最終的なpathとrow countは、推測せずmanifestの`artifacts`をsource of truthとして確認する。既存runと入力/config identityが異なる場合、同じrun nameは上書きされず失敗する。

## 8. scan-source-driven実行

次に、暫定20/10を含むsource-driven removal configを実行する。

```bash
uv run python run_pipeline.py \
  --dataset 202604081400 \
  --config configs/scan_source_driven_removal.yaml
```

run nameは`scan_source_driven_removal`である。flow generation semanticsが同じなのでcanonical flow cacheはfingerprintが一致すれば再利用される。Aguri cacheも入力・実行ファイル・options等を含むfingerprintが一致する場合に再利用される。scan statisticsも適合するprovenanceを持つ既存runから再利用できる。manual copyは不要であり、cache/provenanceの検証に任せる。

実行後、`run_manifest.json` でstage statusとartifactを確認する。特に次を確認する。

- `source_scan_windows.csv` と `source_scan_summary.csv` にsource scan統計があること。
- `flow_labels.csv` にRaw / Strict / Broad comparison用のflow labelsがあること。
- Strict/Broad labelが暫定20/10 config hashに対応すること。
- manifestの`status`が`success`であり、stageが`completed`または正当な`reused`であること。

このrunの`prefixes.csv`と`flow_prefix_membership.csv`はRaw trafficから導出された固定set/membershipとしてcomparisonに用いる。条件別のprefix再選択はしない。

## 9. single-dataset Notebook検証

`02_main_prefix_comparison.ipynb` は一つのrunのcanonical artifactsからRaw / Strict / Broadを比較する。研究室PCで`scan_source_driven_removal` runを検証する例は次のとおり。

```bash
cd <analysis-root>/mawi-global-analysis
export MAWI_ANALYSIS_ROOT="$PWD"
export MAWI_DATASET_ID=202604081400
export MAWI_RUN_NAME=scan_source_driven_removal
jupyter notebook notebooks/02_main_prefix_comparison.ipynb
```

Jupyter上でRun Allを行い、次が生成・表示されることを確認する。

- Raw / Strict / Broadのoverallおよびper-prefix table
- removal volume（flow / packet / frame-byte）
- overall median movement
- Overall vs Prefixの比較
- per-prefix changes

これはE2E sanity validationであり、この時点で研究結論を出さない。Notebookはzero-survivor prefixを保持し、ゼロ除算由来の不正なratioを避ける設計である。

## 10. 実データsanity checklist

single-day結果では、少なくとも以下をチェックする。

- pipeline manifestの`status`が`success`である。
- `strict_removed_flow_ids ⊆ broad_removed_flow_ids` が成立する。
- survivor countが `Broad <= Strict <= Raw` である。
- 全条件が同じ固定Raw-derived selected prefix setを使う。
- 条件別のAguri/prefix selection再実行がcomparisonに混入していない。
- zero-survivor prefixが除外・欠落ではなく適切に扱われている。
- Strict/Broad双方についてremoved flow ratio、removed packet ratio、removed frame-byte ratioを確認する。
- overall/per-prefix集計に予期しない`inf`がない。
- Notebookがclean kernelから最後まで実行成功する。

removalが極端に大きい、prefixがゼロ、unexpected `inf`、subset/monotonicity violation、またはmanifest失敗があれば、直ちに科学的結論へ進まない。config hash、input checksum、cache fingerprints、labels、source-window evidence、prefix ledgerを先に確認する。

## 11. multi-dataset実行

batchへはsingle-datasetが正常に完走し、そのsanity reviewを終えてから進む。`datasets/validation_days.txt` は現在repositoryに存在しないため、実行前に研究対象のdataset IDを1行ずつ入れたUTF-8 fileとして作成する必要がある（空行は無視され、duplicate IDは拒否される）。

single configの例:

```bash
uv run python run_batch.py \
  --datasets datasets/validation_days.txt \
  --config configs/baseline.yaml \
  --batch-name multi-day-baseline
```

Raw / Strict / Broad comparisonに必要なdataset × config matrixの例:

```bash
uv run python run_batch.py \
  --datasets datasets/validation_days.txt \
  --configs \
    configs/baseline.yaml \
    configs/scan_source_driven_removal.yaml \
  --batch-name multi-day-scan-comparison
```

`--config` と `--configs` は排他的である。batchは通常、失敗jobをrecordして次のjobを続行する。`--fail-fast` を渡すと最初の失敗で後続jobを実行しない。

## 12. batch outputsと失敗意味論

batch outputは正確に次のlayoutである。

```text
results/batches/<batch-name>/
├── batch_manifest.json
└── batch.log
```

`batch_manifest.json` はdataset list/hash、config paths/hashes、dataset-major job matrix、job status、実行時刻、failure summary、成功jobがlinkしたrun provenanceを記録する。`batch.log` はstart/done/failの逐次記録である。

defaultはcontinue-on-errorである。ただし、**一つでもjobが失敗すればbatch processの最終exit statusはnon-zero**になる。成功jobは、dataset/config hashと`status: success`を確認済みのlinked `run_manifest.json` を持つ。

## 13. multi-dataset Notebook

batchが完了した後、`04_multi_dataset_validation.ipynb` を実行する。このNotebookの必須入力は`MAWI_BATCH_MANIFEST`だけであり、`batch_manifest.json`のpathを指定する。

```bash
cd <analysis-root>/mawi-global-analysis
export MAWI_BATCH_MANIFEST="$PWD/results/batches/multi-day-scan-comparison/batch_manifest.json"
jupyter notebook notebooks/04_multi_dataset_validation.ipynb
```

Run Allで、datasetごと・conditionごとに少なくとも次を確認する。

- selected native-prefix count
- Overall medians
- Prefix Q25 / median / Q75
- Strict/Broad removal ratios
- Overall-vs-Prefix absolute difference

このNotebookは、single-dayで見た傾向が別datasetでも再現するかを検証するためのものだ。single-dayの結果を既定の結論として扱うためのものではない。

## 14. まだ検証されていないこと

以下を混同しない。

**Implementation verified:**

- unit/full tests
- synthetic batch E2E
- synthetic clean-kernel notebooks

**Real-data not yet verified:**

- `202604081400` full pipeline
- Raw/Strict/Broad actual removal volumes
- actual research result
- multi-day real-data reproducibility
- provisional 20/10のscientific adequacy

「実装が通った」と「研究仮説が実データで確認された」は別の主張である。本Runbookの実行は後者の検証を開始する手順であり、事前にその成立を主張するものではない。

## 15. 推奨実行順序

1. 容量の大きいfilesystemへcloneし、Python/uv/submodule/Aguriをsetupする。
2. `df -h .` とanalysis root（カレントディレクトリ）を確認する。
3. `202604081400` のbaseline dry-runを確認する。
4. `202604081400` で`baseline.yaml`を実行する。
5. `202604081400` で`scan_source_driven_removal.yaml`を実行する。
6. `02_main_prefix_comparison.ipynb`を実行する。
7. single-day sanity checklistをreviewする。
8. `datasets/validation_days.txt` を作成し、対象日を確定する。
9. batchを実行する。
10. `04_multi_dataset_validation.ipynb`を実行する。
11. 全てのprovenance・sanity確認後にのみ、科学的解釈へ進む。

## 付記: `01_scan_threshold_exploration.ipynb` の移植性

このNotebookの現行inputは環境変数ではなく、特定Macのabsolute `repo_root` と `202604081400/threshold_exploration/source_scan_windows.csv` を直接指定している。そのため研究室PCでそのままRun Allするportable contractは現状存在しない。これは今回のdocumentation-only scopeでは変更しない。必要なら将来、`02`と同様のmanifest/root環境変数ベースのloaderへ修正する別タスクとして扱う。
