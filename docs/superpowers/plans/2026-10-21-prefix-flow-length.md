# Prefix flow-length histograms implementation plan

**Goal:** 保存済みrunだけを読み、選定nativeプレフィックスごとのRaw / Broad removed / Broad retainedを比較する。ユーザーの今回の依頼を仕様・実行承認とし、設計を先に提示して同じセッションで実装する。

**Architecture:** manifest参照のチャンク読込と一時SQLiteによるID照合・集計を新規ヘルパーに分離する。新規Notebookに設定、診断、統計表、共通ビンの一覧図を置く。既存Notebook、成果物、パイプラインの研究意味論は変更しない。

**Tech stack:** Python 3.12, pandas, numpy, matplotlib, SQLite (標準ライブラリ), Jupyter。

## Constraints and verified discovery

- Base: `a0aa4f74a2f64c3d394afaa2ece3947604c4d4ad`。元checkoutはcleanなmain。作業用ローカルcloneの `codex/prefix-flow-length-histograms` に未コミットで残す。
- `README.md`, `configs/scan_source_driven_removal.yaml`, `docs/agent/*`, `pipeline.py`, `flow_stage.py`, `io.py`, `prefix.py`, `membership.py`, `scan_labels.py`, `hashing.py`, notebooks/02と03、添付Markdownを確認。
- 過去02の保存出力: native選定18、native所属550289行、一意549990フロー、IPv4 Raw33295132。これは保存出力の記録であり今回の実データ再現ではない。新規入力では台帳から再検査する。
- run入口: `results/<D>/<run>/run_manifest.json`。statusはsuccess必須。相対artifact pathはroot基準、絶対pathはそのまま。`flows_csv`互換名を許容するが`flows`と同時なら停止。
- flows: `data/<D>/processed/flows/tcp-udp-no-timeout-<fingerprint[:10]>/flows.csv` と `flow_manifest.json`。必須使用列はflow_id, ip_version, packet_count, src_ip, dst_ip, observed_tcp_pattern。ラベル整合性検査にprotocol, initial_syn_sender_ipも使用。
- labels: run内 `flow_labels.csv`、flow_idとstrict_scan_like, broad_scan_like, strict_removed, broad_removed。
- prefixes: run内 `prefixes.csv`、prefix, selected_for_analysis。corrected ledger全列の存在を検査。
- membership: run内 `flow_prefix_membership.csv`、flow_id, analysis_scope, analysis_prefix, src_match, dst_match。
- source_scan_windows/summaryだけではflow長分布は復元不可。AguriやPCAPを再実行しない。SSH・転送をしない。
- 双方向5タプル・timeoutなし、nativeとnormalized_24の意味を維持。nativeのみを図示し、normalized所属もファイル整合性を検査。
- 1,2,3独立、以後4–7,8–15…の共通区間。群内比率は各群のflow数を分母にし、密度と混同しない。中央値/p95はビンから推測せず整数値の度数から線形補間する。

## Tasks

- [x] 1. 新規 `tests/unit/test_flow_length.py` に合成CSVの既知解と失敗系を書く。未実装による失敗を確認する。
- [x] 2. 新規 `src/mawi_global_analysis/flow_length.py` に `inspect_run(root, dataset_id, run_name)`、`analyze_run(..., chunksize, scratch_dir, progress)` と `make_demo_run(root)` を実装。manifest設定ハッシュ・現行実験設定・flow cache identity/行数/カラムを検査。重複ID、欠落labels、孤立membership、誤ったboolやpacket_countを拒否。SQLiteで全CSVを照合し、個別集計と一意unionを別に計算。memoryはchunkと固定SQLite cacheを中心とし、scratchディスクを使用。
- [x] 3. 新規 `notebooks/06_prefix_flow_length_histograms.ipynb` を作成。既定はrealモードで環境変数かパラメータを明示、欠落なら診断停止。デモは明示選択のみ。一覧表と各prefixの度数/構成比、union図、重複件数、18件履歴との比較を表示。出力保存は新規フォルダに限定。
- [x] 4. 新規 `docs/guide/prefix-flow-length-histograms.md` に発見箇所、パス、列、設定方法、証拠の限界、disk要件を記載。Notebookデモ実行、欠落データ停止、focused/full pytestを実行する。

## Review focus

1. flow/labelの順序不一致・チャンク境界を跨ぐ重複でも正しく照合する。
2. 1フローが2prefixに属す場合にunionを二重計数しない。同一所属行の重複は隠さない。
3. 保存設定の3/2閾値、60/10秒、IPv4・src_or_dst・timeoutなしの不一致を止める。
4. 空群・ゼロフローprefix・小標本・長いtailで統計と共通ビンを壊さない。
5. 移動済み絶対パスを勝手に推測しない。元CSVを変更せず、デモへの自動フォールバックをしない。

## Execution record

- Read-only discovery complete; short design and dependency table presented before implementation.
- No commits/push/PR requested; leave all additions uncommitted for review.

- Implementation complete: only five new repository files; no modified/deleted tracked files. Original checkout remains clean.
- Independent review found stale-kernel export risk and ignored producer contradictions. Both fixed with regression tests (RED then GREEN). A result-consuming cell now requires a successful matching input context; analysis refreshes its source manifest/inventory. Recorded producer flow/cache/prefix bindings are checked when present.
- Focused verification: `PYTHONPATH=src python -m pytest -q tests/unit/test_flow_length.py` -> 31 passed.
- Final full verification: `MPLCONFIGDIR=/private/tmp/mawi-flow-length-mpl PYTHONPATH=src /Users/shunta/mawi-global-analysis/.venv/bin/python -m pytest -q` -> 495 passed in 11.82s.
- Notebook validation: nbformat schema and every code-cell syntax passed; distributed Notebook has no saved outputs.
- Notebook execution: explicit synthetic mode through Jupyter nbconvert, all cells succeeded; summary/histogram CSV, two PNG pages and analysis manifest exported into a new validation folder outside the repository. Local Jupyter kernel needed sandbox escalation for loopback socket binding; no external connection used. Original sandbox attempt failed before notebook execution; escalated final execution succeeded.
- PNG layout visually inspected. No real-data run, PCAP processing, SSH or data transfer performed. Large real-data time/disk usage remains unmeasured.
- Research semantics unchanged. Historical 18-count is a comparison record, never a hardcoded selection. Exact byte identity remains unverifiable for old CSVs without recorded checksums.
- Integration: keep the requested isolated local branch, uncommitted; no stage, commit, push, PR or merge performed (repository Git-history rule).
