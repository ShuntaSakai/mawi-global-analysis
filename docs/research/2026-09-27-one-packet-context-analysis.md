# 1 packet flow context analysis（Phase 1）

## 目的と対象

2026-04-08 のMAWI DITL 24時間トレースから14:00–14:15 JSTを切り出し、
既存の `scan_source_driven_removal` 解析で Broad Scan-like 除外後にも残る
1 packet flow を、後続段階で同じDITL capture内の通信contextと照合する。
15分captureを用いるのは、対象flowと既存pipelineの観測を同じDITL匿名IP空間に
保つためである。daily trace `202604081400` とDITLの匿名IPを直接対応づけない。

既存pipelineはこの15分subcaptureに再利用する。scan設定のsource of truthは
`configs/scan_source_driven_removal.yaml` であり、strict閾値は pattern count 3、
unique targets 2（60秒window、10秒step、broad有効）である。pipelineが出力するのは
観測事実であり、正常通信または攻撃を自動断定しない。

## Phase境界

Phase 1は、timezone-awareな `[start, end)` を指定してPCAP/PCAP.gz/PCAPNGを
streamingでstandard PCAP subcaptureへ抽出し、checksumを含む
`window_manifest.json` を記録するだけである。24時間全体はcanonical flow化しない。

後続Phaseで、15分subcaptureを既存 `run_pipeline.py --input` に渡して1 packet flowを
抽出し、対象flowに関係するpacketだけを24時間DITLからstreaming探索する。cohort/context
CSV、reverse context、same-5tuple scanner、長期統計、MAC/TTL/fragmentation解析、
notebookはPhase 1の対象外である。
