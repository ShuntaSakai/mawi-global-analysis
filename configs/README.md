# configs

名前付き実験の YAML 設定を置くディレクトリです。flow、prefix、scan、Aguri、analysis
の実行条件を 1 ファイルにまとめます。

ここには実験設定のみを置き、PCAP、生成結果、Notebook 固有の表示設定は置きません。

主な設定は `baseline.yaml`、`paper_legacy.yaml`、`threshold_exploration.yaml`、
`scan_source_driven_removal.yaml` です。

実行方法と実データの注意点は [実データ実行 runbook](../docs/real-data-execution-runbook.md)、
全体の入口は [ルート README](../README.md) を参照してください。
