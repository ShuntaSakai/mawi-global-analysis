# notebooks

実験結果の集計、検査、可視化を行う Jupyter Notebook を置くディレクトリです。pipeline
が出力した artifact を読み、研究上の集計や図の作成を明示します。

卒論フェーズのcanonical main comparison Notebookは
[02_main_prefix_comparison.ipynb](02_main_prefix_comparison.ipynb)です。過去の発表・実験履歴は
[archive/society-2026/](archive/society-2026/) に保存します。生成済み CSV、PCAP、pipeline 実装は
ここに置きません。

[05_one_packet_context.ipynb](05_one_packet_context.ipynb) は、Broad 除外後に残る
one-packet flow をfull-capture contextとともに記述的に確認する卒論向けfollow-up Notebookです。
完了済みのone-packet context runを必要とし、manifest/provenance-aware API経由でartifactを
読みます。実データの解釈は実装・fixture検証とは別に行います。

実行に必要な artifact と環境変数は [実データ実行 runbook](../docs/guide/real-data-execution-runbook.md)、
全体の入口は [ルート README](../README.md) を参照してください。
