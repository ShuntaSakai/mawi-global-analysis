# MAWI Global Analysis

MAWI のパケットキャプチャを対象に、フロー、プレフィックス、および
scan-like な観測パターンを再現可能に分析するためのリポジトリです。過去の
論文再現用の実験と、現在の corrected analysis を分けて扱います。

## 処理の流れ

```text
MAWI raw data
  -> 再利用可能な flow / Aguri cache
  -> 実験ごとの結果と provenance
  -> Notebook による集計・可視化
```

共有可能な PCAP 由来の観測結果は `data/` に、実験固有のラベル・プレフィックス
選択・manifest は `results/` に保存します。研究上の意味論や証拠の区別は、実装から
推測せず関連ドキュメントと設定を確認してください。

## セットアップ

Python 環境は `uv` で同期します。Aguri stage を実行する場合は、vendored Agurim の
実行ファイルも必要です。

```bash
git clone --recurse-submodules <repository-url> mawi-global-analysis
cd mawi-global-analysis
uv sync
make -C vendor/agurim/src
```

実データの事前確認、実行順序、ストレージ要件の注意点は
[実データ実行 runbook](docs/guide/real-data-execution-runbook.md) を参照してください。

## ディレクトリ案内

| ディレクトリ | 役割 |
| --- | --- |
| [configs/](configs/README.md) | 名前付き実験の YAML 設定。 |
| [data/](data/) | raw capture と再利用可能な処理済み cache。通常は Git 管理外。 |
| [datasets/](datasets/README.md) | batch 実行で使うデータセット一覧。 |
| [docs/](docs/) | 運用・設計・AI 向けドキュメント。 |
| [notebooks/](notebooks/README.md) | 結果の集計、検査、可視化。 |
| [results/](results/README.md) | 実験固有の artifact、manifest、batch 出力。 |
| [scripts/](scripts/README.md) | 検証・運用向けの補助スクリプト。 |
| [src/](src/README.md) | 解析パイプラインの Python パッケージ。 |
| [tests/](tests/README.md) | unit、integration、fixture、golden validation。 |
| [vendor/](vendor/README.md) | リポジトリに同梱する外部ソース。 |

## 実験と解析

利用する実験条件は [configs/](configs/README.md) から選びます。実行済みの結果は
[results/](results/README.md) の run manifest とともに確認し、Notebook で集計・可視化
します。実行コマンドと raw data の扱いは、先に
[実データ実行 runbook](docs/guide/real-data-execution-runbook.md) を確認してください。

AI エージェント向けの参照順と研究契約は [docs/agent/](docs/agent/README.md) にあります。
