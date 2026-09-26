# vendor

リポジトリとともに管理する外部ソースを置くディレクトリです。

現在は Aguri 処理に使う `agurim/` を含みます。外部ツールの build artifact、実験結果、
独自の解析コードはここに置きません。Agurim は必要な場合に `vendor/agurim/src` で build
します。

セットアップと実行時の注意点は [実データ実行 runbook](../docs/real-data-execution-runbook.md)、
全体の入口は [ルート README](../README.md) を参照してください。
