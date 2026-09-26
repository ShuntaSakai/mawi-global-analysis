# tests

パイプラインの振る舞いと artifact 契約を検証するテストを置くディレクトリです。

`unit/` には小さな機能単位のテスト、`integration/` には stage や pipeline をまたぐ
テスト、`fixtures/` には小さな PCAP・設定・legacy golden などの検証用入力を置きます。
実データ、長期保存する run 結果、研究用 Notebook はここに置きません。

テストは implementation verification であり、実データ検証や科学的結論とは区別します。
全体の入口は [ルート README](../README.md) を参照してください。
