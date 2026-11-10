# Aguri 選定Prefixの個別CDF

[Aguri Selection Comparison v2](aguri-selection-comparison.md#推奨フロー4条件のv2) の出力先にある
`prefix_dashboard.html` をブラウザで開く。HTMLは単体でオフライン閲覧できる。
同梱の `dashboard.html` は、Overall と A／B／C-packet／C-flow の native union を比較する画面。

## 一覧と詳細

- A、B、C-packet、C-flow の各タブには、その条件で選定された native CIDR だけが並ぶ。
- CIDR 検索、Flow count・Median・P95・1パケット率・Prefix による並べ替え、昇順／降順、ページ切替を使える。
- カードをクリック、またはフォーカスして Enter／Space を押すと詳細が開く。詳細を閉じるボタンや Escape で一覧へ戻る。
- 詳細グラフはボタン・ドラッグ・ホイールで拡大できる。ホバーで最も近い保存点の整数度数・累積件数を確認でき、SVGも保存できる。

## CDFの読み方

横軸は1フロー当たりの `packet_count`（対数）、縦軸は累積フロー割合。カードの軸範囲は共通。
各CIDRの範囲をそのまま使い、src または dst が一致するフローを `flow_id` ごとに1回数える。
C-packet と C-flow の違いは選定時の重みで、CDFの横軸とフローの数え方は共通。
縮約時の階段は下界、帯は上界を示す。正確な整数頻度は `modes/<条件>/frequencies.csv` にある。

`prefix_ecdf.json` は表示点と条件別の選定情報を持つ。複数条件で選定された同じCIDRは曲線を共有する。
`comparison_manifest.json` が両HTML、個別CDFデータ、完全度数、保存済みrunの来歴を結び付ける。
HTMLのコピーを単体で閲覧できる。度数や来歴も調べる場合はバンドル一式を保管する。
