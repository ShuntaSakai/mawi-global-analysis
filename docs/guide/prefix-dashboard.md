# MAWI Prefix Flow Length Dashboard

保存済みのflow-lengthキャッシュから、単体で開けるHTMLを生成します。
閲覧時はPython・インターネット・ローカルサーバを必要としません。
06ノートブック、解析処理、Scan判定、フロー定義は変更しません。

## 研究室PCで生成する

リポジトリのrootから実行してください。Python 3.12と既存依存だけを使用します。
生成対象は既存の `scan_source_driven_removal` 設定に一致する成功済みrunです。

```bash
uv sync --locked
PYTHONPATH=src uv run python scripts/export_prefix_dashboard.py \
  --root /home/s-sakai/mawi-global-analysis \
  --dataset 202604081400 \
  --run scan_source_driven_removal \
  --cache-dir /home/s-sakai/mawi-global-analysis/results/flow_length_exact_cache/202604081400/scan_source_driven_removal \
  --output /home/s-sakai/mawi-global-analysis/reports/prefix-dashboard-202604081400.html \
  --notes examples/prefix_notes.json
```

`--notes` は省略可能です。`--output` はまだ存在しない `.html` ファイルを指定します。
既存ファイル、入力成果物、キャッシュは上書きしません。キャッシュ内への出力も拒否します。

`--cache-dir` は06で指定した `MAWI_FLOW_LENGTH_EXACT_CACHE_DIR` と同じ**キャッシュ基底ディレクトリ**です。
その下のハッシュ名ディレクトリや `exact_counts.sqlite` 自体ではありません。
`load_cached_run()` を通じてmanifestと成果物の識別情報・キャッシュのハッシュを照合します。
元CSVの存在・ヘッダー等も検査するので、キャッシュだけをMacへコピーして生成する用途には使えません。
manifestに記録された元成果物の参照が有効な研究室PCで生成してください。

このコマンドはPCAP解析・フロー生成・Scan再判定・再集計を行いません。
キャッシュがない、入力が更新された、キャッシュが壊れた、表の整合性が崩れた場合は理由を表示して停止します。
自動的にキャッシュを作成・修復する動作はありません。必要な場合は別途06ノートブックの手順で
既存CSVからキャッシュを準備してから、生成コマンドを再実行してください。
高速な入力照合は既存APIと同じpath/size/mtime方式であり、意図的にmetadataを維持した内容置換を証明するものではありません。

## Macへコピーして開く

生成されたHTMLだけをコピーします。転送元・ホスト名は実際の環境に合わせてください。
Macのターミナルでの例：

```bash
scp user@lab-pc:/home/s-sakai/mawi-global-analysis/reports/prefix-dashboard-202604081400.html ~/Downloads/
open ~/Downloads/prefix-dashboard-202604081400.html
```

Finderからダブルクリックしても開けます。画像・データ・CSS・JavaScriptはすべて埋め込み済みです。
JavaScriptを有効にした現在のSafari・Chromeなどで利用してください。閲覧操作はファイルへ保存されません。
HTMLには分布・統計値・メモが含まれるため、共有対象に合った内容で生成してください。

## 画面の使い方

- 一覧のRaw / removed / retained切替で、すべてのカードの小図・統計値が切り替わります。
- 小図は共通ビン・symlog軸ですが、縦軸上限はカードごとに自動調整します。棒の高さだけで件数を比較せず、表示された数値も参照してください。
- プレフィックス名またはメモで検索し、現在の群のフロー数・中央値・除外率で並べ替えできます。未定義値は末尾に表示します。
- ホバーまたはキーボードフォーカスで要約、クリックで詳細を固定表示します。検索や並べ替えで選択中の詳細は変わりません。
- `selected_union` と `overall_ipv4` は参照用集計として別枠に表示します。unionは保存済みの重複排除結果を使用し、個別値の合計から再構築しません。
- 詳細はRaw・removed・retainedの3群を常に表示します。左はsymlog(linthresh=1)の度数、右は各群の全フロー数を分母とする0〜100%の割合です。「グラフを拡大」で読みやすく表示できます。
- removedはBroad Scan-likeの除外対象、retainedは除外後に残ったフローです。除外率はremoved / Rawです。
- 0件群の率・分位点は「—」。Raw = removed + retainedを対象全体と各ビンで検査します。
- 共通ビンは既存 `bin_edges` を使います。幅の異なる区間を等間隔に並べたカテゴリであり、確率密度ではありません。

## 考察メモ

[サンプル](../../examples/prefix_notes.json)をコピーして編集します。
キーは `notes → dataset_id → run_name → prefix` です。他のdatasetやrunのメモは混ざりません。
選択scope内の値は文字列のみで、使える項目は次の3つです。

```json
{
  "schema_version": 1,
  "notes": {
    "202604081400": {
      "scan_source_driven_removal": {
        "157.53.116.16/28": {
          "observation": "実際に確認した観測事実を記入",
          "interpretation": "その事実に基づく仮説を記入",
          "next_check": "仮説を確認する追加調査を記入"
        }
      }
    }
  }
}
```

上記は書式の例であり、実データについての結論ではありません。
メモ省略・対象の記載なし・空文字は「未記入」と表示します。不正なJSONや文字列以外の値は診断して停止します。
メモはHTMLやMarkdownとして実行せず、文字列として安全に表示します。自動的な攻撃・正常判定は行いません。

## 合成データで動作確認する

以下は明示的に合成runとキャッシュを新しい一時フォルダへ作成する準備コードです。
**HTML生成処理自身は、この準備や再集計を実行しません。** 実MAWIデータの再現・検証にはなりません。

```bash
PYTHONPATH=src uv run python - <<'PY'
from pathlib import Path
import tempfile
from mawi_global_analysis.flow_length import make_demo_run, analyze_run
from mawi_global_analysis.prefix_dashboard import export_dashboard
root = Path(tempfile.mkdtemp(prefix='mawi-dashboard-demo-'))
dataset, run = make_demo_run(root)
cache = root / 'cache'
analyze_run(root, dataset, run, exact_cache_dir=cache)
output = export_dashboard(root, dataset, run, cache, root / 'dashboard.html',
                          notes=Path('examples/prefix_notes.json'))
print(output)
PY
```

合成runではヘッダーと比較図に `SYNTHETIC DEMO` と表示します。
保存済みrunのHTMLにも「実データの再検証は未実施」と表示します。

## 検証・制約

```bash
PYTHONPATH=src uv run pytest -q tests/test_prefix_dashboard.py
PYTHONPATH=src uv run pytest -q
```

新規テストは合成キャッシュによる生成・入力不変性、対象全体/各ビンの整合性、35プレフィックス、
空群、全対象の比較図、メモscopeとエスケープ、キャッシュ欠落・破損・変更、CLIと上書き拒否を確認します。
ブラウザ操作・ネットワーク遮断下の検証結果はPRの検証記録を参照してください。

全選定対象を扱いますが、画像数とHTMLサイズ・生成時間は対象数に比例します。
Matplotlib図は静止画像です。棒ごとの数値ホバー・ビン変更・再分類は行いません。
30件規模の閲覧を目的とし、非常に多数の対象に対する性能保証はありません。

## ブラウザでメモを編集・保存する（Phase 1）

詳細の「観測事実」「考察・仮説」「追加調査事項」を直接編集できます。参照用集計も
同様に編集でき、プレフィックス切替・検索・並べ替え・群切替でも入力は保持されます。
編集すると「未保存の変更あり」を表示し、離脱時はブラウザが対応する範囲で警告します。
再読み込みや終了を越える自動保存はありません。

「メモをJSONに保存」で全対象を `prefix_notes_<dataset_id>.json` にダウンロードします。
保存済み表示はダウンロード開始を意味します。実際の保存完了はブラウザで確認してください。
既存HTMLは変更されません。同名ファイルの扱いはブラウザの保存設定に従います。
復元は「JSONからメモを読み込む」でファイルを選び、内容が異なる場合に上書きを確認します。
検証失敗・キャンセル時は現在の編集内容を保持します。

ブラウザ保存形式は以下です。上のCLI `--notes` 用の階層形式とは異なり、相互にそのまま
読み込むことはできません。全プレフィックスと参照用集計について3項目が必要です。

```json
{"schema_version":1,"dataset_id":"202604081400","run_name":"scan_source_driven_removal","notes":{"157.53.116.16/28":{"observation":"観測","interpretation":"仮説","next_check":"追加調査"}}}
```

この例は1対象のみの省略例です。実際には画面の保存ボタンで全対象を出力してください。
バージョン・dataset・run・対象名・項目・文字列型を検証します。上限はJSON全体5 MiB、
各項目10,000 UTF-16コード単位（絵文字などは2単位）で、保存・読み込みに共通です。
生成時の既存メモが上限を超える場合も、短くするまでブラウザ保存を拒否します。
メモはプレーンテキストで扱い、外部通信は行いません。メモ付きHTMLの新規保存は
Phase 2の対象であり、今回は対応していません。

ブラウザJavaScriptの動作テストにはNode.jsも必要です。
`PYTHONPATH=src uv run pytest -q tests/test_prefix_dashboard_notes.py` で、埋め込まれた
JavaScriptをDOM代替環境で実行します（実ブラウザでのダウンロード完了検証とは異なります）。
