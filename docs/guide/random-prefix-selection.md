# 既存Flow・Packet選定を除いたRandom /24対照群

## 研究上の定義

Uは保存済みcanonical **IPv4 TCP/UDP**フローのsrc・dstのいずれかに
出現したIPv4 /24の重複なし集合。FはFlow基準で選定済みのnative18件、
PはPacket基準で選定済みのnative15件。
E = {parent24(x) | x ∈ F ∪ P} とし、Randomは **U − E** から18件を抽出する。
/25〜/32が選定されている場合も包含する/24全体を除く。
未選定Aguri候補は除かない。最低flow/packet/byte閾値は設けない。

この条件付き対照群は、通信量重視の既存選定が拾わなかったPrefixの記述的比較に使う。
全IPv4空間・全IPv4プロトコル出現Prefixの代表標本、優れた選定方式とは扱わない。
Flow18・Packet15・Random18の件数差を維持し、Packetへ追加しない。
既存nativeは/24〜/32、Randomは/24固定なので、粒度による交絡がある。
既存のnormalized /24分析を補助比較に使えるが、既存ダッシュボードへの
Random自動追加はこの機能の対象外。同一フローの他端点が別群に所属する場合があり、
Prefix除外はフロー集合の独立性を保証しない。

同じ観測点・期間・PCAP、src OR dst所属、scan除外なしで比較する。
canonical候補はTCP/UDPのみだが、連携先のプロトコル構成比は非TCP/UDPを含むIPv4を集計する。
canonicalのbyte_countはcaptured Ethernet frame長の合計でframe_byte_countと等しい。
連携先のoriginal_frame_bytesはPCAPのorig_lenを使うため、snaplen切詰め時には異なる。
Randomのobserved_byte_countはcanonical定義を維持する。プロトコル比較の3群には
連携先の同一byte定義を適用し、両カウンタの同値性を仮定しない。

## 固定アルゴリズム

ID `mawi-random24-sha256-v1`、version 1。
入力byte列はASCII ID、NUL 1byte、seedのunsigned 64-bit big-endian 8byte、
/24ネットワークアドレスのnetwork byte order 4byteをこの順で連結する。
SHA-256 digestのbyte列昇順、衝突時はネットワークアドレスの数値昇順で順位を決め、
先頭count件を非復元抽出。既定count=18、seed=20260408。
seedは整数0〜2**64−1。結果を見てseedを探索する機能はない。
暗号学的ハッシュによる疑似乱数順位であり、有限seed空間での厳密一様性の証明は主張しない。

集合hashはASCII `mawi-random24-set-v1` + NUL + 数値昇順packed address列のSHA-256。
選定hashはASCII `mawi-random24-selection-v1` + NUL + 順位順packed address列のSHA-256。
候補の行順・CSVチャンクサイズを変えても抽出集合と順位は同じ。
入力CSVのbyte hashは行順で変わる。membership保存順は元フロー順、scope順(native,
normalized_24)、抽出順位順で、チャンク分割には依存しない。

## 厳密な入力検証

成功した `aguri-two-stage-run-v1` のFlow・Packet runのみを受け付ける。
Flow18件・Packet15件、全行の選定フラグ、重複、native CIDR、台帳のcandidate由来の
完全一致、source schema・方式・両段threshold1/heuristics0・Raw設定を検証する。
同じcanonical CSVパス・byte hash・flow_manifest hash・fingerprint・capture hash、
build・wire/converter・共通設定を要求する。--flowsはmanifest記録先との一致が必要。
単に同じ内容を別パスにコピーして指定する方法は受け付けない。
既存専用validatorでcanonical binary全record、wire、build/source/binary hashも読む。
Aguriを実行・buildしない。欠損・旧identity不一致はエラー終了し、黙って緩和しない。
全フローのIDと逆向きを同一視した5-tuple重複もディスク上で検査する。

入力PCAP自体は開かない。input.sha256は検証した既存manifest間で結合した来歴であり、
PCAP実体をその場で再hashした証拠ではない。manifestにはpcap_bytes_verified=falseを記録。
観測点・期間はdataset文字列だけで認定しない。canonical生成はファイル全体、連携先は
2026-04-08 14:00〜14:15 JSTの900秒窓を使うので、実機で元PCAPの対象範囲を確認する。
連携先はファイルbytesまたは展開後PCAP bytesのSHA-256をselection manifestと照合する。

## 成果物と検証

新runはresults/<dataset>/<run>/に作る。既存ディレクトリ(空でも)・ファイル・symlinkは
拒否。既存run/cache/dataや連携先を更新しない。PCAP・canonicalフローを再生成しない。

- prefixes.csv: 選定行のみ。prefix, prefix_length, normalized_prefix_24,
  selected_for_analysis, analysis_scope(native), selection_rank,
  observed_flow_count, observed_packet_count, observed_byte_count。
- flow_prefix_membership.csv: flow_id, analysis_scope, analysis_prefix,
  src_match, dst_match。nativeとnormalized_24を保存。両端同じPrefixでもscopeごとに1行。
- selection_population.csv: 観測済み/24全候補の数値昇順台帳。除外・eligible・選定状態・順位。
- excluded_prefixes.csv: Flow18行＋Packet15行のnative→親/24対応。
  33行でも除外集合は重複排除され、33件とは限らない。
- selection_config.yaml: アルゴリズム・定義・比較制約。manifest内にも本文とhashを保存。
- run_manifest.json: schema=random-prefix-selection-run-v1、status=success、入力来歴、
  元集合数、E件数、実際に除いたU∩E件数、eligible件数、集合/結果hash、全出力パス/件数/hash、
  実装hash/Git commit、入力同一性検証を保持。configのrow_count=1は設定文書1件を意味する。

すべてを一時領域で作り、同じ入力から再構成した成果物と一致することを確認してから
公開する。成功manifestは最後に公開する。例外時は自分が公開したファイルを取り除く。
強制終了・電源断で未完成ディレクトリが残る可能性はあるが、成功manifestなしでは成功と
扱わず、自動上書きしない。作成後のverifyも元入力から再構成する。
保存済み絶対パス・同一実装・元cache/buildが必要で、移動可能な独立配布bundleではない。

候補・ID/tuple検証はSQLite、CSVはチャンク処理。全flows.csvをRAMに展開しない。
membershipは既存builderをチャンク単位で使い、18 Prefixでは行数は最大4×入力フロー数。
生成と再検証でcanonicalを複数回読む。元validatorもbinary/wire/hashを逐次照合する。
生成・再構成の一時SQLiteとmembershipが併存するので十分な空きdiskが必要。
実MAWI規模の実行時間・最大RSS・disk使用量は未測定。初回は実機で記録する。

## 研究室PCでの手順

以下は実行手順であり、この環境で実MAWIの18件を抽出した結果ではない。
研究室PCに本変更を反映し、既存のlocked環境を利用できる状態で実行する。
rootは依頼の研究室PC配置を使用。canonicalパスはaudit-inputsが既存manifestから解決する。
実runの18/15件・hash・設定に不一致があれば、以下のコマンドは停止する。

まずBashで次を実行する。既存run名と重なる場合、勝手に上書きせず停止する。

```bash
bash <<'SH'
set -euo pipefail
cd /home/s-sakai/mawi-global-analysis
AUDIT_FILE="$(mktemp)"
trap 'rm -f "$AUDIT_FILE"' EXIT
uv run --locked python -m mawi_global_analysis.random_prefix_selection audit-inputs \
  --root /home/s-sakai/mawi-global-analysis --dataset 202604081400 \
  --flow-run canonical-2stage-flow-t1-h0 \
  --packet-run canonical-2stage-packet-t1-h0 --json > "$AUDIT_FILE"
cat "$AUDIT_FILE"
FLOW_CSV="$(uv run --locked python -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["source"]["path"])' "$AUDIT_FILE")"
uv run --locked python -m mawi_global_analysis.random_prefix_selection run \
  --root /home/s-sakai/mawi-global-analysis --dataset 202604081400 \
  --flows "$FLOW_CSV" \
  --flow-run canonical-2stage-flow-t1-h0 \
  --packet-run canonical-2stage-packet-t1-h0 \
  --count 18 --seed 20260408 --chunksize 100000 \
  --run random24-exclude-flow-packet-s20260408 --json
uv run --locked python -m mawi_global_analysis.random_prefix_selection verify \
  /home/s-sakai/mawi-global-analysis/results/202604081400/random24-exclude-flow-packet-s20260408/run_manifest.json --json
SH
```

次に実PCAPの絶対パスを入力する。未確認のPCAPパスはここで作り込まない。
別名のPCAPでもselection manifestのhashと一致しなければ連携先が拒否する。

```bash
bash <<'SH'
set -euo pipefail
cd /home/s-sakai/mawi-protocol-analysis
read -r -p '対象PCAP(.pcap/.pcap.gz)の絶対パス: ' PCAP </dev/tty
[[ "$PCAP" = /* && -f "$PCAP" ]]
RANDOM_RUN=/home/s-sakai/mawi-global-analysis/results/202604081400/random24-exclude-flow-packet-s20260408
uv run --locked mawi-protocol-analysis "$PCAP" \
  --prefixes "$RANDOM_RUN/prefixes.csv" \
  --selection-manifest "$RANDOM_RUN/run_manifest.json" \
  --expected-prefix-count 18 --output-root results/random24-s20260408
SH
```

同じPCAPでFlow群は--expected-prefix-count 18、Packet群は15を指定する。
--prefixesと--selection-manifestをそれぞれ元runの成果物に置き換え、出力rootを分ける。
下流出力には202604081400/prefix_protocol_distribution/が追加される。

## 検証の境界

合成canonical・合成PCAP・実際にcompileした既存2段階コードからFlow18/Packet15を作り、
Random18と実際の連携先loader/CLIを検証する。これは実装検証でありMAWI実データ検証ではない。
研究室PCの実CIDR一覧・実パス・実18件の抽出は未実施。接続先未提供のため捏造しない。
