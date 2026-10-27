# プレフィックス内のRaw送信観測IP挙動（v1）

## 範囲と証拠

正式計画は [計画書](../plan/prefix-ip-behavior.md)。Phase Aは保存済みrunの
CSVのみを集計し、Phase Bは検証済み集約を既存の信頼HTMLまたはexact-cacheから
出力するHTMLへ追加する。PCAP読込・Scan再判定はしない。
`flows-v3`、現行run config、run/cache manifestの識別情報が一致する必要がある。
標準対象は `202604081400 / scan_source_driven_removal` の選定native 18件。
`--expected-prefix-count` の標準値は18。合成フィクスチャ以外で理由なく変更しない。

この変更の検証は合成データの実装検証であり、研究室PC上の実データ検証ではない。
既存host数とフロー長cacheの定義IDは変更しない。受信のみのIP、特に後続調査の
216アドレスをRaw送信IP母集団に追加しない。

## CSV schema: prefix-ip-behavior-v1

`prefix_ip_behavior.csv` は `dataset_id,run_name,prefix,ip,group` をキーとし、
Rawで送信パケットが1以上のIPについてRaw/removed/retainedを必ず3行出力する。
IPはIPv4、prefixはnative、groupはこの3値のみ。ゼロフローprefixは行なしで
manifest/validationに残る。非送信groupもゼロ行を保持するが、受信だけ残るgroupは
受信量とフロー数を保持する。

| 列 | 定義（対象IPに接続したフローの群別集計） |
| --- | --- |
| flow_count | 対象IPを端点に持つdistinctフロー数。IPの送信0のフローも含む |
| sent_packets / received_packets | IP側 / 相手側のpackets_from_src/dstを割当てた総和 |
| sent_frame_bytes / received_frame_bytes | 同じ方向のbytes_from_src/dst総和。Ethernet-frame bytes |
| tcp_flow_count / udp_flow_count | プロトコル6 / 17のflow_count |
| tcp_sent_packets / udp_sent_packets | プロトコル別sent_packets |
| tcp_received_packets / udp_received_packets | プロトコル別received_packets |
| plain_syn_sent_count_observed_post_init | 最初のplain SYN（それ自身を含む）以降のsyn_from_initiator/responderをIP側へ割当てた総和 |
| synack_sent_count_observed_post_init | 同条件でsynack_from_initiator/responderを割当てた総和 |
| rst_sent_count_observed_post_init | 同条件でrst_from_initiator/responderを割当てた総和 |
| tcp_syn_attempt_flows | initial_syn_sender_ipが当該IPのフロー数 |
| tcp_syn_receiver_flows | initial_syn_receiver_ipが当該IPのフロー数 |
| tcp_synack_response_flows / tcp_rst_response_flows | 当該IPのSYN受信側端点からのpost-init SYN-ACK / RSTを1以上観測したフロー数 |
| tcp_payload_observed_flows | フロー全体でtransport_payload_observed=trueのTCPフロー数。対象IPの送信ペイロードとは限らない |
| unique_peer_ips / unique_tcp_peer_ips / unique_udp_peer_ips | 全体 / TCP / UDPで対象IPと通信する相手IP集合の濃度 |

全metricは非負整数で、出力/HTMLはJavaScriptの安全整数上限 `2**53-1` を超えたら
停止する。観測フラグの0は「定義された観測カウンターが0」で、全キャプチャ中の
フラグ不存在を意味しない。SYN未観測時は役割unknown、post-initカウンター0。
全ACK・FIN・PSH、複合フラグ分布は提供しない。

同一IPが両端の場合: flow_count・プロトコルフロー数・各フロー根拠は1回、
送受信量と方向別フラグカウンターは両端分を加算。sent_packetsとreceived_packetsは
それぞれフロー全パケット数となる。peerは自分自身を1件とする。SYN送信側・受信側は
両方1になり得る。役割の割当てにはIPに加えポートを使用し、IPだけで判定しない。
同一IP・同一portの両端はflow.pyの端点tuple一致規則に従いsrc/initiatorへ割当てる。

`prefix_ip_ports.csv` は上記5キーに
`protocol,port_side,observed_role,port` を追加したキーで一意。
protocolはTCP/UDP、portは0..65535。
`port_side=local` は対象端点のポート、`peer` は相手端点のポート。
`observed_role` はTCPで `syn_sender|syn_receiver|unknown`、UDPでは
`first_packet_sender|first_packet_receiver`（最初の観測方向）。UDPの役割は開始側、
client/serverの断定ではない。`flow_count` は同じキーに寄与するdistinctフロー数、
`sent_packets` はそのキーの対象端点が送ったパケット数。
同一IPの両端が同じキーに寄与すればフローは1回、パケットは合算する。
異なるローカルポート/観測役割なら複数キーとなるため、port行のフロー数総和は
IPのflow_countより大きくなり得る（最大2倍）。localとpeerは別の見方なので
両側を合算してはいけない。各protocol/sideの送信パケット合計はIPの対応する
protocol送信パケット数と一致する。

加算列（flow_countからtcp_payload_observed_flowsまで）はRaw=removed+retained。
peer数・送信IP数等のdistinct濃度は集合和であり単純加算しない。
IP別flow_countを合算してprefix全フロー数と比較してはいけない。

## 検証と再現性

入力は標準csvでストリーミングし、一時SQLiteにID、membership、対象IP端点、
port寄与を保存する。flows CSVの構文解析は1走査。その後のRaw cohort確定と
集計はSQLiteを読む。RAMはSQLiteの32 MiB page cacheと小さいprefix/IP表示集合。
SQLite一時sortもディスクを使う。全peerや全portをPython集合へ格納しない。

全flow ID/labelの一対一対応、全native/normalized membershipの正確性と完全性、
重複、整数/boolean、IPv4/IPv6、方向別パケット・frame byte整合、SYN端点を検証する。
重複membershipは黙って二重集計/正規化せずエラーとする（計画書内の正規化記述に
対する実装上の選択）。native以外のmembershipは検証するがIP集計には含めない。
既存summarize_host_countsを同じディスク索引へ適用し、全prefix/3群のsender数と照合。
prefixフロー数は独立した元flow端点の所属走査とも照合し、HTML取込み時には保存済み
flow_length/HTMLのprefix別3群フロー数とも照合する。

入力CSVのSHA-256を初回に別の連続読込で取得し、run manifestに記録されたhashが
ある場合は照合する。古いrunにCSV hashがない場合、今回の入力スナップショットの
識別情報として記録する。歴史的な生成時点とのbyte一致を新たに証明したとは言わない。
処理後に入力size/mtimeとrun manifest SHAを再照合する。出力manifestはschema、
入力hash/サイズ/行数、run SHA、Python情報、集計ソースとconfigのSHA、出力hash/行数、validation hashを記録。
validationは群別sender数、prefixフロー数、入力行数、不正0件と各検証項目を記録する。

CSVとvalidation/manifestは同じファイルシステム上のstagingで作成し、検証とfsync後に
新しいディレクトリへrenameする。HTMLも一時ファイルにflush/fsync後、同一ファイルシステムのhard-linkで完全な内容をatomic配置する。既存出力は拒否。失敗時は所有する一時領域のみ
自動削除し、元CSVは変更しない。中断からの再開機構はなく再実行する。
HTMLは全CSVのhash・キー・3群・加算列・distinct濃度の集合上下限・host数・prefix数を
検証し、port全キーはディスク上で加算と総量を検証する。peer集合の要素そのものは
CSVに含まれないため、取込み時に厳密なpeer集合を再構成することはできない。
元集計はSQL DISTINCTの集合和を使用し、取込み時は集合濃度の整合性を検証する。

## 研究室PCでの実行

リポジトリ直下で既存環境を利用する。`/path/to/...` の2箇所は実在する
保存先と十分な空き容量のあるscratchへ置換する。

```sh
PYTHONPATH=src uv run --no-sync python scripts/aggregate_prefix_ip_behavior.py \
  --root "$PWD" \
  --dataset 202604081400 \
  --run scan_source_driven_removal \
  --scratch-dir /path/to/large-local-scratch \
  --output-dir "$PWD/results/202604081400/scan_source_driven_removal/ip_behavior"

PYTHONPATH=src uv run --no-sync python scripts/enrich_prefix_ip_behavior.py \
  --input /path/to/prefix-dashboard-202604081400-hosts-v2.html \
  --behavior-csv "$PWD/results/202604081400/scan_source_driven_removal/ip_behavior/prefix_ip_behavior.csv" \
  --ports-csv "$PWD/results/202604081400/scan_source_driven_removal/ip_behavior/prefix_ip_ports.csv" \
  --manifest "$PWD/results/202604081400/scan_source_driven_removal/ip_behavior/ip_behavior_manifest.json" \
  --output "$PWD/reports/prefix-dashboard-202604081400-ip-behavior.html"
```

集計の想定出力は10万行ごとの進捗と `Validated bundle: .../ip_behavior`。
新規directoryには2 CSV、manifest、validationの4ファイルができ、
validation.statusはpassed、選定prefix数は18、CSV行数は実測Raw sender総数×3。
93件などの固定値は仮定しない。HTML追加は `HTML: ...html` を表示する。
既存HTMLにhost_summaryまたはrun manifest SHAがなければ停止する。
既存host-summary追加経路を先に利用し、推測データで補わない。
exact-cacheからの新規生成には既存exportコマンドに
`--ip-behavior-bundle results/202604081400/scan_source_driven_removal/ip_behavior` を付ける。

scratchの事前目安は入力4 CSVサイズ総和×6 + 64 MiB。実測最大値の保証ではない。
全flow ID、port多様性、SQLite index/sortに比例して増え、大規模runは長時間かかる。
scratchと出力先の両方に余裕を確保する。入力hash計算でもCSV全体の追加I/Oがある。
進捗の停止直後でもSQLiteの集計やindex作成中の場合がある。
HTML取込みのport検証にも一時ディスクを使うため必要ならTMPDIRを同じ大容量領域へ設定。

HTMLは各IP/群/protocol/local・peerごとに送信パケット数、フロー数、port、roleで
決定的に順位づけたTop10を保存する。全件はCSVに保持し、表示キー数・省略キー数・
全件送信packet合計・端点フロー合計を併記する。参照2集計はIP個別データ未集計。
全18件の選択、3群、検索/ソート、ゼロ群、メモJSON往復・メモ付きHTML再保存、
サムネイル、外部通信なし/CSPを実データHTMLでも人間が最終確認する。

## テスト仕様と残作業

`PYTHONPATH=src uv run --no-sync pytest -q` で全体を検証する。
新規unitケースは手計算の方向割当、canonical dstのSYN送信、/24・/28・/32、
ゼロprefix、同一IP両端、両端同一prefix、SYN-ACK/RST/payload、unknown、
UDP、巨大ID、peer重複と非加算、入力順の決定性、不正値・重複/欠損membership/label、
hash不一致、容量不足、既存出力保護、破損bundle、キャッシュからのattachを含む。
既存Node実行テストはIP選択・検索・ゼロ群・未集計参照、メモと全payloadの
HTML往復/CSP維持を同じオフラインDOMで検証する。

残作業: 研究室PCで18prefixの実データ集計を実行し、runtime/scratch peak、manifest、
validation、host counts、保存HTMLを確認する。実データの成功はこのMacの合成テスト
成功から推定しない。216アドレスの受信コホート分析は今回の範囲外。
