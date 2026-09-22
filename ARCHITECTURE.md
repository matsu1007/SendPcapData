# send_pcap.py 内部構造

`send_pcap.py` の実装を理解するための技術ドキュメントです。使い方は [README.md](README.md) を参照してください。

## 全体像

`main()` の末尾で、指定されたモードに応じて3つの経路のいずれかに分岐します（優先順位は `--tcp-raw-session` > `--tcp-session` > 基本モード）。

```
--tcp-raw-session が指定されている → replay_raw_tcp_session()  （生パケットでTCPヘッダごとファジングを再現）
--tcp-session が指定されている     → replay_tcp_session() / replay_tcp_session_until_disconnect()  （通常socketでペイロードのファジングを再現）
どちらも指定なし                    → 基本モードのループ（generate_rewrite_packet + send_packet）
```

3モードは実装難易度・必要権限が異なります。

| モード | 通信方式 | 管理者権限/Npcap | 用途 |
| --- | --- | --- | --- |
| 基本モード | 生パケット（`sendp`/`send`） | 必要 | 単純な再送信、宛先変更、非TCPやプロトコル非依存のリプレイ |
| `--tcp-session` | 通常の`socket` | 不要 | TCPペイロード（アプリ層データ）のファジング再現 |
| `--tcp-raw-session` | 生パケット＋自前ハンドシェイク | 必要 | TCPヘッダ自体（フラグ/window/urgent pointer/予約ビット/seq・ack）のファジング再現 |

## 共通ユーティリティ

### `packet_matches_src(pkt, src_ip, src_mac, src_port=None)`

送信元フィルタ。`--src-ip` / `--src-mac` / `--src-port` の条件にすべて合致するかを判定する。Device A（フィルタリング元の送信元）の送信だけを抜き出すために、3モード共通で使われる。

### `wait_between_payloads(delay, interval, realtime)`

`--realtime`（pcap記録時の間隔を再現）と `--interval`（固定間隔）の共通処理。`--tcp-session` と `--tcp-raw-session` の両方から呼ばれる。

## 基本モード

### `rewrite_packet(pkt, dst_ip, dst_port, dst_mac, keep_checksum)`

`--dst-ip` / `--dst-port` / `--dst-mac` で指定された宛先フィールドを書き換える。

設計上のポイント: **書き換えで実際に値が変わった層（`dirty_layers`）だけ**チェックサムを削除して scapy に再計算させる。宛先を一切書き換えない場合は何も削除しないため、元のpcapに記録された（意図的に不正な場合もある）チェックサムがそのまま維持される。これは「Device Aが送信したおかしなデータをそのまま再現したい」という要件のための設計で、以前は無条件にチェックサムを削除していたバグがあった（宛先を書き換えなくても正常なチェックサムに"修復"されてしまっていた）。

`--keep-checksum` を指定すると、宛先を書き換えてもチェックサムの再計算自体を行わない。

長さフィールド（IPのtotal lengthなど）は触らない。宛先の書き換えはパケット長を変えないため再計算が不要であり、元のpcapが意図的に不正な長さを記録していてもそのまま維持される。

### `send_packet(pkt, iface)`

Ethernetヘッダの有無で `sendp`（L2送信）と `send`（L3送信）を切り替える。

### 実行ループ（`main()` 末尾）

`--loop` 回、`PcapReader` でpcap全体を毎回読み直し、`packet_matches_src` → `rewrite_packet` → `send_packet`（または `--dry-run` なら `pkt.show()`）という単純なパイプライン。

## `--tcp-session`（ペイロードのファジング再現）

### `extract_tcp_payloads(pcap_path, src_ip, src_mac, src_port)`

pcapを1回走査し、Device AのTCPペイロード（`bytes(pkt[TCP].payload)`）が空でないパケットだけを `(直前の対象パケットからの経過秒, ペイロード)` のリストとして抜き出す。SYN/ACK/FINのみの制御パケット（ペイロードが空）は自動的に除外される。

これは「TCPの生パケットをそのまま再送すると、宛先のOSがseq/ack不整合でRSTを返す」問題への対処。ハンドシェイクとseq/ack管理をOSの`socket`に委譲し、アプリ層に渡るバイト列だけを忠実に再現する設計。

### `replay_tcp_session(payloads, dst_ip, dst_port, interval, realtime, dry_run, timeout)`

`socket.create_connection()` で実際にTCP接続を確立し、`payloads` を順番に `sendall()` で送る。`--loop` はこの関数を複数回呼ぶことで実現しており、毎回新しい接続を張り直す。

### `replay_tcp_session_until_disconnect(payloads, dst_ip, dst_port, interval, realtime, timeout)`

同じ接続を張ったまま `payloads` を無限にループ送信し続ける。`sendall()` が `OSError` を送出した時点（TCP送信バッファの都合で実際の切断より遅れて検知されることがある）で「対象がクラッシュ/再起動した」とみなし、何周目・何件目で切断されたかを報告する。

## `--tcp-raw-session`（TCPヘッダのファジング再現）

3モードの中で最も複雑。**自前でTCPクライアントのハンドシェイク処理を実装**している。通常の`socket`ではTCPフラグ・window・urgent pointer・予約ビットを直接操作できず、かつ対象デバイスは異常パケットを「実際に確立されたセッションのseq/ackに整合していないと受理しない」という制約のため、この方式が必要になった。

### 抽出フェーズ: `extract_raw_tcp_stream(pcap_path, src_ip, src_mac, src_port)`

pcapを1回走査しながら、状態を進める小さな状態機械になっている。

1. **`local_isn` 未確定の間**: Device AからのSYN（SYN=1, ACK=0）を探す。見つかったら `local_isn`（元のISN）・`local_port`・`remote_port`・`remote_ip` を記録。
2. **`remote_isn` 未確定の間**: 手順1で特定した相手からのSYN-ACK（SYN=1, ACK=1）を探し、`remote_isn` を記録。
3. **それ以降**: パケットをDevice A由来／Device B由来に振り分ける。
   - Device B由来（応答）: 直前に追加された `followups` の要素の `"responses"` リストに追加する。
   - Device A由来: ハンドシェイクを完了させるだけの素のACK（`flags == ACK_FLAG` かつペイロード空、最初の1回だけ）は除外し、それ以外は `followups` に `{"delay":..., "pkt":..., "responses": []}` として追加する。

戻り値の `followups` は、後段の送信フェーズでそのままオフセット付きで再送される「異常ヘッダを持つパケット列」であり、各要素の `"responses"` は元のpcapでの対象機の反応（あれば）。

### `find_crash_point(followups)`

`followups` の中で最後に `"responses"` が非空だった要素のインデックス（1始まり）を返す。これを `total_followups` と比較することで、「元のpcapでは何回目の送信まで応答があったか＝クラッシュ推定地点」を求める。`--dry-run` 時に参考情報として表示される。

### `ArpResponder`（コンテキストマネージャ）

`--spoof-ip` で名乗る送信元IPアドレス宛のARP who-has要求に、実際のMACアドレス（`get_if_hwaddr(iface)`）で応答し続けるバックグラウンドスレッド。

背景: 送信元IPを自分（Windows機）の実IPにすると、対象からのSYN-ACKを見てWindows自身のTCP/IPスタックが「身に覚えのない接続」と判断し、自動的にRSTを送り返してセッションを壊してしまう。これを避けるため、このマシンに割り当てられていないIP（`--spoof-ip`）を名乗る。その代償として、対象機は偽装IPのMACアドレスをARPで問い合わせてくるため、`ArpResponder` が自動応答する。

`__enter__` でスレッドを起動して0.5秒待機（対象機からのARP要求に間に合わせるため）、`__exit__` で `threading.Event` をセットしてスレッドを停止させる（`sniff` の `stop_filter` で検知）。

### `probe_target_alive(dst_ip, dst_port, timeout)`

生パケットの送信（`send`/`sendp`）は fire-and-forget で失敗が返ってこないため、`--until-disconnect` でのクラッシュ検知には使えない。そのため、生セッションとは**別の、独立した通常`socket`接続**を試みることで対象への疎通を確認する。

### `send_raw_followups_round(...)`

`followups` を1周ぶん送信する。各要素の `seq`/`ack` に `offset_local`/`offset_remote`（後述）を加算した新しい値を使い、フラグ・window・urgent pointer・予約ビット・オプションは元のまま `IP()/TCP()` を新規構築して送信する。戻り値は送信件数（`--until-disconnect` の累計カウントに使う）。

### 送信フェーズ: `replay_raw_tcp_session(...)`

1. `extract_raw_tcp_stream` で元セッション情報を復元し、`find_crash_point` の結果を表示する。
2. `--dry-run` ならここで打ち切り、各 followup とその元の応答を表示して終了する。
3. `ArpResponder` を起動した状態で、自前のSYN（ランダムな `new_local_isn`）を `sr1()` で送信し、SYN-ACKを受信する。
4. SYN-ACKから得た `new_remote_isn` を使ってACKを送信し、ハンドシェイクを完了させる。
5. **オフセット計算**: `offset_local = new_local_isn - stream["local_isn"]`、`offset_remote = new_remote_isn - stream["remote_isn"]`（いずれも `mod 2**32`）。元のpcapのseq/ack値にこのオフセットを足すことで、新しいセッションのISNを基準にした値へ読み替える。
6. `until_disconnect` が偽なら `send_raw_followups_round` を1回呼んで終了。真なら、周回ごとに `probe_target_alive` で生存確認しながら無限ループし、疎通が取れなくなった時点で停止・報告する。

## 主要な設計判断のまとめ

- **チェックサムは触った層だけ再計算**（基本モード）: 意図的な異常データを誤って「修復」しないため。
- **`--tcp-session` は通常`socket`、`--tcp-raw-session` は自前ハンドシェイク**: ファジング対象がペイロードかヘッダかで、必要な制御レベルが異なるため使い分けている。
- **IPアドレス偽装 + ARP自動応答**: Windowsファイアウォールの設定変更なしに、自前TCPセッションに対するOSの妨害（自動RST）を回避するため。
- **クラッシュ検知はモードごとに異なる方式**: `--tcp-session` は `sendall()` の例外、`--tcp-raw-session` は独立した `socket` 接続によるポーリング。生パケット送信には失敗通知が無いため、後者では能動的な生存確認が必須。
