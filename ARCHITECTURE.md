# send_pcap 内部構造

`send_pcap.py` とその周辺モジュールの実装を理解するための技術ドキュメントです。使い方は [README.md](README.md) を参照してください。

## ファイル構成

モードごとにファイルを分割している（フラットなモジュール構成で、パッケージ化はしていない）。`python send_pcap.py ...` という起動方法はこの分割の影響を受けない。

| ファイル | 役割 |
| --- | --- |
| `send_pcap.py` | エントリポイント。argparseの定義・バリデーション・各モードへの振り分け（`main()`）のみを持つ |
| `pcap_filters.py` | 3モード共通のフィルタ・待機処理 |
| `basic_mode.py` | 基本モードの実装 |
| `tcp_session_mode.py` | `--tcp-session` の実装 |
| `tcp_raw_session_mode.py` | `--tcp-raw-session` の実装（自前TCPハンドシェイク・ARP応答など） |

## 全体像

`send_pcap.py` の `main()` の末尾で、指定されたモードに応じて3つの経路のいずれかに分岐する（優先順位は `--tcp-raw-session` > `--tcp-session` > 基本モード）。

```
--tcp-raw-session が指定されている → tcp_raw_session_mode.replay_raw_tcp_session()  （生パケットでTCPヘッダごとファジングを再現）
--tcp-session が指定されている     → tcp_session_mode.replay_tcp_session() / replay_tcp_session_until_disconnect()  （通常socketでペイロードのファジングを再現）
どちらも指定なし                    → basic_mode.run_basic_mode()
```

3モードは実装難易度・必要権限が異なる。

| モード | 通信方式 | 管理者権限/Npcap | 用途 |
| --- | --- | --- | --- |
| 基本モード | 生パケット（`sendp`/`send`） | 必要 | 単純な再送信、宛先変更、非TCPやプロトコル非依存のリプレイ |
| `--tcp-session` | 通常の`socket` | 不要 | TCPペイロード（アプリ層データ）のファジング再現 |
| `--tcp-raw-session` | 生パケット＋自前ハンドシェイク | 必要 | TCPヘッダ自体（フラグ/window/urgent pointer/予約ビット/seq・ack）のファジング再現 |

## 共通ユーティリティ（`pcap_filters.py`）

### `packet_matches_src(pkt, src_ip, src_mac, src_port=None)`

送信元フィルタ。`--src-ip` / `--src-mac` / `--src-port` の条件にすべて合致するかを判定する。Device A（フィルタリング元の送信元）の送信だけを抜き出すために、3モード共通で使われる。

### `wait_between_payloads(delay, interval, realtime)`

`--realtime`（pcap記録時の間隔を再現）と `--interval`（固定間隔）の共通処理。`--tcp-session` と `--tcp-raw-session` の両方から呼ばれる。

## 基本モード（`basic_mode.py`）

### `rewrite_packet(pkt, dst_ip, dst_port, dst_mac, keep_checksum)`

`--dst-ip` / `--dst-port` / `--dst-mac` で指定された宛先フィールドを書き換える。

設計上のポイント: **書き換えで実際に値が変わった層（`dirty_layers`）だけ**チェックサムを削除して scapy に再計算させる。宛先を一切書き換えない場合は何も削除しないため、元のpcapに記録された（意図的に不正な場合もある）チェックサムがそのまま維持される。これは「Device Aが送信したおかしなデータをそのまま再現したい」という要件のための設計で、以前は無条件にチェックサムを削除していたバグがあった（宛先を書き換えなくても正常なチェックサムに"修復"されてしまっていた）。

`--keep-checksum` を指定すると、宛先を書き換えてもチェックサムの再計算自体を行わない。

長さフィールド（IPのtotal lengthなど）は触らない。宛先の書き換えはパケット長を変えないため再計算が不要であり、元のpcapが意図的に不正な長さを記録していてもそのまま維持される。

### `send_packet(pkt, iface)`

Ethernetヘッダの有無で `sendp`（L2送信）と `send`（L3送信）を切り替える。

### `run_basic_mode(...)`

`--loop` 回、`PcapReader` でpcap全体を毎回読み直し、`packet_matches_src` → `rewrite_packet` → `send_packet`（または `--dry-run` なら `pkt.show()`）という単純なパイプライン。`send_pcap.py` の `main()` から呼ばれる。

## `--tcp-session`（ペイロードのファジング再現、`tcp_session_mode.py`）

### `extract_tcp_payloads(pcap_path, src_ip, src_mac, src_port)`

pcapを1回走査し、Device AのTCPペイロード（`bytes(pkt[TCP].payload)`）が空でないパケットだけを `(直前の対象パケットからの経過秒, ペイロード)` のリストとして抜き出す。SYN/ACK/FINのみの制御パケット（ペイロードが空）は自動的に除外される。

これは「TCPの生パケットをそのまま再送すると、宛先のOSがseq/ack不整合でRSTを返す」問題への対処。ハンドシェイクとseq/ack管理をOSの`socket`に委譲し、アプリ層に渡るバイト列だけを忠実に再現する設計。

### `replay_tcp_session(payloads, dst_ip, dst_port, interval, realtime, dry_run, timeout)`

`socket.create_connection()` で実際にTCP接続を確立し、`payloads` を順番に `sendall()` で送る。`--loop` はこの関数を複数回呼ぶことで実現しており、毎回新しい接続を張り直す。

### `replay_tcp_session_until_disconnect(payloads, dst_ip, dst_port, interval, realtime, timeout)`

同じ接続を張ったまま `payloads` を無限にループ送信し続ける。`sendall()` が `OSError` を送出した時点（TCP送信バッファの都合で実際の切断より遅れて検知されることがある）で「対象がクラッシュ/再起動した」とみなし、何周目・何件目で切断されたかを報告する。

## `--tcp-raw-session`（TCPヘッダのファジング再現、`tcp_raw_session_mode.py`）

3モードの中で最も複雑。**自前でTCPクライアントのハンドシェイク処理を実装**している。通常の`socket`ではTCPフラグ・window・urgent pointer・予約ビットを直接操作できず、かつ対象デバイスは異常パケットを「実際に確立されたセッションのseq/ackに整合していないと受理しない」という制約のため、この方式が必要になった。

元のファジングテストは、テストケースごとに送信元ポートを変えて新しいTCP接続を張り直す作りであることが多い。そのため、pcapからは単一のストリームではなく**Device Aが張ったすべてのストリームを出現順に抽出**し、後段で1つずつ同じ手順（自前ハンドシェイク→フォローアップ送信）で再現する。

### 抽出フェーズ: `extract_raw_tcp_streams(pcap_path, src_ip, src_mac)`

pcapを1回走査しながら、複数ストリームを並行して追跡する状態機械になっている。`active_by_key` は `(local_port, remote_port)` をキーに「現在追跡中のストリーム」を指す辞書。

1. Device AからのSYN（SYN=1, ACK=0）が来るたびに、**新しいストリーム**を1つ作って `streams` に追加し、`active_by_key[key]` をそれに差し替える。同じポートが後から再利用されていても、新しいSYNが来た時点で古いストリームへの参照は `active_by_key` から外れ、以降のパケットは新しい方に紐付く。
2. 応答（`reply_key = (dport, sport)` で該当ストリームを検索）は、ストリームの `remote_isn` が未確定ならSYN-ACKとして、確定済みなら直前の `followups` 要素への `"responses"` として記録する。
3. Device A由来でストリームに属するそれ以降のパケットは、ハンドシェイクを完了させるだけの素のACK（最初の1回だけ）を除いて `followups` に `{"delay":..., "pkt":..., "responses": []}` として追加する。

各ストリームの `remote_isn` が `None` のままなら、そのストリームは元のpcapでSYN-ACKが一度も返ってこなかった（＝対象が応答しなかった）ことを意味し、クラッシュ地点の推定に使う。

### `find_crash_point(followups)` / `find_crash_stream_index(streams)`

- `find_crash_point` は1つのストリーム内で、最後に応答があった followup のインデックス（1始まり）を返す（`--dry-run` の各ストリーム表示で使用）。
- `find_crash_stream_index` はストリームのリスト全体から、最後に何らかの応答（SYN-ACKまたはフォローアップへの応答）があったストリームのインデックス（0始まり）を返す。`print_crash_summary` がこれを使い、「元のpcapでは何件目の接続まで応答があったか」を表示する。

### `followups_signature(followups)` / `format_port_list(ports)`

ファジングテストは同じ内容のパケットをポートだけ変えて繰り返し送ることが多いため、`--dry-run` は全接続の内容が同一かどうかを判定し、同一なら代表1件だけを表示して冗長な繰り返し表示を避ける。

- `followups_signature` は followups から `(flags, window, urgptr, reserved, payload)` のタプル列を作る。seq/ack（接続ごとのISNに依存して必然的に変わる）と delay（実測タイミングのゆらぎ）は比較対象から除外する。`replay_raw_tcp_sessions` はこの署名が全ストリームで一致するかを見て、表示を「代表1件+ポート一覧」にするか「接続ごとの詳細」にするかを切り替える。
- `format_port_list` はポート番号のリストを表示用に整形する。10件以下ならすべて、それより多ければ先頭5件・末尾5件と省略件数を表示する。

### `ArpResponder`（コンテキストマネージャ）

`--spoof-ip` で名乗る送信元IPアドレス宛のARP who-has要求に、実際のMACアドレス（`get_if_hwaddr(iface)`）で応答し続けるバックグラウンドスレッド。**全ストリームの再現中、1インスタンスだけ起動したまま使い回す**（ストリームごとに起動し直さない）。

背景: 送信元IPを自分（Windows機）の実IPにすると、対象からのSYN-ACKを見てWindows自身のTCP/IPスタックが「身に覚えのない接続」と判断し、自動的にRSTを送り返してセッションを壊してしまう。これを避けるため、このマシンに割り当てられていないIP（`--spoof-ip`）を名乗る。その代償として、対象機は偽装IPのMACアドレスをARPで問い合わせてくるため、`ArpResponder` が自動応答する。

`__enter__` でスレッドを起動して0.5秒待機（対象機からのARP要求に間に合わせるため）、`__exit__` で `threading.Event` をセットしてスレッドを停止させる（`sniff` の `stop_filter` で検知）。

### `probe_target_alive(dst_ip, dst_port, timeout)`

生パケットの送信（`send`/`sendp`）は fire-and-forget で失敗が返ってこないため、`--until-disconnect` でのクラッシュ検知には使えない。そのため、生セッションとは**別の、独立した通常`socket`接続**を試みることで対象への疎通を確認する。

### `establish_stream_session(...)`

1ストリームぶんの自前ハンドシェイク（SYN送信→`sr1()`でSYN-ACK受信→ACK送信）を行い、`(offset_local, offset_remote)` を返す。`offset_local = new_local_isn - stream["local_isn"]`、`offset_remote = new_remote_isn - stream["remote_isn"]`（いずれも `mod 2**32`）。元のpcapのseq/ack値にこのオフセットを足すことで、新しいセッションのISNを基準にした値へ読み替える。SYN-ACKが返らなければ `None` を返す。

### `send_raw_followups_round(...)`

1ストリームの `followups` を1周ぶん送信する。各要素の `seq`/`ack` に上記のオフセットを加算した新しい値を使い、フラグ・window・urgent pointer・予約ビット・オプションは元のまま `IP()/TCP()` を新規構築して送信する。戻り値は送信件数。

### 並行実行: `replay_stream_worker(...)` / `replay_streams_concurrently(...)`

元のファジングテストは、前の接続が閉じきる前に次の接続を開始する（同時に複数の接続がオープンになっている）ことがある。1ストリームずつ順番に処理する実装ではこの「重なり」を再現できないため、各ストリームを**別スレッドで並行に実行**する。

- `replay_stream_worker` は1ストリームぶんの `establish_stream_session` → `send_raw_followups_round` をまとめた、スレッドの実行単位。
- `replay_streams_concurrently` は `streams` の各要素に対して `threading.Thread` を1つずつ起動する。各スレッドの開始タイミングは:
  - `realtime` 指定時: 最初のストリームの `syn_time` からの相対時間（`float(stream["syn_time"] - base_syn_time)`）だけ待ってから開始 — 元のpcapでのSYN同士の間隔を可能な限り正確に再現する。`pkt.time` はscapyの `EDecimal` 型なので `float()` で明示的に変換する必要がある（変換を忘れると `time.sleep()` が `TypeError` になる）。
  - `interval` 指定時（`realtime` なし）: `i` 番目のストリームは `(i-1) * interval` 秒後に開始（前のストリームの終了を待たない）。
  - どちらも指定が無ければ: 全ストリームをほぼ同時に開始する。
  - 全スレッドの `join()` を待ってから関数が返る。

### 送信フェーズ: `replay_raw_tcp_sessions(...)`

1. `extract_raw_tcp_streams` で全ストリームを復元し、`--src-port` が指定されていればそのポートのストリーム1件に絞り込む。`print_crash_summary` でクラッシュ推定地点を表示する。
2. `followups` が空のストリーム（SYNのみで応答が無い等）は再現対象から除外する（`replayable` リスト）。
3. `--dry-run` ならここで打ち切り、ストリームごとに再現対象パケットとその元の応答を表示して終了する（全接続の内容が同一なら `followups_signature` で検出し簡素化表示にする）。
4. `ArpResponder` を1つ起動した状態で、`replay_streams_concurrently` を呼び `replayable` を1周ぶん（並行に）送信する。
5. `until_disconnect` が真なら、1周送り終えるたびに `probe_target_alive` で生存確認し、失敗した時点で「何周目で停止したか」を報告して終了する。並行実行のため生存確認は「1ストリームごと」ではなく「1周（全ストリーム）ごと」に行う（`--tcp-session` 版と同じ粒度）。

## 主要な設計判断のまとめ

- **チェックサムは触った層だけ再計算**（基本モード）: 意図的な異常データを誤って「修復」しないため。
- **`--tcp-session` は通常`socket`、`--tcp-raw-session` は自前ハンドシェイク**: ファジング対象がペイロードかヘッダかで、必要な制御レベルが異なるため使い分けている。
- **IPアドレス偽装 + ARP自動応答**: Windowsファイアウォールの設定変更なしに、自前TCPセッションに対するOSの妨害（自動RST）を回避するため。
- **クラッシュ検知はモードごとに異なる方式**: `--tcp-session` は `sendall()` の例外、`--tcp-raw-session` は独立した `socket` 接続によるポーリング。生パケット送信には失敗通知が無いため、後者では能動的な生存確認が必須。
- **`--tcp-raw-session` の複数接続はスレッドで並行実行**: 元のファジングテストが接続を閉じきる前に次の接続を開始することがあり、1件ずつ順番に処理するだけでは「同時に複数接続がオープンな状態」を再現できないため。
