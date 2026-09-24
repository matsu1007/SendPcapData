"""--tcp-raw-session: TCPヘッダ自体（フラグの異常な組み合わせ、window/urgent pointer/
予約ビットの異常値、不正なseq/ack等）のファジングを再現する。

対象デバイスは異常パケットを実際に確立されたセッションのseq/ackに整合していないと
受理しないため、自前でTCPハンドシェイクを生パケットで組み立てて実セッションを確立し、
新しいセッションのISNとの差分（オフセット）を使って元のseq/ackを読み替えて送信する。

元のファジングテストは、テストケースごとに送信元ポートを変えて新しいTCP接続を張り直す
作りになっていることが多い。そのためpcapからはDevice Aが張った接続（ストリーム）を
すべて出現順に抽出し、1つずつ同じ手順（自前ハンドシェイク→フォローアップ送信）で
再現する。
"""

import random
import socket
import threading
import time

from scapy.all import ARP, Ether, IP, PcapReader, TCP, get_if_hwaddr, send, sendp, sniff, sr1

from pcap_filters import packet_matches_src, wait_between_payloads

SYN_FLAG = 0x02
ACK_FLAG = 0x10
SYN_ACK_FLAGS = SYN_FLAG | ACK_FLAG


def extract_raw_tcp_streams(pcap_path, src_ip, src_mac):
    """pcapから、Device Aが張ったすべてのTCPストリームを出現順に抽出する。

    各ストリームは新しいSYN（送信元ポートが変わる）で始まる独立した接続として扱う。
    同じポートが後から再利用されていても、新しいSYNが来た時点で別のストリームとして
    扱われる（`active_by_key` を新しいストリームで上書きするため、それ以降のパケットは
    新しい方に紐付く）。

    各ストリームの構造:
      - local_isn / remote_isn: 元のハンドシェイクのISN（remote_isnは応答が無ければNone）
      - local_port / remote_port: 元のポート番号
      - syn_time: SYNパケットのタイムスタンプ（ストリーム間の間隔計算に使う）
      - followups: ハンドシェイク後にDevice Aが送信したパケット列
          （各要素は {"delay":, "pkt":, "responses":[]}）
    """
    streams = []
    active_by_key = {}

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue
            tcp = pkt[TCP]
            ip = pkt[IP]
            flags = int(tcp.flags)

            # Device Aからの新しいSYN（SYN=1, ACK=0） → 新しいストリームの開始
            if packet_matches_src(pkt, src_ip, src_mac) and (flags & SYN_ACK_FLAGS) == SYN_FLAG:
                key = (tcp.sport, tcp.dport)
                stream = {
                    "local_isn": tcp.seq,
                    "local_port": tcp.sport,
                    "remote_port": tcp.dport,
                    "remote_ip": ip.dst,
                    "remote_isn": None,
                    "syn_time": pkt.time,
                    "handshake_ack_skipped": False,
                    "followups": [],
                    "prev_ts": pkt.time,
                }
                streams.append(stream)
                active_by_key[key] = stream
                continue

            # Device Bからの応答（SYN-ACK、またはハンドシェイク後の応答）
            reply_key = (tcp.dport, tcp.sport)
            stream = active_by_key.get(reply_key)
            if stream is not None and ip.src == stream["remote_ip"]:
                if stream["remote_isn"] is None:
                    if (flags & SYN_ACK_FLAGS) == SYN_ACK_FLAGS:
                        stream["remote_isn"] = tcp.seq
                    continue
                if stream["followups"]:
                    stream["followups"][-1]["responses"].append(pkt)
                continue

            # Device Aからの、既存ストリームに属するそれ以降のパケット
            key = (tcp.sport, tcp.dport)
            stream = active_by_key.get(key)
            if stream is None or stream["remote_isn"] is None:
                continue
            if not packet_matches_src(pkt, src_ip, src_mac):
                continue

            if not stream["handshake_ack_skipped"] and flags == ACK_FLAG and not bytes(tcp.payload):
                # 3-way handshakeを完了させるだけの素のACK。ファジングデータではなく、
                # こちら側でも自前のハンドシェイクで同等のACKを送るため対象から除く。
                stream["handshake_ack_skipped"] = True
                stream["prev_ts"] = pkt.time
                continue

            delay = float(pkt.time - stream["prev_ts"]) if stream["prev_ts"] is not None else 0.0
            stream["prev_ts"] = pkt.time
            stream["followups"].append({"delay": delay, "pkt": pkt, "responses": []})

    return streams


def describe_tcp_flags(tcp):
    return tcp.sprintf("%TCP.flags%")


def describe_response_packet(pkt):
    tcp = pkt[TCP]
    payload = bytes(tcp.payload)
    text = f"flags={describe_tcp_flags(tcp)} seq={tcp.seq} ack={tcp.ack} window={tcp.window}"
    if payload:
        text += f" payload={payload!r}"
    return text


def find_crash_point(followups):
    """followupsのうち、最後にDevice Bからの応答が観測できたパケットの位置（1始まり）を返す。
    一度も応答が無ければNoneを返す。
    """
    last_index_with_response = None
    for i, item in enumerate(followups, start=1):
        if item["responses"]:
            last_index_with_response = i
    return last_index_with_response


def stream_got_any_response(stream):
    """このストリームで、元のpcap中にDevice Bからの反応（SYN-ACKまたはフォローアップへの
    応答）が何かしら観測できたかどうかを返す。"""
    return stream["remote_isn"] is not None or any(item["responses"] for item in stream["followups"])


def find_crash_stream_index(streams):
    """streamsのうち、最後に何らかの応答が観測できたストリームのインデックス（0始まり）を返す。
    一度も応答が無ければNoneを返す。それ以降のストリームに応答が無ければ、その接続の後で
    対象機が応答を停止した（クラッシュ/再起動した）可能性が高いと判断できる。
    """
    last_index_with_response = None
    for i, stream in enumerate(streams):
        if stream_got_any_response(stream):
            last_index_with_response = i
    return last_index_with_response


def followups_signature(followups):
    """followups列の「内容」を比較するための署名を返す。フラグ/window/urgent pointer/
    予約ビット/ペイロードだけを見て、seq/ack（接続ごとのISNに依存し必然的に変わる）や
    delay（実測タイミングのゆらぎ）は無視する。同一ファジングデータをポートだけ変えて
    繰り返し送っているケースで、接続間の内容が同じかどうかを判定するために使う。
    """
    sig = []
    for item in followups:
        tcp = item["pkt"][TCP]
        sig.append((int(tcp.flags), tcp.window, tcp.urgptr, tcp.reserved, bytes(tcp.payload)))
    return tuple(sig)


def format_port_list(ports):
    if len(ports) <= 10:
        return ", ".join(str(p) for p in ports)
    head = ", ".join(str(p) for p in ports[:5])
    tail = ", ".join(str(p) for p in ports[-5:])
    return f"{head}, ...（他{len(ports) - 10}件）..., {tail}"


def print_crash_summary(streams):
    total = len(streams)
    crash_index = find_crash_stream_index(streams)
    if crash_index is None:
        print("元のpcapでは、対象機（Device B）からの応答は一度も確認できませんでした")
        return
    if crash_index == total - 1:
        print(f"元のpcapでは、最後（{total}件目、ポート{streams[-1]['local_port']}）の接続まで対象機からの応答が確認できました")
        return
    crash_stream = streams[crash_index]
    print(
        f"元のpcapでは、{crash_index + 1}件目（ポート{crash_stream['local_port']}）の接続までは対象機からの応答が確認できましたが、"
        f"{crash_index + 2}件目以降（残り{total - crash_index - 1}件）の接続では応答が確認できませんでした"
        "（この時点でクラッシュ/再起動した可能性があります）"
    )


class ArpResponder:
    """指定したspoof_ip宛のARP要求(who-has)に、自分の実MACアドレスで応答し続けるバックグラウンド処理。

    送信元IPを偽装したセッションでは、対象機がSYN-ACKの送り先(=偽装IP)のMACアドレスを
    ARPで問い合わせてくる。誰も答えないとSYN-ACKはL2レベルで送信されず、こちらに届かない。
    これに自動応答することで、Windowsファイアウォールの設定変更なしに生セッションを成立させる。
    """

    def __init__(self, iface, spoof_ip):
        self.iface = iface
        self.spoof_ip = spoof_ip
        self.my_mac = get_if_hwaddr(iface)
        self._stop_event = threading.Event()
        self._thread = None

    def _handle(self, pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 1 and pkt[ARP].pdst == self.spoof_ip:
            reply = Ether(dst=pkt[Ether].src) / ARP(
                op=2,
                hwsrc=self.my_mac,
                psrc=self.spoof_ip,
                hwdst=pkt[Ether].src,
                pdst=pkt[ARP].psrc,
            )
            sendp(reply, iface=self.iface, verbose=False)

    def _run(self):
        sniff(
            iface=self.iface,
            filter="arp",
            prn=self._handle,
            store=False,
            stop_filter=lambda p: self._stop_event.is_set(),
        )

    def __enter__(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        time.sleep(0.5)  # 対象機からのARP要求に間に合うよう、送信開始前に少し待つ
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop_event.set()


def probe_target_alive(dst_ip, dst_port, timeout):
    """生セッションとは別に、通常のsocket接続で対象への疎通を確認する（生存確認）。
    生パケットの送信はfire-and-forgetで失敗が返ってこないため、クラッシュ/再起動の検知には
    この独立した疎通確認を使う。
    """
    try:
        with socket.create_connection((dst_ip, dst_port), timeout=timeout):
            return True
    except OSError:
        return False


def send_raw_followups_round(stream, spoof_ip, dst_ip, dst_port, local_port, offset_local, offset_remote, interval, realtime, iface, verbose=True):
    for i, item in enumerate(stream["followups"], start=1):
        wait_between_payloads(item["delay"], interval, realtime)
        pkt = item["pkt"]
        tcp = pkt[TCP]
        new_seq = (tcp.seq + offset_local) % (2**32)
        new_ack = (tcp.ack + offset_remote) % (2**32)
        payload = bytes(tcp.payload)

        new_pkt = IP(src=spoof_ip, dst=dst_ip) / TCP(
            sport=local_port,
            dport=dst_port,
            seq=new_seq,
            ack=new_ack,
            flags=int(tcp.flags),
            window=tcp.window,
            urgptr=tcp.urgptr,
            reserved=tcp.reserved,
            options=tcp.options,
        )
        if payload:
            new_pkt = new_pkt / payload

        send(new_pkt, iface=iface, verbose=False)
        if verbose:
            print(f"    [{i}] flags={describe_tcp_flags(tcp)} seq={new_seq} ack={new_ack} 送信")
    return len(stream["followups"])


def establish_stream_session(stream, spoof_ip, dst_ip, dst_port, local_port, iface, timeout):
    """1つのストリームぶん、自前のSYN→SYN-ACK受信→ACKでハンドシェイクを行い、
    (offset_local, offset_remote) を返す。失敗時はNoneを返す。
    """
    new_local_isn = random.randint(0, 2**32 - 1)
    syn = IP(src=spoof_ip, dst=dst_ip) / TCP(sport=local_port, dport=dst_port, flags="S", seq=new_local_isn)
    synack = sr1(syn, iface=iface, timeout=timeout, verbose=False)
    if synack is None or not synack.haslayer(TCP) or (int(synack[TCP].flags) & SYN_ACK_FLAGS) != SYN_ACK_FLAGS:
        print(
            "    SYN-ACKを受信できませんでした。対象IP/ポートが正しいか、spoof_ipが対象と同じ"
            "サブネット上の未使用アドレスになっているかを確認してください。"
        )
        return None

    new_remote_isn = synack[TCP].seq
    ack = IP(src=spoof_ip, dst=dst_ip) / TCP(
        sport=local_port, dport=dst_port, flags="A", seq=new_local_isn + 1, ack=new_remote_isn + 1
    )
    send(ack, iface=iface, verbose=False)
    print(f"    ハンドシェイク完了: new_local_isn={new_local_isn} new_remote_isn={new_remote_isn}")

    offset_local = (new_local_isn - stream["local_isn"]) % (2**32)
    offset_remote = (new_remote_isn - stream["remote_isn"]) % (2**32)
    return offset_local, offset_remote


def replay_stream_worker(stream, spoof_ip, dst_ip, dst_port_override, local_port_override, interval, realtime, iface, timeout, label):
    """1ストリームぶんのハンドシェイク＋followups送信を行う。スレッドの実行単位。"""
    local_port = local_port_override or stream["local_port"]
    this_dst_port = dst_port_override or stream["remote_port"]
    print(f"[{label}] local_port={local_port} でハンドシェイクを開始します")

    offsets = establish_stream_session(stream, spoof_ip, dst_ip, this_dst_port, local_port, iface, timeout)
    if offsets is None:
        return False
    offset_local, offset_remote = offsets

    send_raw_followups_round(
        stream, spoof_ip, dst_ip, this_dst_port, local_port, offset_local, offset_remote, interval, realtime, iface
    )
    return True


def replay_streams_concurrently(streams, spoof_ip, dst_ip, dst_port_override, local_port_override, interval, realtime, iface, timeout, pass_num):
    """元のpcapで複数の接続が同時にオープンになっていた状態（次の接続が始まるまでに
    前の接続が閉じきっていない）を再現するため、streamsの各ストリームを別スレッドで
    並行に実行する。

    スレッドの開始タイミングは以下の通り:
      - realtime指定時: 元のpcapでの最初のSYNからの相対時間（"syn_time"の差）通りに開始する。
        これにより、元の接続同士の重なり方をできる限り正確に再現する。
      - interval指定時（realtimeなし）: 前の接続の開始からinterval秒後に次の接続を開始する
        （前の接続の終了を待たない）。
      - どちらも指定が無い場合: 全ストリームを即座に（ほぼ同時に）開始する。

    すべてのスレッドが完了するまでブロックする。
    """
    if not streams:
        return

    base_syn_time = streams[0]["syn_time"]
    start_wall = time.monotonic()
    threads = []

    for i, stream in enumerate(streams, start=1):
        if realtime:
            start_delay = float(stream["syn_time"] - base_syn_time)
        elif interval:
            start_delay = (i - 1) * interval
        else:
            start_delay = 0.0

        def launch(stream=stream, i=i, start_delay=start_delay):
            remaining = start_delay - (time.monotonic() - start_wall)
            if remaining > 0:
                time.sleep(remaining)
            replay_stream_worker(
                stream, spoof_ip, dst_ip, dst_port_override, local_port_override, interval, realtime, iface, timeout,
                label=f"{pass_num}周目 {i}/{len(streams)}",
            )

        t = threading.Thread(target=launch, daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()


def replay_raw_tcp_sessions(
    pcap_path,
    src_ip,
    src_mac,
    src_port,
    spoof_ip,
    dst_ip,
    dst_port,
    iface,
    local_port_override,
    interval,
    realtime,
    dry_run,
    timeout,
    until_disconnect,
):
    """TCPスタックそのものを狙うファジングの再現用。pcapからDevice Aが張った全ストリーム
    （テストケースごとにポートを変えた接続）を出現順に抽出し、1つずつ自前のTCPハンドシェイクで
    実セッションを確立して、異常ヘッダのパケットをseq/ack番号だけ新しいセッションに合わせて
    読み替えて送信する。フラグ/window/urgent pointer/予約ビット等は元のまま送信する。

    送信元IPは実際のWindows機のIPではなく spoof_ip（このマシンに割り当てられていない
    未使用IP）を名乗る。これにより、対象からのSYN-ACKはWindows自身のTCPスタックには
    「自分宛ではないパケット」として無視され、身に覚えのない接続に対する自動RSTを防げる
    （ファイアウォールの変更が不要になる）。ただし対象機がspoof_ipのMACアドレスをARPで
    問い合わせてくるため、ArpResponderで自動応答する。

    until_disconnect が真の場合、抽出した全ストリームを1件ずつ再現する処理を最初から
    繰り返し、各ストリームの送信後に別の通常socket接続で対象への疎通を確認する。疎通が
    取れなくなった時点で対象のクラッシュ/再起動と判断して停止する。
    """
    streams = extract_raw_tcp_streams(pcap_path, src_ip, src_mac)
    if not streams:
        print("pcap内にDevice AからのSYNパケットが見つかりませんでした（--src-ip/--src-macを確認してください）")
        return

    if src_port is not None:
        streams = [s for s in streams if s["local_port"] == src_port]
        if not streams:
            print(f"送信元ポート {src_port} に一致する接続が見つかりませんでした")
            return

    replayable = [s for s in streams if s["followups"]]
    print(
        f"pcap内に {len(streams)} 件のTCP接続が見つかりました"
        f"（うちハンドシェイク後にパケットがあり再現対象となるのは {len(replayable)} 件）"
    )
    print_crash_summary(streams)

    if not replayable:
        print("再現対象のパケットを持つ接続がありませんでした")
        return

    effective_dst_port = dst_port or replayable[0]["remote_port"]
    if dst_port is None:
        print(f"宛先ポートはpcap記録時と同じ {effective_dst_port} を使用します（--dst-portで変更可能）")

    if dry_run:
        print(f"[dry-run] 送信元IP {spoof_ip} を名乗り、各接続ごとに新しいSYNでハンドシェイクする想定です")

        signatures = {followups_signature(s["followups"]) for s in replayable}
        all_same_content = len(signatures) == 1 and len(replayable) > 1

        if all_same_content:
            template = replayable[0]
            ports = [s["local_port"] for s in replayable]
            print(
                f"全 {len(replayable)} 件の接続でファジング内容は同一です。代表として1件分の内容を表示します"
                "（実際の送信ではseq/ackが各接続のISNに合わせて自動調整されます）:"
            )
            for i, item in enumerate(template["followups"], start=1):
                tcp = item["pkt"][TCP]
                payload = bytes(tcp.payload)
                print(
                    f"    [{i}] flags={describe_tcp_flags(tcp)} window={tcp.window} "
                    f"urgptr={tcp.urgptr} reserved={tcp.reserved} payload={payload!r}"
                )
            print(f"使用される送信元ポート（{len(ports)}件）: {format_port_list(ports)}")
            return

        for stream_no, stream in enumerate(replayable, start=1):
            local_port = local_port_override or stream["local_port"]
            this_dst_port = dst_port or stream["remote_port"]
            print(
                f"=== 接続 {stream_no}/{len(replayable)}: local_port={local_port} -> "
                f"{dst_ip}:{this_dst_port}（元: local_isn={stream['local_isn']} remote_isn={stream['remote_isn']}） ==="
            )
            for i, item in enumerate(stream["followups"], start=1):
                pkt = item["pkt"]
                tcp = pkt[TCP]
                payload = bytes(tcp.payload)
                print(
                    f"    [{i}] flags={describe_tcp_flags(tcp)} orig_seq={tcp.seq} orig_ack={tcp.ack} "
                    f"window={tcp.window} urgptr={tcp.urgptr} reserved={tcp.reserved} payload={payload!r}"
                )
                if item["responses"]:
                    for resp in item["responses"]:
                        print(f"        -> Device Bの応答（元pcap記録時）: {describe_response_packet(resp)}")
                else:
                    print("        -> Device Bの応答（元pcap記録時）: なし")
        return

    print(f"送信元IP {spoof_ip} で、{len(replayable)} 件の接続を元のタイミング通りに（重複して）再現します")

    effective_dst_port_for_probe = dst_port or replayable[0]["remote_port"]

    with ArpResponder(iface, spoof_ip):
        pass_num = 0
        total_passes_sent = 0
        while True:
            pass_num += 1
            replay_streams_concurrently(
                replayable, spoof_ip, dst_ip, dst_port, local_port_override, interval, realtime, iface, timeout, pass_num
            )
            total_passes_sent += 1
            print(f"{pass_num}周目、全{len(replayable)}件の接続を送信完了。")

            if not until_disconnect:
                return

            print("生存確認します...")
            if not probe_target_alive(dst_ip, effective_dst_port_for_probe, timeout):
                print(
                    f"対象が応答しなくなりました（{pass_num}周目、全{len(replayable)}件の接続を送信した後）。"
                    "クラッシュ/再起動と判断し停止します。"
                )
                return
            print("生存確認OK。最初から繰り返します...")
