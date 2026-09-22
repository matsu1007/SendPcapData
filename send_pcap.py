#!/usr/bin/env python3
"""pcapファイルに記録されたパケットを、宛先を書き換えてネットワークに再送信するツール."""

import argparse
import random
import socket
import sys
import threading
import time

from scapy.all import ARP, Ether, IP, IPv6, PcapReader, TCP, UDP, get_if_hwaddr, get_if_list, send, sendp, sniff, sr1

SYN_FLAG = 0x02
ACK_FLAG = 0x10
SYN_ACK_FLAGS = SYN_FLAG | ACK_FLAG


def packet_matches_src(pkt, src_ip, src_mac, src_port=None):
    """送信元フィルタに合致するか判定する（Device Aからの送信だけを抜き出すため）."""
    if src_mac:
        if not pkt.haslayer(Ether) or pkt[Ether].src.lower() != src_mac.lower():
            return False

    if src_ip:
        if pkt.haslayer(IP) and pkt[IP].src == src_ip:
            pass
        elif pkt.haslayer(IPv6) and pkt[IPv6].src == src_ip:
            pass
        else:
            return False

    if src_port is not None:
        if not pkt.haslayer(TCP) or pkt[TCP].sport != src_port:
            return False

    return True


def rewrite_packet(pkt, dst_ip, dst_port, dst_mac, keep_checksum):
    dirty_layers = set()

    if dst_mac and pkt.haslayer(Ether):
        pkt[Ether].dst = dst_mac

    if dst_ip:
        if pkt.haslayer(IP):
            pkt[IP].dst = dst_ip
            dirty_layers.update(("IP", "TCP", "UDP"))
        elif pkt.haslayer(IPv6):
            pkt[IPv6].dst = dst_ip
            dirty_layers.update(("TCP", "UDP"))

    if dst_port is not None:
        if pkt.haslayer(TCP):
            pkt[TCP].dport = dst_port
            dirty_layers.add("TCP")
        elif pkt.haslayer(UDP):
            pkt[UDP].dport = dst_port
            dirty_layers.add("UDP")

    if keep_checksum:
        # 変更した項目に関わらず、チェックサムは元のpcapの値のまま送信する
        # （異常データをそのまま再現したい場合に使用）
        return pkt

    # 書き換えによって値が合わなくなった層だけチェックサムを再計算させる。
    # ペイロードサイズは変えていないので長さフィールドは触らない
    # （元のpcapが意図的に不正な長さを記録していてもそのまま維持される）。
    for layer_name in dirty_layers:
        if pkt.haslayer(layer_name):
            layer = pkt[layer_name]
            if hasattr(layer, "chksum"):
                del layer.chksum

    return pkt


def send_packet(pkt, iface):
    if pkt.haslayer(Ether):
        sendp(pkt, iface=iface, verbose=False)
    else:
        send(pkt, iface=iface, verbose=False)


def extract_tcp_payloads(pcap_path, src_ip, src_mac, src_port):
    """pcapからDevice Aが送信したTCPペイロード（ファジングデータ本体）だけを
    順番に抜き出す。制御パケット(SYN/ACK/FINのみ)は実接続側で自動処理されるため除外する。
    戻り値は (直前の対象パケットからの経過秒, ペイロードbytes) のリスト。
    """
    payloads = []
    prev_ts = None
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not packet_matches_src(pkt, src_ip, src_mac, src_port):
                continue
            if not pkt.haslayer(TCP):
                continue
            payload = bytes(pkt[TCP].payload)
            if not payload:
                continue
            delay = float(pkt.time - prev_ts) if prev_ts is not None else 0.0
            prev_ts = pkt.time
            payloads.append((delay, payload))
    return payloads


def wait_between_payloads(delay, interval, realtime):
    if realtime and delay > 0:
        time.sleep(delay)
    elif interval:
        time.sleep(interval)


def replay_tcp_session(payloads, dst_ip, dst_port, interval, realtime, dry_run, timeout):
    """TCPフージングの再現用。実際にTCP接続を確立し、Device Aが送信したペイロードだけを
    本物のコネクション上に順番に流す。

    生パケットをそのまま再送すると、宛先のOSがseq/ack番号の不整合からRSTを返したり
    黙って無視したりするため、ハンドシェイクとseq/ack管理はOSのTCPスタックに任せ、
    アプリケーション層に渡るバイト列（＝ファジングされた内容）だけを忠実に再現する。
    """
    sock = None
    if not dry_run:
        sock = socket.create_connection((dst_ip, dst_port), timeout=timeout)

    try:
        for i, (delay, payload) in enumerate(payloads, start=1):
            wait_between_payloads(delay, interval, realtime)
            if dry_run:
                print(f"[{i}] {len(payload)} bytes: {payload!r}")
            else:
                sock.sendall(payload)
    finally:
        if sock is not None:
            sock.close()


def replay_tcp_session_until_disconnect(payloads, dst_ip, dst_port, interval, realtime, timeout):
    """同じTCPコネクション上でpayloadsを繰り返し送り続け、接続が切断される
    （対象デバイスがクラッシュ/再起動する等）まで継続する。
    大量の繰り返し送信でデバイスが落ちる現象の再現を狙ったモード。
    """
    try:
        sock = socket.create_connection((dst_ip, dst_port), timeout=timeout)
    except OSError as exc:
        print(f"接続に失敗しました: {exc}")
        return

    round_num = 0
    total_sent = 0
    idx = 0
    try:
        while True:
            round_num += 1
            for idx, (delay, payload) in enumerate(payloads, start=1):
                wait_between_payloads(delay, interval, realtime)
                sock.sendall(payload)
                total_sent += 1
            print(f"{round_num}周目（{len(payloads)}件）送信完了。累計{total_sent}件。継続します...")
    except OSError as exc:
        print(f"切断を検知しました（{round_num}周目、{idx}/{len(payloads)}件目）: {exc}")
        print(f"合計 {total_sent} 件のペイロードを送信した時点で切断されました。")
    finally:
        sock.close()


def extract_raw_tcp_stream(pcap_path, src_ip, src_mac, src_port):
    """pcapから対象のTCPストリームを特定し、元のハンドシェイクのISN（初期seq番号）と、
    ハンドシェイク後にDevice Aが送信したパケット列（異常ヘッダを含む）を取り出す。
    あわせて、pcapに対象機（Device B）からの応答が含まれている場合は、各パケットの直後に
    観測された応答をそのパケットに紐付けて記録する（送信結果の確認・クラッシュ発生地点の
    推定に使う）。

    TCPスタック自体を狙うファジング（フラグの異常な組み合わせ、window/urgent pointer/
    予約ビットの異常値、不正なseq/ack等）は、実際に確立された接続のseq/ackに整合していないと
    対象デバイスに受理されない。そのため通常のsocketやパケットのそのままの再送では再現できず、
    新しく確立するセッションのISNとの差分（オフセット）を使って元のseq/ackを読み替える必要がある。
    """
    local_isn = None
    local_port = None
    remote_port = None
    remote_ip = None
    remote_isn = None
    handshake_ack_skipped = False
    followups = []
    prev_ts = None

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue
            tcp = pkt[TCP]
            ip = pkt[IP]
            flags = int(tcp.flags)

            if local_isn is None:
                # Device Aが送った最初のSYN（SYN=1, ACK=0）を探す
                if packet_matches_src(pkt, src_ip, src_mac, src_port) and (flags & SYN_ACK_FLAGS) == SYN_FLAG:
                    local_isn = tcp.seq
                    local_port = tcp.sport
                    remote_port = tcp.dport
                    remote_ip = ip.dst
                    prev_ts = pkt.time
                continue

            if remote_isn is None:
                # 相手からのSYN-ACK（SYN=1, ACK=1）を探す
                if ip.src == remote_ip and tcp.sport == remote_port and tcp.dport == local_port and (
                    flags & SYN_ACK_FLAGS
                ) == SYN_ACK_FLAGS:
                    remote_isn = tcp.seq
                continue

            is_from_device_a = packet_matches_src(pkt, src_ip, src_mac, src_port) and (
                tcp.sport == local_port and tcp.dport == remote_port
            )
            is_from_device_b = ip.src == remote_ip and tcp.sport == remote_port and tcp.dport == local_port

            if is_from_device_b:
                # Device Bからの応答。直前のDevice Aパケットに紐付けて記録する。
                if followups:
                    followups[-1]["responses"].append(pkt)
                continue

            if not is_from_device_a:
                continue

            if not handshake_ack_skipped and flags == ACK_FLAG and not bytes(tcp.payload):
                # 3-way handshakeを完了させるだけの素のACK。ファジングデータではなく、
                # こちら側でも自前のハンドシェイクで同等のACKを送るため対象から除く。
                handshake_ack_skipped = True
                prev_ts = pkt.time
                continue

            delay = float(pkt.time - prev_ts) if prev_ts is not None else 0.0
            prev_ts = pkt.time
            followups.append({"delay": delay, "pkt": pkt, "responses": []})

    return {
        "local_isn": local_isn,
        "remote_isn": remote_isn,
        "local_port": local_port,
        "remote_port": remote_port,
        "followups": followups,
    }


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
    一度も応答が無ければNoneを返す。それ以降のパケットに応答が無ければ、その時点で対象機が
    応答を停止した（クラッシュ/再起動した）可能性が高いと判断できる。
    """
    last_index_with_response = None
    for i, item in enumerate(followups, start=1):
        if item["responses"]:
            last_index_with_response = i
    return last_index_with_response


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
            print(f"[{i}] flags={describe_tcp_flags(tcp)} seq={new_seq} ack={new_ack} 送信")
    return len(stream["followups"])


def replay_raw_tcp_session(
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
    """TCPスタックそのものを狙うファジングの再現用。自前でTCPハンドシェイクを生パケットで
    組み立てて実セッションを確立し、Device Aが送った異常ヘッダのパケットをseq/ack番号だけ
    新しいセッションに合わせて読み替えつつ、フラグ/window/urgent pointer/予約ビット等は
    元のまま送信する。

    送信元IPは実際のWindows機のIPではなく spoof_ip（このマシンに割り当てられていない
    未使用IP）を名乗る。これにより、対象からのSYN-ACKはWindows自身のTCPスタックには
    「自分宛ではないパケット」として無視され、身に覚えのない接続に対する自動RSTを防げる
    （ファイアウォールの変更が不要になる）。ただし対象機がspoof_ipのMACアドレスをARPで
    問い合わせてくるため、ArpResponderで自動応答する。

    until_disconnect が真の場合、同じセッション（同じseq/ack）でfollowupsを繰り返し送信し、
    各周回の後に別の通常socket接続で対象への疎通を確認する。疎通が取れなくなった時点で
    対象のクラッシュ/再起動と判断して停止する（生パケット送信はfire-and-forgetで失敗が
    返ってこないため、独立した疎通確認でしか検知できない）。
    """
    stream = extract_raw_tcp_stream(pcap_path, src_ip, src_mac, src_port)
    if stream["local_isn"] is None:
        print("pcap内にDevice AからのSYNパケットが見つかりませんでした（--src-ip/--src-mac/--src-portを確認してください）")
        return
    if stream["remote_isn"] is None:
        print("SYNに対する相手側のSYN-ACKパケットが見つかりませんでした（ハンドシェイクが完了していないpcapの可能性があります）")
        return
    if not stream["followups"]:
        print("ハンドシェイク後にDevice Aが送信したパケットが見つかりませんでした")
        return

    local_port = local_port_override or stream["local_port"]
    dst_port = dst_port or stream["remote_port"]

    print(
        f"元のセッション: local_isn={stream['local_isn']} remote_isn={stream['remote_isn']} "
        f"local_port={stream['local_port']} remote_port={stream['remote_port']} "
        f"（{len(stream['followups'])}件のパケットを再現します）"
    )
    if dst_port == stream["remote_port"]:
        print(f"宛先ポートはpcap記録時と同じ {dst_port} を使用します（--dst-portで変更可能）")

    crash_point = find_crash_point(stream["followups"])
    total_followups = len(stream["followups"])
    if crash_point is None:
        print("元のpcapでは、対象機（Device B）からの応答は一度も確認できませんでした")
    elif crash_point == total_followups:
        print(f"元のpcapでは、最後（{total_followups}回目）の送信まで対象機からの応答が確認できました")
    else:
        print(
            f"元のpcapでは、{crash_point}回目の送信までは対象機からの応答が確認できましたが、"
            f"{crash_point + 1}回目以降（残り{total_followups - crash_point}件）は応答が確認できませんでした"
            "（この時点でクラッシュ/再起動した可能性があります）"
        )

    if dry_run:
        print(
            f"[dry-run] 送信元IP {spoof_ip} を名乗り、新しいローカルポート {local_port} で "
            f"{dst_ip}:{dst_port} へSYNを送りハンドシェイクする想定です"
        )
        for i, item in enumerate(stream["followups"], start=1):
            pkt = item["pkt"]
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)
            print(
                f"[{i}] flags={describe_tcp_flags(tcp)} orig_seq={tcp.seq} orig_ack={tcp.ack} "
                f"window={tcp.window} urgptr={tcp.urgptr} reserved={tcp.reserved} payload={payload!r}"
            )
            if item["responses"]:
                for resp in item["responses"]:
                    print(f"    -> Device Bの応答（元pcap記録時）: {describe_response_packet(resp)}")
            else:
                print("    -> Device Bの応答（元pcap記録時）: なし")
        return

    print(f"送信元IP {spoof_ip} / ローカルポート {local_port} でハンドシェイクを開始します")

    with ArpResponder(iface, spoof_ip):
        new_local_isn = random.randint(0, 2**32 - 1)
        syn = IP(src=spoof_ip, dst=dst_ip) / TCP(sport=local_port, dport=dst_port, flags="S", seq=new_local_isn)
        synack = sr1(syn, iface=iface, timeout=timeout, verbose=False)
        if synack is None or not synack.haslayer(TCP) or (int(synack[TCP].flags) & SYN_ACK_FLAGS) != SYN_ACK_FLAGS:
            print(
                "SYN-ACKを受信できませんでした。対象IP/ポートが正しいか、spoof_ipが対象と同じ"
                "サブネット上の未使用アドレスになっているかを確認してください。"
            )
            return

        new_remote_isn = synack[TCP].seq
        ack = IP(src=spoof_ip, dst=dst_ip) / TCP(
            sport=local_port, dport=dst_port, flags="A", seq=new_local_isn + 1, ack=new_remote_isn + 1
        )
        send(ack, iface=iface, verbose=False)
        print(f"ハンドシェイク完了: new_local_isn={new_local_isn} new_remote_isn={new_remote_isn}")

        offset_local = (new_local_isn - stream["local_isn"]) % (2**32)
        offset_remote = (new_remote_isn - stream["remote_isn"]) % (2**32)

        if not until_disconnect:
            send_raw_followups_round(
                stream, spoof_ip, dst_ip, dst_port, local_port, offset_local, offset_remote, interval, realtime, iface
            )
            return

        round_num = 0
        total_sent = 0
        while True:
            round_num += 1
            total_sent += send_raw_followups_round(
                stream,
                spoof_ip,
                dst_ip,
                dst_port,
                local_port,
                offset_local,
                offset_remote,
                interval,
                realtime,
                iface,
                verbose=False,
            )
            print(f"{round_num}周目（{len(stream['followups'])}件）送信完了。累計{total_sent}件。生存確認します...")
            if not probe_target_alive(dst_ip, dst_port, timeout):
                print(
                    f"対象が応答しなくなりました（{round_num}周目終了後、累計{total_sent}件送信時点）。"
                    "クラッシュ/再起動と判断し停止します。"
                )
                return
            print("生存確認OK。継続します...")


def main():
    parser = argparse.ArgumentParser(description="pcapファイルのパケットを再送信します")
    parser.add_argument("pcap", nargs="?", help="読み込むpcapファイルのパス")
    parser.add_argument("-i", "--iface", help="送信に使うネットワークインターフェース名")
    parser.add_argument("--src-ip", help="この送信元IPのパケットだけを対象にする（Device Aの送信のみ抽出する場合に指定）")
    parser.add_argument("--src-mac", help="この送信元MACのパケットだけを対象にする（Device Aの送信のみ抽出する場合に指定）")
    parser.add_argument("--src-port", type=int, help="この送信元ポートのパケットだけを対象にする（同じ送信元に複数のTCP接続がある場合に区別する）")
    parser.add_argument(
        "--dst-ip", help="宛先IPアドレス。--tcp-session/--tcp-raw-session時は接続先として必須"
    )
    parser.add_argument(
        "--dst-port",
        type=int,
        help="宛先ポート。--tcp-session時は接続先として必須。--tcp-raw-session時は省略可（省略時はpcap記録時のポートを再利用）",
    )
    parser.add_argument("--dst-mac", help="宛先MACアドレスを書き換える場合に指定（--tcp-session時は無効）")
    parser.add_argument(
        "--keep-checksum",
        action="store_true",
        help="宛先を書き換えてもチェックサムは元のpcapの値のまま送信する（異常データをそのまま再現したい場合。--tcp-session時は無効）",
    )
    parser.add_argument(
        "--tcp-session",
        action="store_true",
        help="TCPフージングの再現向け。実際にTCP接続を確立し、Device Aが送信したペイロードだけを"
        "そのコネクション上に順番に流す（生パケットの再送はTCPの整合性が取れず宛先に拒否されるため）。"
        "--dst-ip/--dst-portが接続先、--iface/--dst-macは不要",
    )
    parser.add_argument(
        "--until-disconnect",
        action="store_true",
        help="--tcp-session/--tcp-raw-session専用。同じセッション上でpcap中のペイロード/パケット列を"
        "繰り返し送り続け、対象が応答しなくなる（クラッシュ/再起動など）まで継続する",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="--tcp-session/--tcp-raw-session専用。接続・送信のタイムアウト秒。デフォルト5.0",
    )
    parser.add_argument(
        "--tcp-raw-session",
        action="store_true",
        help="TCPスタック自体を狙うファジング（フラグの異常な組み合わせ、window/urgent pointer/予約ビット、"
        "不正なseq/ack等）の再現向け。自前でTCPハンドシェイクを生パケットで組み立てて実セッションを確立し、"
        "Device Aが送った異常ヘッダのパケットをseq/ack番号だけ新セッションに合わせて読み替えて送信する。"
        "--iface/--dst-ip/--spoof-ipが必須",
    )
    parser.add_argument(
        "--spoof-ip",
        help="--tcp-raw-session専用。送信元として名乗るIPアドレス（このWindows機に割り当てられていない、"
        "対象と同じサブネット上の未使用IPを指定）。実IPを使うとWindows自身が身に覚えのないSYN-ACKに"
        "RSTを返しセッションを壊してしまうため、これを避けるために必須",
    )
    parser.add_argument(
        "--local-port",
        type=int,
        help="--tcp-raw-session専用。新しいセッションで使うローカルポート。省略時はpcap記録時のDevice Aの送信元ポートを再利用",
    )
    parser.add_argument("--interval", type=float, default=0.0, help="パケット間の固定送信間隔(秒)。デフォルト0")
    parser.add_argument("--realtime", action="store_true", help="pcap記録時のタイムスタンプ間隔を再現して送信する")
    parser.add_argument("--loop", type=int, default=1, help="pcap全体を繰り返す回数。デフォルト1")
    parser.add_argument("--dry-run", action="store_true", help="送信せず、書き換え後の内容を表示するだけ")
    parser.add_argument("--list-ifaces", action="store_true", help="利用可能なインターフェース一覧を表示して終了")
    args = parser.parse_args()

    if args.list_ifaces:
        for name in get_if_list():
            print(name)
        return

    if not args.pcap:
        parser.error("pcapファイルを指定してください")

    if args.tcp_raw_session:
        if not args.dst_ip:
            parser.error("--tcp-raw-session には --dst-ip（接続先）が必要です")
        if not args.dry_run and not args.iface:
            parser.error("--tcp-raw-session には --iface（一覧は --list-ifaces）が必要です")
        if not args.spoof_ip:
            parser.error("--tcp-raw-session には --spoof-ip（対象と同じサブネット上の未使用IP）が必要です")
        if args.until_disconnect and args.dry_run:
            parser.error("--until-disconnect と --dry-run は併用できません（実接続なしでは生存確認ができないため）")
        replay_raw_tcp_session(
            args.pcap,
            args.src_ip,
            args.src_mac,
            args.src_port,
            args.spoof_ip,
            args.dst_ip,
            args.dst_port,
            args.iface,
            args.local_port,
            args.interval,
            args.realtime,
            args.dry_run,
            args.timeout,
            args.until_disconnect,
        )
        return

    if args.tcp_session:
        if not args.dst_ip or not args.dst_port:
            parser.error("--tcp-session には --dst-ip と --dst-port（接続先）が必要です")
        if args.until_disconnect and args.dry_run:
            parser.error("--until-disconnect と --dry-run は併用できません（実接続なしでは切断を検知できないため）")

        payloads = extract_tcp_payloads(args.pcap, args.src_ip, args.src_mac, args.src_port)
        if not payloads:
            parser.error("条件に合うTCPペイロードがpcap内に見つかりませんでした（--src-ip/--src-mac/--src-portを確認してください）")

        if args.until_disconnect:
            replay_tcp_session_until_disconnect(
                payloads, args.dst_ip, args.dst_port, args.interval, args.realtime, args.timeout
            )
        else:
            for _ in range(args.loop):
                replay_tcp_session(
                    payloads, args.dst_ip, args.dst_port, args.interval, args.realtime, args.dry_run, args.timeout
                )
        return

    if not args.dry_run and not args.iface:
        parser.error("送信するには --iface でインターフェースを指定してください（一覧は --list-ifaces）")

    for _ in range(args.loop):
        prev_ts = None
        with PcapReader(args.pcap) as reader:
            for pkt in reader:
                if not packet_matches_src(pkt, args.src_ip, args.src_mac, args.src_port):
                    continue

                if args.realtime and prev_ts is not None:
                    delay = float(pkt.time - prev_ts)
                    if delay > 0:
                        time.sleep(delay)
                elif args.interval:
                    time.sleep(args.interval)
                prev_ts = pkt.time

                pkt = rewrite_packet(pkt, args.dst_ip, args.dst_port, args.dst_mac, args.keep_checksum)

                if args.dry_run:
                    pkt.show()
                else:
                    send_packet(pkt, args.iface)


if __name__ == "__main__":
    sys.exit(main())
