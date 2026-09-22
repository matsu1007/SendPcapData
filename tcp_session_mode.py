"""--tcp-session: TCPペイロード（アプリ層データ）のファジングを再現する。

通常のsocket接続でハンドシェイクとseq/ack管理をOSのTCPスタックに任せ、
アプリケーション層に渡るバイト列（＝ファジングされた内容）だけを忠実に再現する。
"""

import socket

from scapy.all import PcapReader, TCP

from pcap_filters import packet_matches_src, wait_between_payloads


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
