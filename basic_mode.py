"""基本モード: pcapのパケットを（必要なら宛先を書き換えて）そのまま再送信する."""

import time

from scapy.all import Ether, IP, IPv6, PcapReader, TCP, UDP, send, sendp

from pcap_filters import packet_matches_src


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


def run_basic_mode(
    pcap_path,
    src_ip,
    src_mac,
    src_port,
    dst_ip,
    dst_port,
    dst_mac,
    keep_checksum,
    iface,
    interval,
    realtime,
    loop,
    dry_run,
):
    for _ in range(loop):
        prev_ts = None
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                if not packet_matches_src(pkt, src_ip, src_mac, src_port):
                    continue

                if realtime and prev_ts is not None:
                    delay = float(pkt.time - prev_ts)
                    if delay > 0:
                        time.sleep(delay)
                elif interval:
                    time.sleep(interval)
                prev_ts = pkt.time

                pkt = rewrite_packet(pkt, dst_ip, dst_port, dst_mac, keep_checksum)

                if dry_run:
                    pkt.show()
                else:
                    send_packet(pkt, iface)
