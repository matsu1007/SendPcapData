"""3モード共通のパケットフィルタ・待機処理."""

import time

from scapy.all import Ether, IP, IPv6, TCP


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


def wait_between_payloads(delay, interval, realtime):
    if realtime and delay > 0:
        time.sleep(delay)
    elif interval:
        time.sleep(interval)
