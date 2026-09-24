#!/usr/bin/env python3
"""pcapファイルに記録されたパケットを、宛先を書き換えてネットワークに再送信するツール."""

import argparse
import sys

from scapy.all import get_if_list

from basic_mode import run_basic_mode
from tcp_raw_session_mode import replay_raw_tcp_sessions
from tcp_session_mode import extract_tcp_payloads, replay_tcp_session, replay_tcp_session_until_disconnect


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
        replay_raw_tcp_sessions(
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

    run_basic_mode(
        args.pcap,
        args.src_ip,
        args.src_mac,
        args.src_port,
        args.dst_ip,
        args.dst_port,
        args.dst_mac,
        args.keep_checksum,
        args.iface,
        args.interval,
        args.realtime,
        args.loop,
        args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main())
