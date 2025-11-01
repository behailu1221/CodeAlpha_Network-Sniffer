#!/usr/bin/env python3
"""
Simple network sniffer using scapy.
Run as root/administrator:
  sudo python3 sniffer_scapy.py --iface eth0 --count 0
"""

import argparse
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, wrpcap
import datetime
import os

def parse_packet(pkt):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    proto = "OTHER"
    src = dst = "-"
    sport = dport = "-"
    payload = b""

    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        src = ip.src
        dst = ip.dst
        proto = ip.nh

    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
    elif ICMP in pkt:
        proto = "ICMP"
        # ICMP has no ports; payload maybe present
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
    else:
        # other protocols - try Raw
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)

    payload_len = len(payload)
    # Print a one-line summary
    print(f"[{ts}] {proto:5} {src}:{sport} -> {dst}:{dport} | payload={payload_len} bytes")
    # Print small hexdump / ASCII preview (first 64 bytes)
    if payload_len > 0:
        preview = payload[:64]
        # printable ASCII fallback
        printable = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in preview)
        hexpreview = preview.hex()
        print(f"    payload(hexdump): {hexpreview}")
        print(f"    payload(ascii) : {printable}")

def main():
    parser = argparse.ArgumentParser(description="Simple scapy sniffer")
    parser.add_argument("--iface", required=False, help="Interface to sniff (e.g., eth0, wlan0). If omitted, scapy chooses.")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--filter", default="", help="BPF filter (e.g., 'tcp and port 80')")
    parser.add_argument("--save", default="", help="Optional pcap file to save captured packets")
    args = parser.parse_args()

    packets = []

    def _callback(pkt):
        try:
            parse_packet(pkt)
            if args.save:
                packets.append(pkt)
        except Exception as e:
            print("Error parsing packet:", e)

    print("Starting sniffing... (press Ctrl+C to stop)")
    try:
        sniff(iface=args.iface, prn=_callback, store=False if not args.save else True, count=args.count or 0, filter=args.filter)
    except KeyboardInterrupt:
        print("Stopped by user")
    finally:
        if args.save and packets:
            print(f"Saving {len(packets)} packets to {args.save}")
            wrpcap(args.save, packets)

if __name__ == "__main__":

    main()
