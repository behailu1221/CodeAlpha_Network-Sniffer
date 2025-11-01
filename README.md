Network Sniffer

A simple, educational Python network sniffer built during my Cyber Security Internship at CodeAlpha.
This tool captures live network traffic, parses common protocol fields, and prints concise, human-friendly summaries (with hex + ASCII payload previews). It can also save captures to a PCAP file for later analysis in Wireshark.

Features

Capture live packets from a chosen network interface

Display timestamp, protocol, source/destination IPs and ports, and payload length

Show a short hex dump and ASCII preview (first 64 bytes) of packet payloads

Apply BPF filters (e.g., tcp and port 80) to limit what you capture

Optionally save captured packets to a .pcap file (openable in Wireshark)

Lightweight, single-file script suitable for learning and demoing packet analysis

Requirements

Python 3 

scapy library

Optional (for extended features):

pyshark + tshark — for richer protocol dissection

rich — for colored terminal output

Installation

Create and activate a virtual environment (recommended):

python -m venv venv
# Linux 
source venv/bin/activate

Install dependencies:

pip install scapy
# optional extras
# pip install pyshark rich

Usage

Save the provided script as sniffer.py. Run it with appropriate privileges (sniffing usually requires root/administrator):

Basic (default interface, unlimited):

sudo python sniffer.py


Capture N packets:

sudo python sniffer.py --count 100


Specify interface:

sudo python sniffer.py --iface wlan0


Use a BPF filter:

sudo python sniffer.py --filter "tcp and port 80"


Save captures to PCAP:

sudo python sniffer.py --save capture.pcap


You can combine options:

sudo python sniffer.py --iface eth0 --count 500 --filter "udp" --save dns_capture.pcap

Command-line Options

--iface : Interface to sniff (e.g., eth0, wlan0). If omitted, Scapy chooses a default.

--count : Number of packets to capture (0 or omitted = unlimited).

--filter : BPF (libpcap) filter string (e.g., "tcp and port 443").

--save : File path to write captured packets in .pcap format.

Example Output
[2025-11-01 10:32:44.321] TCP   192.168.1.10:443 -> 192.168.1.5:52344 | payload=128 bytes
    payload(hexdump): 474554202f20485454502f312e310d0a486f73743a20676f6f676c652e636f6d0d0a0d0a
    payload(ascii) : GET / HTTP/1.1..Host: google.com....

How it works (brief)

Uses Scapy's sniff() to capture packets on an interface.

For each packet, a callback inspects layers (IP/IPv6, TCP, UDP, ICMP, Raw, DNS, etc.).

Extracts fields (src/dst, ports, protocol), obtains payload bytes (if any), and prints a timestamped one-line summary plus a short hex/ASCII preview.

Optionally stores captured packets in memory and writes them to a PCAP using wrpcap().

Development & Extension Ideas

Add session reassembly (reconstruct TCP streams to view full HTTP requests/responses)

Export CSV/JSON summaries (top talkers, protocol counts)

Integrate pyshark for deeper protocol parsing (TLS SNI, HTTP headers)

Add multi-threaded processing to handle high-throughput captures

Add colored or tabular terminal output (use rich or prettytable)

 
 
  Disclaimer

⚠️ Use responsibly!
This tool is for educational and ethical cybersecurity research only.
Unauthorized network sniffing may violate laws or privacy policies.
Always ensure you have permission before capturing network traffic.

 Author
Behailu Yigeramu
Cyber Security Intern @ CodeAlpha
🔗 LinkedIn
 https://www.linkedin.com/in/behailu-yigeramu-405875316/
 
 
 Support & Contribution
If you find this tool helpful:
Give it a ⭐ on GitHub
Fork it, improve it, and submit a pull request
