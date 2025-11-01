# Network-Sniffer
A simple yet powerful Python Network Sniffer built during my Cyber Security Internship at CodeAlpha. This tool captures, analyzes, and displays real-time network packets — similar to tcpdump or Wireshark (but lightweight and fully written in Python ).
Features

 Capture live network packets in real-time

 Display source/destination IPs, ports, and protocols

 Show readable payload data (both Hex and ASCII view)

 Apply custom filters (TCP, UDP, ICMP, specific ports, etc.)

 Save captured traffic to .pcap files (viewable in Wireshark)

 Fully configurable through command-line arguments

Requirements

Python 3

Required libraries:

pip install scapy argparse

On Linux, you might need sudo/root privileges to capture packets:

sudo python sniffer.py

 Usage
 1.Basic Capture
 
   $ python sniffer.py

Starts sniffing on the default interface until you stop with Ctrl+C.


2. Capture on a Specific Interface
 
   $ python sniffer.py --iface wlan0

Sniffs packets on the Wi-Fi interface.

3. Limit the Number of Packets

    $ python sniffer.py --count 10

Captures only 10 packets and then exits.


5. Apply a Filter
 
   $ python sniffer.py --filter "tcp and port 80"

Only capture HTTP (TCP port 80) packets.

6. Save Packets to a File

    $ python sniffer.py --save capture.pcap

Saves all captured packets to capture.pcap, which you can open in Wireshark.


 Example Output

Starting sniffing... (press Ctrl+C to stop)

[2025-11-01 10:32:44.321] TCP   192.168.1.10:443 -> 192.168.1.5:52344 | payload=128 bytes
 
    payload(hexdump): 474554202f20485454502f312e310d0a486f73743a20676f6f676c652e636f6d0d0a0d0a
  
    payload(ascii) : GET / HTTP/1.1..Host: google.com....

[2025-11-01 10:32:45.101] UDP   192.168.1.5:57632 -> 8.8.8.8:53 | payload=64 bytes
 
    payload(hexdump): 1a2b0100000100000000000004676f6f676c6503636f6d0000010001
  
    payload(ascii) : .......google.com.....

Stopped by user

Saving 23 packets to capture.pcap

How It Works

Uses Scapy to sniff packets on a chosen interface

Extracts protocol, IPs, ports, and payload data

Displays a formatted summary per packet

Optionally stores packets in memory

Saves them as .pcap for Wireshark analysis

 Command-Line Options

Argument	Description	Example

--iface	Network interface to capture from	--iface wlan0

--count	Number of packets to capture (0 = unlimited)	--count 100

--filter	BPF-style capture filter	--filter "tcp and port 443"

--save	Save captured packets to .pcap file	--save output.pcap
 
 
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
