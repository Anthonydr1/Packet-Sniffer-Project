## Packet Sniffer Project

I wrote a Python script using Scapy to capture and analyze TCP network traffic on interface `en0`. The sniffer flags high ports (>49152) as potential anomalies and saves packets to `capture.pcap`. This script is labeled as "tcponly_packetsniffer.py" and it only analyzes TCP packets. I then modified the script to also capture and analyze UDP traffic and anomalies, this script is labeled as "udpincluded_packetsniffer.py". 

## Skills Learned
- Network traffic analysis
- Python (Scapy)
- TCP/IP/UDP fundamentals

## Usage
Run with `python3 packet_sniffer.py` on macOS terminal. Interface or count should be adjusted in code for your network.
