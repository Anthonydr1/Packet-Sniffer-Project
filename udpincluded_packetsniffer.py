from scapy.all import sniff, wrpcap #loads sniff and wrpcap from Scapy
from scapy.layers.inet import IP, TCP, UDP #defines network protocols being analyzed (UPD added)

# Callback function to process each packet captured by sniff
def packet_callback(packet): 
    if packet.haslayer(IP): #checks if packet has an IP layer
        ip_src = packet[IP].src #gets the source IP
        ip_dst = packet[IP].dst #gets the destination IP

        if packet.haslayer(TCP): #checks for TCP packets
            port_src = packet[TCP].sport #source port num
            port_dst = packet[TCP].dport #destination port num
            if port_dst > 49152:  # High ports often indicate ephemeral or unusual traffic
                print(f"[ANOMALY] TCP Packet: {ip_src}:{port_src} -> {ip_dst}:{port_dst} (High Port)")
            else:
                print(f"TCP Packet: {ip_src}:{port_src} -> {ip_dst}:{port_dst}")
        elif packet.haslayer(UDP): #new function to analyze UDP traffic
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            #Common UDP ports: DNS-> 53, NTP-> 123, SNMP-> 161
            common_ports = {53, 123, 161}
            if port_dst > 49152 or port_dst not in common_ports: #detects packets with high ports
                print(f"[ANOMALY] UDP Packet: {ip_src}:{port_src} -> {ip_dst}:{port_dst} (Unusual Port)")
            else:
                print(f"UDP Packet: {ip_src}:{port_src} -> {ip_dst}:{port_dst}")
            
        wrpcap("capture.pcap", packet, append=True)  # Append each packet to the file

# Sniff packets
def start_sniffing(interface="en0", count=1500): #count increased since more traffic is analyzed
    print(f"Sniffing on {interface}...")
    sniff(iface=interface, prn=packet_callback, count=count) #removed filter= "tcp"

if __name__ == "__main__":
    start_sniffing()  # Runs with en0, count can be adjusted
#navigate the directory and run "python3 packet_sniffer.py"
#capture.pcap can be read with wireshark or tcpdump (tcpdump -r capture.pcap)