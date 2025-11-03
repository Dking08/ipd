from scapy.all import sniff, ARP

DISCOVERY_IP = "10.255.255.255"
discovered = {}

def handle_packet(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].pdst == DISCOVERY_IP:
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        if src_ip not in discovered:
            discovered[src_ip] = src_mac
            print(f"[NEW PEER] {src_ip} | MAC: {src_mac}")

def listen_for_beacons():
    print("[*] Listening for ARP discovery packets...")
    sniff(filter="arp", prn=handle_packet, store=0)

if __name__ == "__main__":
    listen_for_beacons()
