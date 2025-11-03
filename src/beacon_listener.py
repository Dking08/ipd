from scapy.all import sniff, ARP
import os

DISCOVERY_IP = os.environ.get("DISCOVERY_IP", "10.255.255.255")
IFACE_ENV = os.environ.get("IFACE") or None
discovered = {}


def handle_packet(pkt):
    if pkt.haslayer(ARP):
        if DISCOVERY_IP == "all":
            if pkt[ARP].op in [1, 2]:
                src_ip = pkt[ARP].psrc
                src_mac = pkt[ARP].hwsrc

                # Also capture target info from ARP replies
                if pkt[ARP].op == 2:  # ARP reply
                    dst_ip = pkt[ARP].pdst
                    dst_mac = pkt[ARP].hwdst
                    if dst_ip and dst_ip not in discovered:
                        discovered[dst_ip] = dst_mac
                        print(f"[NEW PEER] {dst_ip} | MAC: {dst_mac}", flush=True)

                if src_ip and src_ip not in discovered:
                    discovered[src_ip] = src_mac
                    print(f"[NEW PEER] {src_ip} | MAC: {src_mac}", flush=True)

        if pkt[ARP].pdst == DISCOVERY_IP:
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            if src_ip not in discovered:
                discovered[src_ip] = src_mac
                print(f"[NEW PEER] {src_ip} | MAC: {src_mac}", flush=True)


def listen_for_beacons():
    print(
        "[*] Listening for ARP discovery packets to "
        f"{DISCOVERY_IP}" + (f" on '{IFACE_ENV}'" if IFACE_ENV else "")
    )
    sniff(filter="arp", prn=handle_packet, store=0, iface=IFACE_ENV)


if __name__ == "__main__":
    listen_for_beacons()
