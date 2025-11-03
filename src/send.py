from scapy.all import Ether, ARP, sendp, get_if_hwaddr
import time
import socket

DISCOVERY_IP = "10.255.255.255"   # marker IP used as beacon
INTERVAL = 2                      # seconds between beacons


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def main():
    iface = None
    # try to auto-detect a reasonable interface (not loopback)
    from scapy.all import get_if_list
    candidates = [i for i in get_if_list() if i != "lo"]
    if candidates:
        iface = candidates[0]
    local_ip = get_local_ip()
    local_mac = get_if_hwaddr(iface) if iface else None
    print(f"[Sender] iface={iface} ip={local_ip} mac={local_mac}")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(op=1, pdst=DISCOVERY_IP, psrc=local_ip, hwsrc=local_mac)
    try:
        while True:
            sendp(ether/arp, iface=iface, verbose=False)
            print(f"[Sender] Beacon sent from {local_ip} on {iface}")
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    main()
