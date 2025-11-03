from scapy.all import Ether, ARP, sendp, get_if_hwaddr
import time
import socket
import os

DISCOVERY_IP = os.environ.get("DISCOVERY_IP", "10.255.255.255")

# Optional runtime parameters via environment variables so frontends (TUI/CLI)
# can configure behavior without changing this file's API.
SRC_IP_ENV = os.environ.get("SRC_IP", "auto")
SRC_MAC_ENV = os.environ.get("SRC_MAC", "00:11:22:33:44:55")
INTERVAL = float(os.environ.get("INTERVAL", "5"))
IFACE_ENV = os.environ.get("IFACE") or None


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def main():
    iface = IFACE_ENV
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
