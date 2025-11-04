from scapy.all import ARP, Ether, sendp
import time
import socket
import os

DISCOVERY_IP = os.environ.get("DISCOVERY_IP", "10.255.255.255")

# Optional runtime parameters via environment variables so frontends (TUI/CLI)
# can configure behavior without changing this file's API.
SRC_IP_ENV = os.environ.get("SRC_IP", "auto")
SRC_MAC_ENV = os.environ.get("SRC_MAC", "00:11:22:33:44:55")
INTERVAL_ENV = float(os.environ.get("INTERVAL", "5"))
IFACE_ENV = os.environ.get("IFACE") or None

def get_local_ip():
    # Quick trick to get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def send_beacon():
    # Resolve source IP
    if SRC_IP_ENV.lower() == "auto":
        local_ip = get_local_ip()
    else:
        local_ip = SRC_IP_ENV

    print(
        f"[+] Sending discovery beacons from {local_ip} to {DISCOVERY_IP}"
        + (f" on iface '{IFACE_ENV}'" if IFACE_ENV else "")
    )

    # Ethernet frame with broadcast MAC
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(op=1, pdst=DISCOVERY_IP, psrc=local_ip, hwsrc=SRC_MAC_ENV)

    interval = INTERVAL_ENV
    while True:
        sendp(
            ether / arp, verbose=False, iface=IFACE_ENV
        )  # type: ignore[arg-type]
        print("[>] Beacon sent.")
        time.sleep(interval)  # send every N seconds


if __name__ == "__main__":
    send_beacon()
