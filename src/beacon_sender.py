from scapy.all import ARP, Ether, sendp
import time
import socket

DISCOVERY_IP = "10.255.255.255"

def get_local_ip():
    # Quick trick to get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def send_beacon():
    local_ip = get_local_ip()
    print(f"[+] Sending discovery beacons from {local_ip}")
    
    # Ethernet frame with broadcast MAC
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    arp = ARP(op=1, pdst=DISCOVERY_IP, psrc=local_ip, hwsrc="00:11:22:33:44:55")

    while True:
        sendp(ether/arp, verbose=False)
        print("[>] Beacon sent.")
        time.sleep(5)  # send every 5 seconds

if __name__ == "__main__":
    send_beacon()
