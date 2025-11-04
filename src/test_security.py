"""
Test script to verify ARP spoofing detection is working
This simulates what happens when you change MAC addresses in the TUI
"""

from scapy.all import ARP, Ether, sendp
import time
import os

# Get interface from environment or use default
IFACE = os.environ.get("IFACE", None)

def send_test_arp(src_ip, src_mac, dst_ip, dst_mac="ff:ff:ff:ff:ff:ff"):
    """Send a test ARP packet"""
    ether = Ether(dst=dst_mac)
    arp = ARP(
        op=1,  # ARP request
        pdst=dst_ip,
        psrc=src_ip,
        hwsrc=src_mac
    )
    sendp(ether / arp, verbose=False, iface=IFACE)
    print(f"[SENT] ARP from {src_ip} ({src_mac}) -> {dst_ip}")


def test_arp_spoofing():
    """Test ARP spoofing detection"""
    print("=" * 60)
    print("ARP SPOOFING DETECTION TEST")
    print("=" * 60)
    print()
    
    # Test IP and different MAC addresses
    test_ip = "10.0.0.100"
    discovery_ip = "10.255.255.255"
    mac1 = "00:11:22:33:44:55"
    mac2 = "00:AA:BB:CC:DD:EE"
    
    print(f"Step 1: Sending ARP with IP {test_ip} and MAC {mac1}")
    send_test_arp(test_ip, mac1, discovery_ip)
    time.sleep(2)
    
    print(f"\nStep 2: Sending ARP with SAME IP {test_ip} but DIFFERENT MAC {mac2}")
    print("This should trigger an ARP spoofing alert!")
    send_test_arp(test_ip, mac2, discovery_ip)
    time.sleep(2)
    
    print(f"\nStep 3: Sending ARP again with IP {test_ip} and original MAC {mac1}")
    print("This should trigger another ARP spoofing alert!")
    send_test_arp(test_ip, mac1, discovery_ip)
    time.sleep(2)
    
    print("\n" + "=" * 60)
    print("Test complete! Check the dashboard for security alerts.")
    print("Dashboard: http://localhost:8080")
    print("=" * 60)


if __name__ == "__main__":
    print("\nMake sure the dashboard is running first!")
    print("Press Ctrl+C to cancel, or Enter to continue...")
    try:
        input()
        test_arp_spoofing()
    except KeyboardInterrupt:
        print("\nTest cancelled.")
