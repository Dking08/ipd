"""
Advanced Network Discovery & Monitoring System
Features: Device discovery, OS fingerprinting, ARP spoofing detection,
          traffic analysis, and web dashboard

Modular architecture with OUI database integration
"""

from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP
import os
import time
import threading
import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import http.server
import socketserver

# Configuration
DISCOVERY_IP = os.environ.get("DISCOVERY_IP", "10.255.255.255")
IFACE_ENV = os.environ.get("IFACE") or None
WEB_PORT = int(os.environ.get("WEB_PORT", "8080"))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0") == "1"

# Data structures
discovered_devices = {}
arp_history = defaultdict(list)  # Track MAC changes per IP
traffic_stats = defaultdict(
    lambda: {"packets": 0, "bytes": 0, "protocols": defaultdict(int)}
)
alerts = []

# OUI Database - loaded from CSV
OUI_DATABASE = {}


class OUILookup:
    """Handle OUI database loading and vendor lookup"""

    def __init__(self):
        self.oui_db = {}
        self.load_oui_database()

    def load_oui_database(self):
        """Load OUI database from oui.csv file"""
        try:
            # Try to find oui.csv in parent directories
            current_dir = Path(__file__).resolve().parent
            possible_paths = [
                # Go up to workspace root
                current_dir.parent.parent.parent / "oui.csv",
                current_dir.parent.parent / "oui.csv",
                current_dir.parent / "oui.csv",
                current_dir / "oui.csv",
            ]
            
            oui_path = None
            for path in possible_paths:
                if path.exists():
                    oui_path = path
                    break
            
            if oui_path:
                print(
                    f"[📚 OUI] Loading vendor database from {oui_path}",
                    flush=True
                )
                with open(oui_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    count = 0
                    for row in reader:
                        # Assignment: MAC prefix (6 hex digits)
                        mac_prefix = row.get('Assignment', '').strip().upper()
                        org_name = row.get('Organization Name', '').strip()
                        if mac_prefix and org_name:
                            # Store as XX:XX:XX format for matching
                            formatted_prefix = ':'.join(
                                [mac_prefix[i:i+2] for i in range(0, 6, 2)]
                            )
                            self.oui_db[formatted_prefix] = org_name
                            count += 1
                print(f"[📚 OUI] Loaded {count} vendor entries", flush=True)
            else:
                print(
                    "[⚠️  OUI] oui.csv not found, using fallback database",
                    flush=True
                )
                self._load_fallback_database()
        except Exception as e:
            print(
                f"[⚠️  OUI] Error loading database: {e}, using fallback",
                flush=True
            )
            self._load_fallback_database()
    
    def _load_fallback_database(self):
        """Load minimal fallback OUI database"""
        self.oui_db = {
            "00:1A:2B": "Apple",
            "00:50:56": "VMware",
            "08:00:27": "VirtualBox",
            "00:0C:29": "VMware",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
            "E4:5F:01": "Raspberry Pi",
            "00:15:5D": "Microsoft Hyper-V",
            "00:16:3E": "Xen",
            "52:54:00": "QEMU/KVM",
        }
    
    def get_vendor(self, mac):
        """Get vendor from MAC address OUI"""
        if not mac or len(mac) < 8:
            return "Unknown"
        
        # Extract first 3 octets (XX:XX:XX format)
        oui = mac[:8].upper()
        
        # Try exact match first
        if oui in self.oui_db:
            return self.oui_db[oui]
        
        # Try without separators
        mac_clean = (
            mac.replace(':', '').replace('-', '').replace('.', '').upper()
        )
        if len(mac_clean) >= 6:
            oui_alt = ':'.join([mac_clean[i:i+2] for i in range(0, 6, 2)])
            if oui_alt in self.oui_db:
                return self.oui_db[oui_alt]
        
        return "Unknown Vendor"


# Initialize OUI lookup
oui_lookup = OUILookup()


def get_vendor(mac):
    """Get vendor from MAC OUI - wrapper for backward compatibility"""
    return oui_lookup.get_vendor(mac)


class OSFingerprinter:
    """OS fingerprinting based on packet characteristics"""
    
    @staticmethod
    def fingerprint_by_ttl(ttl):
        """Identify OS based on TTL value"""
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Cisco/Network Device"
        return "Unknown"
    
    @staticmethod
    def fingerprint_packet(pkt):
        """Comprehensive OS fingerprinting from packet"""
        if pkt.haslayer(IP):
            ttl = pkt[IP].ttl
            
            # TTL-based detection
            os_guess = OSFingerprinter.fingerprint_by_ttl(ttl)
            
            # Additional heuristics
            if pkt.haslayer(TCP):
                window = pkt[TCP].window
                # Windows typically uses larger window sizes
                if window > 32768:
                    os_guess = "Windows (likely)"
            
            return os_guess
        
        return "Unknown"


class SecurityMonitor:
    """Monitor for security threats and anomalies"""
    
    @staticmethod
    def detect_arp_spoofing(ip, mac):
        """Detect potential ARP spoofing attacks"""
        # Always track MAC history
        if ip not in arp_history:
            arp_history[ip] = []
        
        previous_macs = arp_history[ip]
        
        # Check if MAC changed (and we have previous history)
        if previous_macs and previous_macs[-1] != mac:
            msg = (
                f"MAC address changed for {ip}: "
                f"{previous_macs[-1]} -> {mac}"
            )
            alert = {
                "type": "ARP_SPOOFING",
                "severity": "HIGH",
                "timestamp": datetime.now().isoformat(),
                "ip": ip,
                "old_mac": previous_macs[-1],
                "new_mac": mac,
                "message": msg
            }
            alerts.append(alert)
            print(
                f"\n🚨 [SECURITY ALERT] ARP Spoofing Detected!\n"
                f"   IP: {ip}\n"
                f"   Old MAC: {previous_macs[-1]}\n"
                f"   New MAC: {mac}\n"
                f"   Time: {datetime.now().strftime('%H:%M:%S')}",
                flush=True
            )
            # Add to history after alert
            arp_history[ip].append(mac)
            return True
        elif not previous_macs:
            # First time seeing this IP, just record it
            print(f"[📝 TRACKING] First MAC for {ip}: {mac}", flush=True)
            arp_history[ip].append(mac)
            return False
        else:
            # Same MAC, no change
            return False
    
    @staticmethod
    def detect_port_scan(ip, time_window=60):
        """Detect potential port scanning activity"""
        # Check if many different ports accessed in short time
        if ip in traffic_stats:
            protocols = traffic_stats[ip]["protocols"]
            # Threshold for port scan detection
            if protocols.get("TCP", 0) > 50:
                msg = f"Potential port scan detected from {ip}"
                alert = {
                    "type": "PORT_SCAN",
                    "severity": "MEDIUM",
                    "timestamp": datetime.now().isoformat(),
                    "ip": ip,
                    "message": msg
                }
                alerts.append(alert)
                print(f"\n[⚠️  ALERT] Possible Port Scan: {msg}", flush=True)
                return True
        return False


def fingerprint_os(pkt):
    """Basic OS fingerprinting - wrapper for backward compatibility"""
    return OSFingerprinter.fingerprint_packet(pkt)


def detect_arp_spoofing(ip, mac):
    """Detect ARP spoofing - wrapper for backward compatibility"""
    return SecurityMonitor.detect_arp_spoofing(ip, mac)


class DeviceDiscovery:
    """Handle device discovery and tracking"""

    @staticmethod
    def create_device_info(ip, mac):
        """Create a new device information dictionary"""
        vendor = get_vendor(mac)
        return {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "first_seen": time.time(),
            "last_seen": time.time(),
            "os": "Unknown",
            "hostname": None,
            "open_ports": [],
            "packets_sent": 0,
            "bytes_sent": 0,
            "protocols_used": set()
        }
    
    @staticmethod
    def update_device(ip, **kwargs):
        """Update device information"""
        if ip in discovered_devices:
            discovered_devices[ip].update(kwargs)
            discovered_devices[ip]["last_seen"] = time.time()

    @staticmethod
    def add_device(ip, mac):
        """Add a newly discovered device"""
        if ip not in discovered_devices:
            device_info = DeviceDiscovery.create_device_info(ip, mac)
            discovered_devices[ip] = device_info
            vendor = device_info['vendor']
            print(
                f"[🔍 NEW DEVICE] {ip} | MAC: {mac} | "
                f"Vendor: {vendor}",
                flush=True
            )
            return True
        else:
            discovered_devices[ip]["last_seen"] = time.time()
            return False


def handle_discovery_packet(pkt):
    """Handle custom discovery ARP packets with security monitoring"""
    if not pkt.haslayer(ARP):
        return
    
    # Process all ARP packets (requests and replies)
    src_ip = pkt[ARP].psrc
    src_mac = pkt[ARP].hwsrc
    
    if DEBUG_MODE:
        op_type = "Request" if pkt[ARP].op == 1 else "Reply"
        print(
            f"[🔍 ARP {op_type}] {src_ip} ({src_mac}) -> "
            f"{pkt[ARP].pdst}",
            flush=True
        )
    
    # IMPORTANT: Check for ARP spoofing BEFORE adding/updating device
    # This detects when the same IP is seen with different MAC addresses
    if src_ip and src_mac:
        # Check if this IP already exists with a different MAC
        if src_ip in discovered_devices:
            existing_mac = discovered_devices[src_ip]["mac"]
            if existing_mac != src_mac:
                # MAC address changed - potential ARP spoofing!
                detect_arp_spoofing(src_ip, src_mac)
                # Update the device with new MAC after alert
                discovered_devices[src_ip]["mac"] = src_mac
                discovered_devices[src_ip]["vendor"] = get_vendor(src_mac)
                discovered_devices[src_ip]["last_seen"] = time.time()
            else:
                # Same MAC, just update last seen
                discovered_devices[src_ip]["last_seen"] = time.time()
        else:
            # New device, add it
            DeviceDiscovery.add_device(src_ip, src_mac)
    
    # Handle different ARP packet types
    if DISCOVERY_IP == "all":
        if pkt[ARP].op in [1, 2]:
            # Also check target info from ARP replies
            if pkt[ARP].op == 2:  # ARP reply
                dst_ip = pkt[ARP].pdst
                dst_mac = pkt[ARP].hwdst
                if dst_ip and dst_mac:
                    # Check for spoofing on destination too
                    if dst_ip in discovered_devices:
                        existing_mac = discovered_devices[dst_ip]["mac"]
                        if existing_mac != dst_mac:
                            detect_arp_spoofing(dst_ip, dst_mac)
                            discovered_devices[dst_ip]["mac"] = dst_mac
                            discovered_devices[dst_ip]["vendor"] = get_vendor(
                                dst_mac
                            )
                            discovered_devices[dst_ip]["last_seen"] = time.time()
                    elif dst_ip not in discovered_devices:
                        DeviceDiscovery.add_device(dst_ip, dst_mac)


class TrafficAnalyzer:
    """Analyze and classify network traffic"""
    
    @staticmethod
    def analyze_protocol(pkt, src_ip):
        """Detect and categorize protocols"""
        protocols = traffic_stats[src_ip]["protocols"]
        
        if pkt.haslayer(TCP):
            protocols["TCP"] += 1
            dport, sport = pkt[TCP].dport, pkt[TCP].sport
            
            # Common service ports
            if dport == 80 or sport == 80:
                protocols["HTTP"] += 1
            elif dport == 443 or sport == 443:
                protocols["HTTPS"] += 1
            elif dport == 22 or sport == 22:
                protocols["SSH"] += 1
            elif dport == 21 or sport == 21:
                protocols["FTP"] += 1
            elif dport == 25 or sport == 25:
                protocols["SMTP"] += 1
            elif dport in [3306, 5432, 1433]:  # MySQL, PostgreSQL, MSSQL
                protocols["Database"] += 1
                
        elif pkt.haslayer(UDP):
            protocols["UDP"] += 1
            dport, sport = pkt[UDP].dport, pkt[UDP].sport
            
            if dport == 53 or sport == 53:
                protocols["DNS"] += 1
            elif dport == 67 or sport == 67 or dport == 68 or sport == 68:
                protocols["DHCP"] += 1
                
        elif pkt.haslayer(ICMP):
            protocols["ICMP"] += 1
    
    @staticmethod
    def update_traffic_stats(src_ip, pkt_len):
        """Update traffic statistics for an IP"""
        traffic_stats[src_ip]["packets"] += 1
        traffic_stats[src_ip]["bytes"] += pkt_len


def handle_all_traffic(pkt):
    """Analyze all network traffic with security monitoring"""
    try:
        # Track ALL ARP packets for spoofing detection (both requests & replies)
        if pkt.haslayer(ARP):
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            
            # Check both requests (op=1) and replies (op=2)
            if pkt[ARP].op in [1, 2] and src_ip and src_mac:
                # Check if IP exists with different MAC
                if src_ip in discovered_devices:
                    existing_mac = discovered_devices[src_ip]["mac"]
                    if existing_mac != src_mac:
                        detect_arp_spoofing(src_ip, src_mac)
                        # Update device info after alert
                        discovered_devices[src_ip]["mac"] = src_mac
                        discovered_devices[src_ip]["vendor"] = get_vendor(
                            src_mac
                        )
                        discovered_devices[src_ip]["last_seen"] = time.time()
        
        # Traffic statistics
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            pkt_len = len(pkt)
            
            # Update traffic stats
            TrafficAnalyzer.update_traffic_stats(src_ip, pkt_len)
            TrafficAnalyzer.analyze_protocol(pkt, src_ip)
            
            # OS fingerprinting
            if src_ip in discovered_devices:
                os_guess = fingerprint_os(pkt)
                if discovered_devices[src_ip]["os"] == "Unknown":
                    discovered_devices[src_ip]["os"] = os_guess
                
                # Update device stats
                stats = traffic_stats[src_ip]
                discovered_devices[src_ip]["packets_sent"] = stats["packets"]
                discovered_devices[src_ip]["bytes_sent"] = stats["bytes"]
                
                # Track protocols used
                protocols_set = discovered_devices[src_ip].get(
                    "protocols_used", set()
                )
                for proto in stats["protocols"].keys():
                    protocols_set.add(proto)
    
    except Exception:
        pass  # Silently ignore malformed packets


def discovery_listener():
    """Listen for custom discovery packets"""
    iface_name = IFACE_ENV or 'default interface'
    print(f"[📡 DISCOVERY] Listening on {iface_name}", flush=True)
    sniff(filter="arp", prn=handle_discovery_packet, store=0, iface=IFACE_ENV)


def traffic_analyzer():
    """Analyze all network traffic"""
    iface_name = IFACE_ENV or 'default interface'
    print(f"[📊 ANALYZER] Monitoring all traffic on {iface_name}", flush=True)
    sniff(prn=handle_all_traffic, store=0, iface=IFACE_ENV)


class DashboardGenerator:
    """Generate HTML dashboard with statistics"""
    
    @staticmethod
    def get_stats_summary():
        """Get summary of traffic statistics"""
        return {
            "total_devices": len(discovered_devices),
            "total_alerts": len(alerts),
            "total_packets": sum(s['packets'] for s in traffic_stats.values()),
            "total_bytes": sum(s['bytes'] for s in traffic_stats.values())
        }
    
    @staticmethod
    def format_bytes(bytes_val):
        """Format bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} TB"
    
    @staticmethod
    def format_time_ago(timestamp):
        """Format timestamp to 'X seconds/minutes ago'"""
        diff = int(time.time() - timestamp)
        if diff < 60:
            return f"{diff}s ago"
        elif diff < 3600:
            return f"{diff // 60}m ago"
        elif diff < 86400:
            return f"{diff // 3600}h ago"
        else:
            return f"{diff // 86400}d ago"


def generate_dashboard_html():
    """Generate HTML dashboard"""
    summary = DashboardGenerator.get_stats_summary()
    fmt = DashboardGenerator

    # Generate device rows
    device_rows = []
    for dev in sorted(
        discovered_devices.values(),
        key=lambda d: d['last_seen'],
        reverse=True
    ):
        device_rows.append(f"""
            <tr>
                <td>{dev['ip']}</td>
                <td>{dev['mac']}</td>
                <td title="{dev['vendor']}">{dev['vendor'][:30]}...</td>
                <td>{dev['os']}</td>
                <td>{dev['packets_sent']}</td>
                <td>{fmt.format_bytes(dev['bytes_sent'])}</td>
                <td>{fmt.format_time_ago(dev['last_seen'])}</td>
            </tr>
        """)

    # Generate alert rows (most recent first)
    alert_items = []
    recent_alerts = list(reversed(alerts[-20:]))  # Show last 20, newest first
    for alert in recent_alerts:
        severity_color = {
            'HIGH': '#ff4444',
            'MEDIUM': '#ff8800',
            'LOW': '#ffaa00'
        }.get(alert.get('severity', 'LOW'), '#ffaa00')
        
        severity_emoji = {
            'HIGH': '🚨',
            'MEDIUM': '⚠️',
            'LOW': 'ℹ️'
        }.get(alert.get('severity', 'LOW'), '⚠️')
        
        # Format timestamp
        alert_time = datetime.fromisoformat(alert['timestamp'])
        time_str = alert_time.strftime('%H:%M:%S')
        
        # <strong>{severity_emoji} {alert['type']}</strong>
        alert_items.append(f"""
        <div class="alert" style="border-left-color: {severity_color};">
            <strong> {alert['type']} </strong>
            <span style="color: {severity_color}; margin-left: 10px;">
                [{alert.get('severity', 'LOW')}]
            </span>
            <br>
            {alert['message']}
            <div class="alert-time">{time_str}</div>
        </div>
        """)

    # Generate traffic stat rows
    traffic_rows = []
    for ip, stats in sorted(
        traffic_stats.items(),
        key=lambda x: x[1]['packets'],
        reverse=True
    )[:20]:  # Top 20
        protocol_badges = ''.join(
            f'<span class="protocol-badge">{proto}: {count}</span>'
            for proto, count in stats['protocols'].items()
        )
        traffic_rows.append(f"""
            <tr>
                <td>{ip}</td>
                <td>{stats['packets']}</td>
                <td>{fmt.format_bytes(stats['bytes'])}</td>
                <td>{protocol_badges}</td>
            </tr>
        """)

    html = f"""<!DOCTYPE html>
<html><head><title>Network Monitor Dashboard</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;
background:#0a0e27;color:#e0e0e0}}
.container{{max-width:1400px;margin:0 auto}}
h1{{color:#00d9ff;border-bottom:2px solid #00d9ff;padding-bottom:10px}}
h2{{color:#00ff88;margin-top:30px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
gap:15px;margin:20px 0}}
.stat-card{{background:#1a1f3a;padding:20px;border-radius:8px;
border-left:4px solid #00d9ff}}
.stat-value{{font-size:2em;font-weight:bold;color:#00d9ff}}
.stat-label{{color:#888;margin-top:5px}}
table{{width:100%;border-collapse:collapse;background:#1a1f3a;
border-radius:8px;overflow:hidden}}
th{{background:#252b47;padding:12px;text-align:left;color:#00d9ff}}
td{{padding:10px;border-top:1px solid #2a3050}}
tr:hover{{background:#252b47}}
.alert{{background:#3a1a1a;border-left:4px solid #ff4444;
padding:12px;margin:10px 0;border-radius:4px}}
.alert-time{{color:#888;font-size:0.9em}}
.protocol-badge{{display:inline-block;padding:3px 8px;margin:2px;
background:#2a3050;border-radius:3px;font-size:0.85em}}
.refresh-btn{{background:#00d9ff;color:#0a0e27;border:none;
padding:10px 20px;border-radius:5px;cursor:pointer;
font-weight:bold;font-size:1em}}
.refresh-btn:hover{{background:#00ff88}}
.info-text{{color:#888;font-style:italic}}
</style>
<script>
function refreshData(){{location.reload();}}
setInterval(refreshData,5000);
</script>
</head><body><div class="container">
<h1>Network Monitor Dashboard</h1>
<button class="refresh-btn" onclick="refreshData()">Refresh Now</button>
<div class="stats">
    <div class="stat-card">
        <div class="stat-value">{summary['total_devices']}</div>
        <div class="stat-label">Devices Discovered</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{summary['total_alerts']}</div>
        <div class="stat-label">Security Alerts</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{summary['total_packets']}</div>
        <div class="stat-label">Total Packets</div>
    </div>
    <div class="stat-card">
        <div class="stat-value">{fmt.format_bytes(summary['total_bytes'])}</div>
        <div class="stat-label">Total Traffic</div>
    </div>
</div>
<h2>Discovered Devices ({len(discovered_devices)})</h2>
<table><tr>
    <th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>OS</th>
    <th>Packets</th><th>Traffic</th><th>Last Seen</th>
</tr>{''.join(device_rows) if device_rows else '<tr><td colspan="7" class="info-text">No devices discovered yet...</td></tr>'}
</table>
<h2>Security Alerts ({len(alerts)})</h2>
{''.join(alert_items) if alert_items else '<p class="info-text">No alerts detected</p>'}
<h2>Traffic Statistics (Top 20)</h2>
<table><tr>
    <th>IP Address</th><th>Packets</th><th>Bytes</th><th>Protocols</th>
</tr>{''.join(traffic_rows) if traffic_rows else '<tr><td colspan="4" class="info-text">No traffic data yet...</td></tr>'}
</table>
</div></body></html>"""
    return html


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler for dashboard requests"""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = generate_dashboard_html()
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        pass  # Suppress HTTP logs


def start_web_server():
    """Start web dashboard server"""
    with socketserver.TCPServer(("", WEB_PORT), DashboardHandler) as httpd:
        print(
            f"[🌐 DASHBOARD] Running at http://localhost:{WEB_PORT}",
            flush=True
        )
        httpd.serve_forever()


def main():
    """Main entry point for the network monitoring system"""
    print("=" * 60)
    print("  🚀 Advanced Network Discovery & Monitoring System")
    print("=" * 60)
    print(f"  Interface: {IFACE_ENV or 'default'}")
    print(f"  Discovery IP: {DISCOVERY_IP}")
    print(f"  Web Dashboard: http://localhost:{WEB_PORT}")
    print("=" * 60)
    print()

    # Start threads
    threads = [
        threading.Thread(target=discovery_listener, daemon=True),
        threading.Thread(target=traffic_analyzer, daemon=True),
        threading.Thread(target=start_web_server, daemon=True)
    ]

    for t in threads:
        t.start()

    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[👋 SHUTDOWN] Stopping all monitors...")


if __name__ == "__main__":
    main()
