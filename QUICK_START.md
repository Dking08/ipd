# Quick Start Guide - Improved Dashboard

## Installation

No additional dependencies required beyond the existing `requirements.txt`:
- scapy
- Other existing dependencies

## Running the Dashboard

### Option 1: Direct Execution
```powershell
cd "d:\5th Sem\ARP_CN\ipd\ipd\src"
python dashboard.py
```

### Option 2: With Environment Variables
```powershell
# Set interface (optional)
$env:IFACE = "Wi-Fi"

# Set discovery IP (optional)
$env:DISCOVERY_IP = "10.255.255.255"

# Set web port (optional, default: 8080)
$env:WEB_PORT = "8080"

# Run
python dashboard.py
```

### Option 3: Using existing beacon system
The dashboard works alongside the existing beacon sender/listener system.

## Accessing the Dashboard

1. Start the dashboard
2. Open your browser
3. Navigate to: `http://localhost:8080`
4. Dashboard auto-refreshes every 5 seconds

## Dashboard Features

### 1. Summary Cards (Top)
- **Devices Discovered**: Total unique devices found
- **Security Alerts**: Total security events detected
- **Total Packets**: Aggregate packet count
- **Total Traffic**: Human-readable traffic volume

### 2. Discovered Devices Table
Columns:
- **IP Address**: Device IP
- **MAC Address**: Hardware address
- **Vendor**: Manufacturer from OUI database
- **OS**: Detected operating system
- **Packets**: Number of packets sent
- **Traffic**: Data volume sent
- **Last Seen**: Time since last activity

### 3. Security Alerts
Color-coded by severity:
- 🔴 **Red**: HIGH (ARP Spoofing)
- 🟠 **Orange**: MEDIUM (Port Scanning)
- 🟡 **Yellow**: LOW (Other alerts)

Shows last 10 alerts with timestamps.

### 4. Traffic Statistics
Top 20 most active IPs showing:
- **IP Address**: Source IP
- **Packets**: Total packets sent
- **Bytes**: Data volume with human-readable format
- **Protocols**: Badge-style protocol list

## OUI Database

### Location
The dashboard automatically searches for `oui.csv` in:
1. `d:\5th Sem\ARP_CN\oui.csv` (workspace root)
2. `d:\5th Sem\ARP_CN\ipd\ipd\oui.csv`
3. `d:\5th Sem\ARP_CN\ipd\ipd\src\oui.csv`

### Current Database
- **38,291 entries** from IEEE
- Covers major manufacturers globally
- Includes IoT, networking, mobile devices

### Example Vendors Detected
- Apple
- Espressif (ESP8266/ESP32)
- Raspberry Pi Foundation
- Cisco
- Intel
- Samsung
- Extreme Networks
- And many more...

## Security Monitoring

### ARP Spoofing Detection
**What it detects**: MAC address changes for the same IP

**Alert Example**:
```
[⚠️ ALERT] Possible ARP Spoofing: MAC address changed for 192.168.1.100: 
AA:BB:CC:DD:EE:FF -> 11:22:33:44:55:66
```

**What to do**:
1. Check if device legitimately changed
2. Verify if IP was reassigned
3. Investigate potential attack

### Port Scan Detection
**What it detects**: High volume of TCP connections from single IP

**Threshold**: > 50 TCP packets

**Alert Example**:
```
[⚠️ ALERT] Possible Port Scan: Potential port scan detected from 192.168.1.200
```

## Protocol Detection

### Supported Protocols
- **TCP**: General TCP traffic
- **UDP**: General UDP traffic
- **HTTP**: Web traffic (port 80)
- **HTTPS**: Secure web (port 443)
- **SSH**: Secure shell (port 22)
- **FTP**: File transfer (port 21)
- **SMTP**: Email (port 25)
- **DNS**: Domain resolution (port 53)
- **DHCP**: IP assignment (ports 67/68)
- **Database**: MySQL (3306), PostgreSQL (5432), MSSQL (1433)
- **ICMP**: Ping and diagnostic

## OS Fingerprinting

### Detection Method
Based on TTL (Time To Live) values:
- **TTL ≤ 64**: Linux/Unix
- **TTL ≤ 128**: Windows
- **TTL ≤ 255**: Cisco/Network Device

### Additional Heuristics
- Window size analysis for Windows detection
- Packet characteristics

## Troubleshooting

### Dashboard not loading?
```powershell
# Check if Python is running
Get-Process python

# Check if port 8080 is in use
netstat -ano | findstr :8080

# Try different port
$env:WEB_PORT = "8090"
python dashboard.py
```

### OUI database not loading?
```powershell
# Verify file exists
Test-Path "d:\5th Sem\ARP_CN\oui.csv"

# Check file permissions
Get-Acl "d:\5th Sem\ARP_CN\oui.csv"

# Dashboard will use fallback database if CSV is missing
```

### No devices discovered?
1. Verify network interface is correct
   ```powershell
   # List interfaces
   ipconfig
   
   # Set correct interface
   $env:IFACE = "Ethernet"  # or "Wi-Fi"
   ```

2. Check if beacon sender is running
   ```powershell
   python beacon_sender.py
   ```

3. Verify firewall isn't blocking ARP packets

### Permission errors?
May need administrator privileges for packet capture:
```powershell
# Run PowerShell as Administrator
# Then run dashboard
python dashboard.py
```

## Architecture Overview

```
┌─────────────────────────────────────┐
│        Web Browser                  │
│    (http://localhost:8080)          │
└──────────────┬──────────────────────┘
               │ HTTP
               ▼
┌─────────────────────────────────────┐
│     Dashboard HTTP Server           │
│   (DashboardHandler)                │
└──────────────┬──────────────────────┘
               │
    ┌──────────┴──────────┬─────────┐
    ▼                     ▼         ▼
┌──────────┐      ┌──────────┐  ┌──────────┐
│Discovery │      │ Traffic  │  │ OUI      │
│ Listener │      │ Analyzer │  │ Lookup   │
│ Thread   │      │ Thread   │  │          │
└──────────┘      └──────────┘  └──────────┘
    │                  │             │
    ▼                  ▼             ▼
┌─────────────────────────────────────┐
│      Scapy Packet Sniffing          │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│      Network Interface              │
└─────────────────────────────────────┘
```

## Performance Considerations

- **Memory**: Stores all discovered devices in RAM
- **CPU**: Minimal overhead, threaded design
- **Network**: Passive monitoring, low impact
- **Auto-refresh**: 5-second interval is configurable in HTML

## Tips & Best Practices

1. **For large networks**: Consider increasing alert thresholds
2. **For monitoring**: Leave running in background, access via browser as needed
3. **For security**: Monitor ARP alerts carefully
4. **For analysis**: Export data periodically (future feature)
5. **For accuracy**: Ensure OUI database is loaded successfully

## Integration with Existing Tools

The dashboard works seamlessly with:
- `beacon_sender.py`: Sends discovery packets
- `beacon_listener.py`: Receives discovery responses
- `tui.py`: Text-based interface (can run separately)
- `utils.py`: Backend process management

## Example Output

### Console Output
```
============================================================
  🚀 Advanced Network Discovery & Monitoring System
============================================================
  Interface: default
  Discovery IP: 10.255.255.255
  Web Dashboard: http://localhost:8080
============================================================

[📚 OUI] Loading vendor database from d:\5th Sem\ARP_CN\oui.csv
[📚 OUI] Loaded 38291 vendor entries
[📡 DISCOVERY] Listening on default interface
[📊 ANALYZER] Monitoring all traffic on default interface
[🌐 DASHBOARD] Running at http://localhost:8080
[🔍 NEW DEVICE] 192.168.1.50 | MAC: E4:65:B8:12:34:56 | Vendor: Espressif Inc.
[🔍 NEW DEVICE] 192.168.1.1 | MAC: 04:A9:59:AB:CD:EF | Vendor: New H3C Technologies Co., Ltd
```

## Keyboard Shortcuts

While dashboard is running:
- **Ctrl+C**: Stop all monitors and exit
- **F5** (in browser): Manual refresh
- **Ctrl+R** (in browser): Manual refresh

## Questions?

Refer to:
- `DASHBOARD_IMPROVEMENTS.md`: Detailed technical documentation
- `README.md`: Project overview
- Source code comments: Inline documentation
