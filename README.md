# IPD TUI

A simple Textual-based terminal UI to send and listen for ARP discovery beacons used by the IPD exercises.

## Features

- Start/stop sending ARP beacons to a configurable discovery IP
- Start/stop listening for ARP discovery packets and list discovered peers (IP, MAC)
- Configure source IP (auto), source MAC, interval, and optional interface
- Live status log

## Requirements

- Python 3.9+
- Windows, macOS, or Linux
- Administrator privileges for raw packet send/receive (run your terminal as Administrator on Windows)

Install dependencies (using the `ipd/requirements.txt`):

```pwsh
# From repo root or the ipd folder
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install -r ipd/requirements.txt
```

If you're using the provided `venipd` environment, just activate it instead:

```pwsh
# From repo root
. ipd/ipd/Scripts/Activate.ps1
```

## Run the TUI

```pwsh
# From repo root
python ipd/ipd/src/tui.py
```

Tips:
- Interface name is optional. On Windows, you may need to choose the correct NPF interface name (e.g., `Ethernet`).
- Use the same Discovery IP (`10.255.255.255`) across sender and listener for them to match.
- Run as Administrator to allow Scapy to send/receive at layer 2.

## Troubleshooting

- If you see permission errors or no packets observed, run PowerShell as Administrator.
- If no interface is specified and nothing shows up, try setting the exact interface name.
- On Windows, make sure Npcap is installed with "Support raw 802.11 traffic (and monitor mode)" if you plan to use Wi‑Fi.
