import os
import sys
import threading
import subprocess
from pathlib import Path
from typing import Optional, Callable


class BackendProcessManager:
    """Manage backend processes for sender and listener.

    Spawns the existing Python scripts as subprocesses so the TUI can remain a
    thin front-end. We pass configuration via environment variables.
    """

    def __init__(self, repo_root: Optional[str] = None) -> None:
        self._sender_proc: Optional[subprocess.Popen] = None
        self._listener_proc: Optional[subprocess.Popen] = None
        self._listener_thread: Optional[threading.Thread] = None
        base = Path(__file__).resolve().parents[2]
        self._repo_root = Path(repo_root) if repo_root else base

    # -------------- Utilities --------------
    def _python(self) -> str:
        return sys.executable

    def _script(self, name: str) -> str:
        # return str(self._repo_root / "ipd" / "ipd" / "src" / f"{name}.py")
        return str(self._repo_root / "ipd" / "src" / f"{name}.py")

    # -------------- Sender -----------------
    def start_sender(
        self,
        discovery_ip: str,
        src_ip: str,
        src_mac: str,
        interval: float,
        iface: Optional[str] = None,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> None:
        if self._sender_proc and self._sender_proc.poll() is None:
            return

        env = os.environ.copy()
        env.update(
            {
                "DISCOVERY_IP": discovery_ip,
                "SRC_IP": src_ip,
                "SRC_MAC": src_mac,
                "INTERVAL": str(interval),
            }
        )
        if iface:
            env["IFACE"] = iface
        else:
            env.pop("IFACE", None)

        self._sender_proc = subprocess.Popen(
            [self._python(), self._script("beacon_sender")],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            bufsize=1,
        )

        if on_output and self._sender_proc.stdout:
            t = threading.Thread(
                target=self._pump_output,
                args=(self._sender_proc, on_output),
                daemon=True,
            )
            t.start()

    def stop_sender(self) -> None:
        if self._sender_proc and self._sender_proc.poll() is None:
            self._sender_proc.terminate()
            try:
                self._sender_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._sender_proc.kill()
        self._sender_proc = None

    # -------------- Listener ---------------
    def start_listener(
        self,
        discovery_ip: str,
        iface: Optional[str] = None,
        on_output: Optional[Callable[[str], None]] = None,
        on_peer: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        if self._listener_proc and self._listener_proc.poll() is None:
            return

        env = os.environ.copy()
        env.update({"DISCOVERY_IP": discovery_ip})
        if iface:
            env["IFACE"] = iface
        else:
            env.pop("IFACE", None)

        self._listener_proc = subprocess.Popen(
            [self._python(), self._script("beacon_listener")],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            bufsize=1,
        )

        # Pump listener output (detect peers)
        if self._listener_proc.stdout:
            self._listener_thread = threading.Thread(
                target=self._pump_listener,
                args=(self._listener_proc, on_output, on_peer),
                daemon=True,
            )
            self._listener_thread.start()

    def stop_listener(self) -> None:
        if self._listener_proc and self._listener_proc.poll() is None:
            self._listener_proc.terminate()
            try:
                self._listener_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._listener_proc.kill()
        self._listener_proc = None
        self._listener_thread = None

    # -------------- Pumpers ----------------
    def _pump_output(
        self, proc: subprocess.Popen, cb: Callable[[str], None]
    ) -> None:
        assert proc.stdout
        for line in proc.stdout:
            cb(line.rstrip())

    def _pump_listener(
        self,
        proc: subprocess.Popen,
        on_output: Optional[Callable[[str], None]],
        on_peer: Optional[Callable[[str, str], None]],
    ) -> None:
        assert proc.stdout
        for raw in proc.stdout:
            line = raw.rstrip()
            if on_output:
                on_output(line)
            # Parse standard format: [NEW PEER] <ip> | MAC: <mac>
            if line.startswith("[NEW PEER]"):
                try:
                    # Split robustly
                    head, rest = line.split("]", 1)
                    rest = rest.strip()
                    ip_part, mac_part = rest.split("|", 1)
                    ip = ip_part.strip()
                    if ip.startswith("[NEW PEER]"):
                        ip = ip[len("[NEW PEER]"):].strip()
                    mac = mac_part.replace("MAC:", "").strip()
                    if on_peer:
                        on_peer(ip, mac)
                except Exception:
                    # Ignore parse errors, still forward output
                    pass
