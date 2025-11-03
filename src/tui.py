import time
from typing import Optional  # noqa: F401 (reserved for future use)

# Textual TUI
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container, VerticalScroll
from textual.widgets import (
    Header,
    Footer,
    Button,
    Input,
    Static,
    Label,
    DataTable,
)
from textual.reactive import reactive

try:
    # When running as a script from this folder
    from utils import BackendProcessManager  # type: ignore
except Exception:  # pragma: no cover
    # When imported as a package module
    from .utils import BackendProcessManager  # type: ignore


DEFAULT_DISCOVERY_IP = "10.255.255.255"


class Status(Static):
    """A scrollable widget to show status lines with auto-scroll."""

    lines = reactive([], layout=True)  # type: ignore[assignment]

    def push(self, text: str) -> None:
        now = time.strftime("%H:%M:%S")
        new_line = f"[dim]{now}[/dim] {text}"
        self.lines = (self.lines + [new_line]) if self.lines else [new_line]
        # Keep last 200 lines
        if len(self.lines) > 200:
            self.lines = self.lines[-200:]
        self.update("\n".join(self.lines))


class StatsPanel(Static):
    """Display statistics about sending/listening."""

    sent_count = reactive(0)
    peer_count = reactive(0)
    is_sending = reactive(False)
    is_listening = reactive(False)

    def render(self) -> str:
        send_status = "[green]●[/green] Active" if self.is_sending else "[dim]○[/dim] Inactive"
        listen_status = "[green]●[/green] Active" if self.is_listening else "[dim]○[/dim] Inactive"
        
        return (
            f"[b]Sender:[/b] {send_status}  |  "
            f"[b]Beacons Sent:[/b] {self.sent_count}  |  "
            f"[b]Listener:[/b] {listen_status}  |  "
            f"[b]Peers Found:[/b] {self.peer_count}"
        )


class IPDApp(App):
    CSS = """
    Screen { 
        layout: vertical;
        background: $surface;
    }
    
    #stats_panel {
        dock: top;
        height: 3;
        background: $boost;
        border: tall $primary;
        padding: 1;
        text-align: center;
    }
    
    #main_container {
        layout: vertical;
        height: 1fr;
    }
    
    #controls_section {
        height: auto;
        border: tall $primary;
        background: $panel;
        margin: 1 1 0 1;
    }
    
    #controls_header {
        dock: top;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
        text-style: bold;
    }
    
    .controls_grid {
        padding: 1;
        layout: grid;
        grid-size: 3 2;
        grid-gutter: 1 2;
        height: auto;
    }
    
    .control_group {
        layout: vertical;
        height: auto;
    }
    
    .control_label {
        color: $text-muted;
        text-style: bold;
        margin-bottom: 1;
    }
    
    Input {
        border: tall $primary-lighten-1;
        width: 100%;
    }
    
    Input:focus {
        border: tall $accent;
    }
    
    #buttons_section {
        layout: horizontal;
        height: auto;
        padding: 1;
        margin: 0 1;
        background: $panel;
        border: tall $primary;
        align: center middle;
    }
    
    #buttons_section Button {
        margin: 0 1;
        min-width: 16;
    }
    
    #content_area {
        layout: horizontal;
        height: 1fr;
        margin: 1;
    }
    
    #status_section {
        width: 1fr;
        border: tall $primary;
        background: $panel;
        margin-right: 1;
    }
    
    #status_header {
        dock: top;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
        text-style: bold;
    }
    
    #status_scroll {
        height: 1fr;
        padding: 1;
        overflow-y: scroll;
    }
    
    #peers_section {
        width: 2fr;
        border: tall $primary;
        background: $panel;
    }
    
    #peers_header {
        dock: top;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
        text-style: bold;
    }
    
    DataTable {
        height: 1fr;
        margin: 1;
    }
    
    .collapsible {
        transition: height 200ms;
    }
    
    .hidden {
        display: none;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "toggle_controls", "Controls"),
        ("s", "focus_send", "Send"),
        ("l", "focus_listen", "Listen"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.backend = BackendProcessManager()
        self.controls_visible = True

    # -------------------------- Compose UI ------------------------
    def compose(self) -> ComposeResult:  # type: ignore[override]
        yield Header(show_clock=True)
        yield StatsPanel(id="stats_panel")
        
        with Container(id="main_container"):
            # Controls section
            with Container(id="controls_section"):
                yield Label("⚙ Configuration", id="controls_header")
                with Container(classes="controls_grid"):
                    # Row 1
                    with Vertical(classes="control_group"):
                        yield Label("Discovery IP", classes="control_label")
                        yield Input(value=DEFAULT_DISCOVERY_IP, id="discovery_ip", 
                                  placeholder="e.g., 10.255.255.255")
                    
                    with Vertical(classes="control_group"):
                        yield Label("Source IP", classes="control_label")
                        yield Input(value="auto", id="src_ip", 
                                  placeholder="auto or IP")
                    
                    with Vertical(classes="control_group"):
                        yield Label("Source MAC", classes="control_label")
                        yield Input(value="00:11:22:33:44:55", id="src_mac",
                                  placeholder="MAC address")
                    
                    # Row 2
                    with Vertical(classes="control_group"):
                        yield Label("Interval (seconds)", classes="control_label")
                        yield Input(value="5", id="interval",
                                  placeholder="e.g., 5")
                    
                    with Vertical(classes="control_group"):
                        yield Label("Interface (optional)", classes="control_label")
                        yield Input(placeholder="e.g., eth0", id="iface")
                    
                    with Vertical(classes="control_group"):
                        yield Static("")  # Spacer
            
            # Buttons section
            with Horizontal(id="buttons_section"):
                yield Button("▶ Start Send", id="start_send", variant="success")
                yield Button("⏹ Stop Send", id="stop_send", variant="warning")
                yield Button("🎧 Start Listen", id="start_listen", variant="primary")
                yield Button("⏹ Stop Listen", id="stop_listen", variant="warning")
                yield Button("🗑 Clear Peers", id="clear_peers", variant="default")
            
            # Content area (Status + Peers)
            with Horizontal(id="content_area"):
                # Status log
                with Container(id="status_section"):
                    yield Label("📋 Status Log", id="status_header")
                    with VerticalScroll(id="status_scroll"):
                        yield Status(id="status")
                
                # Peers table
                with Container(id="peers_section"):
                    yield Label("👥 Discovered Peers", id="peers_header")
                    table = DataTable(id="peers_table")
                    table.add_columns("IP Address", "MAC Address")
                    yield table

        yield Footer()

    def action_toggle_controls(self) -> None:
        """Toggle visibility of controls section."""
        controls = self.query_one("#controls_section", Container)
        self.controls_visible = not self.controls_visible
        if self.controls_visible:
            controls.remove_class("hidden")
        else:
            controls.add_class("hidden")

    def action_focus_send(self) -> None:
        """Focus the start send button."""
        self.query_one("#start_send", Button).focus()

    def action_focus_listen(self) -> None:
        """Focus the start listen button."""
        self.query_one("#start_listen", Button).focus()

    # -------------------------- Helpers --------------------------
    def _get_input(self, id_: str) -> str:
        widget = self.query_one(f"#{id_}", Input)
        return (widget.value or "").strip()

    def _status(self, msg: str) -> None:
        self.query_one(Status).push(msg)

    def _update_stats(self) -> None:
        """Update the statistics panel."""
        stats = self.query_one(StatsPanel)
        stats.is_sending = self.backend.sender_running if hasattr(self.backend, 'sender_running') else False
        stats.is_listening = self.backend.listener_running if hasattr(self.backend, 'listener_running') else False
        table = self.query_one("#peers_table", DataTable)
        stats.peer_count = len(table.rows)

    # -------------------------- Actions --------------------------
    def on_button_pressed(
        self, event: Button.Pressed
    ) -> None:  # type: ignore[override]
        btn_id = event.button.id
        if btn_id == "start_send":
            self._start_sending()
        elif btn_id == "stop_send":
            self._stop_sending()
        elif btn_id == "start_listen":
            self._start_listening()
        elif btn_id == "stop_listen":
            self._stop_listening()
        elif btn_id == "clear_peers":
            self._clear_peers()
        
        self._update_stats()

    # -------------------------- Send flow ------------------------
    def _start_sending(self) -> None:
        try:
            discovery_ip = (
                self._get_input("discovery_ip") or DEFAULT_DISCOVERY_IP
            )
            src_ip = self._get_input("src_ip")
            if src_ip.lower() == "auto":
                # Lazy local IP detection via socket trick
                import socket

                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect(("8.8.8.8", 80))
                    src_ip = s.getsockname()[0]
                finally:
                    s.close()

            src_mac = self._get_input("src_mac") or "00:11:22:33:44:55"
            interval = float(self._get_input("interval") or "5")
            iface = self._get_input("iface") or None

            # Launch backend sender process and stream logs
            stats = self.query_one(StatsPanel)
            stats.sent_count = 0

            def on_output(line: str) -> None:
                if "Beacon sent" in line:
                    stats.sent_count += 1
                    self.call_from_thread(self._update_stats)
                self.call_from_thread(self._status, line)

            self.backend.start_sender(
                discovery_ip=discovery_ip,
                src_ip=src_ip,
                src_mac=src_mac,
                interval=interval,
                iface=iface,
                on_output=on_output,
            )
            self._status(
                f"[green]✓[/green] Started sending to {discovery_ip} "
                f"as {src_ip} ({src_mac}) every {interval}s"
                + (f" on interface '{iface}'" if iface else "")
            )
            self._update_stats()
        except Exception as e:
            self._status(f"[red]✗[/red] Failed to start sending: {e}")

    def _stop_sending(self) -> None:
        self.backend.stop_sender()
        self._status("[yellow]⏹[/yellow] Stopped sending beacons")
        self._update_stats()

    # -------------------------- Listen flow ----------------------
    def _start_listening(self) -> None:
        try:
            discovery_ip = (
                self._get_input("discovery_ip") or DEFAULT_DISCOVERY_IP
            )
            iface = self._get_input("iface") or None

            table = self.query_one("#peers_table", DataTable)
            table.clear()
            # table.add_columns("IP Address", "MAC Address")

            def on_output(line: str) -> None:
                self.call_from_thread(self._status, line)

            def on_peer(ip: str, mac: str) -> None:
                def _add() -> None:
                    table.add_row(ip, mac)
                    self._update_stats()
                self.call_from_thread(_add)

            self.backend.start_listener(
                discovery_ip=discovery_ip,
                iface=iface,
                on_output=on_output,
                on_peer=on_peer,
            )
            self._status(
                f"[green]✓[/green] Listening for ARP discovery to {discovery_ip}"
                + (f" on interface '{iface}'" if iface else "")
            )
            self._update_stats()
        except Exception as e:
            self._status(f"[red]✗[/red] Failed to start listener: {e}")

    def _stop_listening(self) -> None:
        self.backend.stop_listener()
        self._status("[yellow]⏹[/yellow] Stopped listening")
        self._update_stats()

    # -------------------------- Misc -----------------------------
    def _clear_peers(self) -> None:
        table = self.query_one("#peers_table", DataTable)
        table.clear()
        # table.add_columns("IP Address", "MAC Address")
        self._status("[blue]ℹ[/blue] Cleared discovered peers table")
        self._update_stats()


if __name__ == "__main__":
    IPDApp().run()