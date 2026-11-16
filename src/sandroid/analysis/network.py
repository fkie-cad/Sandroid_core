# ensure that we only see errors from scapy
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from logging import getLogger
from typing import Any

from sandroid.core.adb import Adb
from sandroid.core.events.events import (
    NetworkEvent,
    TaskOutput,
    TaskStopped,
)
from sandroid.services import get_network_capture_service

from .base_di import DataGatherBase

logger = getLogger(__name__)

# ----------------------------------------------------------------------
# Dry-run (background) comparison thresholds
# ----------------------------------------------------------------------
# A destination (IP:port) or DNS name that also shows up in the dry-run
# "noise" capture is *not* dropped just for having been seen: shared CDN /
# load-balancer IPs (Wikimedia serves en.wikipedia.org, meta and
# intake-analytics from one address) are often touched once in the
# background and then carry megabytes when the app is actually used.
# Instead the busiest action run is compared with the dry run, per
# destination, and the destination stays in the result when *any* of
#
#     action payload bytes  > FACTOR * background bytes       + BYTES_FLOOR
#     action packets        > FACTOR * background packets     + PACKETS_FLOOR
#     action connections    > FACTOR * background connections + CONN_FLOOR
#
# holds. It is then annotated with "also seen in background: ...". Only
# destinations whose volume is comparable to the background count as noise;
# they are listed (with both volumes) under Other Data -> Filtered Noise.
# The factor absorbs normal run-to-run jitter of periodic background traffic
# (a dry run and an action run last about as long); the floors keep a
# handful of extra packets (one retransmit, a keep-alive, a second TLS
# session) from turning a background destination into a finding.
#: Multiple of the dry-run volume an action run must exceed.
NOISE_VOLUME_FACTOR = 3.0
#: Payload bytes an action run may exceed ``FACTOR x`` background by.
NOISE_BYTES_FLOOR = 2048
#: Packets an action run may exceed ``FACTOR x`` background by.
NOISE_PACKETS_FLOOR = 20
#: Connections (distinct local ports) an action run may exceed it by.
NOISE_CONNECTIONS_FLOOR = 2
#: DNS queries for a name an action run may exceed ``FACTOR x`` it by. A
#: DNS name is also kept whenever a destination reported above background
#: resolved to it -- the query count alone says little because resolvers
#: cache answers.
NOISE_DNS_QUERIES_FLOOR = 2


@dataclass
class _Volume:
    """Traffic to/from one destination within one capture."""

    sent: int = 0
    received: int = 0
    packets: int = 0
    local_ports: set[int] = field(default_factory=set)

    @property
    def total(self) -> int:
        """Payload bytes in both directions."""
        return self.sent + self.received

    @property
    def connections(self) -> int:
        """Distinct guest-side ports, i.e. TCP connections / UDP flows."""
        return len(self.local_ports)

    def describe(self) -> str:
        """``12345B in 7 packets / 2 connections``."""
        return (
            f"{self.total}B in {self.packets} packets / {self.connections} connections"
        )


def _above_background(action: _Volume, noise: _Volume) -> bool:
    """Whether ``action`` is substantially more than the dry-run ``noise``.

    See the threshold constants above for the rule and its rationale.
    """
    factor = NOISE_VOLUME_FACTOR
    return (
        action.total > factor * noise.total + NOISE_BYTES_FLOOR
        or action.packets > factor * noise.packets + NOISE_PACKETS_FLOOR
        or action.connections > factor * noise.connections + NOISE_CONNECTIONS_FLOOR
    )


# Lazy import for scapy to avoid slow module-level import that blocks TUI
# Scapy's import can take several seconds and holds the GIL
_scapy_imported = False


def _ensure_scapy():
    """Lazily import scapy modules only when needed for packet analysis."""
    global _scapy_imported
    if not _scapy_imported:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        global DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP, rdpcap
        from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, IPv6, rdpcap

        _scapy_imported = True


class Network(DataGatherBase):
    """Handles network traffic measurement and analysis.

    **Attributes:**
        internal_run_counter (int): Counter for internal runs.
        connections_made (None): Placeholder for connections made.
        dns_requests (set): Set of DNS requests.
        logger (Logger): Logger instance for the class.
        _emulator_path (str): Path on the emulator for storing trace files.
        _trace_file_name (str): Base name for trace files.
        performed_diff (bool): Flag indicating if the diff has been performed.
        _current_capture_file (str): Path to the currently active capture file.
        _capture_running (bool): Flag indicating if capture is running.
        _stop_event (threading.Event): Event to signal thread to stop early.
    """

    # Class-level variables for shared state
    internal_run_counter = 1
    connections_made = None
    dns_requests = set()
    _emulator_path = "data/local/tmp/"
    _trace_file_name = "network_trace_run_"
    performed_diff = False

    def __init__(self, **kwargs) -> None:
        """Initialize Network instance with proper instance variables.

        Args:
            **kwargs: Arguments passed to DataGatherBase including:
                - forensic_service: ForensicService for file tracking.
                - adb: ADB interface for device communication.
                - config: Configuration object.
                - logger: Logger instance.
        """
        super().__init__(**kwargs)
        self._current_capture_file = None
        self._capture_running = False
        self._stop_event = None
        self._thread = None
        self._capture_start_time = None
        self._stop_lock = threading.Lock()
        # Dry-run destinations / DNS names subtracted from the result
        # (``{section: {entry: reason}}``), surfaced by the analysis engine
        # under Other Data -> Filtered Noise instead of dropping them.
        self.filtered_network_noise: dict[str, dict[str, str]] = {}

    def get_expected_capture_path(self) -> str:
        """Get the expected capture file path without starting capture.

        This allows callers to know where the capture will be saved before
        starting, useful for showing confirmation dialogs.

        Returns:
            The full path where the next capture will be saved.
        """
        toolbox = self._get_toolbox()
        base_path = self._get_path()
        if toolbox.is_dry_run():
            return f"{base_path}{self._trace_file_name}noise.pcap"
        return f"{base_path}{self._trace_file_name}{self.internal_run_counter!s}.pcap"

    @classmethod
    def _get_path(cls) -> str:
        """Get the network trace path dynamically.

        The environment variable may not be set at import time, so this method
        retrieves the path lazily.

        Returns:
            The full path for storing network trace files, combining the
            RAW_RESULTS_PATH environment variable with 'network_trace_pull/'.
        """
        raw_results_path = os.getenv("RAW_RESULTS_PATH", "")
        return f"{raw_results_path}network_trace_pull/"

    def gather(self) -> None:
        """Start network traffic capture in a dedicated background thread.

        Initiates a tcpdump-based network capture on the emulator. ALL capture
        operations run in a daemon thread to avoid blocking the TUI or command
        execution. The capture continues until stop() is called.

        The capture can be stopped by calling the stop() method (e.g., when
        user presses 'w' again).
        """
        logger.info("Starting network capture thread")
        self._stop_event = threading.Event()
        self._capture_running = True  # Set immediately to avoid race condition
        self._capture_start_time = time.time()

        # Start dedicated capture thread - ALL work happens there
        self._thread = threading.Thread(
            target=self._capture_thread_worker, args=(), daemon=True
        )
        self._thread.start()
        # Return immediately - don't wait for thread to initialize

    def gather_for_duration(self, duration_seconds: int) -> str:
        """Start network capture for a specified duration, then auto-stop.

        Duration-based capture entry point for headless/CLI mode. Starts a
        background capture thread and blocks the calling thread for the
        specified number of seconds before automatically stopping.

        Args:
            duration_seconds: How many seconds to capture. Must be >= 5.

        Returns:
            The path to the generated PCAP file, or None if capture failed
            to start.

        Raises:
            ValueError: If duration_seconds < 5.
        """
        if duration_seconds < 5:
            raise ValueError(
                f"Capture duration must be at least 5 seconds, got {duration_seconds}"
            )

        logger.info(f"Starting headless network capture for {duration_seconds}s")
        self._stop_event = threading.Event()
        self._capture_running = True
        self._capture_start_time = time.time()

        # Start dedicated headless capture thread
        self._thread = threading.Thread(
            target=self._headless_capture_worker, daemon=True
        )
        self._thread.start()

        # Block calling thread for the specified duration
        self._stop_event.wait(timeout=duration_seconds)

        # Auto-stop capture
        self.stop()

        return self._current_capture_file

    def _capture_thread_worker(self) -> None:
        """Worker thread for network capture - runs completely in background.

        This method runs all capture operations in a dedicated thread to avoid
        blocking the TUI. Event publishing also happens here.
        """
        try:
            # NOTE: TaskStarted event is published by task_service.register()
            # in _start_network_capture_worker() - don't duplicate here

            # Run the actual capture
            self.tcpdump_thread()
        except Exception as e:
            logger.exception(f"Network capture thread error: {e}")
            self._capture_running = False

    def _headless_capture_worker(self) -> None:
        """Worker thread for headless network capture.

        A simplified capture worker for headless mode that avoids TUI-specific
        dry_run logic and run counter. Generates a timestamp-based PCAP file,
        starts tcpdump capture, and blocks until the stop event is signalled
        by gather_for_duration's timeout.
        """
        try:
            from pathlib import Path

            base_path = self._get_path()
            base_path_obj = Path(base_path)
            base_path_obj.mkdir(parents=True, exist_ok=True)
            base_path = str(base_path_obj.resolve()) + os.sep

            # Generate timestamp-based filename
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            capture_file = f"{base_path}headless_capture_{timestamp}.pcap"
            self._current_capture_file = capture_file

            # Start capture service
            get_network_capture_service().start_capture(
                capture_file, capture_type="tcpdump"
            )

            # Send telnet command to start capture
            command = f"network capture start {capture_file}"
            out, err = Adb.send_telnet_command(command)

            # Verify capture started successfully
            if "OK" not in out:
                logger.error(f"Headless network capture failed to start: {out} {err}")
                with self._stop_lock:
                    self._capture_running = False
                get_network_capture_service().stop_capture()
                return

            # Register tool usage
            self._get_toolbox().mark_tool_used("network", files=[capture_file])

            # Wait until stop event is signalled by gather_for_duration
            if self._stop_event:
                self._stop_event.wait()

            # Stop capture cleanly
            self._stop_capture()
        except Exception as e:
            logger.exception(f"Headless capture thread error: {e}")
            self._capture_running = False

    def return_data(self) -> dict[str, Any]:
        """Return the gathered DNS requests and target IP:port connections.

        Processes captured PCAP files to extract DNS queries and TCP connection
        targets. Results are compared with the dry-run 'noise' capture: only
        destinations whose volume is comparable to the background are
        subtracted (and kept in :attr:`filtered_network_noise`); busier ones
        stay, annotated with their background volume.

        Returns:
            A dictionary with two keys:
                - "Network": List of unique DNS domain names queried (a name
                  also queried in the dry run carries an "(also seen in
                  background: N queries)" suffix).
                - "Network IP:Port (send/recv)": List of unique IP:port targets
                  with byte counts sent and received.
        """
        if not self.performed_diff:
            self._analyse_all_pcaps()
        return {
            "Network": self.dns_requests,
            "Network IP:Port (send/recv)": self.target_ips_and_ports,
        }

    def analyze_pcap(self, pcap_path: str) -> dict[str, Any]:
        """Analyze a single PCAP file without noise subtraction.

        Extracts DNS queries, TCP connection targets, and byte counts from
        a single PCAP file. Unlike return_data(), this does not require a
        noise baseline capture for comparison -- it returns raw results
        from the specified file.

        Designed for headless/CLI mode where a single capture is analyzed
        directly.

        Args:
            pcap_path: Path to the PCAP file to analyze.

        Returns:
            A dictionary containing:
                - pcap_file: Path to the analyzed file
                - dns_queries: Sorted list of queried domain names
                - tcp_connections: Sorted list of IP:port targets
                - ip_analysis: List of dicts with ip, port, bytes_sent,
                  bytes_received for each connection
                - total_dns_queries: Count of unique DNS queries
                - total_tcp_connections: Count of unique TCP connections
        """
        _ensure_scapy()

        packets = self._read_pcap(pcap_path)

        # Extract DNS requests
        dns_queries = self._dns_queries_in(packets)

        # Extract connection targets (TCP SYNs + non-DNS UDP)
        tcp_targets = self._targets_in(packets)

        # Calculate byte counts for each connection
        dns_names = self._dns_answers_in(packets)
        ip_analysis = []
        for ip_and_port in sorted(tcp_targets):
            target_ip, target_port, proto = self._parse_endpoint(ip_and_port)
            bytes_sent, bytes_received = self._count_bytes_in(
                packets, target_ip, target_port, proto
            )
            sni = (
                self._sni_names_in(packets, target_ip, target_port)
                if proto == "tcp"
                else set()
            )
            ip_analysis.append(
                {
                    "ip": target_ip,
                    "port": target_port,
                    "protocol": proto,
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
                    "dns_names": sorted(dns_names.get(target_ip, set())),
                    "tls_sni": sorted(sni),
                }
            )

        return {
            "pcap_file": pcap_path,
            "dns_queries": sorted(dns_queries),
            "tcp_connections": sorted(tcp_targets),
            "ip_analysis": ip_analysis,
            "total_dns_queries": len(dns_queries),
            "total_tcp_connections": len(tcp_targets),
        }

    def pretty_print(self) -> str:
        """Return a Rich-formatted string of network analysis results.

        Formats the DNS requests and IP:port connection data with Rich markup
        for display in the terminal. Results are sorted for consistency.

        Returns:
            A Rich-formatted string containing DNS requests and target IP:port
            connections with send/receive byte counts.
        """
        if not self.performed_diff:
            self._analyse_all_pcaps()

        result = (
            "[warning bold]"
            "\n—————————————————NETWORK=(DNS requests made by emulator)———————————————————————————————————————————————\n"
            "[/warning bold]"
        )
        for entry in sorted(self.dns_requests):
            result += f"[warning]{entry}[/warning]\n"
        result = result + (
            "[warning bold]"
            "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            "[/warning bold]"
        )

        result += (
            "[accent bold]"
            "\n—————————————————NETWORK=(Target IP ports)———————————————————————————————————————————————————————\n"
            "[/accent bold]"
        )
        for entry in self.target_ips_and_ports:
            result += f"[accent]{entry}[/accent]\n"
        hidden = sum(len(v) for v in self.filtered_network_noise.values())
        if hidden:
            result += (
                f"[accent]({hidden} DNS name(s) / target(s) comparable to the "
                "dry-run background hidden, see Other Data -> Filtered Noise)"
                "[/accent]\n"
            )
        result += (
            "[accent bold]"
            "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
            "[/accent bold]"
        )

        return result

    def tcpdump_thread(self) -> None:
        """Execute network capture via ADB emulator telnet command.

        This method is designed to run in a background thread. It starts a
        tcpdump capture on the emulator and waits indefinitely until stop()
        is called (typically when user presses 'w' again).

        During dry runs, captures to a 'noise' file for baseline comparison.
        During normal runs, captures are numbered sequentially.

        The method publishes TaskStopped and TaskOutput events upon completion.
        """
        base_path = self._get_path()

        # Ensure capture directory exists and convert to absolute path
        # The emulator's telnet "network capture start" command requires an absolute path
        from pathlib import Path

        base_path_obj = Path(base_path)
        base_path_obj.mkdir(parents=True, exist_ok=True)
        base_path = str(base_path_obj.resolve()) + "/"  # Ensure trailing slash

        noise_path = f"{base_path}{self._trace_file_name}noise.pcap"
        path = f"{base_path}{self._trace_file_name}{self.internal_run_counter!s}.pcap"
        accumulated_errors = ""
        toolbox = self._get_toolbox()
        if toolbox.is_dry_run():
            command = f"network capture start {noise_path}"
            capture_file = noise_path
        else:
            command = f"network capture start {path}"
            capture_file = path

        # Track current capture file (capture_running already set in gather())
        self._current_capture_file = capture_file
        get_network_capture_service().start_capture(
            capture_file, capture_type="tcpdump"
        )

        out, err = Adb.send_telnet_command(command)
        accumulated_errors += err

        # Verify capture started successfully
        if "OK" not in out:
            logger.error(f"Network capture failed to start: {out} {err}")
            with self._stop_lock:
                self._capture_running = False
            get_network_capture_service().stop_capture()
            TaskStopped(
                task_name="network",
                display_name="Network Capture",
                success=False,
                duration_seconds=0,
                source="network",
            ).publish()
            return

        # Register tool usage for exit summary
        toolbox.mark_tool_used("network", files=[capture_file])

        # Wait indefinitely until stop() is called (user presses 'w' again)
        # The stop_event will be set when user wants to stop capture
        if self._stop_event:
            self._stop_event.wait()  # No timeout - runs until manually stopped
        else:
            # Fallback: wait indefinitely (should not happen in normal usage)
            while self._capture_running:
                time.sleep(1)

        # Stop capture - lock ensures single execution even if stop() was called
        self._stop_capture()

        self.internal_run_counter += 1
        if accumulated_errors:
            logger.error(
                f"Errors occurred during network capture: {accumulated_errors}"
            )

    def _stop_capture(self) -> None:
        """Stop the current network capture and publish completion events.

        Sends the stop command to the emulator via telnet, calculates capture
        duration, and publishes TaskStopped and TaskOutput events. This method
        is thread-safe and idempotent - safe to call from multiple threads.
        """
        # Atomically check and clear _capture_running
        with self._stop_lock:
            if not self._capture_running:
                return
            self._capture_running = False
            capture_file = self._current_capture_file
            start_time = self._capture_start_time

        # Calculate duration outside lock
        duration = 0.0
        if start_time:
            duration = time.time() - start_time

        # Send stop command (correct syntax - no filename parameter)
        success = True
        if capture_file:
            out, err = Adb.send_telnet_command("network capture stop")
            if err or "OK" not in out:
                logger.error(f"Error stopping network capture: {err or out}")
                success = False
            # NOTE: Don't log here - network_capture_service.stop_capture() logs it
        else:
            logger.debug("Network capture stopped before file was set")

        # Update service state
        get_network_capture_service().stop_capture()

        # Publish task stopped event
        TaskStopped(
            task_name="network",
            display_name="Network Capture",
            success=success,
            duration_seconds=duration,
            source="network",
        ).publish()

        # Publish summary output
        TaskOutput(
            task_name="network",
            message=f"Network capture completed after {duration:.1f}s",
            level="info",
            source="network",
        ).publish()

    def stop(self) -> None:
        """Stop network capture early before the configured timeout.

        Signals the capture thread to wake up from its wait state and stops
        the active capture. This method is thread-safe and can be called
        even if no capture is currently running.
        """
        # Signal the thread to wake up from Event.wait()
        if self._stop_event:
            self._stop_event.set()

        # Call _stop_capture() - lock ensures it only runs once
        self._stop_capture()

        # Wait for thread to finish cleanly
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    @classmethod
    def get_path(cls) -> str:
        """Return the path for storing network trace files.

        Returns:
            The full path for storing network trace PCAP files.
        """
        return cls._get_path()

    @classmethod
    def get_file_name(cls) -> str:
        """Return the base name prefix for trace files.

        Returns:
            The base name prefix used for network trace files
            (e.g., 'network_trace_run_').
        """
        return cls._trace_file_name

    # ------------------------------------------------------------------
    # PCAP discovery / reading
    # ------------------------------------------------------------------

    def _run_pcap_paths(self) -> list[str]:
        """Return the existing per-run capture files, in run order.

        Discovered from disk instead of derived from ``internal_run_counter``:
        the old ``range(1, counter - 1)`` arithmetic assumed a dry-run capture
        had also bumped the counter, so with the noise filter off (or a single
        run) the last real capture was silently never analysed.
        """
        base_path = self._get_path()
        found: list[tuple[int, str]] = []
        try:
            names = os.listdir(base_path)
        except OSError:
            return []
        prefix = self._trace_file_name
        for name in names:
            if not (name.startswith(prefix) and name.endswith(".pcap")):
                continue
            index = name[len(prefix) : -len(".pcap")]
            if index.isdigit():
                found.append((int(index), os.path.join(base_path, name)))
        return [path for _, path in sorted(found)]

    def _noise_pcap_path(self) -> str:
        """Path of the dry-run (noise) capture."""
        return f"{self._get_path()}{self._trace_file_name}noise.pcap"

    @staticmethod
    def _read_pcap(pcap_path: str) -> list[Any]:
        """Read a capture, returning ``[]`` if it is missing or unreadable.

        A missing noise capture (noise filter off) or a capture that never
        started must not abort the whole network result.
        """
        _ensure_scapy()
        if not pcap_path or not os.path.isfile(pcap_path):
            logger.debug(f"No capture file at {pcap_path}")
            return []
        try:
            return list(rdpcap(pcap_path))
        except Exception as exc:
            logger.warning(f"Could not read capture {pcap_path}: {exc}")
            return []

    # ------------------------------------------------------------------
    # Packet parsing helpers (operate on already-read packet lists)
    # ------------------------------------------------------------------

    @staticmethod
    def _ip_layer(pkt: Any) -> Any:
        """Return the IPv4 or IPv6 layer of ``pkt`` (or ``None``)."""
        if pkt.haslayer(IP):
            return pkt[IP]
        if pkt.haslayer(IPv6):
            return pkt[IPv6]
        return None

    @staticmethod
    def _format_endpoint(ip: str, port: int, proto: str) -> str:
        """``ip:port`` for TCP, ``ip:port/udp`` for UDP; IPv6 in brackets."""
        host = f"[{ip}]" if ":" in ip else ip
        suffix = "/udp" if proto == "udp" else ""
        return f"{host}:{port}{suffix}"

    @staticmethod
    def _parse_endpoint(endpoint: str) -> tuple[str, int, str]:
        """Inverse of :meth:`_format_endpoint`."""
        proto = "tcp"
        if endpoint.endswith("/udp"):
            proto = "udp"
            endpoint = endpoint[: -len("/udp")]
        host, _, port = endpoint.rpartition(":")
        return host.strip("[]"), int(port), proto

    @staticmethod
    def _is_local_or_multicast(ip: str) -> bool:
        """Whether ``ip`` is the emulator's virtual LAN, multicast or broadcast."""
        if ip.startswith(("10.0.2.", "224.", "239.", "255.", "ff0", "fe80:")):
            return True
        return ip in ("0.0.0.0", "::")  # nosec B104 - comparison only

    @classmethod
    def _dns_queries_in(cls, packets: list[Any]) -> set[str]:
        domain_names: set[str] = set()
        for pkt in packets:
            if not pkt.haslayer(DNS):
                continue
            dns = pkt.getlayer(DNS)
            if dns.qr != 0 or not dns.qd:
                continue
            try:
                dns_query = dns.qd[0]
            except (IndexError, TypeError):
                continue
            if dns_query is not None and isinstance(dns_query, DNSQR):
                # mDNS (5353) is LAN service discovery, not a lookup.
                if pkt.haslayer(UDP) and pkt[UDP].dport == 5353:
                    continue
                domain_names.add(dns_query.qname.decode(errors="replace"))
        return domain_names

    @classmethod
    def _targets_in(cls, packets: list[Any]) -> set[str]:
        """Outbound connection targets: TCP SYNs + non-DNS unicast UDP."""
        targets: set[str] = set()
        for pkt in packets:
            ip = cls._ip_layer(pkt)
            if ip is None:
                continue
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                # SYN without ACK == connection initiation by the guest.
                if "S" in str(flags) and "A" not in str(flags):
                    targets.add(cls._format_endpoint(ip.dst, pkt[TCP].dport, "tcp"))
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                if udp.dport in (53, 5353, 67, 68) or udp.sport in (53, 5353):
                    continue
                if cls._is_local_or_multicast(ip.dst):
                    continue
                targets.add(cls._format_endpoint(ip.dst, udp.dport, "udp"))
        return targets

    @classmethod
    def _count_bytes_in(
        cls, packets: list[Any], ip_address: str, port: int, proto: str = "tcp"
    ) -> tuple[int, int]:
        """Payload bytes (sent to, received from) ``ip_address:port``."""
        layer = TCP if proto == "tcp" else UDP
        sent_bytes = 0
        received_bytes = 0
        for pkt in packets:
            ip = cls._ip_layer(pkt)
            if ip is None or not pkt.haslayer(layer):
                continue
            seg = pkt[layer]
            if ip.dst == ip_address and seg.dport == port:
                sent_bytes += cls._payload_len(ip, seg, proto)
            elif ip.src == ip_address and seg.sport == port:
                received_bytes += cls._payload_len(ip, seg, proto)
        return sent_bytes, received_bytes

    @staticmethod
    def _payload_len(ip: Any, seg: Any, proto: str) -> int:
        """Transport payload length taken from the IP/UDP length fields.

        The header fields give the size on the wire, so Ethernet padding of
        short frames is not counted as payload and captures cut by a snap
        length still count every byte. Falls back to the captured payload
        when a length field is missing.
        """
        try:
            if proto == "udp" and seg.len is not None:
                return max(0, seg.len - 8)
            header = (seg.dataofs or 5) * 4
            if pkt_len := getattr(ip, "len", None):  # IPv4 total length
                return max(0, pkt_len - ip.ihl * 4 - header)
            if (plen := getattr(ip, "plen", None)) is not None:  # IPv6
                # Extension headers sit between the IPv6 header and TCP.
                extension = len(ip.payload) - len(seg) if ip.nh != 6 else 0
                return max(0, plen - extension - header)
        except (AttributeError, TypeError):
            pass
        return len(seg.payload)

    @classmethod
    def _volumes_in(cls, packets: list[Any], targets: set[str]) -> dict[str, _Volume]:
        """Per-destination traffic volume for ``targets`` in one pass."""
        volumes: dict[str, _Volume] = {}
        for pkt in packets:
            ip = cls._ip_layer(pkt)
            if ip is None:
                continue
            if pkt.haslayer(TCP):
                seg, proto = pkt[TCP], "tcp"
            elif pkt.haslayer(UDP):
                seg, proto = pkt[UDP], "udp"
            else:
                continue
            outbound = cls._format_endpoint(ip.dst, seg.dport, proto)
            if outbound in targets:
                volume = volumes.setdefault(outbound, _Volume())
                volume.sent += cls._payload_len(ip, seg, proto)
                volume.local_ports.add(seg.sport)
            else:
                inbound = cls._format_endpoint(ip.src, seg.sport, proto)
                if inbound not in targets:
                    continue
                volume = volumes.setdefault(inbound, _Volume())
                volume.received += cls._payload_len(ip, seg, proto)
                volume.local_ports.add(seg.dport)
            volume.packets += 1
        return volumes

    @classmethod
    def _dns_query_counts(cls, packets: list[Any]) -> dict[str, int]:
        """How often each name was queried (same filtering as queries)."""
        counts: dict[str, int] = {}
        for pkt in packets:
            for name in cls._dns_queries_in([pkt]):
                counts[name] = counts.get(name, 0) + 1
        return counts

    @classmethod
    def _dns_answers_in(cls, packets: list[Any]) -> dict[str, set[str]]:
        """Map each resolved IP to *every* queried name that resolved to it.

        CDNs and load balancers share one IP between many hosts (Wikimedia
        serves en.wikipedia.org and intake-analytics.wikimedia.org from the
        same address), so keeping only the first answer mislabelled all
        traffic to that IP.
        """
        answers: dict[str, set[str]] = {}
        for pkt in packets:
            if not pkt.haslayer(DNS):
                continue
            dns = pkt.getlayer(DNS)
            if dns.qr != 1 or not dns.an:
                continue
            try:
                qname = dns.qd[0].qname.decode(errors="replace") if dns.qd else ""
                records = list(dns.an)
            except Exception:
                continue
            for rr in records:
                if isinstance(rr, DNSRR) and rr.type in (1, 28) and qname:
                    answers.setdefault(str(rr.rdata), set()).add(qname.rstrip("."))
        return answers

    @staticmethod
    def _tls_sni(payload: bytes) -> str | None:
        """Server name from a TLS ClientHello record, or ``None``.

        A minimal parser (record -> handshake -> extensions -> server_name)
        so no TLS dissector has to be loaded; any malformed or truncated
        record simply yields ``None``.
        """
        try:
            if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
                return None
            pos = 9 + 2 + 32  # record + handshake headers, version, random
            pos += 1 + payload[pos]  # session id
            pos += 2 + int.from_bytes(payload[pos : pos + 2], "big")  # ciphers
            pos += 1 + payload[pos]  # compression methods
            end = pos + 2 + int.from_bytes(payload[pos : pos + 2], "big")
            pos += 2
            while pos + 4 <= min(end, len(payload)):
                ext_type = int.from_bytes(payload[pos : pos + 2], "big")
                ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
                pos += 4
                if ext_type == 0:  # server_name: list len, type, name len
                    if payload[pos + 2] != 0:
                        return None
                    name_len = int.from_bytes(payload[pos + 3 : pos + 5], "big")
                    name = payload[pos + 5 : pos + 5 + name_len]
                    if len(name) != name_len:
                        return None
                    return name.decode("ascii", errors="replace")
                pos += ext_len
        except IndexError:
            return None
        return None

    @classmethod
    def _sni_names_in(cls, packets: list[Any], ip_address: str, port: int) -> set[str]:
        """TLS SNI host names the guest sent to ``ip_address:port``."""
        names: set[str] = set()
        for pkt in packets:
            ip = cls._ip_layer(pkt)
            if ip is None or not pkt.haslayer(TCP):
                continue
            seg = pkt[TCP]
            if ip.dst != ip_address or seg.dport != port:
                continue
            name = cls._tls_sni(bytes(seg.payload))
            if name:
                names.add(name)
        return names

    @classmethod
    def _got_reply(
        cls, packets: list[Any], ip_address: str, port: int, proto: str
    ) -> bool:
        """Whether any packet came back from ``ip_address:port``."""
        layer = TCP if proto == "tcp" else UDP
        for pkt in packets:
            ip = cls._ip_layer(pkt)
            if ip is None or not pkt.haslayer(layer):
                continue
            if ip.src == ip_address and pkt[layer].sport == port:
                return True
        return False

    @staticmethod
    def _host_label(dns_names: set[str], sni_names: set[str]) -> str:
        """`` [a, b] (TLS SNI: c)`` -- every DNS name of the IP, plus SNI.

        The SNI note is only added when it says something the DNS names do
        not: HTTP/2 clients (OkHttp) coalesce requests for several hosts on
        one connection to a shared IP, so the SNI alone is not attribution.
        """
        names = sorted(dns_names) or sorted(sni_names)
        if not names:
            return ""
        label = f" [{', '.join(names)}]"
        if dns_names and sni_names and sorted(sni_names) != names:
            label += f" (TLS SNI: {', '.join(sorted(sni_names))})"
        return label

    # ------------------------------------------------------------------
    # Public extraction API
    # ------------------------------------------------------------------

    def extract_dns_requests_for_all_pcaps(self) -> list[str]:
        """DNS names queried in the action runs, compared with the dry run.

        See :meth:`_analyse_all_pcaps`. Names also queried in the dry run
        stay in the list (annotated ``"(also seen in background: N
        queries)"``) when a destination reported above background resolved
        to them or they were queried substantially more often; the rest are
        moved to :attr:`filtered_network_noise`.

        Returns:
            The DNS names (with trailing dot, as queried), sorted.
        """
        self._analyse_all_pcaps()
        return self.dns_requests

    @classmethod
    def extract_dns_requests_from_pcap(cls, pcap_path: str) -> set[str]:
        """Extract all DNS query domain names from a PCAP file.

        Args:
            pcap_path: Path to the PCAP file to analyze (missing -> empty set).

        Returns:
            A set of domain names that were queried in the capture.
        """
        return cls._dns_queries_in(cls._read_pcap(pcap_path))

    def extract_target_ips_and_ports_for_all_pcaps(self) -> list[str]:
        """Connection targets of the action runs, compared with the dry run.

        See :meth:`_analyse_all_pcaps`.

        Returns:
            Formatted strings, e.g.
            ``"192.102.162.236:443 [fkie.fraunhofer.de] (42B sent to / 0B
            received from)"``; UDP targets carry a ``/udp`` port suffix.
        """
        self._analyse_all_pcaps()
        return self.target_ips_and_ports

    def _analyse_all_pcaps(self) -> None:
        """Analyse every run capture against the dry-run capture (once).

        TCP targets come from guest SYN packets, UDP targets from non-DNS
        unicast datagrams. Each entry is annotated with every DNS name that
        resolved to the IP (shared CDN / load-balancer IPs serve several
        hosts), the TLS SNI when it narrows that down, and the bytes
        sent/received in the first run capture that contains it. A target
        that never answered (e.g. an IPv6 SYN on an emulator without IPv6
        routing) is marked as a connection attempt.

        A target or DNS name also present in the dry-run capture is only
        subtracted when its volume in the busiest action run is comparable
        to the background (see ``NOISE_VOLUME_FACTOR`` and the floors at
        the top of this module); otherwise it is kept and annotated with
        ``"also seen in background: ..."``. Everything subtracted is kept,
        with both volumes, in :attr:`filtered_network_noise`.

        Sets :attr:`dns_requests`, :attr:`target_ips_and_ports`,
        :attr:`filtered_network_noise` and :attr:`performed_diff`, and
        publishes one ``NetworkEvent`` per reported DNS name / target.
        """
        if self.performed_diff:
            return
        logger.info("Analyzing pcaps for network targets, this could take a minute...")

        runs: list[tuple[list[Any], set[str]]] = []
        all_targets: set[str] = set()
        dns_names: dict[str, set[str]] = {}
        run_queries: dict[str, int] = {}  # name -> most queries in one run
        for path in self._run_pcap_paths():
            packets = self._read_pcap(path)
            targets = self._targets_in(packets)
            runs.append((packets, targets))
            all_targets.update(targets)
            for ip, names in self._dns_answers_in(packets).items():
                dns_names.setdefault(ip, set()).update(names)
            for name, count in self._dns_query_counts(packets).items():
                run_queries[name] = max(run_queries.get(name, 0), count)
        run_volumes = [self._volumes_in(p, t) for p, t in runs]

        noise_packets = self._read_pcap(self._noise_pcap_path())
        noise_targets = self._targets_in(noise_packets)
        noise_volumes = self._volumes_in(noise_packets, noise_targets & all_targets)
        noise_queries = self._dns_query_counts(noise_packets)

        targets_out: list[str] = []
        filtered_targets: dict[str, str] = {}
        reported_names: set[str] = set()
        for endpoint in sorted(all_targets):
            target_ip, target_port, proto = self._parse_endpoint(endpoint)
            first = next(i for i, (_, t) in enumerate(runs) if endpoint in t)
            packets = runs[first][0]
            shown = run_volumes[first].get(endpoint, _Volume())
            busiest = max(
                (v.get(endpoint, _Volume()) for v in run_volumes),
                key=lambda v: (v.total, v.packets),
            )
            sni = (
                self._sni_names_in(packets, target_ip, target_port)
                if proto == "tcp"
                else set()
            )
            names = dns_names.get(target_ip, set())
            label = endpoint + self._host_label(names, sni)
            note = ""
            if endpoint in noise_targets:
                noise = noise_volumes.get(endpoint, _Volume())
                if not _above_background(busiest, noise):
                    filtered_targets[label] = (
                        f"comparable to background: dry run {noise.describe()}, "
                        f"busiest action run {busiest.describe()}"
                    )
                    continue
                note = f"; also seen in background: {noise.describe()}"
            reported_names.update(names)
            if shown.total == 0 and not self._got_reply(
                packets, target_ip, target_port, proto
            ):
                note = "; no reply, connection attempt only" + note
            targets_out.append(
                f"{label} ({shown.sent}B sent to / {shown.received}B received from"
                f"{note})"
            )
            NetworkEvent(
                event_type_name="connection",
                protocol=proto,
                source_ip="",
                dest_ip=target_ip,
                dest_port=target_port,
                data_size=shown.total,
                source="network",
            ).publish()

        dns_out: list[str] = []
        filtered_dns: dict[str, str] = {}
        factor = NOISE_VOLUME_FACTOR
        for name in sorted(run_queries):
            entry = name
            if name in noise_queries:
                background = noise_queries[name]
                busiest_queries = run_queries[name]
                if (
                    name.rstrip(".") not in reported_names
                    and busiest_queries <= factor * background + NOISE_DNS_QUERIES_FLOOR
                ):
                    filtered_dns[name] = (
                        f"comparable to background: dry run {background} "
                        f"queries, busiest action run {busiest_queries} queries, "
                        "no destination above background resolved to it"
                    )
                    continue
                entry = f"{name} (also seen in background: {background} queries)"
            dns_out.append(entry)
            NetworkEvent(
                event_type_name="dns_request",
                protocol="dns",
                source_ip="",
                dest_ip=name,
                dest_port=53,
                data_size=0,
                source="network",
            ).publish()

        self.dns_requests = dns_out
        self.target_ips_and_ports = targets_out
        self.filtered_network_noise = {
            "Network": filtered_dns,
            "Network IP:Port (send/recv)": filtered_targets,
        }
        self.performed_diff = True

        hidden = len(filtered_dns) + len(filtered_targets)
        TaskOutput(
            task_name="network",
            message=(
                f"Found {len(dns_out)} DNS names and {len(targets_out)} IP:port "
                f"targets ({hidden} comparable to the dry-run background hidden, "
                "see Other Data -> Filtered Noise)"
            ),
            level="info",
            source="network",
        ).publish()

    @classmethod
    def extract_target_ips_and_ports(cls, pcap_path: str) -> set[str]:
        """Extract all connection targets from a PCAP file.

        Args:
            pcap_path: Path to the PCAP file to analyze (missing -> empty set).

        Returns:
            A set of targets in ``"IP:Port"`` (TCP) / ``"IP:Port/udp"`` format.
        """
        return cls._targets_in(cls._read_pcap(pcap_path))

    def count_bytes(
        self, ip_address: str, port: int, pcap_file: str
    ) -> tuple[int, int]:
        """Count TCP+UDP payload bytes sent to / received from ``ip:port``.

        Args:
            ip_address: The target IP address to analyze.
            port: The target port number to analyze.
            pcap_file: Path to the PCAP file to analyze.

        Returns:
            A tuple of (sent_bytes, received_bytes).
        """
        packets = self._read_pcap(pcap_file)
        sent_tcp, recv_tcp = self._count_bytes_in(packets, ip_address, port, "tcp")
        sent_udp, recv_udp = self._count_bytes_in(packets, ip_address, port, "udp")
        return sent_tcp + sent_udp, recv_tcp + recv_udp
