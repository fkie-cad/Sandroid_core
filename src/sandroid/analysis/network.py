# ensure that we only see errors from scapy
import logging
import os
import socket
import struct
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

# ----------------------------------------------------------------------
# Capture analysis bounds
# ----------------------------------------------------------------------
#: Packets analysed per capture. A dup-ACK / FIN storm on a half-open
#: connection restored from the snapshot produced 1.3 M packets (94 MB) in a
#: 41 s run; the streaming parser handles that in seconds, this cap only
#: bounds pathological captures. A cut capture is reported in the results
#: ("analysis truncated after N packets").
MAX_ANALYSED_PACKETS = 5_000_000
#: Minimum seconds between two "Analysing <pcap>: N packets" progress lines.
PROGRESS_LOG_SECONDS = 5.0


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
        global DNS, DNSQR, DNSRR, IP, IPv6
        from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6

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
        summary = self._summarise_pcap(pcap_path)
        tcp_targets = summary.targets
        dns_names = summary.dns_answers
        ip_analysis = []
        for ip_and_port in sorted(tcp_targets):
            target_ip, target_port, proto = self._parse_endpoint(ip_and_port)
            bytes_sent, bytes_received = summary.bytes_to_from(
                target_ip, target_port, proto
            )
            sni = summary.sni_names(target_ip, target_port) if proto == "tcp" else set()
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
        dns_queries = set(summary.dns_queries)
        extra = (
            {"analysis_note": summary.truncation_note()} if summary.truncated else {}
        )

        return {
            "pcap_file": pcap_path,
            "dns_queries": sorted(dns_queries),
            "tcp_connections": sorted(tcp_targets),
            "ip_analysis": ip_analysis,
            "total_dns_queries": len(dns_queries),
            "total_tcp_connections": len(tcp_targets),
            "packets_analysed": summary.packets,
            **extra,
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

    @classmethod
    def _summarise_pcap(
        cls, pcap_path: str, max_packets: int | None = None
    ) -> "_PcapSummary":
        """Stream a capture once and aggregate everything the analysis needs.

        Packets are read one at a time (never the whole file) and parsed with
        a small header parser; only DNS packets are handed to scapy. The
        result is per-flow aggregates, so memory does not grow with the
        number of packets. Zero-payload TCP segments that repeat the previous
        segment of their flow (dup-ACK / FIN retransmission storms on a
        half-open connection restored from a snapshot) are only counted, not
        treated as traffic. After ``max_packets`` (default
        :data:`MAX_ANALYSED_PACKETS`) the summary is marked truncated.

        A missing or unreadable capture (noise filter off, a capture that
        never started) yields an empty summary instead of aborting the whole
        network result.
        """
        summary = _PcapSummary(path=pcap_path or "")
        if not pcap_path or not os.path.isfile(pcap_path):
            logger.debug(f"No capture file at {pcap_path}")
            return summary
        _ensure_scapy()
        from scapy.utils import RawPcapReader

        limit = MAX_ANALYSED_PACKETS if max_packets is None else max_packets
        name = os.path.basename(pcap_path)
        summary.file_bytes = os.path.getsize(pcap_path)
        started = last_log = time.monotonic()
        try:
            reader = RawPcapReader(pcap_path)
        except Exception as exc:
            logger.warning(f"Could not read capture {pcap_path}: {exc}")
            return summary
        try:
            default_link = getattr(reader, "linktype", 1)
            for data, meta in reader:
                if summary.packets >= limit:
                    summary.truncated = True
                    break
                summary.packets += 1
                summary.bytes_read += len(data) + 16
                cls._account_packet(
                    summary, data, getattr(meta, "linktype", default_link)
                )
                if summary.packets % 100_000 == 0:
                    now = time.monotonic()
                    if now - last_log >= PROGRESS_LOG_SECONDS:
                        last_log = now
                        logger.info(
                            f"Analysing {name}: {summary.packets:,} packets "
                            f"(~{summary.bytes_read / 1e6:.0f} of "
                            f"{summary.file_bytes / 1e6:.0f} MB) after "
                            f"{now - started:.0f}s"
                        )
        except Exception as exc:
            logger.warning(
                f"Could not read the rest of capture {pcap_path} after "
                f"{summary.packets} packets: {exc}"
            )
        finally:
            reader.close()
        elapsed = time.monotonic() - started
        if summary.duplicates:
            logger.info(
                f"{name}: {summary.duplicates:,} of {summary.packets:,} packets "
                "were repeated zero-payload TCP segments (dup-ACK / FIN "
                "retransmissions) and were not counted as traffic"
            )
        if summary.truncated:
            logger.warning(f"{name}: {summary.truncation_note()}")
        logger.debug(f"Analysed {name}: {summary.packets} packets in {elapsed:.1f}s")
        return summary

    @staticmethod
    def _ip_offset(linktype: int, data: bytes) -> int | None:
        """Offset of the IPv4/IPv6 header in a frame of ``linktype``."""
        if linktype == 1:  # Ethernet (the emulator's capture format)
            offset, ethertype = 14, data[12:14]
            while ethertype in (b"\x81\x00", b"\x88\xa8"):  # VLAN tags
                ethertype = data[offset + 2 : offset + 4]
                offset += 4
            return offset if ethertype in (b"\x08\x00", b"\x86\xdd") else None
        if linktype in (12, 14, 101, 228, 229):  # raw IP
            return 0
        if linktype in (0, 108):  # BSD loopback
            return 4
        if linktype == 113:  # Linux cooked v1
            return 16 if data[14:16] in (b"\x08\x00", b"\x86\xdd") else None
        if linktype == 276:  # Linux cooked v2
            return 20 if data[0:2] in (b"\x08\x00", b"\x86\xdd") else None
        return None

    @classmethod
    def _account_packet(
        cls, summary: "_PcapSummary", data: bytes, linktype: int
    ) -> None:
        """Add one raw frame to ``summary`` (malformed frames are skipped)."""
        try:
            offset = cls._ip_offset(linktype, data)
            if offset is None:
                data, offset = cls._ip_bytes_via_scapy(linktype, data), 0
                if not data:
                    return
            cls._account_ip(summary, data, offset)
        except (IndexError, struct.error, ValueError, OSError):
            return

    @staticmethod
    def _ip_bytes_via_scapy(linktype: int, data: bytes) -> bytes:
        """IP bytes of a frame of an unusual link type (slow path)."""
        from scapy.config import conf

        layer = conf.l2types.get(linktype)
        if layer is None:
            return b""
        pkt = layer(data)
        for ip_layer in (IP, IPv6):
            if pkt.haslayer(ip_layer):
                return bytes(pkt[ip_layer])
        return b""

    @classmethod
    def _account_ip(cls, summary: "_PcapSummary", data: bytes, off: int) -> None:
        """Parse the IP packet at ``data[off:]`` and aggregate it."""
        version = data[off] >> 4
        if version == 4:
            ihl = (data[off] & 0x0F) * 4
            total, frag, proto = (
                _U16.unpack_from(data, off + 2)[0],
                _U16.unpack_from(data, off + 6)[0] & 0x1FFF,
                data[off + 9],
            )
            if frag:  # a later fragment carries no transport header
                return
            src = socket.inet_ntoa(data[off + 12 : off + 16])
            dst = socket.inet_ntoa(data[off + 16 : off + 20])
            l4 = off + ihl
            end = off + total if total else len(data)  # drop Ethernet padding
            # Payload bytes per the IP length field (on the wire, so frames
            # cut by a snap length still count fully); None -> captured size.
            ip_payload = total - ihl if total else None
        elif version == 6:
            plen, proto = _U16.unpack_from(data, off + 4)[0], data[off + 6]
            src = socket.inet_ntop(socket.AF_INET6, data[off + 8 : off + 24])
            dst = socket.inet_ntop(socket.AF_INET6, data[off + 24 : off + 40])
            l4, extension = off + 40, 0
            while proto in (0, 43, 44, 60):  # extension headers
                if proto == 44:  # fragment header
                    if _U16.unpack_from(data, l4 + 2)[0] >> 3:
                        return
                    length = 8
                else:
                    length = (data[l4 + 1] + 1) * 8
                proto = data[l4]
                l4 += length
                extension += length
            end = off + 40 + plen if plen else len(data)
            ip_payload = plen - extension
        else:
            return

        if proto == 6:
            if len(data) < l4 + 20:
                return
            sport, dport, seq, ack, offset_flags = _TCP.unpack_from(data, l4)
            header = ((offset_flags >> 12) or 5) * 4
            flags = offset_flags & 0x1FF
            if ip_payload is None:
                size = max(0, end - l4 - header)
            else:
                size = max(0, ip_payload - header)
            if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                summary.targets.add(cls._format_endpoint(dst, dport, "tcp"))
            flow = summary.flow((src, sport, dst, dport, "tcp"))
            if size == 0:
                state = (seq, ack, flags)
                if flow.last == state:
                    flow.duplicates += 1
                    summary.duplicates += 1
                    return
                flow.last = state
            else:
                flow.last = None
                if data[l4 + header : l4 + header + 1] == b"\x16":
                    name = cls._tls_sni(data[l4 + header : end])
                    if name:
                        summary.sni.setdefault((dst, dport), set()).add(name)
            flow.packets += 1
            flow.payload += size
        elif proto == 17:
            if len(data) < l4 + 8:
                return
            sport, dport, length = _UDP.unpack_from(data, l4)
            size = max(0, length - 8)
            if sport in _DNS_PORTS or dport in _DNS_PORTS:
                cls._account_dns(summary, data[off:end], version, dport)
            elif dport not in (67, 68) and not cls._is_local_or_multicast(dst):
                summary.targets.add(cls._format_endpoint(dst, dport, "udp"))
            flow = summary.flow((src, sport, dst, dport, "udp"))
            flow.packets += 1
            flow.payload += size

    @staticmethod
    def _account_dns(
        summary: "_PcapSummary", ip_bytes: bytes, version: int, dport: int
    ) -> None:
        """Record the query / answers of one DNS packet (scapy-decoded)."""
        try:
            pkt = (IP if version == 4 else IPv6)(ip_bytes)
            if not pkt.haslayer(DNS):
                return
            dns = pkt.getlayer(DNS)
            if dns.qr == 0:
                # mDNS (5353) is LAN service discovery, not a lookup.
                if not dns.qd or dport == 5353:
                    return
                query = dns.qd[0]
                if query is not None and isinstance(query, DNSQR):
                    name = query.qname.decode(errors="replace")
                    summary.dns_queries[name] = summary.dns_queries.get(name, 0) + 1
                return
            if dns.qr != 1 or not dns.an:
                return
            qname = dns.qd[0].qname.decode(errors="replace") if dns.qd else ""
            for rr in list(dns.an):
                if isinstance(rr, DNSRR) and rr.type in (1, 28) and qname:
                    summary.dns_answers.setdefault(str(rr.rdata), set()).add(
                        qname.rstrip(".")
                    )
        except Exception:  # malformed DNS must not stop the analysis
            return

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

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
        return set(cls._summarise_pcap(pcap_path).dns_queries)

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

        Each capture is streamed once (see :meth:`_summarise_pcap`); a
        capture cut at :data:`MAX_ANALYSED_PACKETS` adds an "analysis
        truncated" note as the last IP:port entry.

        Sets :attr:`dns_requests`, :attr:`target_ips_and_ports`,
        :attr:`filtered_network_noise` and :attr:`performed_diff`, and
        publishes one ``NetworkEvent`` per reported DNS name / target.
        """
        if self.performed_diff:
            return
        started = time.monotonic()
        logger.info("Analyzing pcaps for network targets...")

        runs = [self._summarise_pcap(path) for path in self._run_pcap_paths()]
        all_targets: set[str] = set()
        dns_names: dict[str, set[str]] = {}
        run_queries: dict[str, int] = {}  # name -> most queries in one run
        for run in runs:
            all_targets.update(run.targets)
            for ip, names in run.dns_answers.items():
                dns_names.setdefault(ip, set()).update(names)
            for name, count in run.dns_queries.items():
                run_queries[name] = max(run_queries.get(name, 0), count)
        run_volumes = [run.volumes(run.targets) for run in runs]

        noise = self._summarise_pcap(self._noise_pcap_path())
        noise_volumes = noise.volumes(noise.targets & all_targets)
        noise_queries = noise.dns_queries

        targets_out: list[str] = []
        filtered_targets: dict[str, str] = {}
        reported_names: set[str] = set()
        for endpoint in sorted(all_targets):
            target_ip, target_port, proto = self._parse_endpoint(endpoint)
            first = next(i for i, run in enumerate(runs) if endpoint in run.targets)
            run = runs[first]
            shown = run_volumes[first].get(endpoint, _Volume())
            busiest = max(
                (v.get(endpoint, _Volume()) for v in run_volumes),
                key=lambda v: (v.total, v.packets),
            )
            sni = run.sni_names(target_ip, target_port) if proto == "tcp" else set()
            names = dns_names.get(target_ip, set())
            label = endpoint + self._host_label(names, sni)
            note = ""
            if endpoint in noise.targets:
                background = noise_volumes.get(endpoint, _Volume())
                if not _above_background(busiest, background):
                    filtered_targets[label] = (
                        f"comparable to background: dry run "
                        f"{background.describe()}, "
                        f"busiest action run {busiest.describe()}"
                    )
                    continue
                note = f"; also seen in background: {background.describe()}"
            reported_names.update(names)
            if shown.total == 0 and not run.got_reply(target_ip, target_port, proto):
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
                background_queries = noise_queries[name]
                busiest_queries = run_queries[name]
                if (
                    name.rstrip(".") not in reported_names
                    and busiest_queries
                    <= factor * background_queries + NOISE_DNS_QUERIES_FLOOR
                ):
                    filtered_dns[name] = (
                        f"comparable to background: dry run {background_queries} "
                        f"queries, busiest action run {busiest_queries} queries, "
                        "no destination above background resolved to it"
                    )
                    continue
                entry = (
                    f"{name} (also seen in background: {background_queries} queries)"
                )
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

        # A cut capture must be visible in the result itself, not only in
        # the log: the note travels into run.json, the TUI and the PDF.
        for summary in [*runs, noise]:
            if summary.truncated:
                note = (
                    f"({os.path.basename(summary.path)}: {summary.truncation_note()})"
                )
                targets_out.append(note)
                TaskOutput(
                    task_name="network",
                    message=note,
                    level="warning",
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
        packets = sum(s.packets for s in [*runs, noise])
        logger.info(
            f"Analyzed {len(runs) + bool(noise.packets)} capture(s), "
            f"{packets:,} packets, in {time.monotonic() - started:.1f}s"
        )
        TaskOutput(
            task_name="network",
            message=(
                f"Found {len(dns_out)} DNS names and "
                f"{len(targets_out) - sum(s.truncated for s in [*runs, noise])} "
                f"IP:port targets ({hidden} comparable to the dry-run background "
                "hidden, see Other Data -> Filtered Noise)"
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
        return cls._summarise_pcap(pcap_path).targets

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
        summary = self._summarise_pcap(pcap_file)
        sent_tcp, recv_tcp = summary.bytes_to_from(ip_address, port, "tcp")
        sent_udp, recv_udp = summary.bytes_to_from(ip_address, port, "udp")
        return sent_tcp + sent_udp, recv_tcp + recv_udp


# ----------------------------------------------------------------------
# Streaming capture summary
# ----------------------------------------------------------------------

_U16 = struct.Struct("!H")
_TCP = struct.Struct("!HHIIH")
_UDP = struct.Struct("!HHH")
_DNS_PORTS = (53, 5353)

#: (src ip, src port, dst ip, dst port, "tcp"/"udp") -- one flow direction.
_FlowKey = tuple[str, int, str, int, str]


@dataclass
class _Flow:
    """Aggregate of one direction of one TCP connection / UDP flow."""

    payload: int = 0
    packets: int = 0
    duplicates: int = 0
    #: (seq, ack, flags) of the last zero-payload TCP segment.
    last: tuple[int, int, int] | None = None


@dataclass
class _PcapSummary:
    """Everything the network analysis needs from one capture."""

    path: str = ""
    flows: dict[_FlowKey, _Flow] = field(default_factory=dict)
    targets: set[str] = field(default_factory=set)
    dns_queries: dict[str, int] = field(default_factory=dict)
    dns_answers: dict[str, set[str]] = field(default_factory=dict)
    sni: dict[tuple[str, int], set[str]] = field(default_factory=dict)
    packets: int = 0
    duplicates: int = 0
    bytes_read: int = 0
    file_bytes: int = 0
    truncated: bool = False

    def flow(self, key: _FlowKey) -> _Flow:
        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows[key] = _Flow()
        return flow

    def truncation_note(self) -> str:
        """Human-readable "analysis truncated" note."""
        return (
            f"analysis truncated after {self.packets:,} packets "
            f"(~{self.bytes_read / 1e6:.0f} of {self.file_bytes / 1e6:.0f} MB); "
            "traffic after that point is not in these results, open the "
            "capture in Wireshark for the rest"
        )

    def volumes(self, targets: set[str]) -> dict[str, _Volume]:
        """Per-destination traffic volume for ``targets``."""
        volumes: dict[str, _Volume] = {}
        fmt = Network._format_endpoint
        for (src, sport, dst, dport, proto), flow in self.flows.items():
            outbound = fmt(dst, dport, proto)
            if outbound in targets:
                volume = volumes.setdefault(outbound, _Volume())
                volume.sent += flow.payload
                volume.local_ports.add(sport)
            else:
                inbound = fmt(src, sport, proto)
                if inbound not in targets:
                    continue
                volume = volumes.setdefault(inbound, _Volume())
                volume.received += flow.payload
                volume.local_ports.add(dport)
            volume.packets += flow.packets
        return volumes

    def bytes_to_from(self, ip: str, port: int, proto: str) -> tuple[int, int]:
        """Payload bytes (sent to, received from) ``ip:port``."""
        sent = received = 0
        for (src, sport, dst, dport, flow_proto), flow in self.flows.items():
            if flow_proto != proto:
                continue
            if dst == ip and dport == port:
                sent += flow.payload
            elif src == ip and sport == port:
                received += flow.payload
        return sent, received

    def got_reply(self, ip: str, port: int, proto: str) -> bool:
        """Whether any packet came back from ``ip:port``."""
        return any(
            src == ip and sport == port and flow_proto == proto
            for (src, sport, _, _, flow_proto) in self.flows
        )

    def sni_names(self, ip: str, port: int) -> set[str]:
        """TLS SNI host names the guest sent to ``ip:port``."""
        return set(self.sni.get((ip, port), set()))
