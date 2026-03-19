# ensure that we only see errors from scapy
import logging
import os
import threading
import time
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

# Lazy import for scapy to avoid slow module-level import that blocks TUI
# Scapy's import can take several seconds and holds the GIL
_scapy_imported = False


def _ensure_scapy():
    """Lazily import scapy modules only when needed for packet analysis."""
    global _scapy_imported
    if not _scapy_imported:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        global DNS, DNSQR, IP, TCP, rdpcap
        from scapy.all import DNS, DNSQR, IP, TCP, rdpcap

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
            base_path = str(base_path_obj.resolve()) + "/"

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
        targets. Results are filtered against a 'noise' baseline capture to
        identify application-specific network activity.

        Returns:
            A dictionary with two keys:
                - "Network": List of unique DNS domain names queried.
                - "Network IP:Port (send/recv)": List of unique IP:port targets
                  with byte counts sent and received.
        """
        if not self.performed_diff:
            self.dns_requests = self.extract_dns_requests_for_all_pcaps()
            self.target_ips_and_ports = (
                self.extract_target_ips_and_ports_for_all_pcaps()
            )
            self.performed_diff = True
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

        # Extract DNS requests
        dns_queries = self.extract_dns_requests_from_pcap(pcap_path)

        # Extract TCP connection targets
        tcp_targets = self.extract_target_ips_and_ports(pcap_path)

        # Calculate byte counts for each connection
        ip_analysis = []
        for ip_and_port in sorted(tcp_targets):
            target_ip = ip_and_port.split(":")[0]
            target_port = int(ip_and_port.split(":")[1])
            bytes_sent, bytes_received = self.count_bytes(
                target_ip, target_port, pcap_path
            )
            ip_analysis.append(
                {
                    "ip": target_ip,
                    "port": target_port,
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
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
            self.dns_requests = self.extract_dns_requests_for_all_pcaps()
            self.target_ips_and_ports = (
                self.extract_target_ips_and_ports_for_all_pcaps()
            )
            self.performed_diff = True

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

    def extract_dns_requests_for_all_pcaps(self) -> list[str]:
        """Extract DNS requests from all PCAP files, filtering out baseline noise.

        Analyzes all numbered PCAP files from capture runs, extracts DNS queries,
        and removes any domains that also appeared in the baseline 'noise' capture.
        Publishes NetworkEvent for each unique DNS request found.

        Returns:
            A list of unique DNS domain names that were queried during the
            capture runs but not present in the baseline noise capture.
        """
        # Set to store DNS requests from all pcaps except the noise pcap
        all_dns_requests = set()

        logger.info("Analyzing pcaps for DNS requests, this could take a minute...")

        # Iterate over PCAP files
        base_path = self._get_path()
        for i in range(1, self.internal_run_counter - 1):
            path = f"{base_path}{self._trace_file_name}{i}.pcap"

            # Extract DNS requests and add them to the set
            dns_requests = self.extract_dns_requests_from_pcap(path)
            all_dns_requests.update(dns_requests)

        # Extract DNS requests from the noise pcap
        noise_path = f"{base_path}{self._trace_file_name}noise.pcap"
        noise_dns_requests = self.extract_dns_requests_from_pcap(noise_path)

        # Return only the DNS names that were in all_dns_requests but not in noise_dns_requests as a list
        diff = list(all_dns_requests - noise_dns_requests)

        # Publish NetworkEvent for each unique DNS request
        for dns_request in diff:
            NetworkEvent(
                event_type_name="dns_request",
                protocol="dns",
                source_ip="",
                dest_ip=dns_request,
                dest_port=53,
                data_size=0,
                source="network",
            ).publish()

        # Publish summary
        TaskOutput(
            task_name="network",
            message=f"Found {len(diff)} unique DNS requests",
            level="info",
            source="network",
        ).publish()

        return diff

    @classmethod
    def extract_dns_requests_from_pcap(cls, pcap_path: str) -> set[str]:
        """Extract all DNS query domain names from a PCAP file.

        Parses the PCAP file and extracts domain names from DNS query packets
        (qr=0 indicates a query, not a response).

        Args:
            pcap_path: Path to the PCAP file to analyze.

        Returns:
            A set of domain names that were queried in the capture.
        """
        _ensure_scapy()  # Lazy import scapy
        domain_names = set()

        # Read the pcap file
        packets = rdpcap(pcap_path)

        # Iterate over each packet
        for pkt in packets:
            # Check if the packet is a DNS request
            if (
                pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0
            ):  # qr == 0 indicates a query
                # Extract the queried domain names
                dns_query = pkt.getlayer(DNS).qd[0]  # DNS question section
                if dns_query is not None and isinstance(dns_query, DNSQR):
                    domain_names.add(dns_query.qname.decode())

        # TODO: also store IPs of answer so they can be correlated later on
        return domain_names

    def extract_target_ips_and_ports_for_all_pcaps(self) -> list[str]:
        """Extract target IP:port connections from all PCAPs, filtering baseline noise.

        Analyzes all numbered PCAP files, extracts TCP SYN packets to identify
        connection targets, and removes any that also appeared in the baseline
        'noise' capture. Calculates bytes sent/received for each connection.
        Publishes NetworkEvent for each unique connection found.

        Returns:
            A list of formatted strings with IP:port and byte counts, e.g.,
            "192.168.1.1:443 (100B sent to / 500B received from)".
        """
        # Set to store target IPs and ports from all pcaps except the noise pcap
        all_target_ips_and_ports = set()

        logger.info(
            "Analyzing pcaps for target IPs and ports, this could take a minute..."
        )

        # Iterate over PCAP files
        base_path = self._get_path()
        for i in range(1, self.internal_run_counter - 1):
            path = f"{base_path}{self._trace_file_name}{i}.pcap"

            # Extract target IPs and ports and add them to the set
            target_ips_and_ports = self.extract_target_ips_and_ports(path)
            all_target_ips_and_ports.update(target_ips_and_ports)

        # Extract target IPs and ports from the noise pcap
        noise_path = f"{base_path}{self._trace_file_name}noise.pcap"
        noise_target_ips_and_ports = self.extract_target_ips_and_ports(noise_path)

        # Return only the target IPs and ports that were in all_target_ips_and_ports but not in noise_target_ips_and_ports
        diff = list(all_target_ips_and_ports - noise_target_ips_and_ports)

        # Calculate the number of bytes sent and received over each connection
        result = []
        for ip_and_port in diff:
            target_IP = ip_and_port.split(":")[0]
            target_port = int(ip_and_port.split(":")[1])
            pcap_path = f"{base_path}network_trace_run_1.pcap"
            sent_bytes, received_bytes = self.count_bytes(
                target_IP, target_port, pcap_path
            )
            result.append(
                f"{target_IP}:{target_port} ({sent_bytes}B sent to / {received_bytes}B received from)"
            )

            # Publish NetworkEvent for each unique connection
            NetworkEvent(
                event_type_name="connection",
                protocol="tcp",
                source_ip="",
                dest_ip=target_IP,
                dest_port=target_port,
                data_size=sent_bytes + received_bytes,
                source="network",
            ).publish()

        # Publish summary
        TaskOutput(
            task_name="network",
            message=f"Found {len(result)} unique IP:port connections",
            level="info",
            source="network",
        ).publish()

        return result

    @classmethod
    def extract_target_ips_and_ports(cls, pcap_path: str) -> set[str]:
        """Extract all TCP connection targets from a PCAP file.

        Parses the PCAP file and extracts destination IP:port pairs from
        TCP SYN packets (connection initiation).

        Args:
            pcap_path: Path to the PCAP file to analyze.

        Returns:
            A set of target addresses in "IP:Port" format.
        """
        _ensure_scapy()  # Lazy import scapy
        target_ips_and_ports = set()

        # Read the pcap file
        packets = rdpcap(pcap_path)

        # Iterate over each packet
        packet_number = 0
        for pkt in packets:
            if packet_number % 500 == 0:
                logger.debug(f"Progress: {packet_number}/{len(packets)}")
            # Check if the packet is an IP packet
            if pkt.haslayer(IP):
                # Check if the packet is a TCP packet and if it is a SYN packet
                if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
                    # Extract the target IP and port
                    target_ip = pkt[IP].dst
                    target_port = pkt[TCP].dport
                    target_ips_and_ports.add(f"{target_ip}:{target_port}")
            packet_number += 1

        return target_ips_and_ports

    def count_bytes(
        self, ip_address: str, port: int, pcap_file: str
    ) -> tuple[int, int]:
        """Count bytes sent to and received from a specific IP:port.

        Analyzes all TCP/UDP packets in the PCAP file that match the specified
        IP address and port, summing payload sizes for each direction.

        Args:
            ip_address: The target IP address to analyze.
            port: The target port number to analyze.
            pcap_file: Path to the PCAP file to analyze.

        Returns:
            A tuple of (sent_bytes, received_bytes) where:
                - sent_bytes: Total payload bytes sent to the IP:port.
                - received_bytes: Total payload bytes received from the IP:port.
        """
        _ensure_scapy()  # Lazy import scapy
        packets = rdpcap(pcap_file)
        sent_bytes = 0
        received_bytes = 0
        for packet in packets:
            if packet.haslayer("IP"):
                ip = packet["IP"]
                if ip.haslayer("TCP") or ip.haslayer("UDP"):
                    tcp_udp = ip["TCP"] if ip.haslayer("TCP") else ip["UDP"]
                    if tcp_udp.dport == port or tcp_udp.sport == port:
                        if ip.src == ip_address:
                            received_bytes += len(tcp_udp.payload)
                        if ip.dst == ip_address:
                            sent_bytes += len(tcp_udp.payload)
        return sent_bytes, received_bytes
