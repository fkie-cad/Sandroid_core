# ensure that we only see errors from scapy
import logging
import os
import threading
import time
from logging import getLogger

from colorama import Fore, Style

from sandroid.core.adb import Adb
from sandroid.core.toolbox import Toolbox

from .datagather import DataGather

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, IP, TCP, rdpcap

logger = getLogger(__name__)


class Network(DataGather):
    """Handles network traffic measurement and analysis.

    **Attributes:**
        internal_run_counter (int): Counter for internal runs.
        connections_made (None): Placeholder for connections made.
        dns_requests (set): Set of DNS requests.
        logger (Logger): Logger instance for the class.
        _path (str): Path for storing network trace files.
        _emulator_path (str): Path on the emulator for storing trace files.
        _trace_file_name (str): Base name for trace files.
        performed_diff (bool): Flag indicating if the diff has been performed.
    """

    internal_run_counter = 1
    connections_made = None
    dns_requests = set()
    _path = f"{os.getenv('RAW_RESULTS_PATH')}network_trace_pull/"
    _emulator_path = "data/local/tmp/"
    _trace_file_name = "network_trace_run_"
    performed_diff = False

    def gather(self):
        """Starts a timed thread to measure network traffic."""
        logger.info("Measuring network traffic")
        t1 = threading.Thread(target=self.tcpdump_thread, args=())
        t1.start()
        # time.sleep(0.5)

    def return_data(self):
        """Returns the gathered DNS requests and target IPs and ports.

        :returns: Dictionary containing DNS requests and target IPs and ports.
        :rtype: dict
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

    def pretty_print(self):
        """Returns a formatted string of DNS requests and target IPs and ports.

        :returns: Formatted string of DNS requests and target IPs and ports.
        :rtype: str
        """
        if not self.performed_diff:
            self.dns_requests = self.extract_dns_requests_for_all_pcaps()
            self.target_ips_and_ports = (
                self.extract_target_ips_and_ports_for_all_pcaps()
            )
            self.performed_diff = True

        result = (
            Fore.YELLOW
            + Style.BRIGHT
            + "\n—————————————————NETWORK=(DNS requests made by emulator)———————————————————————————————————————————————\n"
        )
        for entry in sorted(self.dns_requests):
            result += Fore.YELLOW + entry + "\n"
        result = result + (
            Fore.YELLOW
            + Style.BRIGHT
            + "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
        )

        result += (
            Fore.LIGHTYELLOW_EX
            + Style.BRIGHT
            + "\n—————————————————NETWORK=(Target IP ports)———————————————————————————————————————————————————————\n"
        )
        for entry in self.target_ips_and_ports:
            result += Fore.LIGHTYELLOW_EX + entry + "\n"
        result += (
            Fore.LIGHTYELLOW_EX
            + Style.BRIGHT
            + "———————————————————————————————————————————————————————————————————————————————————————————————————————\n"
        )

        return result

    def tcpdump_thread(self):
        """Meant to be run as a Thread that uses adb emu network capture."""
        noise_path = f"{self._path}{self._trace_file_name}noise.pcap"
        path = f"{self._path}{self._trace_file_name}{self.internal_run_counter!s}.pcap"
        accumulated_errors = ""
        runtime = Toolbox.get_action_duration()
        if Toolbox.is_dry_run():
            command = f"network capture start {noise_path}"
        else:
            command = f"network capture start {path}"
        out, err = Adb.send_telnet_command(command)
        accumulated_errors += err

        time.sleep(runtime)

        if Toolbox.is_dry_run():
            out, err = Adb.send_telnet_command(f"network capture stop {noise_path}")
        else:
            out, err = Adb.send_telnet_command(f"network capture stop {path}")
        accumulated_errors += err
        self.internal_run_counter += 1
        if accumulated_errors:
            logger.error(
                f"Errors occurred during network capture: {accumulated_errors}"
            )

    @classmethod
    def get_path(cls):
        """Returns the path for storing network trace files.

        :returns: Path for storing network trace files.
        :rtype: str
        """
        return cls._path

    @classmethod
    def get_file_name(cls):
        """Returns the base name for trace files.

        :returns: Base name for trace files.
        :rtype: str
        """
        return cls._trace_file_name

    def extract_dns_requests_for_all_pcaps(self):
        """Extracts DNS requests from a series of PCAP files and compares them
        against a 'noise' PCAP file to identify unique DNS requests.

        :returns: A list of unique DNS requests found in the PCAP files excluding those found in the 'noise' PCAP.
        :rtype: list
        """
        # Set to store DNS requests from all pcaps except the noise pcap
        all_dns_requests = set()

        logger.info("Analyzing pcaps for DNS requests, this could take a minute...")

        # Iterate over PCAP files
        for i in range(1, self.internal_run_counter - 1):
            path = f"{self._path}{self._trace_file_name}{i}.pcap"

            # Extract DNS requests and add them to the set
            dns_requests = self.extract_dns_requests_from_pcap(path)
            all_dns_requests.update(dns_requests)

        # Extract DNS requests from the noise pcap
        noise_path = f"{self._path}{self._trace_file_name}noise.pcap"
        noise_dns_requests = self.extract_dns_requests_from_pcap(noise_path)

        # Return only the DNS names that were in all_dns_requests but not in noise_dns_requests as a list
        diff = list(all_dns_requests - noise_dns_requests)
        return diff

    @classmethod
    def extract_dns_requests_from_pcap(cls, pcap_path):
        """Extracts all requested domain names from a PCAP file.

        :param pcap_path: Path to the PCAP file
        :returns: A set of domain names.
        :rtype: set
        """
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

    def extract_target_ips_and_ports_for_all_pcaps(self):
        """Extracts target IPs and ports from a series of PCAP files and compares them
        against a 'noise' PCAP file to identify unique target IPs and ports.

        :returns: A set of unique target IPs and ports found in the PCAP files excluding those found in the 'noise' PCAP.
        :rtype: set
        """
        # Set to store target IPs and ports from all pcaps except the noise pcap
        all_target_ips_and_ports = set()

        logger.info(
            "Analyzing pcaps for target IPs and ports, this could take a minute..."
        )

        # Iterate over PCAP files
        for i in range(1, self.internal_run_counter - 1):
            path = f"{self._path}{self._trace_file_name}{i}.pcap"

            # Extract target IPs and ports and add them to the set
            target_ips_and_ports = self.extract_target_ips_and_ports(path)
            all_target_ips_and_ports.update(target_ips_and_ports)

        # Extract target IPs and ports from the noise pcap
        noise_path = f"{self._path}{self._trace_file_name}noise.pcap"
        noise_target_ips_and_ports = self.extract_target_ips_and_ports(noise_path)

        # Return only the target IPs and ports that were in all_target_ips_and_ports but not in noise_target_ips_and_ports
        diff = list(all_target_ips_and_ports - noise_target_ips_and_ports)

        # Calculate the number of bytes sent and received over each connection
        result = []
        for ip_and_port in diff:
            target_IP = ip_and_port.split(":")[0]
            target_port = int(ip_and_port.split(":")[1])
            pcap_path = self._path + "/network_trace_run_1.pcap"
            sent_bytes, received_bytes = self.count_bytes(
                target_IP, target_port, pcap_path
            )
            result.append(
                f"{target_IP}:{target_port} ({sent_bytes}B sent to / {received_bytes}B received from)"
            )

        return result

    @classmethod
    def extract_target_ips_and_ports(cls, pcap_path):
        """Extract all target IPs and ports from a pcap file.

        :param pcap_path: Path to the pcap file.
        :type pcap_path: str
        :returns: A set of target IPs and ports in the format "IP:Port".
        :rtype: set
        """
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

    def count_bytes(self, ip_address, port, pcap_file):
        """Internal helper function that counts how many bytes were sent from and to an IP address on a specified port

        :param ip_address: IP address to investigate
        :type ip_address: str
        :param port: port to investigate
        :type port: int
        :param pcap_file: pcap file to take information from
        :type pcap_file: str
        :returns: Number of bytes sent
        :rtype: int
        :returns: Number of bytes received
        :rtype: int
        """
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
