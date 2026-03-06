#!/usr/bin/env python3
"""
Packet capture module for Killswitch.
Handles packet sniffing using scapy with a clean callback interface.
"""
import logging
from ipaddress import ip_address, ip_network
from threading import Thread, Event
from typing import Callable, Dict, Optional

from scapy.all import sniff, IP, UDP

from src.config import config
from src.state import SessionState

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Captures network packets and feeds them to a processor callback.

    Scapy runs in its own thread. The processor callback is invoked
    directly from the sniffer thread — keep it lightweight.
    """

    def __init__(self, state: SessionState):
        """Initialize packet capture.

        Args:
            state: Shared session state (used for paused flag)
        """
        self.state = state
        self.running = False
        self.stop_event = Event()

        self.sniffer_thread: Optional[Thread] = None
        self.packet_processor: Optional[Callable[[Dict], None]] = None

        # Parse ignored IPs/CIDRs once into network objects
        self._ignore_networks: list = []
        self._parse_ignore_list()

        # Cache for IP ignore checks — avoids creating ip_address objects
        # per packet for IPs we've already seen. Bounded by unique peer
        # count (hundreds over a multi-hour session).
        self._ignore_cache: Dict[str, bool] = {}

    def set_processor(self, processor: Callable[[Dict], None]) -> None:
        """Set the callback function for processing packets."""
        self.packet_processor = processor

    def _build_capture_filter(self) -> str:
        """Build BPF filter string for RDO/GTAO ports."""
        port_filter = " or ".join(
            [f"port {p}" for p in config.all_ports]
        )
        return f"udp and ({port_filter})"

    def _parse_ignore_list(self) -> None:
        """Parse ignored_ips config into network objects."""
        for entry in config.ignored_ips:
            self._ignore_networks.append(
                ip_network(entry, strict=False)
            )

    def _should_ignore(self, ip: str) -> bool:
        """Check if an IP should be ignored, with caching."""
        if ip not in self._ignore_cache:
            addr = ip_address(ip)
            self._ignore_cache[ip] = any(
                addr in network for network in self._ignore_networks
            )
        return self._ignore_cache[ip]

    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """
        Extract relevant information from a scapy packet.

        Returns:
            Dict with packet info, or None if packet should be ignored.
        """
        try:
            if IP not in packet or UDP not in packet:
                return None

            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            sport = packet[UDP].sport
            dport = packet[UDP].dport

            # Ignore local/server IPs
            if self._should_ignore(ip_src):
                return None

            # Only process packets on RDO ports
            if sport not in config.all_ports and dport not in config.all_ports:
                return None

            # Determine which port is the RDO port
            port = sport if sport in config.all_ports else dport

            return {
                "timestamp": packet.time,
                "ip_src": ip_src,
                "ip_dst": ip_dst,
                "sport": sport,
                "dport": dport,
                "port": port,
                "size": len(packet),
            }

        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None

    def _packet_handler(self, packet) -> None:
        """Handler called by scapy for each captured packet.

        Reads state.paused without the lock — a stale read just means
        one extra packet processed before pause takes effect.
        """
        if self.state.paused:
            return

        packet_info = self._extract_packet_info(packet)
        if packet_info and self.packet_processor:
            try:
                self.packet_processor(packet_info)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")

    def _sniffer_worker(self, interface: Optional[str]) -> None:
        """Worker thread that runs the scapy sniffer."""
        try:
            sniff_kwargs = {
                "prn": self._packet_handler,
                "store": 0,
                "filter": self._build_capture_filter(),
                "stop_filter": lambda _: self.stop_event.is_set(),
            }

            if interface:
                sniff_kwargs["iface"] = interface

            sniff(**sniff_kwargs)

        except Exception as e:
            logger.error(f"Sniffer error: {e}")
            self.running = False

    def start(self, interface: Optional[str] = None) -> bool:
        """
        Start packet capture.

        Args:
            interface: Network interface to capture on (None for auto)

        Returns:
            True if started successfully
        """
        if self.running:
            logger.warning("Capture already running")
            return False

        if not self.packet_processor:
            logger.error("No packet processor set")
            return False

        self.stop_event.clear()
        self._ignore_cache.clear()

        # Start sniffer thread
        self.sniffer_thread = Thread(
            target=self._sniffer_worker,
            args=(interface,),
            name="PacketSniffer",
            daemon=True
        )
        self.sniffer_thread.start()

        self.running = True
        iface_name = interface or "auto"
        logger.debug(f"Packet capture started on {iface_name}")
        return True

    def stop(self) -> bool:
        """Stop packet capture."""
        if not self.running:
            return False

        self.stop_event.set()

        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)

        self.running = False
        logger.debug("Packet capture stopped")
        return True
