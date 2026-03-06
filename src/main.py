#!/usr/bin/env python3
"""
Main module for Killswitch.
Orchestrates the capture -> analyze -> block pipeline.
"""
import argparse
import logging
import select
import signal
import sys
import threading
import time
from typing import Dict, Optional

from src.config import config, update_config
from src.state import SessionState, HistoryManager
from src.capture import PacketCapture
from src.analyzer import GapAnalyzer
from src.session import SessionManager
from src.firewall import create_firewall, Firewall
from src.reporter import (
    setup_logging, log_session_start, log_session_end,
    log_commands, log_status,
)

logger = logging.getLogger(__name__)


class Killswitch:
    """
    Main Killswitch application.
    Coordinates the capture -> analyze -> block pipeline.
    """

    def __init__(self, operational: bool = True, debug: bool = False):
        """
        Initialize Killswitch.

        Args:
            operational: True for blocking mode, False for analysis only
            debug: Enable debug logging to console
        """
        self.operational = operational
        self.debug = debug

        # Setup logging first
        setup_logging(debug=debug)

        # Initialize shared state
        self.state = SessionState()
        self.history = HistoryManager(config.history_file)

        # Initialize components
        self.capture = PacketCapture(self.state)
        self.analyzer = GapAnalyzer(self.state, self.history)
        self.session = SessionManager(self.state)
        self.firewall: Firewall = create_firewall(self.state, operational)

        # Control state
        self.command_thread: Optional[threading.Thread] = None
        self.periodic_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

    def _process_packet(self, packet_info: Dict) -> None:
        """
        Process a packet through the analysis pipeline.

        This is called for each packet by the capture module.
        Paused check already done by capture's _packet_handler.
        Periodic tasks run on a separate timer thread.
        """
        self.analyzer.process_packet(packet_info)

    def _periodic_loop(self) -> None:
        """
        Run periodic tasks on a fixed timer, independent of packet flow.

        This ensures host detection, blocking, and stats logging
        all happen even during quiet periods with no packets.
        """
        last_host_check = 0.0
        last_block_check = 0.0
        last_stats_log = 0.0
        last_decay = time.time()

        while not self.stop_event.wait(timeout=1.0):
            if self.state.paused:
                last_decay = time.time()  # Don't accumulate decay while paused
                continue

            now = time.time()

            # Check warmup status
            self.state.check_warmup()

            # Host detection during warmup or periodically
            if now - last_host_check > 5.0:
                self._check_host()
                last_host_check = now

            # Score decay for unconfirmed IPs
            decay_elapsed = now - last_decay
            if decay_elapsed > 0:
                self.analyzer.apply_score_decay(decay_elapsed)
                last_decay = now

            # Block confirmed switchers (after warmup)
            if not self.state.warmup_active and now - last_block_check > 1.0:
                self._apply_blocks()
                last_block_check = now

            # Periodic diagnostic stats
            if now - last_stats_log > config.stats_interval:
                self.analyzer.log_stats()
                last_stats_log = now

    def _check_host(self) -> None:
        """Check for session host."""
        if self.state.host_ip is None or self.state.warmup_active:
            host = self.session.find_session_host()
            if host and host != self.state.host_ip:
                self.state.set_host(host)
                logger.warning(f"📍 Session host: {host}")

    def _apply_blocks(self) -> None:
        """Apply pending blocks."""
        to_block = self.state.get_blockable_confirmed()
        for ip in to_block:
            self.firewall.block(ip)

    def start(self, interface: Optional[str] = None) -> bool:
        """
        Start Killswitch.

        Args:
            interface: Network interface to capture on

        Returns:
            True if started successfully
        """
        # Initialize firewall
        if not self.firewall.initialize():
            logger.error("Failed to initialize firewall")
            return False

        # Reset state for new session
        self.state.reset(warmup_period=config.warmup_period)
        self.analyzer.reset()
        self.session.reset()

        # Load known bad actors from history into state and block them
        bad_actors = self.history.get_known_bad_actors(
            min_score=config.score_threshold
        )
        for ip, score in bad_actors.items():
            self.state.confirmed_switchers.add(ip)
            self.state.scores[ip] = score
            if self.operational and self.state.is_blockable(ip):
                self.firewall.block(ip)
        if bad_actors:
            logger.info(
                f"Loaded {len(bad_actors)} known bad actors from history"
            )

        # Setup capture
        self.capture.set_processor(self._process_packet)

        if not self.capture.start(interface):
            logger.error("Failed to start packet capture")
            return False

        # Start background threads
        self.stop_event.clear()

        self.periodic_thread = threading.Thread(
            target=self._periodic_loop,
            name="PeriodicTasks",
            daemon=True
        )
        self.periodic_thread.start()

        self.command_thread = threading.Thread(
            target=self._command_loop,
            name="CommandLoop",
            daemon=True
        )
        self.command_thread.start()

        # Log session start
        log_session_start(self.state.session_id, interface, self.operational)
        log_commands()

        return True

    def stop(self) -> None:
        """Stop Killswitch. Called once from main thread after stop_event."""
        logger.info("Shutting down...")

        # Stop background threads
        self.stop_event.set()
        if self.periodic_thread:
            self.periodic_thread.join(timeout=2)
        if self.command_thread:
            self.command_thread.join(timeout=1)

        # Stop capture
        self.capture.stop()

        # Save stats before clearing firewall (clear_all wipes rules only,
        # not state — we clear state ourselves after).
        with self.state.locked():
            blocked_count = len(self.state.blocked_ips)

        # Clear firewall rules (does not touch state)
        self.firewall.clear_all()

        # Clear blocked state now that rules are gone
        with self.state.locked():
            self.state.blocked_ips.clear()

        # Save history
        self.history.save()

        # Log session end
        duration = time.time() - self.state.start_time
        log_session_end(self.state, duration, blocked_count)

    def pause(self) -> None:
        """Pause packet processing and clear unconfirmed scores.

        Pausing means PvP is over, so any accumulated scores below the
        confirmation threshold are noise from transitions. Confirmed
        switchers (already blocked) keep their scores.
        """
        self.state.paused = True
        cleared = self.state.clear_unconfirmed()

        if cleared:
            logger.info(f"⏸️ PAUSED (cleared {cleared} unconfirmed scores)")
        else:
            logger.info("⏸️ PAUSED")

    def resume(self) -> None:
        """Resume packet processing."""
        self.state.paused = False

        # Brief warmup after resume for host detection
        self.state.start_warmup(config.resume_warmup_period)

        logger.info(
            f"▶️ RESUMED ({config.resume_warmup_period:.0f}s warmup)"
        )

    def _command_loop(self) -> None:
        """Monitor for user commands."""
        while not self.stop_event.is_set():
            try:
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    line = sys.stdin.readline().strip().lower()
                    self._handle_command(line)
            except Exception as e:
                logger.debug(f"Command loop error: {e}")
                time.sleep(0.1)

    def _handle_command(self, command: str) -> None:
        """Handle a user command."""
        if not command:
            return

        if command == 'p':
            if self.state.paused:
                self.resume()
            else:
                self.pause()

        elif command == 'l':
            log_status(self.state, self.history.count())

        elif command == 'q':
            self.stop_event.set()

        elif command.startswith('c '):
            ip = command[2:].strip()
            if ip:
                old_score = self.state.clear_ip(ip)
                self.firewall.unblock(ip)
                self.history.remove(ip)
                logger.info(f"Cleared: {ip} (was score: {old_score:.1f})")

        elif command.startswith('u '):
            try:
                threshold = float(command[2:].strip())
                count = 0
                # Snapshot blocked IPs to iterate safely
                blocked_snapshot = self.state.get_blocked_snapshot()
                for ip in blocked_snapshot:
                    with self.state.locked():
                        score = self.state.scores.get(ip, 0)
                    if score <= threshold:
                        self.state.clear_ip(ip)
                        self.firewall.unblock(ip)
                        self.history.remove(ip)
                        count += 1
                logger.info(
                    f"Unblocked {count} IPs with score <= {threshold}"
                )
            except ValueError:
                logger.info("Usage: u <score>")

        else:
            logger.info(f"Unknown command: {command}")
            log_commands()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Killswitch - Lag switch detector and blocker "
                    "for P2P games"
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug logging to console"
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["analyze", "operational"],
        default="operational",
        help="Operation mode (default: operational)"
    )
    parser.add_argument(
        "-s", "--score-threshold",
        type=float,
        default=10.0,
        help="Score threshold for confirmation (default: 10)"
    )

    args = parser.parse_args()

    # Update config from args
    update_config(score_threshold=args.score_threshold)

    # Create app
    operational = args.mode == "operational"
    app = Killswitch(operational=operational, debug=args.debug)

    # Ctrl+C signals shutdown, main loop handles cleanup
    signal.signal(signal.SIGINT, lambda _sig, _frame: app.stop_event.set())

    # Start
    if not app.start(args.interface):
        print("Failed to start Killswitch")
        return 1

    # Run until stopped — all shutdown paths set stop_event
    try:
        app.stop_event.wait()
    finally:
        app.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
