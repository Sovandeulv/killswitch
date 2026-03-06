#!/usr/bin/env python3
"""
Packet analyzer module for Killswitch.
Detects lag switching through gap analysis on the primary gaming port.

Simple and direct: every gap on the primary port is immediately scored
and accumulated per IP. When the score crosses the threshold, the IP
is confirmed as a lag switcher and blocked.

The user controls when scoring is active via pause/resume (p command).
Pause before lobby transitions, resume when PvP starts.

Gap classification:
- < 0.5s: ignored (normal network variance / MTU tweaking)
- 0.5-0.8s: short gap, score +3
- 0.8-2.0s: medium gap, score +8
- > 2.0s: long gap, score +10
"""
import logging
from typing import Dict, List, Set, Tuple

from src.config import config
from src.state import SessionState, HistoryManager

logger = logging.getLogger(__name__)


class GapAnalyzer:
    """
    Analyzes network packet timing to detect lag switching.

    For each packet on the primary port, measures the time since the
    last packet from the same IP. If the gap falls within the detection
    range, it is classified, scored, and accumulated immediately.

    DESIGN NOTE: This is deliberately simple. We tried two more complex
    approaches that failed in real PvP testing:

    1. Deferred scoring (PendingGap): gaps were held and only scored if
       10+ packets arrived within 2s. Failed because lag-switchers still
       sent enough packets to confirm, and lobby transitions sometimes
       did too.

    2. Pre-gap streak filter: required N consecutive packets before a gap
       could be scored. Failed because real lag-switchers operated with
       sub-0.5s gaps (6000+ packet streaks with zero detectable gaps).

    Both added complexity without catching real cheaters. Manual
    pause/resume + simultaneous gap filter handles transitions better.
    See NOTES.md for full details.
    """

    def __init__(self, state: SessionState, history: HistoryManager):
        """
        Initialize the analyzer.

        Args:
            state: Shared session state
            history: Persistent history manager
        """
        self.state = state
        self.history = history

        # Last packet info per IP: {ip: (timestamp, port)}
        # Only accessed from the sniffer thread — no lock needed.
        self.last_packet: Dict[str, Tuple[float, int]] = {}

        # Recent gaps for simultaneous gap detection: [(ip, timestamp)]
        # Only accessed from the sniffer thread — no lock needed.
        self._recent_gaps: List[Tuple[str, float]] = []

        # Periodic stats counters (reset each stats interval).
        # Written by sniffer thread, read+reset by periodic thread.
        # Best-effort diagnostic data — no lock needed.
        self._stats_packets: int = 0
        self._stats_primary: int = 0
        self._stats_active_ips: Set[str] = set()
        self._stats_gaps_suppressed: int = 0

    def reset(self) -> None:
        """Reset analyzer state for a new session."""
        self.last_packet.clear()
        self._recent_gaps.clear()
        self._stats_packets = 0
        self._stats_primary = 0
        self._stats_active_ips.clear()
        self._stats_gaps_suppressed = 0

    def process_packet(self, packet_info: Dict) -> None:
        """
        Process a packet and check for lag switching patterns.

        Called from the sniffer thread for each captured packet.

        Args:
            packet_info: Dict with timestamp, ip_src, port, size
        """
        ip = packet_info["ip_src"]
        timestamp = packet_info["timestamp"]
        port = packet_info["port"]

        # Track stats for periodic diagnostics (best-effort, no lock)
        self._stats_packets += 1
        self._stats_active_ips.add(ip)
        if port == config.primary_port:
            self._stats_primary += 1

        # Update packet counts (thread-safe via state lock)
        # All IPs, no clean client skip — we tried protecting "clean" clients
        # identified during warmup, but host rotation added 8/11 IPs as clean
        # and players turn hostile mid-session.
        self.state.increment_packet_count(ip)

        # Gap detection on primary port only (auxiliary ports carry
        # voice/matchmaking, not combat data, so gaps there are meaningless
        # for lag-switch detection).
        # We keep scoring confirmed IPs so the history file reflects true
        # severity (scapy still sees their packets — captures before PF
        # drops them).
        if (ip in self.last_packet
                and port == config.primary_port):
            last_time, _ = self.last_packet[ip]
            gap = timestamp - last_time

            if config.min_gap_threshold <= gap <= config.max_gap_threshold:
                if self._is_simultaneous_gap(ip, timestamp):
                    self._stats_gaps_suppressed += 1
                    logger.debug(
                        f"SUPPRESSED [{ip}]: {gap:.3f}s "
                        f"(simultaneous gap burst)"
                    )
                else:
                    self._score_gap(ip, gap)

        self.last_packet[ip] = (timestamp, port)

    def _is_simultaneous_gap(self, ip: str, timestamp: float) -> bool:
        """
        Check if this gap is part of a simultaneous burst across many IPs.

        If multiple IPs all gap within a short window, it's likely a
        lobby transition or network event, not individual lag switching.

        NOTE: The first N-1 IPs in a burst will be scored before the burst
        is detected. This is acceptable — those scores are small (+3 to +10)
        and decay away at 0.5/min. The primary defense against lobby
        transitions is the user pausing via the `p` command.

        Args:
            ip: Source IP of current gap
            timestamp: When the gap was detected

        Returns:
            True if this gap should be suppressed
        """
        window = config.gap_burst_window
        min_ips = config.gap_burst_min_ips

        # Prune old entries
        cutoff = timestamp - window
        self._recent_gaps = [
            (g_ip, g_ts) for g_ip, g_ts in self._recent_gaps
            if g_ts >= cutoff
        ]

        # Add this gap
        self._recent_gaps.append((ip, timestamp))

        # Count unique IPs that gapped in the window
        unique_ips = {g_ip for g_ip, _ in self._recent_gaps}
        return len(unique_ips) >= min_ips

    def apply_score_decay(self, elapsed_seconds: float) -> None:
        """
        Decay scores for unconfirmed IPs over time.

        Called periodically from the periodic thread. Delegates to
        state.decay_scores() which handles locking internally.

        Args:
            elapsed_seconds: Time since last decay call
        """
        if config.score_decay_per_min <= 0:
            return

        decay = config.score_decay_per_min * (elapsed_seconds / 60.0)
        self.state.decay_scores(decay)

    def _score_gap(self, ip: str, gap: float) -> None:
        """
        Score a detected gap immediately.

        Uses state.record_gap() for thread-safe atomic scoring.
        If the IP is newly confirmed, records it in history (under
        history's own lock, never nested with state lock).

        Args:
            ip: Source IP
            gap: Gap duration in seconds
        """
        gap_type, score = self._classify_gap(gap)

        # Atomic: update gap counts, score, and check confirmation
        new_score, newly_confirmed = self.state.record_gap(
            ip, gap_type, score, config.score_threshold
        )

        logger.debug(
            f"GAP [{ip}]: {gap:.3f}s ({gap_type}) "
            f"+{score:.1f} -> total: {new_score:.1f}"
        )

        if newly_confirmed:
            # Log and persist — history.add() uses its own lock
            self.history.add(ip, new_score)
            with self.state.locked():
                gap_counts = self.state.get_gap_counts(ip)
                short = gap_counts["short"]
                medium = gap_counts["medium"]
                long = gap_counts["long"]
            logger.warning(
                f"CONFIRMED LAG SWITCHER: {ip} (score: {new_score:.1f}, "
                f"gaps: {short}S/{medium}M/{long}L)"
            )
        elif new_score >= config.score_threshold:
            # Already confirmed — keep history score up to date
            self.history.update_score(ip, new_score)

    def log_stats(self) -> None:
        """
        Log periodic diagnostic stats and reset counters.

        Shows packet flow, port distribution, and current scores
        to help diagnose detection behavior.
        """
        if self._stats_packets == 0:
            logger.debug("STATS: no packets received")
            self._stats_active_ips.clear()
            return

        # Snapshot shared state under lock for consistent display
        with self.state.locked():
            blocked = len(self.state.blocked_ips)
            unconfirmed = len([
                ip for ip in self.state.scores
                if ip not in self.state.confirmed_switchers
            ])
            scored_ips = sorted(
                self.state.scores.items(),
                key=lambda x: x[1], reverse=True
            )[:5]
            confirmed = set(self.state.confirmed_switchers)

        clean = len(self._stats_active_ips) - blocked - unconfirmed

        suppressed = (f" | {self._stats_gaps_suppressed} suppressed"
                      if self._stats_gaps_suppressed > 0 else "")

        # Summary line — always logged at debug
        logger.debug(
            f"STATS: {self._stats_packets:,} pkts "
            f"({self._stats_primary:,} on :{config.primary_port}) | "
            f"{len(self._stats_active_ips)} IPs "
            f"({blocked} blocked, {unconfirmed} scoring, {clean} clean)"
            f"{suppressed}"
        )

        # Per-IP scores — debug only, useful for troubleshooting
        if scored_ips:
            parts = []
            for ip, s in scored_ips:
                marker = "*" if ip in confirmed else ""
                parts.append(f"{ip}={s:.1f}{marker}")
            logger.debug(f"  scores: {', '.join(parts)}")

        # Reset counters (best-effort, no lock — diagnostic only)
        self._stats_packets = 0
        self._stats_primary = 0
        self._stats_active_ips.clear()
        self._stats_gaps_suppressed = 0

    def _classify_gap(self, gap: float) -> Tuple[str, float]:
        """
        Classify a gap and return its type and score contribution.

        The 0.5s floor was chosen after testing: 0.3-0.4s overlaps with
        MTU tweakers and normal protocol behaviour. Below 0.5s we cannot
        reliably distinguish lag switching from network noise.

        Args:
            gap: Gap duration in seconds

        Returns:
            Tuple of (gap_type, score)
        """
        if gap < 0.8:
            # Short: 0.5-0.8s
            return ("short", config.score_short)
        elif gap <= config.medium_gap_end:
            # Medium: 0.8-2.0s
            return ("medium", config.score_medium)
        else:
            # Long: > 2.0s
            return ("long", config.score_long)
