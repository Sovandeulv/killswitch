#!/usr/bin/env python3
"""
Session management module for Killswitch.
Handles host detection based on traffic patterns.

These are all state-based queries that operate on SessionState data
populated by the analyzer and other components.
"""
import logging
from typing import Dict, Optional

from src.config import config
from src.state import SessionState

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages session-level decisions: host detection.

    Operates entirely on SessionState — no packet-level analysis.
    """

    def __init__(self, state: SessionState):
        """
        Initialize session manager.

        Args:
            state: Shared session state
        """
        self.state = state

        # Cumulative host candidate scores across checks.
        # Each 5s check adds to the tally, so the consistently
        # highest-traffic IP emerges as leader over time.
        self.host_candidates: Dict[str, float] = {}

    def reset(self) -> None:
        """Reset session manager state for a new session."""
        self.host_candidates.clear()

    def find_session_host(self) -> Optional[str]:
        """
        Find the likely session host based on cumulative traffic patterns.

        Called every 5s during warmup. Each call scores all active IPs
        and accumulates into host_candidates. The cumulative leader is
        returned — this prevents transient traffic spikes (e.g. a
        shootout) from flipping the host away from the true leader.

        Thread safety: Takes a consistent snapshot of state under the
        lock, then processes without holding the lock.

        Returns:
            IP of cumulative leader, or None if no candidates yet
        """
        min_packets = (config.min_active_packets_warmup
                       if self.state.warmup_active
                       else config.min_active_packets)

        # Snapshot state under lock for consistent reads
        with self.state.locked():
            packet_counts = dict(self.state.packet_counts)
            confirmed = set(self.state.confirmed_switchers)
            scores = dict(self.state.scores)
            gap_counts = {
                ip: dict(counts)
                for ip, counts in self.state.gap_counts.items()
            }

        # Score this round's candidates and accumulate (no lock needed)
        for ip, count in packet_counts.items():
            if count < min_packets:
                continue
            if ip in confirmed:
                continue

            score = self._calculate_host_score(
                ip, count, scores, gap_counts
            )
            if score > 0:
                self.host_candidates[ip] = (
                    self.host_candidates.get(ip, 0) + score
                )

        if not self.host_candidates:
            return None

        # Pick the cumulative leader
        best_ip = max(self.host_candidates, key=self.host_candidates.get)
        best_score = self.host_candidates[best_ip]

        logger.debug(
            f"Host candidate: {best_ip} (cumulative: {best_score:.1f})"
        )
        return best_ip

    def _calculate_host_score(self, ip: str, packet_count: int,
                              scores: Dict[str, float],
                              gap_counts: Dict[str, Dict[str, int]]
                              ) -> float:
        """Calculate host likelihood score for an IP.

        Args:
            ip: IP address to score.
            packet_count: Number of packets from this IP.
            scores: Snapshot of suspicion scores.
            gap_counts: Snapshot of gap counts per IP.

        Returns:
            Host likelihood score (higher = more likely host).
        """
        score = packet_count / 50.0

        # Penalize for suspicious score
        sus_score = scores.get(ip, 0)
        if sus_score > 0:
            score *= max(0.3, 1.0 - (sus_score / 4.0))

        # Penalize for gaps
        ip_gaps = gap_counts.get(ip, {})
        total_gaps = (ip_gaps.get("short", 0)
                      + ip_gaps.get("medium", 0)
                      + ip_gaps.get("long", 0))
        if total_gaps > 0:
            score *= max(0.3, 1.0 - (total_gaps * 0.3))

        return score
