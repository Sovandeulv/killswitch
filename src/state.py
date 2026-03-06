#!/usr/bin/env python3
"""
Session state module for Killswitch.
Single source of truth for all session-related state.

Thread safety: SessionState uses a threading.Lock to protect all mutable
collections. Mutation methods acquire the lock internally. For consistent
multi-field reads, callers use `with state.locked():`.
"""
import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class LagSwitcherRecord:
    """Record of a known lag switcher."""
    first_seen: float
    last_seen: float
    score: float
    count: int = 1


@dataclass
class SessionState:
    """
    Single source of truth for all session state.
    All components read from and write to this shared state.

    Thread safety: All mutable collections (scores, gap_counts, packet_counts,
    confirmed_switchers, blocked_ips) are protected by _lock. Use the mutation
    methods for writes, and `with state.locked():` for consistent multi-field
    reads.

    The `paused` flag may be read without the lock on the hot path (capture.py)
    — a stale read just means one extra packet processed before pause takes
    effect.
    """
    # Session identification
    session_id: str = ""
    start_time: float = 0.0

    # Session host (never block)
    host_ip: Optional[str] = None

    # Currently blocked IPs this session
    blocked_ips: Set[str] = field(default_factory=set)

    # Confirmed lag switchers this session (IPs that crossed the score threshold)
    confirmed_switchers: Set[str] = field(default_factory=set)

    # Suspicion scores for all tracked IPs
    scores: Dict[str, float] = field(default_factory=dict)

    # Gap counts per IP: {ip: {"short": 0, "medium": 0, "long": 0}}
    gap_counts: Dict[str, Dict[str, int]] = field(default_factory=dict)

    # Packet tracking
    packet_counts: Dict[str, int] = field(default_factory=dict)

    # Gap stats (session-level counter, updated by analyzer)
    gaps_detected: int = 0

    # Pipeline control
    paused: bool = False
    warmup_active: bool = True
    warmup_end_time: float = 0.0

    # Threading lock — protects all mutable collections above.
    # Not included in dataclass __init__/__repr__ via field(init=False, repr=False).
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )

    # --- Context manager for consistent multi-field reads ---

    @contextmanager
    def locked(self):
        """Acquire the state lock for consistent multi-field reads.

        Usage::

            with state.locked():
                snapshot = dict(state.scores)
                blocked = set(state.blocked_ips)
        """
        with self._lock:
            yield

    # --- Lifecycle (called before threads start, no lock needed) ---

    def reset(self, session_id: Optional[str] = None,
              warmup_period: float = 45.0):
        """Reset state for a new session. Call before starting threads."""
        self.session_id = session_id or f"session_{int(time.time())}"
        self.start_time = time.time()
        self.host_ip = None
        self.blocked_ips.clear()
        self.confirmed_switchers.clear()
        self.scores.clear()
        self.gap_counts.clear()
        self.packet_counts.clear()
        self.gaps_detected = 0
        self.paused = False
        self.warmup_active = True
        self.warmup_end_time = time.time() + warmup_period

    # --- Thread-safe mutation methods ---

    def increment_packet_count(self, ip: str) -> None:
        """Increment packet count for an IP. Called per-packet (hot path)."""
        with self._lock:
            self.packet_counts[ip] = self.packet_counts.get(ip, 0) + 1

    def record_gap(self, ip: str, gap_type: str, score: float,
                   threshold: float) -> Tuple[float, bool]:
        """Record a scored gap and check for confirmation.

        Atomically updates gap_counts, gaps_detected, scores, and
        confirmed_switchers under the lock.

        Args:
            ip: Source IP that produced the gap.
            gap_type: "short", "medium", or "long".
            score: Score to add for this gap.
            threshold: Score threshold for confirmation.

        Returns:
            (new_score, newly_confirmed) — newly_confirmed is True only
            the first time this IP crosses the threshold.
        """
        with self._lock:
            # Update gap counts
            if ip not in self.gap_counts:
                self.gap_counts[ip] = {"short": 0, "medium": 0, "long": 0}
            self.gap_counts[ip][gap_type] += 1
            self.gaps_detected += 1

            # Accumulate score
            new_score = self.scores.get(ip, 0) + score
            self.scores[ip] = new_score

            # Check confirmation
            newly_confirmed = (
                new_score >= threshold
                and ip not in self.confirmed_switchers
            )
            if newly_confirmed:
                self.confirmed_switchers.add(ip)

            return new_score, newly_confirmed

    def decay_scores(self, decay_amount: float) -> None:
        """Decay scores for unconfirmed IPs.

        Subtracts decay_amount from each unconfirmed IP's score.
        Removes IPs whose score drops to zero or below.

        Args:
            decay_amount: Amount to subtract from each score.
        """
        with self._lock:
            to_remove: List[str] = []
            for ip, score in self.scores.items():
                if ip in self.confirmed_switchers:
                    continue
                new_score = score - decay_amount
                if new_score <= 0:
                    to_remove.append(ip)
                else:
                    self.scores[ip] = new_score

            for ip in to_remove:
                del self.scores[ip]
                self.gap_counts.pop(ip, None)

    def clear_ip(self, ip: str) -> float:
        """Clear all tracking for an IP.

        Removes from scores, gap_counts, and confirmed_switchers.
        Does NOT remove from blocked_ips — use mark_unblocked() for that.

        Args:
            ip: IP to clear.

        Returns:
            The old score (0 if not tracked).
        """
        with self._lock:
            old_score = self.scores.pop(ip, 0.0)
            self.gap_counts.pop(ip, None)
            self.confirmed_switchers.discard(ip)
            return old_score

    def clear_unconfirmed(self) -> int:
        """Clear scores for all unconfirmed IPs.

        Used when pausing — unconfirmed scores are likely false positives
        from the lobby transition the user is pausing for.

        Returns:
            Number of IPs cleared.
        """
        with self._lock:
            cleared = 0
            for ip in list(self.scores):
                if ip not in self.confirmed_switchers:
                    del self.scores[ip]
                    self.gap_counts.pop(ip, None)
                    cleared += 1
            return cleared

    def start_warmup(self, duration: float) -> None:
        """Start (or restart) the warmup period.

        Args:
            duration: Warmup duration in seconds.
        """
        with self._lock:
            self.warmup_active = True
            self.warmup_end_time = time.time() + duration

    def set_host(self, ip: str) -> None:
        """Set the session host IP.

        Only the host is protected from blocking. When the host changes,
        the old host loses protection and is analyzed like any other player.
        """
        with self._lock:
            if self.host_ip != ip:
                logger.debug(f"Session host set to {ip}")
                self.host_ip = ip
                # Unblock host if it was blocked (e.g., from history)
                self.confirmed_switchers.discard(ip)
                self.blocked_ips.discard(ip)
                self.scores.pop(ip, None)

    def check_warmup(self) -> bool:
        """Check and update warmup status. Returns True if warmup just ended."""
        with self._lock:
            if self.warmup_active and time.time() >= self.warmup_end_time:
                self.warmup_active = False
                logger.info("Warmup period ended - blocking is now active")
                return True
            return False

    def is_blockable(self, ip: str) -> bool:
        """Check if an IP can be blocked (not host).

        Safe to call without the lock — reads a single reference (host_ip).
        """
        return ip != self.host_ip

    def get_gap_counts(self, ip: str) -> Dict[str, int]:
        """Get gap counts for an IP, initializing if needed.

        Caller should hold the lock if using from a non-sniffer thread.
        """
        if ip not in self.gap_counts:
            self.gap_counts[ip] = {"short": 0, "medium": 0, "long": 0}
        return self.gap_counts[ip]

    # --- Blocked IP management (called by firewall layer) ---

    def mark_blocked(self, ip: str) -> None:
        """Mark an IP as blocked in state."""
        with self._lock:
            self.blocked_ips.add(ip)

    def mark_unblocked(self, ip: str) -> None:
        """Mark an IP as unblocked in state."""
        with self._lock:
            self.blocked_ips.discard(ip)

    def get_blocked_snapshot(self) -> Set[str]:
        """Return a snapshot of currently blocked IPs.

        Safe to iterate without holding the lock.
        """
        with self._lock:
            return set(self.blocked_ips)

    def get_blockable_confirmed(self) -> List[str]:
        """Get confirmed switchers that should be blocked.

        Returns:
            List of IPs that are confirmed but not yet blocked and not host.
        """
        with self._lock:
            return [
                ip for ip in self.confirmed_switchers
                if ip not in self.blocked_ips and ip != self.host_ip
            ]


class HistoryManager:
    """
    Manages persistent history of known lag switchers across sessions.

    Thread safety: All public methods are protected by _lock, which
    is independent of SessionState._lock (never nested).
    """

    def __init__(self, history_file: str = "logs/lag_switchers_history.json"):
        """
        Initialize history manager.

        Args:
            history_file: Path to the history JSON file
        """
        self.history_file = history_file
        self.known_lag_switchers: Dict[str, LagSwitcherRecord] = {}
        self._lock = threading.Lock()

        # Ensure logs directory exists
        os.makedirs(os.path.dirname(history_file), exist_ok=True)

        self._load()

    def _load(self) -> None:
        """Load history from file. Called once at init (no lock needed)."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    data = json.load(f)

                for ip, details in data.items():
                    self.known_lag_switchers[ip] = LagSwitcherRecord(
                        first_seen=details.get("first_seen", time.time()),
                        last_seen=details.get("last_seen", time.time()),
                        score=details.get("score", 0),
                        count=details.get("count", 1)
                    )

                if self.known_lag_switchers:
                    logger.debug(
                        f"Loaded {len(self.known_lag_switchers)} known "
                        f"lag switchers from history"
                    )
            except Exception as e:
                logger.error(f"Error loading history: {e}")
                self.known_lag_switchers = {}

    def _save_locked(self) -> None:
        """Save history to file. Caller must hold _lock."""
        try:
            data = {
                ip: {
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                    "score": record.score,
                    "count": record.count
                }
                for ip, record in self.known_lag_switchers.items()
            }

            with open(self.history_file, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug(
                f"Saved {len(self.known_lag_switchers)} lag switchers "
                f"to history"
            )
        except Exception as e:
            logger.error(f"Error saving history: {e}")

    def save(self) -> None:
        """Save history to file (thread-safe)."""
        with self._lock:
            self._save_locked()

    def add(self, ip: str, score: float) -> None:
        """Add or update a lag switcher in history."""
        with self._lock:
            now = time.time()

            if ip in self.known_lag_switchers:
                record = self.known_lag_switchers[ip]
                record.last_seen = now
                record.score = max(record.score, score)
                record.count += 1
            else:
                self.known_lag_switchers[ip] = LagSwitcherRecord(
                    first_seen=now,
                    last_seen=now,
                    score=score,
                    count=1
                )

            # Save immediately to prevent data loss
            self._save_locked()

    def update_score(self, ip: str, score: float) -> None:
        """Update score for a known lag switcher in-memory (no disk save)."""
        with self._lock:
            if ip in self.known_lag_switchers:
                record = self.known_lag_switchers[ip]
                if score > record.score:
                    record.score = score

    def remove(self, ip: str) -> None:
        """Remove an IP from history (e.g., if it becomes session host)."""
        with self._lock:
            if ip in self.known_lag_switchers:
                del self.known_lag_switchers[ip]
                self._save_locked()
                logger.debug(f"Removed {ip} from lag switcher history")

    def get_known_bad_actors(self, min_score: float = 0) -> Dict[str, float]:
        """
        Get known bad actors that meet the score threshold.

        Args:
            min_score: Minimum score to include

        Returns:
            Dict of IP -> score for matching lag switchers
        """
        with self._lock:
            return {
                ip: record.score
                for ip, record in self.known_lag_switchers.items()
                if record.score >= min_score
            }

    def count(self) -> int:
        """Return number of known lag switchers (thread-safe)."""
        with self._lock:
            return len(self.known_lag_switchers)
