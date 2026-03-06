#!/usr/bin/env python3
"""
Configuration module for Killswitch.
Centralized configuration with sensible defaults.
"""
from dataclasses import dataclass, field
from typing import FrozenSet, List


@dataclass
class Config:
    """
    Configuration for Killswitch.
    All values have sensible defaults for RDO/GTAO.
    """

    # === Gap Detection Thresholds ===
    # Gaps below this are ignored (normal network variance)
    min_gap_threshold: float = 0.5
    # Gaps above this are likely disconnections, not lag switching
    max_gap_threshold: float = 5.0

    # Gap classification boundary
    medium_gap_end: float = 2.0     # End of medium / start of long

    # === Scoring ===
    # Score threshold to confirm as lag switcher
    score_threshold: float = 10.0

    # Score values for different gap types
    score_short: float = 3.0           # 0.5-0.8s gaps
    score_medium: float = 8.0         # 0.8-2.0s gaps
    score_long: float = 10.0          # >2.0s gaps

    # Score decay per minute for unconfirmed IPs (0 = disabled)
    score_decay_per_min: float = 0.5

    # === Simultaneous Gap Filter ===
    # If this many IPs gap within the window, treat as lobby transition
    gap_burst_min_ips: int = 3
    # Time window for simultaneous gap detection (seconds)
    gap_burst_window: float = 3.0

    # === Timing ===
    # Warmup period before blocking starts (seconds)
    warmup_period: float = 45.0
    # Warmup period after resume (shorter, just for host re-detection)
    resume_warmup_period: float = 10.0

    # === Network ===
    # Primary gaming data port (position, combat, etc.)
    primary_port: int = 6672
    # All RDO/GTAO ports for monitoring
    all_ports: FrozenSet[int] = field(default_factory=lambda: frozenset({6672, 61455, 61456, 61457, 61458}))

    # IPs/networks to ignore (exact IPs or CIDR notation)
    ignored_ips: List[str] = field(default_factory=lambda: [
        "185.56.65.0/24",   # Rockstar servers
        "192.168.0.0/16",   # Local network
        "10.0.0.0/8",       # Local network
        "172.16.0.0/12",    # Local network
    ])

    # === Host Detection ===
    # Minimum packets to consider a player as host candidate
    min_active_packets: int = 100
    min_active_packets_warmup: int = 50

    # === Diagnostics ===
    # How often to log periodic stats (seconds)
    stats_interval: float = 30.0

    # === Files ===
    history_file: str = "logs/lag_switchers_history.json"
    log_file: str = "logs/killswitch.log"


# Global config instance
config = Config()


def update_config(**kwargs):
    """Update config values from command line arguments or other sources."""
    for key, value in kwargs.items():
        if hasattr(config, key) and value is not None:
            setattr(config, key, value)
