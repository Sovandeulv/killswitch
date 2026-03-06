#!/usr/bin/env python3
"""
Reporter module for Killswitch.
Handles logging configuration and output formatting.

Console output: INFO and above (blocks, confirmations, status, session info)
File output: Full debug logging (for troubleshooting)
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional, TYPE_CHECKING

from src.config import config

if TYPE_CHECKING:
    from src.state import SessionState

logger = logging.getLogger(__name__)


def setup_logging(debug: bool = False,
                  log_file: Optional[str] = None) -> None:
    """
    Configure logging for Killswitch.

    Args:
        debug: If True, also show debug messages on console
        log_file: Path to log file (uses config default if None)
    """
    log_file = log_file or config.log_file

    # Ensure logs directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Create formatters
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(name)s - %(message)s',
        '%Y-%m-%d %H:%M:%S'
    )
    console_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        '%H:%M:%S'
    )

    # Get root logger
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Clear existing handlers
    root.handlers.clear()

    # File handler - INFO normally, DEBUG when debug flag is set
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    file_handler.setFormatter(file_format)
    root.addHandler(file_handler)

    # Console handler - only important messages by default
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_format)

    if debug:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)

    root.addHandler(console_handler)

    logger.debug(f"Logging initialized - file: {log_file}, debug: {debug}")


def log_session_start(session_id: str, interface: Optional[str],
                      operational: bool) -> None:
    """Log session start with configuration summary."""
    mode = "OPERATIONAL" if operational else "ANALYSIS"
    logger.info("=== KILLSWITCH SESSION STARTED ===")
    logger.info(f"Session: {session_id}")
    logger.info(f"Mode: {mode}")
    logger.info(f"Interface: {interface or 'auto'}")
    logger.info(f"Primary port: {config.primary_port}")
    logger.info(f"Score threshold: {config.score_threshold}")
    logger.info(f"Warmup period: {config.warmup_period}s")
    logger.info("=" * 35)


def log_session_end(state: SessionState, duration: float,
                    blocked_count: int = 0) -> None:
    """Log session end summary."""
    hours = int(duration // 3600)
    minutes = int((duration % 3600) // 60)
    seconds = int(duration % 60)

    logger.info("=" * 35)
    logger.info("=== SESSION ENDED ===")
    logger.info(f"Duration: {hours}h {minutes}m {seconds}s")
    logger.info(
        f"Confirmed lag switchers: {len(state.confirmed_switchers)}"
    )
    logger.info(f"Total blocked: {blocked_count}")
    logger.info(f"Gaps detected: {state.gaps_detected}")
    logger.info("=" * 35)


def log_commands() -> None:
    """Log available commands."""
    logger.info(
        "Commands: p=pause/resume, l=list, "
        "c IP=clear score, u SCORE=unblock, q=quit"
    )


def log_status(state: SessionState, history_count: int) -> None:
    """Log current status.

    Takes a consistent snapshot of state under the lock.
    """
    with state.locked():
        host_ip = state.host_ip
        tracked = len(state.packet_counts)
        blocked_ips = sorted(state.blocked_ips)
        blocked_count = len(blocked_ips)
        gaps_detected = state.gaps_detected
        scores_snapshot = {
            ip: state.scores.get(ip, 0) for ip in blocked_ips
        }

    clean = max(0, tracked - blocked_count - (1 if host_ip else 0))

    logger.info("=== STATUS ===")
    logger.info(f"Host: {host_ip or 'detecting...'}")
    logger.info(
        f"Blocked: {blocked_count} | Clean: {clean} "
        f"| Gaps: {gaps_detected}"
    )

    if blocked_ips:
        for ip in blocked_ips:
            score = scores_snapshot.get(ip, 0)
            logger.info(f"  [BLOCKED] {ip} (score: {score:.1f})")

    if history_count > 0:
        logger.info(f"Known from history: {history_count}")

    logger.info("=" * 14)
