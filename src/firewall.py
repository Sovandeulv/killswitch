#!/usr/bin/env python3
"""
Firewall module for Killswitch.
Platform-specific firewall management for blocking lag switchers.

Thread safety: All state mutations go through SessionState's locked methods
(mark_blocked, mark_unblocked, get_blocked_snapshot). Subprocess calls
(pfctl) are made outside any lock to avoid blocking the sniffer thread.
"""
import abc
import logging
import os
import subprocess
import tempfile
from src.state import SessionState

logger = logging.getLogger(__name__)


class Firewall(abc.ABC):
    """Abstract base class for platform-specific firewall implementations."""

    def __init__(self, state: SessionState):
        """
        Initialize firewall.

        Args:
            state: Shared session state
        """
        self.state = state
        self.initialized = False

    @abc.abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the firewall for operation.

        Returns:
            True if successful
        """
        pass

    @abc.abstractmethod
    def block(self, ip: str) -> bool:
        """
        Block an IP address.

        Args:
            ip: IP address to block

        Returns:
            True if successful
        """
        pass

    @abc.abstractmethod
    def unblock(self, ip: str) -> bool:
        """
        Unblock an IP address.

        Args:
            ip: IP address to unblock

        Returns:
            True if successful
        """
        pass

    @abc.abstractmethod
    def clear_all(self) -> bool:
        """
        Clear all firewall rules managed by Killswitch.

        NOTE: This only clears firewall rules. It does NOT modify
        state.blocked_ips — the caller is responsible for that.

        Returns:
            True if successful
        """
        pass


class MacOSFirewall(Firewall):
    """
    macOS implementation using PF (Packet Filter) firewall.

    Requires:
    - sudo privileges
    - PF anchor "killswitch" configured in /etc/pf.conf
    """

    ANCHOR_NAME = "killswitch"

    def initialize(self) -> bool:
        """Initialize PF firewall."""
        try:
            # Check if PF is enabled
            result = subprocess.run(
                ["sudo", "pfctl", "-s", "info"],
                capture_output=True,
                text=True
            )

            if "Status: Enabled" not in result.stdout:
                # Enable PF
                subprocess.run(
                    ["sudo", "pfctl", "-e"],
                    capture_output=True, text=True
                )
                logger.debug("PF firewall enabled")

            # Clear any existing rules in our anchor
            self._clear_anchor_rules()

            self.initialized = True
            logger.debug("macOS firewall initialized")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize firewall: {e}")
            return False

    def block(self, ip: str) -> bool:
        """Block an IP using PF."""
        if not self.state.is_blockable(ip):
            logger.warning(f"Cannot block {ip} - protected IP")
            return False

        # Check if already blocked (thread-safe snapshot)
        if ip in self.state.get_blocked_snapshot():
            return True  # Already blocked

        try:
            # Update state first (thread-safe)
            self.state.mark_blocked(ip)

            # Update firewall rules (outside any lock)
            if not self._update_rules():
                self.state.mark_unblocked(ip)
                return False

            logger.warning(f"🛡️ BLOCKED: {ip}")
            return True

        except Exception as e:
            logger.error(f"Error blocking {ip}: {e}")
            self.state.mark_unblocked(ip)
            return False

    def unblock(self, ip: str) -> bool:
        """Unblock an IP."""
        if ip not in self.state.get_blocked_snapshot():
            return True  # Not blocked

        try:
            self.state.mark_unblocked(ip)

            if not self._update_rules():
                self.state.mark_blocked(ip)
                return False

            logger.debug(f"Unblocked: {ip}")
            return True

        except Exception as e:
            logger.error(f"Error unblocking {ip}: {e}")
            self.state.mark_blocked(ip)
            return False

    def clear_all(self) -> bool:
        """Clear all PF rules in our anchor.

        Only clears firewall rules — does NOT modify state.blocked_ips.
        The caller is responsible for clearing state after this returns.
        """
        return self._clear_anchor_rules()

    def _clear_anchor_rules(self) -> bool:
        """Clear PF rules in the killswitch anchor."""
        try:
            result = subprocess.run(
                ["sudo", "pfctl", "-a", self.ANCHOR_NAME, "-F", "rules"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"Error clearing firewall: {result.stderr}")
                return False

            logger.debug("Firewall rules cleared")
            return True

        except Exception as e:
            logger.error(f"Error clearing firewall: {e}")
            return False

    def _update_rules(self) -> bool:
        """Write all current block rules to PF.

        Takes a snapshot of blocked_ips under the state lock, then
        writes rules and runs pfctl outside any lock.
        """
        if not self.initialized:
            if not self.initialize():
                return False

        # Snapshot blocked IPs (thread-safe)
        blocked = self.state.get_blocked_snapshot()

        temp_file = None
        try:
            # Create temp file with rules
            with tempfile.NamedTemporaryFile(
                mode='w', delete=False
            ) as f:
                temp_file = f.name
                for ip in blocked:
                    # Block both directions
                    f.write(
                        f"block drop inet from {ip} to any no state\n"
                    )
                    f.write(
                        f"block drop inet from any to {ip} no state\n"
                    )

            # Clear existing rules
            subprocess.run(
                ["sudo", "pfctl", "-a", self.ANCHOR_NAME, "-F", "rules"],
                capture_output=True,
                text=True
            )

            # Apply new rules if any
            if blocked:
                result = subprocess.run(
                    ["sudo", "pfctl", "-a", self.ANCHOR_NAME,
                     "-f", temp_file],
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    logger.error(
                        f"Error applying rules: {result.stderr}"
                    )
                    return False

            # Ensure PF is enabled
            subprocess.run(
                ["sudo", "pfctl", "-e"],
                capture_output=True, text=True
            )

            return True

        except Exception as e:
            logger.error(f"Error updating firewall rules: {e}")
            return False
        finally:
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)


class LinuxFirewall(Firewall):
    """
    Linux implementation using iptables.

    Stub implementation - to be completed for cross-platform support.
    """

    def initialize(self) -> bool:
        """Initialize iptables."""
        logger.error("Linux firewall not yet implemented")
        return False

    def block(self, ip: str) -> bool:
        """Block using iptables."""
        logger.error("Linux firewall not yet implemented")
        return False

    def unblock(self, ip: str) -> bool:
        """Unblock using iptables."""
        logger.error("Linux firewall not yet implemented")
        return False

    def clear_all(self) -> bool:
        """Clear iptables rules."""
        logger.error("Linux firewall not yet implemented")
        return False


class WindowsFirewall(Firewall):
    """
    Windows implementation using Windows Firewall.

    Stub implementation - to be completed for cross-platform support.
    """

    def initialize(self) -> bool:
        """Initialize Windows Firewall."""
        logger.error("Windows firewall not yet implemented")
        return False

    def block(self, ip: str) -> bool:
        """Block using Windows Firewall."""
        logger.error("Windows firewall not yet implemented")
        return False

    def unblock(self, ip: str) -> bool:
        """Unblock using Windows Firewall."""
        logger.error("Windows firewall not yet implemented")
        return False

    def clear_all(self) -> bool:
        """Clear Windows Firewall rules."""
        logger.error("Windows firewall not yet implemented")
        return False


class NoOpFirewall(Firewall):
    """
    No-op firewall for analysis mode.
    Tracks what would be blocked without actually blocking.
    """

    def initialize(self) -> bool:
        """No-op initialization."""
        self.initialized = True
        logger.info("Running in analysis mode - no actual blocking")
        return True

    def block(self, ip: str) -> bool:
        """Track block without actually blocking."""
        if not self.state.is_blockable(ip):
            return False

        if ip in self.state.get_blocked_snapshot():
            return True  # Already tracked

        self.state.mark_blocked(ip)
        logger.info(f"[ANALYSIS] Would block: {ip}")
        return True

    def unblock(self, ip: str) -> bool:
        """Track unblock."""
        self.state.mark_unblocked(ip)
        logger.info(f"[ANALYSIS] Would unblock: {ip}")
        return True

    def clear_all(self) -> bool:
        """No-op clear — caller manages state."""
        return True


def create_firewall(state: SessionState,
                    operational: bool = True) -> Firewall:
    """
    Create the appropriate firewall implementation for the current platform.

    Args:
        state: Shared session state
        operational: True for actual blocking, False for analysis mode

    Returns:
        Firewall instance
    """
    if not operational:
        return NoOpFirewall(state)

    import platform
    system = platform.system()

    if system == "Darwin":
        return MacOSFirewall(state)
    elif system == "Linux":
        return LinuxFirewall(state)
    elif system == "Windows":
        return WindowsFirewall(state)
    else:
        logger.warning(
            f"Unknown platform: {system}, using no-op firewall"
        )
        return NoOpFirewall(state)
