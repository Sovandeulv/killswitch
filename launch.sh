#!/bin/bash
# Killswitch v2.0 Launcher

# Check for sudo
if [ "$EUID" -ne 0 ]; then
    echo "Killswitch requires sudo privileges for network capture and firewall management"
    echo "Please run with: sudo ./launch.sh"
    exit 1
fi

# Change to script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Header
echo "========================================================"
echo "  KILLSWITCH v2.0 - Lag Switch Detector for RDO/GTAO"
echo "========================================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found."
    exit 1
fi

# Check scapy
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "Error: scapy not found. Install with: pip3 install scapy"
    exit 1
fi

# Get default interface
default_interface=$(route -n get default 2>/dev/null | awk '/interface: / {print $2}')

# Configuration
echo "Select mode:"
echo "  1) Operational (detect and block)"
echo "  2) Analysis (detect only)"
read -p "Choice [1]: " mode_choice
mode_choice=${mode_choice:-1}

if [ "$mode_choice" = "2" ]; then
    mode="analyze"
    echo "→ Analysis mode"
else
    mode="operational"
    echo "→ Operational mode"
fi

echo ""
read -p "Network interface [$default_interface]: " interface
interface=${interface:-$default_interface}
echo "→ Interface: $interface"

echo ""
read -p "Score threshold [10]: " threshold
threshold=${threshold:-10}
echo "→ Threshold: $threshold"

echo ""
echo "Debug mode? (verbose console output)"
read -p "Enable debug? [n]: " debug_choice
debug_flag=""
if [ "$debug_choice" = "y" ] || [ "$debug_choice" = "Y" ]; then
    debug_flag="--debug"
    echo "→ Debug enabled"
fi

echo ""
echo "========================================================"
echo "Starting Killswitch..."
echo "Commands: p=pause/resume, l=list, c IP=clear score, u SCORE=unblock, q=quit"
echo "========================================================"
echo ""

python3 -m src.main --interface "$interface" --mode "$mode" --score-threshold "$threshold" $debug_flag
