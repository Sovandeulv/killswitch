#!/bin/bash
# Killswitch Launcher

# Change to script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check Python (needed for version lookup and the app itself)
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found."
    exit 1
fi

# Read canonical version from src/__init__.py
VERSION=$(python3 -c "from src import __version__; print(__version__)" 2>/dev/null)
VERSION=${VERSION:-unknown}

# Parse arguments (before sudo check, so -h and -v work without sudo)
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            cat <<EOF
Killswitch v$VERSION - Lag Switch Detector for RDO/GTAO

Usage: sudo ./launch.sh [OPTIONS]

Options:
  -h, --help     Show this help and exit
  -v, --version  Show version and exit

Run without options to start interactively. The launcher will prompt
for mode (operational/analysis), network interface, and score threshold.

See README.md for setup and usage.
EOF
            exit 0
            ;;
        -v|--version)
            echo "Killswitch v$VERSION"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Try './launch.sh --help' for usage."
            exit 1
            ;;
    esac
done

# Check for sudo
if [ "$EUID" -ne 0 ]; then
    echo "Killswitch requires sudo privileges for network capture and firewall management"
    echo "Please run with: sudo ./launch.sh"
    exit 1
fi

# Header
echo "========================================================"
echo "  KILLSWITCH v$VERSION - Lag Switch Detector for RDO/GTAO"
echo "========================================================"
echo ""

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
echo "Commands: p=pause/resume, l=list, c IP=clear score, u SCORE=unblock, h=help, q=quit"
echo "========================================================"
echo ""

python3 -m src.main --interface "$interface" --mode "$mode" --score-threshold "$threshold" $debug_flag
