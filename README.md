# Killswitch: Lag Switch Detector and Blocker

> Full functionality (analysis and blocking) is available on macOS. Analysis mode works cross-platform. Windows and Linux blocking requires implementing the firewall stubs in `firewall.py`.

## Introduction

Red Dead Online (RDO) and GTA Online (GTAO) use a peer-to-peer mesh network for multiplayer sessions. Players connect directly to each other rather than through a central server, with one player acting as session host. This architecture is vulnerable to lag switching, a form of cheating where players intentionally interrupt their own connection to gain advantages in combat.

Both RDO and GTAO share the same network protocols and port configurations (primarily UDP 6672), so Killswitch works for both. The setup described here uses a Mac bridging a console (PlayStation or Xbox), but the detection logic is not platform-specific.

On PC, lag switching exists but is overshadowed by other cheats like mod menus that provide god mode, teleportation, player crashes, and worse. Killswitch targets lag switching, which is the dominant form of cheating on console where mod menus are not (easily) available.

### Understanding Lag Switching

A lag switch is a physical device or software method used to temporarily halt a player's outgoing/incoming packets. During this period, they can still move, freeze, aim, and shoot others on their screen. When they deactivate the switch, all actions performed during the gap are transmitted at once. Other players suddenly see the cheater "teleport", perform impossible movements, or experience instant death.

Experienced cheaters use the switch tactically. They tap briefly, just enough that your hit packets arrive during the gap and get dropped. You land a clean headshot, and it does not register. Their shots land fine. When you catch them off guard, they die normally, but in a direct confrontation, they become effectively invincible. Should you manage to kill them in your screen, they ragdoll, and then a dead player on the ground kills you. This frustrating post-mortem kill and teleporting are classic signs.

Most switchers keep their gaps in the 0.5-1.5 second range. Long enough to block your hits, short enough that the game does not kick them for timeout. Gaps longer than two seconds are rare and usually from someone new to the technique, but when they happen they are unmistakable.

### Lag Switching in Action

For a demonstration of what this looks like in practice, watch this excellent (and funny) video on the [State Of Red Dead Online PVP](https://www.youtube.com/watch?v=CzfKQtQKEAw).

### MTU Tweaking

Another common form of network manipulation is MTU tweaking. On PlayStation, players can lower their Maximum Transmission Unit setting, which causes packet fragmentation and creates consistent micro-interruptions in their connection. The effect is similar to a mild lag switch: the tweaker's hits register more reliably than yours, and they take less damage and become harder to hit as their position updates jitter. The gaps from MTU tweaking (0.1-0.3s) overlap with normal protocol behaviour and can't be reliably distinguished without decrypting game traffic. Setting MTU too low gets you kicked out of a public session by the RAGE engine, which is why some players use it to get solo lobbies.

As someone once put it, Rockstar games are the only ones where a bad connection is beneficial.

### Other Console Cheats

Lag switching and MTU tweaking are the network-level cheats. They are not the only problems.

Cronus Zen (and the older Cronus Max) is a hardware device that sits between the controller and console. It runs scripts that provide rapid fire, auto-headshot etc. In RDO, the telltale sign is a Carcano or repeater firing far faster than its intended rate, often combined with unnatural accuracy and jerky strafing movement. Cronus is common enough in RDO lobbies that most experienced players recognise the signs on sight.

XIM devices are similar in spirit. They let players use a mouse and keyboard on console while the game still sees a standard controller, which means the console's built-in auto-aim and aim-assist stays active on top of the mouse precision. Some game studios now classify both XIM and Cronus as cheat devices and have started injecting artificial input lag when spoofed controller input is detected.

A newer class of cheats runs computer vision externally against the game's video output, this works on console too, via a capture card feeding aim corrections back through a Cronus or XIM.

Rockstar's games are also full of exploitable glitches, which are a category of their own.

None of these are problems Killswitch can solve. It operates at the network layer, and these cheats leave no trace in packet timing. They are worth knowing about so you can make an informed decision if it's worth playing PVP at all.

### How Killswitch Helps

Killswitch monitors packet flow between your router and console. When a player’s packets go silent and resume, the gap is classified and scored per IP. Crossing the threshold blocks the player in the firewall. In **analysis mode**, it detects and logs without blocking, useful for studying sessions or verifying setups. In **operational mode**, it blocks the player.

Even without blocking, **monitoring** is valuable. Without Killswitch, you land a headshot that does not register and have no idea why. Was it lag? A bug? Your aim? With Killswitch running, you see exactly which players are producing gaps, how severe the switching is, and how many cheaters are in the session. The gameplay goes from opaque and frustrating to transparent and frustrating. It also makes plainly visible something Rockstar would rather you not think about: in a P2P session, every player's IP address is exposed to every other player. Killswitch shows you theirs. A packet sniffer shows them yours. This is a fundamental property of P2P architecture, and a **security concern**. Anyone in your session can see your IP, and with it they can DDoS you offline, geolocate you to your city, or target you across sessions.

**Blocking** works because of the P2P mesh. A firewall block does not remove a player from the session. Their game state still reaches you indirectly through the host and other peers, and yours reaches them the same way. The block is mutual: both sides get a slightly higher-latency connection. In practice, you are partially lag switching them back. The post-mortem kill problem largely goes away, the cheater's auto-aim might have trouble locking on, and their timing advantage shrinks.

Killswitch is *not a silver bullet*. Blocked players' actions still propagate through the mesh. The one player Killswitch cannot block is the session host, and in RDO's Takeover and Shootout series, the host is often a cheater. When that is the case, you are exposed to their switching regardless. Killswitch still helps in cheater-heavy lobbies, but when the host is switching and 80% of the session is blocked, the best move is to find a different session, or better yet, a different game.

Killswitch does not distinguish between a lag switcher, an MTU tweaker, and a player with a genuinely terrible connection. All three produce the same pattern on the wire and degrade your gameplay the same way. It treats them identically.

## P2P Mesh Resilience

RDO/GTAO's mesh network is remarkably resilient. The game relays player information through the mesh, so even when you block a direct connection, that player's movements and actions still reach you through the session host and other clean players. This adds a slight latency to interactions with blocked players but keeps the session intact. The blocked player experiences the same latency on you, which is part of what makes blocking effective. Connections to clean players remain unaffected.

The critical link is the session host. As long as your connection to the host stays up, the gameplay experience remains largely intact. You can block all other players except the session host and still play. Killswitch attempts to identify the host during warmup and protects that IP from being blocked. Losing your connection to the host usually means losing the session. If the host migrates to a blocked player, the same thing happens. You might see a network error and you're kicked back to the main menu. This is thankfully an infrequent occurrence.

If you become the session host (after host migration), blocked players will likely drop from the session, which is a good outcome, but the session can become lonely.

## Requirements

- macOS (for blocking; analysis mode works cross-platform)
- Python 3.9+
- scapy (`pip3 install scapy`)
- Two network interfaces on the Mac (built-in Ethernet + a USB/Thunderbolt Ethernet adapter)
- Sudo privileges

## Setup

There are three parts: hardware, macOS network sharing, and the PF firewall.

### 1. Hardware

The Mac sits between your router and console, acting as a bridge. All console traffic passes through it, which is what allows Killswitch to see and block packets.

You need two Ethernet connections on the Mac. On newer Mac models you'll need USB or Thunderbolt Ethernet adapters.

```
┌─────────┐    Ethernet    ┌───────────┐    Ethernet    ┌─────────────┐
│ Router/ │────────────────│  Mac with │────────────────│ PlayStation │
│ Modem   │                │ Killswitch│                │ or Xbox     │
└─────────┘                └───────────┘                └─────────────┘
```

Connect the router to one Ethernet interface and the console to the other. Avoid WiFi for either link as it might introduce extra latency.

### 2. Internet Sharing

The console needs to reach the internet through the Mac. macOS handles this with Internet Sharing.

On **macOS** (Ventura and later):

1. Open System Settings > General > Sharing.
2. Click the (i) next to Internet Sharing (don't toggle it on yet).
3. Set "Share your connection from" to your router-connected interface (e.g. `Ethernet` or `en0`).
4. Under "To computers using", check the console-connected interface (e.g. `USB Ethernet` or `Thunderbolt Ethernet`).
5. Go back and toggle Internet Sharing on. Confirm when prompted.

To identify your interface names:

```bash
# Show the default (router-connected) interface
route -n get default | awk '/interface: / {print $2}'
```

Test that it works by running a network test on your console. The console should have internet access through the Mac.

### 3. Firewall (PF)

Killswitch uses macOS's built-in PF (Packet Filter) firewall to block confirmed lag switchers. PF needs an anchor point where Killswitch can insert its rules.

Edit `/etc/pf.conf`:

```bash
sudo vi /etc/pf.conf
```

The file will look something like this:

```
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
...
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
```

Add the Killswitch anchor after the existing Apple anchors, before the final `load` line:

```
anchor "killswitch"
```

Save the file, then reload PF and verify:

```bash
# Reload the configuration
sudo pfctl -f /etc/pf.conf

# Enable PF if not already enabled
sudo pfctl -e

# Verify the anchor exists (should list "killswitch")
sudo pfctl -s Anchors
```

This is a one-time setup. The anchor persists across reboots.

## Usage

```bash
sudo ./launch.sh
```

The interactive launcher prompts for operation mode (analysis or operational), network interface, and score threshold.

### Workflow

1. Verify your console has internet through the Mac.
2. Start RDO/GTAO and enter a session.
3. Launch Killswitch with `sudo ./launch.sh`.
4. Killswitch runs a 45-second warmup to identify the session host, then starts monitoring.
5. Press `p` before entering a PvP lobby (pauses scoring during the transition).
6. Press `p` again when the match starts (resumes scoring).
7. Killswitch blocks confirmed lag switchers automatically in operational mode.
8. Use `l` to check status during play.

The pause/resume step matters. Lobby transitions cause packet gaps that look like lag switching. Pausing prevents false positives. See [NOTES.md](NOTES.md) for why this manual approach works better than automatic detection.

### Commands

All commands require pressing Enter.

| Command | Action |
|---|---|
| `p` | Pause/resume scoring (use around lobby transitions) |
| `l` | Show status: host, blocked IPs, scores |
| `c IP` | Clear accumulated score for an IP (unblocks if blocked) |
| `u SCORE` | Unblock all IPs with score at or below SCORE |
| `q` | Quit gracefully |

### Gap Detection

Gaps on the primary port (UDP 6672) are classified and scored immediately:

| Gap Duration | Type | Score | Notes |
|---|---|---|---|
| < 0.5s | — | 0 | Ignored, normal variance / MTU tweaking |
| 0.5 - 0.8s | Short | +3 | Needs ~4 occurrences to confirm |
| 0.8 - 2.0s | Medium | +8 | 2 gaps confirms |
| > 2.0s | Long | +10 | Single gap confirms |

The confirmation threshold is 10 by default.

Scoring is direct and cumulative. Every gap is scored immediately with no deferred logic. Unconfirmed scores decay at 0.5 points/minute to prevent false positives from accumulating. If 3+ IPs gap simultaneously (lobby transition), those gaps are automatically suppressed.

Use the `p` command to pause scoring before lobby transitions and resume when PvP starts. See [NOTES.md](NOTES.md) for design decisions and what we tried before this approach.

## Troubleshooting

**Firewall errors**: make sure you're running with sudo. Enable PF with `sudo pfctl -e`.

**No packets captured**: verify the correct interface. Test with `sudo tcpdump -i YOUR_INTERFACE udp port 6672`.

**No blocking**: verify operational mode and that the score threshold isn't too high. Check that the PF anchor exists and inspect active rules:

```bash
# Verify the killswitch anchor is loaded
sudo pfctl -s Anchors

# Show active block rules in the killswitch anchor
sudo pfctl -a killswitch -s rules
```

**Console has no internet**: check that Internet Sharing is enabled and cables are connected. If RDO loses connection when your Mac sleeps, restart both.

**Rockstar network error after extended play**: after an hour or two of playing, Rockstar may throw a network error and kick you back to the main menu. This appears to be a problem with macOS Internet Sharing. Restarting both your Mac and PlayStation resolves it.

## Architecture

```
Capture -> Analyze -> Block
   |          |         |
   |          |         └── firewall.py (macOS PF, stubs for Linux/Windows)
   |          └── analyzer.py (direct gap scoring)
   └── capture.py (scapy packet sniffing)
```

See [NOTES.md](NOTES.md) for detailed architecture notes, threading model, and design history.

## Acknowledgements

Developed in response to the lag-switching problem in Red Dead Online's Shootout and Takeover series. The same protection applies to GTA Online, and given Rockstar's longstanding commitment to P2P networking, will likely apply to GTA VI Online as well.

Thanks to all legitimate RDO and GTAO players who keep playing despite the cheaters. And a begrudging acknowledgment to the lag switchers in Takeover who, while attempting to ruin the experience, provided invaluable test cases.

## License

MIT License. Copyright 2025 Sovandeulv (sovandeulv@gmail.com). See [LICENSE](LICENSE).
