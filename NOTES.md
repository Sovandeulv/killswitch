# Killswitch Development Notes

## Current Approach: Direct Gap Scoring (v3)

Simple and reliable: measure the time gap between consecutive packets per IP on
port 6672. Classify and score immediately. Accumulate. Block when threshold is
reached. The user pauses before lobby transitions and resumes when PvP starts.

This replaced two earlier, more complex approaches that attempted to automate
lobby/transition handling. See "What Didn't Work" below.

### Why Manual Pause/Resume Works

PvP sessions in RDO are typically 5-12 minutes. The user knows exactly when
they enter and leave PvP. Pressing `p` twice per session is trivial compared
to the complexity of automatic detection that kept failing in real games.

Pausing also clears all unconfirmed scores (below threshold). Since pausing
means "PvP is over", any accumulated-but-unconfirmed scores are likely noise
from the lobby transition. Confirmed switchers (already blocked) keep their
scores. This gives a clean slate for the next PvP session.

### Score Decay

Unconfirmed IPs decay at 0.5 points/minute. This prevents borderline false
positives from accumulating over long sessions. A single short gap (+3) decays
to zero in 6 minutes. Confirmed lag switchers do not decay.

### Simultaneous Gap Filter

If 3+ IPs all gap within a 3-second window, all gaps in that burst are
suppressed. This catches lobby transitions where all traffic disrupts at once.
Real lag switching affects one IP at a time.

### Gap Classification

| Gap Duration | Type   | Score | Notes                           |
|-------------|--------|-------|---------------------------------|
| < 0.5s      | —      | 0     | Normal variance / MTU tweaking  |
| 0.5 - 0.8s  | Short  | +3    | Needs ~4 occurrences to confirm |
| 0.8 - 2.0s  | Medium | +8    | 2 gaps confirms                 |
| > 2.0s      | Long   | +10   | Single gap confirms             |

Threshold: 10 (configurable via `--score-threshold`).

## What Didn't Work

### 1. Deferred Gap Scoring (v1)

**Concept**: When a gap was detected, defer scoring as a "PendingGap". Only
score it if 10+ packets arrived within 2 seconds afterward (indicating active
gameplay, not idle/lobby).

**Why it failed**: During real PvP with lag-switchers, packet rates on port 6672
are extremely high (thousands per second). The confirmation packets always
arrived, but the deferred logic added complexity without catching the actual
cheaters. Worse, during lobby transitions the packet rate sometimes remained
high enough to confirm false positives anyway.

**Lesson**: The deferred scoring tried to solve the wrong problem. The real
issue was lobby transitions, which are better handled by manual pause/resume
or the simultaneous gap filter.

### 2. Pre-Gap Streak Filter (v2)

**Concept**: Require N consecutive packets (a "streak") before a gap can be
scored. The idea was that legitimate traffic has long unbroken streaks, and a
gap after a streak is suspicious. Gaps without a preceding streak (e.g., during
lobby transitions) would be filtered out automatically.

**Why it failed in practice**: Real lag-switchers in RDO were operating with
gaps shorter than 0.4-0.5s. During actual PvP testing, a known lag-switcher
accumulated 6,196 consecutive packets with zero gaps >= 0.4s while still being
effectively invincible. The streak filter worked perfectly — it just had nothing
to filter because the gaps were below the detection threshold.

When we considered lowering the threshold to 0.3s to compensate, we ran into
the MTU tweaker range (0.1-0.3s) where false positives are common and
indistinguishable from normal protocol behavior.

**Lesson**: Adding complexity to gap qualification doesn't help when the
fundamental gap detection works. The streak filter was solving an imagined
problem (false gaps during transitions) that manual pause/resume handles better.

### 3. Clean Client Protection

**Concept**: Identify "clean" players during warmup (those with minimal gaps)
and skip them during analysis.

**Why it failed**: Host rotation during warmup added 8 out of 11 players as
clean clients, effectively blinding the analyzer. Worse, players identified as
"clean" during warmup could start lag-switching during PvP. We fixed the host
rotation bug, but then realized the entire clean client concept was flawed —
any player can turn hostile at any time.

**Current**: Only the session host is protected from blocking. No other players
get special treatment.

### 4. Small Gap Detection (< 0.5s)

Explored in the `mtu_tracking` branch. Small gaps are extremely common in normal
protocol behavior. Without decrypting Rockstar's game traffic (impossible without
their keys), we cannot distinguish normal protocol gaps from intentional MTU
tweaking. Players accumulated false positive scores too easily.

MTU tweakers operate in the 0.1-0.3s range and overlap with human reaction time.
At 0.3-0.4s we're already unreliable. At 0.5s we have a comfortable margin where
legitimate lag-switching is detectable and false positives from protocol behavior
are rare.

## Key Technical Facts

### RDO/GTAO Network Architecture
- P2P mesh network, not client-server
- One player acts as session host (highest traffic volume)
- All game traffic is encrypted — detection relies entirely on timing metadata
- Primary port: UDP 6672 (position, combat, game state)
- Auxiliary ports: 61455-61458 (voice, matchmaking, etc.)
- Blocking works because game state propagates through the mesh via other players

### What We Store Per IP
- `last_packet[ip] = (timestamp, port)` — one entry, overwritten each packet
- `scores[ip]` — cumulative float
- `gap_counts[ip]` — dict of short/medium/long counts
- No packet buffers, no arrays, no queues per IP

### Logging
- File: INFO by default, DEBUG with `--debug`
- Console: INFO+ (session info, status, commands, pause/resume)
- WARNING reserved for actionable events (confirmed lag switchers, blocks, host changes)
- Per-gap scoring is DEBUG level (can generate thousands of lines/minute)
- Periodic stats at DEBUG every 30s

### Threading
- Scapy sniffer runs in its own thread (required by scapy)
- Periodic loop (host detection, blocking, score decay, stats) in another thread
- Command reader (stdin) in another thread
- Packet processing runs directly in the sniffer callback — no queue needed
  since the analyzer is just dict lookups and arithmetic

## Future Considerations

- Revisit MTU tweaker detection only if a reliable distinguishing signal is found
- Consider session-aware scoring if multi-session use becomes common
- Monitor whether the 0.4s threshold needs adjustment based on new game updates
