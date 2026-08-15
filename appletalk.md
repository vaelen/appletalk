# AppleTalk protocols

```
┌───────────┬──────────────────────────────────────────────────┐
│ 7 app     │ AFP (files)   PostScript   ASP    PAP   ADSP      │
│ 5-6 sess  │ ASP ── PAP ── (over ATP)          ADSP ─┐         │
│ 4 xport   │ ATP (transactions)  NBP (names)  ZIP  AEP         │
│ 3 network │ DDP ── the datagram layer ── RTMP / AURP (routing)│
│ 2 link    │ LLAP (LocalTalk)  ELAP (Ether)  TLAP  FDDI + AARP │
│ 1 phys    │ STP 230.4kbps │ Ethernet │ Token Ring │ FDDI      │
└───────────┴──────────────────────────────────────────────────┘
```

| Proto | Layer | DDP type | Does                                                            |
|-------|-------|----------|-----------------------------------------------------------------|
| AARP  | 2     | —        | AppleTalk address → MAC. Probe to claim, request to resolve.     |
| DDP   | 3     | —        | Best-effort datagrams, ≤586 bytes of data. `net.node:socket`.    |
| RTMP  | 3     | 1, 5     | Distance-vector routing (a RIP). Routers beacon every 10s.       |
| AURP  | 3     | —        | Tunnels AppleTalk over UDP/IP; update-based, not periodic.       |
| NBP   | 4     | 2        | Name lookup: `object:type@zone` → address. Broadcast-based.      |
| ATP   | 4     | 3        | Request/response transactions, at-most-once or exactly-once.     |
| AEP   | 4     | 4        | Echo. Ping.                                                      |
| ZIP   | 4     | 6        | Which zone names live on which network.                          |
| ADSP  | 5     | 7        | Full-duplex reliable byte stream, straight over DDP.             |
| ASP   | 5     | (ATP)    | Session setup/teardown, ordered commands. Carries AFP.           |
| PAP   | 5     | (ATP)    | Printer connections. Carries PostScript.                         |
| AFP   | 7     | (ASP)    | File sharing — the reason most people ran AppleTalk.             |

## Addressing

16-bit network + 8-bit node + 8-bit socket. Node 0 and 255 reserved (255 =
broadcast); LocalTalk splits 1–127 user / 128–254 server. Net 0 means
"unknown". Nets `0xFF00–0xFFFE` are the *startup range* — a booting node picks
one, probes with AARP, and only learns its real net from RTMP. Sockets 1–63 are
Apple's (1=RTMP, 2=NBP, 4=echo, 6=ZIP), 128–254 dynamic.

## Phase 1 vs Phase 2

Phase 2 (1989) introduced *extended* networks — a cable range instead of one net
number, multiple zones per cable, >254 nodes — and moved EtherTalk onto
802.3/LLC/SNAP. That's the split `Frame::parse()` in `src/wire.rs` handles.

## Build order

AARP (claim an address) → RTMP listener (learn the real net and zone) → AEP
(something can ping you) → NBP (be visible in the Chooser) → ATP → the rest.
