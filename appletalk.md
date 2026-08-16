# AppleTalk protocols

```
┌───────────┬───────────────────────────────────────────────────┐
│ 7 app     │ AFP (files)   PostScript   ASP    PAP   ADSP      │
│ 5-6 sess  │ ASP ── PAP ── (over ATP)          ADSP ─┐         │
│ 4 xport   │ ATP (transactions)  NBP (names)  ZIP  AEP         │
│ 3 network │ DDP ── the datagram layer ── RTMP / AURP (routing)│
│ 2 link    │ LLAP (LocalTalk)  ELAP (Ether)  TLAP  FDDI + AARP │
│ 1 phys    │ STP 230.4kbps │ Ethernet │ Token Ring │ FDDI      │
└───────────┴───────────────────────────────────────────────────┘
```

| Proto | Layer | DDP type | Does                                                          |
|-------|-------|----------|---------------------------------------------------------------|
| AARP  | 2     | —        | AppleTalk address → MAC. Probe to claim, request to resolve.  |
| DDP   | 3     | —        | Best-effort datagrams, ≤586 bytes of data. `net.node:socket`. |
| RTMP  | 3     | 1, 5     | Distance-vector routing (a RIP). Routers beacon every 10s.    |
| AURP  | 3     | —        | Tunnels AppleTalk over UDP/IP; update-based, not periodic.    |
| NBP   | 4     | 2        | Name lookup: `object:type@zone` → address. Broadcast-based.   |
| ATP   | 4     | 3        | Request/response transactions, at-most-once or exactly-once.  |
| AEP   | 4     | 4        | Echo. Ping.                                                   |
| ZIP   | 4     | 6        | Which zone names live on which network.                       |
| ADSP  | 5     | 7        | Full-duplex reliable byte stream, straight over DDP.          |
| ASP   | 5     | (ATP)    | Session setup/teardown, ordered commands. Carries AFP.        |
| PAP   | 5     | (ATP)    | Printer connections. Carries PostScript.                      |
| AFP   | 7     | (ASP)    | File sharing — the reason most people ran AppleTalk.          |

## Addressing

16-bit network + 8-bit node + 8-bit socket. Node 0 and 255 reserved (255 =
broadcast); LocalTalk splits 1–127 user / 128–254 server. Net 0 means
"unknown". Nets `0xFF00–0xFFFE` are the *startup range* — a booting node picks
one, probes with AARP, and only learns its real net from RTMP. Sockets 1–63 are
Apple's (1=RTMP, 2=NBP, 4=echo, 6=ZIP), 128–254 dynamic.

### LLAP (LocalTalk)

LocalTalk's link layer, and the payload LToUDP carries (PDF 65–69). A 3-byte
header — destination node ID, source node ID, type — followed by a data field of
0–600 bytes. Node IDs are assigned dynamically: a node guesses one, sends a
series of `lapENQ` packets to it, and takes it if nothing answers.

| Node ID     | Meaning                                      |
|-------------|----------------------------------------------|
| `0`         | not allowed; treated as unknown              |
| `1`–`127`   | user node IDs                                |
| `128`–`254` | server node IDs                              |
| `255`       | broadcast ID — every node accepts the packet |

| LLAP type         | Meaning                                        |
|-------------------|------------------------------------------------|
| `$00`             | invalid                                        |
| `$01`             | DDP, short header                              |
| `$02`             | DDP, extended header                           |
| `$03`–`$7F`       | other LLAP clients — reserved and experimental |
| `$81`             | lapENQ — "is anyone using this node ID?"       |
| `$82`             | lapACK — "yes, I am"                           |
| `$84`             | lapRTS — request to send                       |
| `$85`             | lapCTS — clear to send                         |
| other `$80`–`$FF` | reserved; must be discarded                    |

Control packets (`$80`–`$FF`) carry **no data field at all**. In a data packet
the **low 10 bits of the data field's first two bytes hold the length of the
data field itself, that length included**; the high 6 bits belong to the client
protocol. So a data field is 2–600 bytes, and a whole packet 5–603.

A real LocalTalk frame ends with a 2-byte frame check sequence — CRC-CCITT over
the header and the data field, flags and abort bits excluded (PDF 70). LToUDP
strips it; `LToUDP.md` has the rest of that story.

## Phase 1 vs Phase 2

Phase 2 (1989) introduced *extended* networks — a cable range instead of one net
number, multiple zones per cable, >254 nodes — and moved EtherTalk onto
802.3/LLC/SNAP. That's the split `Frame::parse()` in `src/wire.rs` handles.

## Inside AppleTalk, 2nd ed. — page index

The book is the authority for every layout here. It is a scanned PDF *with an
OCR text layer*, so grep it rather than reading page images:

```sh
pdftotext -f 209 -l 212 inside-appletalk-second-edition.pdf -    # ATP format
```

Book pages are per-chapter (`9-13`); the numbers below are **PDF** pages.
Packet-format *figures* are images and do not extract — read those pages with
the Read tool when you need the diagram, but the surrounding prose usually
specifies every field.

| Section                         | PDF pages  |
|---------------------------------|------------|
| LLAP node IDs and packet format | 65–69      |
| LLAP timing and framing         | 70–73      |
| AARP packet formats             | 87         |
| AMT entry aging                 | 87–88      |
| ELAP packet format              | 93         |
| AARP on ELAP: multicast, probe  | 98         |
| DDP packet format               | 116–119    |
| Short vs extended DDP header    | 118        |
| DDP checksum + hop counts       | 120        |
| Node address acquisition        | 111–112    |
| Zone acquisition at startup     | 181        |
| RTMP Data packet format         | 136–138    |
| NBP packet formats              | 169–172    |
| ZIP Query / Reply               | 184–187    |
| ZIP ATP requests                | 188        |
| ZIP GetNetInfo request + reply  | 188–191    |
| ATP packet format               | 209–212    |
| PAP packet formats              | 236–239    |
| ASP packet formats              | ch. 11     |
| ADSP packet format              | 297        |
| AFP calls                       | 329–371    |
| Parameters (timers, constants)  | Appendix C |

## Build order

AARP (claim an address) → RTMP listener (learn the real net and zone) → AEP
(something can ping you) → NBP (be visible in the Chooser) → ATP → the rest.
