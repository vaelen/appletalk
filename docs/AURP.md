# AURP — AppleTalk Update-based Routing Protocol

AURP joins two or more AppleTalk internets into one by tunnelling between
their routers over IP. Apple published it in 1993 as RFC 1504 and shipped it in
the Apple Internet Router 3.0 (AIR). Every GlobalTalk site today runs an AURP
router — jrouter, or an AIR on a real Mac — and the tunnels between them are
what make it one internet.

A router with a tunnel port is an **exterior router**. To its own cable it is
an ordinary Phase 2 router: it beacons RTMP, answers ZIP and NBP, forwards DDP.
To the tunnel it is an IP host on UDP port 387 that does two things:

- forwards DDP datagrams to the exterior router nearest their destination,
  each wrapped in a small **domain header**;
- tells every peer which networks and zones live behind it, **once**, and then
  only sends **updates** when that changes. That is the "update-based" part:
  no 10-second RTMP beacon crosses the tunnel.

A tunnel is a virtual data link with no broadcast. Every exterior router on it
must be told about every other one, by configuration or by accepting whoever
sends an Open-Req (jrouter's `open_peering`). There is no discovery.

This document describes the protocol as a minimal implementation needs it, plus
what the reference implementations actually do. Two things it does **not**
cover: point-to-point AURP over PPP, and the optional wide-area features
(network-number remapping, clustering, hop-count reduction, loop probes). See
"Optional features" for why those can be skipped on GlobalTalk.

## Sources

| Source                      | Authority for                                                                                                                                                             |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| RFC 1504                    | Everything below. Page numbers are the RFC's.                                                                                                                             |
| `jrouter` (Go)              | What actually runs on GlobalTalk. `aurp/` is the codec, `router/aurp_peer.go` the state machine. Where the RFC leaves a number unspecified, the value shown is jrouter's. |
| `tashrouter` (Py)           | **Has no AURP at all.** It is a multi-port RTMP/ZIP router (LocalTalk, LToUDP, TashTalk, EtherTalk). Useful as a model for the port abstraction, not for the tunnel.      |
| *Inside AppleTalk*, 2nd ed. | Predates AURP (1990). Cited for the RTMP and ZIP layouts that AURP tuples imitate; page numbers are PDF pages.                                                            |

The RFC's figures were images and did not survive into the text version, so
every byte layout here was reconstructed from its prose and checked against
jrouter's encoder. Where the two disagree, that is called out.

## Transport

| Item          | Value                                                                     |
|---------------|---------------------------------------------------------------------------|
| Protocol      | UDP over IPv4                                                             |
| Port          | 387, both source and destination                                          |
| UDP checksum  | Always set (RFC p. 17)                                                    |
| One datagram  | Exactly one AURP packet, or exactly one DDP datagram plus a domain header |
| Peer identity | The peer's IPv4 address. jrouter keys its peer table on source IP only.   |

jrouter always **sends to port 387** whatever port a packet arrived from, so a
peer behind NAT must forward 387. It reads into a 4096-byte buffer; the RFC
sets no maximum. Keep routing packets under the path MTU (about 1400 bytes)
so they do not fragment — AURP-Tr has no fragmentation of its own and a lost
fragment loses the whole packet.

IPv6 is not defined: the only non-null domain identifier format is an IPv4
address.

## Domain header

Every datagram on the tunnel begins with a domain header. It names the two
exterior routers as **domain identifiers** (DIs) and says what follows.

| Offset | Size | Field          | Value                                            |
|--------|------|----------------|--------------------------------------------------|
| 0      | var  | Destination DI | Receiving exterior router                        |
| var    | var  | Source DI      | Sending exterior router                          |
| +0     | 2    | Version        | `0x0001`                                         |
| +2     | 2    | Reserved       | `0x0000`                                         |
| +4     | 2    | Packet type    | `0x0002` AppleTalk data, `0x0003` routing (AURP) |

Reject any other version or packet type.

### Domain identifiers

A DI is a length byte, an authority byte, and authority-specific bytes. The
length counts everything after the length byte, and is always odd so the
whole DI is an even number of bytes.

| Authority | Name | Length byte | Layout                                                                 |
|-----------|------|-------------|------------------------------------------------------------------------|
| `0x00`    | Null | `0x01`      | `01 00` — two bytes, nothing else                                      |
| `0x01`    | IP   | `0x07`      | `07 01 00 00 a b c d` — two reserved zero bytes, then the IPv4 address |

Every other authority value is reserved; discard the packet.

On an IP tunnel both DIs are IP DIs. The source DI is the sender's own public
address, and it is the sender's **identity**, not merely a return address: a
router behind NAT must be told its public address (jrouter's `local_ip`) or it
will introduce itself with a private one. jrouter follows a "call you by what
you call yourself" rule — whatever source DI a peer uses becomes the
destination DI it is addressed by from then on, regardless of the IP header.

The null DI is for point-to-point links, where there is nothing to
distinguish. Accept it on receive; never send it on an IP tunnel.

Worked example, 192.0.2.2 sending to 192.0.2.1:

```
07 01 00 00 c0 00 02 01   destination DI = 192.0.2.1
07 01 00 00 c0 00 02 02   source DI      = 192.0.2.2
00 01                     version 1
00 00                     reserved
00 03                     packet type: routing
```

## AppleTalk data packets (type 2)

After the domain header comes one complete DDP datagram with the 13-byte
**extended** header (PDF 116–119) — hop count and all — and nothing else: no
link-layer header, no length prefix, no padding. It is the datagram exactly as
it would go onto an EtherTalk cable, minus the Ethernet and SNAP framing.

So the longest data packet is 22 + 13 + 586 = 621 bytes with IP DIs at both
ends.

### Hop counts

The RFC says an exterior router increases the hop count "by at least one" when
forwarding across a tunnel, and discards any packet that arrives through the
tunnel already at 15 (p. 66). AIR and jrouter apply the increment on the
**sending** side: a datagram taken off the local cable is incremented once as
it is forwarded, whether the next hop is another cable or a tunnel peer, and a
datagram arriving from a tunnel is passed to the local cable **without** a
second increment. Whole tunnel, one hop. Do the same, or hop counts drift by
one per tunnel relative to every AIR out there.

### What crosses and what does not

Only unicast datagrams whose destination network is behind the peer cross the
tunnel. Broadcasts (`net 0, node 255`) never do; there is no such thing as a
tunnel broadcast. RTMP never crosses — that is the whole point. ZIP Queries
from local nodes are answered by the exterior router itself from what it
learned over AURP.

NBP is the one protocol a router has to **translate** rather than forward, and
it works across a tunnel exactly as it does across any router:

1. A local node sends a **BrRq** to its router.
2. The router looks up which networks have the requested zone. For each one
   behind a tunnel it sends a **FwdReq** addressed to `net.0` (any router on
   that network), socket 2, and forwards it like any datagram. It crosses the
   tunnel inside a type 2 packet.
3. The exterior router at the far end sees a datagram for `net.0` where `net`
   is one of its own: that is for it. It turns the FwdReq into a **LkUp**,
   rewrites the destination to `0.255`, and zone-multicasts it on the cable.
4. **LkUp-Reply** goes straight back to the address in the NBP tuple as an
   ordinary unicast, through the tunnel, no translation.

So an exterior router must treat every datagram it receives from a tunnel for
`net.0` on one of its own networks as addressed to itself, and only NBP
(socket 2) is expected there.

## Routing packets (type 3)

After the domain header comes an 8-byte routing header, then a body that
depends on the command:

| Offset | Size | Field         | Notes                                                                            |
|--------|------|---------------|----------------------------------------------------------------------------------|
| 0      | 2    | Connection ID | Identifies a one-way connection. 0 is reserved.                                  |
| 2      | 2    | Sequence      | 0 for transactions; 1, 2, … for sequenced data. 0 reserved as a sequence number. |
| 4      | 2    | Command code  | Table below                                                                      |
| 6      | 2    | Flags         | Meaning depends on the command                                                   |

The first four bytes are the **AURP-Tr** header (the transport), the last four
the **AURP** header (the protocol). Every field is big-endian.

### Commands

| Code | Subcode | Name       | Direction       | Kind        | Body                             |
|------|---------|------------|-----------------|-------------|----------------------------------|
| 1    | —       | RI-Req     | receiver→sender | transaction | none                             |
| 2    | —       | RI-Rsp     | sender→receiver | sequenced   | network tuples                   |
| 3    | —       | RI-Ack     | receiver→sender | ack         | none                             |
| 4    | —       | RI-Upd     | sender→receiver | sequenced   | event tuples                     |
| 5    | —       | RD         | sender→receiver | sequenced   | 2-byte error code                |
| 6    | 1       | ZI-Req     | receiver→sender | transaction | network numbers                  |
| 7    | 1 or 2  | ZI-Rsp     | sender→receiver | transaction | zone tuples                      |
| 6    | 3       | GZN-Req    | receiver→sender | transaction | zone name                        |
| 7    | 3       | GZN-Rsp    | sender→receiver | transaction | zone name, count, network tuples |
| 6    | 4       | GDZL-Req   | receiver→sender | transaction | start index                      |
| 7    | 4       | GDZL-Rsp   | sender→receiver | transaction | start index, zone names          |
| 8    | —       | Open-Req   | receiver→sender | transaction | version, options                 |
| 9    | —       | Open-Rsp   | sender→receiver | transaction | rate or error, options           |
| 14   | —       | Tickle     | receiver→sender | transaction | none                             |
| 15   | —       | Tickle-Ack | sender→receiver | transaction | none                             |

Codes 10–13 and anything above 15 are undefined; discard. Commands 6 and 7
carry a 2-byte subcode as the first two bytes of the body.

"Sender" and "receiver" are the roles on a **one-way connection**, defined in
the next section — not who is sending this particular packet.

### Flags

Bit 15 is the most significant bit of the 16-bit flags field.

| Bit   | Mask     | Meaning                             | In               |
|-------|----------|-------------------------------------|------------------|
| 15    | `0x8000` | Last packet of a sequence           | RI-Rsp, GDZL-Rsp |
| 14    | `0x4000` | SUI: send NA events                 | Open-Req, RI-Req |
| 13    | `0x2000` | SUI: send ND and NRC events         | Open-Req, RI-Req |
| 12    | `0x1000` | SUI: send NDC events                | Open-Req, RI-Req |
| 11    | `0x0800` | SUI: send ZC events                 | Open-Req, RI-Req |
| 14    | `0x4000` | Environment: remapping active       | Open-Rsp         |
| 13    | `0x2000` | Environment: hop-count reduction on | Open-Rsp         |
| 12–11 | `0x1800` | Environment: reserved               | Open-Rsp         |
| 14    | `0x4000` | SZI: send zone info for this RI     | RI-Ack           |

Everything else is reserved: send 0, ignore on receive. In practice every
Open-Req and RI-Req carries all four SUI flags (`0x7800`) and every Open-Rsp
carries `0x0000`.

### Error codes

Signed 16-bit, in Open-Rsp (where a non-negative value is a rate instead) and
RD.

| Code | Meaning                  |
|------|--------------------------|
| -1   | Normal connection close  |
| -2   | Routing loop detected    |
| -3   | Connection out of sync   |
| -4   | Option-negotiation error |
| -5   | Invalid version number   |
| -6   | Insufficient resources   |
| -7   | Authentication error     |

## One-way connections

AURP-Tr is deliberately simple: a **one-way connection** carries reliable,
sequenced data from a **data sender** to a **data receiver**, and only **one
sequenced packet may be outstanding** at a time. The receiver opens the
connection, asks for the sender's routes, acknowledges every sequenced packet,
and checks the sender is alive. The sender answers, then pushes updates when
its routes change.

Two peers normally hold **two** one-way connections, one each way, so each is
sender on one and receiver on the other. They are independent: each has its
own connection ID, its own sequence counter, its own state, and either can be
down while the other is up.

Per peer, an implementation therefore keeps:

| State                | Role     | Meaning                                                                                  |
|----------------------|----------|------------------------------------------------------------------------------------------|
| Local connection ID  | receiver | The ID **we** chose in our Open-Req. Peer echoes it on everything it sends us as sender. |
| Remote connection ID | sender   | The ID the **peer** chose in its Open-Req. We put it on everything we send as sender.    |
| Receive sequence     | receiver | Next sequence number we expect from the peer. Reset to 1 on open.                        |
| Send sequence        | sender   | Sequence number of our last sequenced packet. Reset so the first RI-Rsp is 1.            |
| Last packet sent     | sender   | For retransmission until acked.                                                          |
| Pending events       | sender   | Route changes not yet sent in an RI-Upd.                                                 |
| Last heard from      | receiver | For the tickle timer.                                                                    |

### Connection IDs

The receiver picks the ID. It must **differ from the last one used with that
sender** (p. 43): if a receiver restarts and reuses an ID, the sender assumes
the old connection is still live and treats the Open-Req as a retransmission.
jrouter starts from a random non-zero value and increments (skipping 0) every
time it closes as receiver.

A packet whose connection ID does not match the expected one is discarded —
with one exception. An Open-Req arriving on a connection that is already open
with a **different** ID probably means the peer restarted. The sender should
send a null RI-Upd on the old connection; if that is acked, the Open-Req is
bogus and is dropped, otherwise the old connection is closed and the next
Open-Req answered (p. 42). jrouter skips the probe and just adopts the new ID.

A duplicate Open-Req with the **same** ID means the Open-Rsp was lost; answer
it again.

### Sequence numbers

Sequenced data (RI-Rsp, RI-Upd, RD from the sender) starts at 1 and counts up.
65535 is followed by 1; 0 is never used. Transactions always carry 0.

On receiving a sequenced packet, compare it with the expected number `n`
(p. 41):

| Received | Meaning                               | Action                                    |
|----------|---------------------------------------|-------------------------------------------|
| `n`      | New data                              | Process it, send RI-Ack(n), expect n+1    |
| `n-1`    | Duplicate; our RI-Ack was lost        | Re-send RI-Ack(n-1), do **not** reprocess |
| `n+1`    | We missed one; connection out of sync | Discard, close the connection as receiver |
| other    | Stale duplicate                       | Discard silently                          |

The RI-Ack echoes the packet's connection ID and sequence number. On the
sender side, an RI-Ack is only accepted if its sequence number matches the
packet outstanding.

## The dialog

Assume A learns B's address from configuration. Both are exterior routers.

```
A → B  Open-Req    conn=A1 seq=0  flags=SUI(all)  version=1, 0 options
B → A  Open-Rsp    conn=A1 seq=0  flags=0         rate=1
                   (B is now sender on A1; B also wants A's routes, so:)
B → A  Open-Req    conn=B1 seq=0  flags=SUI(all)
A → B  Open-Rsp    conn=B1 seq=0                  rate=1

A → B  RI-Req      conn=A1 seq=0  flags=SUI(all)
B → A  RI-Rsp      conn=A1 seq=1  flags=Last      [B's networks]
A → B  RI-Ack      conn=A1 seq=1  flags=SZI
B → A  ZI-Rsp      conn=A1 seq=0  subcode=1       [zones of every network in that RI-Rsp]

B → A  RI-Req      conn=B1 seq=0
A → B  RI-Rsp      conn=B1 seq=1  flags=Last      [A's networks]
B → A  RI-Ack      conn=B1 seq=1  flags=SZI
A → B  ZI-Rsp      conn=B1 seq=0

           ... quiet, data packets flow both ways ...

B → A  RI-Upd      conn=A1 seq=2                  [NA 2905-2905 dist 0]
A → B  RI-Ack      conn=A1 seq=2  flags=SZI
B → A  ZI-Rsp      conn=A1 seq=0                  [zones of 2905]

           ... 90 s with nothing from B on A1 ...

A → B  Tickle      conn=A1 seq=0
B → A  Tickle-Ack  conn=A1 seq=0

           ... B shuts down ...

B → A  RD          conn=A1 seq=3                  error=-1
A → B  RI-Ack      conn=A1 seq=3
```

Things to notice:

- Both Open-Reqs are needed. Opening one direction does nothing for the other,
  but a router that receives an Open-Req and has no receiver connection to
  that peer should open one immediately (jrouter does).
- The SZI flag on an RI-Ack is a ZI-Req in disguise: "send me the zones for
  every network in the packet I just acked". It saves a round trip, and it is
  the **only** way jrouter ever asks for zones — it never sends a ZI-Req.
- ZI-Rsp is a transaction (seq 0) and is **not acknowledged**. If it is lost,
  the receiver has a network with no zones. The RFC says: periodically scan for
  networks with incomplete zone lists and send ZI-Req for them (p. 25).
  jrouter does not; a lost ZI-Rsp leaves a zoneless network until the next
  NA event or reconnect.
- **Never export a network until its zone list is complete** (p. 24).
  Otherwise the peer asks for zones you cannot answer, forever — a ZIP storm
  over the tunnel.

## Packet bodies

Offsets are from the start of the body, after the 8-byte routing header.

### Open-Req (8)

| Offset | Size | Field         | Value     |
|--------|------|---------------|-----------|
| 0      | 2    | Version       | `0x0001`  |
| 2      | 1    | Option count  | Usually 0 |
| 3      | var  | Option tuples | See below |

Header: connection ID = the new ID, sequence 0, flags = SUI.

### Open-Rsp (9)

| Offset | Size | Field         | Value                                                                       |
|--------|------|---------------|-----------------------------------------------------------------------------|
| 0      | 2    | Rate or error | ≥ 0: update interval in units of 10 s. < 0: error code, connection refused. |
| 2      | 1    | Option count  |                                                                             |
| 3      | var  | Option tuples |                                                                             |

Header: connection ID from the Open-Req, sequence 0, flags = environment.
jrouter answers rate 1, flags 0, no options; it refuses version ≠ 1 with -5
and any options at all with -4.

### Option tuples

| Offset | Size | Field  | Notes                              |
|--------|------|--------|------------------------------------|
| 0      | 1    | Length | Bytes that follow: 1 + data length |
| 1      | 1    | Type   | 1 = authentication; 2–255 reserved |
| 2      | var  | Data   | Undefined for type 1               |

No implementation on GlobalTalk sends options. Accept an empty option list;
refuse or ignore anything else.

### RI-Req (1)

No body. Header: our receiver connection ID, sequence 0, flags = SUI. Also the
way to ask for a complete refresh at any time; the sender restarts its
sequence at 1 in response, and jrouter treats **any** RI-Upd that arrives while
it is not fully connected as a cue to send RI-Req.

### RI-Rsp (2)

Zero or more **network tuples**, back to back, no count. Header: the
receiver's connection ID, sequence ≥ 1, flags = Last on the final packet.

The tuples imitate RTMP's (PDF 136–138), including the trick of hiding the
"extended" flag in the top bit of the distance byte:

| Offset | Size | Field    | Non-extended network   |
|--------|------|----------|------------------------|
| 0      | 2    | Network  |                        |
| 2      | 1    | Distance | Bit 7 clear; 0–15 hops |

| Offset | Size | Field       | Extended network                              |
|--------|------|-------------|-----------------------------------------------|
| 0      | 2    | Range start |                                               |
| 2      | 1    | Distance    | Bit 7 **set**; low 7 bits are the hop count   |
| 3      | 2    | Range end   |                                               |
| 5      | 1    | Zero        | RTMP carries `0x82` here; AURP carries `0x00` |

Read byte 2 first: its top bit decides whether the tuple is 3 or 6 bytes.
Distance is the sender's distance to the network, **not** including the
tunnel hop; the receiver stores distance + 1.

Example, `1a 90 80 1a 90 00`: extended network 6800–6800, 0 hops away from
the sender.

The RFC allows the list to span several RI-Rsp packets, each acked before the
next is sent, with Last set on the final one. jrouter sends everything in one
packet with Last set and has a `TODO` for splitting.

### RI-Ack (3)

No body. Header: the connection ID and sequence number of the packet being
acked; flags = SZI to also request zones. Sent in reply to RI-Rsp, RI-Upd and
RD.

### RI-Upd (4)

One or more **event tuples**, back to back, no count. Header: receiver's
connection ID, next sequence number, flags 0.

| Offset | Size | Field                 | Notes                                             |
|--------|------|-----------------------|---------------------------------------------------|
| 0      | 1    | Event code            | Table below                                       |
| 1      | 2    | Network / range start | Absent for the null event                         |
| 3      | 1    | Distance              | Bit 7 = extended, as in RI-Rsp. 0 for ND and NRC. |
| 4      | 2    | Range end             | Extended only                                     |

Note the extended event tuple is **6** bytes with no trailing zero, unlike the
RI-Rsp tuple. The null event is a single byte.

| Code | Name | Meaning                                                                                 | Receiver does                               |
|------|------|-----------------------------------------------------------------------------------------|---------------------------------------------|
| 0    | null | Liveness probe; no data                                                                 | Ack only                                    |
| 1    | NA   | Network added behind the sender                                                         | Add route at distance+1; set SZI on the ack |
| 2    | ND   | Network deleted                                                                         | Remove the route via this peer              |
| 3    | NRC  | Network route change: sender now reaches it through a tunnel, so split horizon hides it | Same as ND                                  |
| 4    | NDC  | Network distance change                                                                 | Update distance; 15 means delete            |
| 5    | ZC   | Zone change — "reserved for future use"                                                 | Ignore                                      |

Inconsistent events are expected and defined (p. 34): ND or NRC for an unknown
network is ignored, NDC for an unknown network is treated as NA, NA for a
known network is treated as NDC. Process events in packet order.

An update is **batched**: the sender waits at least an update interval (10 s
minimum, and the "rate" in Open-Rsp) between RI-Upds, collapsing multiple
events for one network into one. It must wait for the ack of one RI-Upd before
sending the next, and retransmits the outstanding one until acked or the
retry limit is hit.

### RD (5)

| Offset | Size | Field      |
|--------|------|------------|
| 0      | 2    | Error code |

Sent by the data sender with the next sequence number before going down; the
receiver acks it and drops every route learned from that peer. A receiver may
send one instead with sequence 0 if there is only one connection. Optional —
a crashed router is detected by the tickle timers instead.

### ZI-Req (6/1)

| Offset | Size | Field    | Notes                                                                       |
|--------|------|----------|-----------------------------------------------------------------------------|
| 0      | 2    | Subcode  | `0x0001`                                                                    |
| 2      | 2×n  | Networks | One 2-byte number per network; for an extended network, the range **start** |

Header: our receiver connection ID, sequence 0, flags 0.

### ZI-Rsp (7/1 and 7/2)

| Offset | Size | Field       | Notes                                                                        |
|--------|------|-------------|------------------------------------------------------------------------------|
| 0      | 2    | Subcode     | 1 = non-extended, 2 = extended                                               |
| 2      | 2    | Count       | Non-extended: tuples in this packet. Extended: tuples in the whole zone list |
| 4      | var  | Zone tuples | Tuples for one network are contiguous                                        |

The tuples copy ZIP Reply (PDF 184–187) with one addition, the **optimized
tuple**, which reuses a zone name already spelled out earlier in the packet:

| Offset | Size | Field       | Long tuple                        |
|--------|------|-------------|-----------------------------------|
| 0      | 2    | Network     | Range start for extended networks |
| 2      | 1    | Name length | Bit 7 clear; 1–32                 |
| 3      | var  | Zone name   |                                   |

| Offset | Size | Field   | Optimized tuple                                                                                                                             |
|--------|------|---------|---------------------------------------------------------------------------------------------------------------------------------------------|
| 0      | 2    | Network |                                                                                                                                             |
| 2      | 2    | Offset  | Bit 15 set; low 15 bits are an offset **from the length byte of the first zone name in the packet** to the length byte of the name to reuse |

So the first name in a packet is always long, and an optimized tuple pointing
at it has offset 0 (`80 00`). Senders should use the optimized form; every
receiver must accept it. Extended ZI-Rsp packets (subcode 2) never use it,
because they hold one network's zones and a network never lists a zone twice.

Example, two networks in the same zone:

```
00 02                       2 tuples
1a 90 0c 36 38 6b 20 4d 61 63 20 43 6c 75 62
                            6800, "68k Mac Club"  (long)
0b 59 80 00                 2905, same name       (optimized, offset 0)
```

The RFC is explicit that a receiver must process **all** tuples present
regardless of the count field (p. 53). The subcode 1/2 split is about
splitting one network's zone list over several packets; jrouter's receiver
treats both the same, and its sender picks subcode 2 exactly when the reply
covers a single network, which is harmless but not what the RFC describes.
Accept both without caring which.

### GZN-Req (6/3) and GZN-Rsp (7/3)

"Which of your networks are in zone X?" Optional; answering "not supported"
is enough.

| GZN-Req offset | Size | Field                      |
|----------------|------|----------------------------|
| 0              | 2    | Subcode `0x0003`           |
| 2              | 1+n  | Zone name, length-prefixed |

| GZN-Rsp offset | Size | Field                                                        |
|----------------|------|--------------------------------------------------------------|
| 0              | 2    | Subcode `0x0003`                                             |
| 2              | 1+n  | Zone name                                                    |
| var            | 2    | Tuple count; `0xffff` (-1) = not supported; 0 = unknown zone |
| var            | var  | Network tuples, as in RI-Rsp                                 |

jrouter's encoder **omits the count field** when it does support the request
(it writes the tuples directly after the name), and its handler always answers
with zero tuples and no count — two bytes short of the RFC's "unknown zone"
form. Nobody sends GZN-Req on GlobalTalk, so this has not mattered. Reply
`-1` and be done.

### GDZL-Req (6/4) and GDZL-Rsp (7/4)

"List every zone in your local internet", paged by index. Optional.

| GDZL-Req offset | Size | Field            |
|-----------------|------|------------------|
| 0               | 2    | Subcode `0x0004` |
| 2               | 2    | Start index      |

| GDZL-Rsp offset | Size | Field                                                     |
|-----------------|------|-----------------------------------------------------------|
| 0               | 2    | Subcode `0x0004`                                          |
| 2               | 2    | Start index from the request, or `0xffff` = not supported |
| 4               | var  | Zone names — format **not given** by the RFC              |

Last flag in the header on the final page. jrouter guesses length-prefixed
names, always answers -1, and has never seen a real one. Answer -1.

### Tickle (14) and Tickle-Ack (15)

No body. Tickle carries the receiver's connection ID; Tickle-Ack echoes it.
Both sequence 0.

## Timers and limits

The RFC fixes only a few numbers and asks for adaptive retransmission like
TCP's. jrouter uses fixed timers; these are its values, and they interoperate
with AIR.

| Timer                        | RFC                                                                      | jrouter                                                                |
|------------------------------|--------------------------------------------------------------------------|------------------------------------------------------------------------|
| Open-Req retransmit          | ≥ 2 s, exponential backoff                                               | 10 s, 5 tries, then give up until reconnect                            |
| Last-heard-from              | ≥ 30 s, configurable                                                     | 90 s, then Tickle                                                      |
| Tickle retransmit            | "several"                                                                | 10 s, 10 tries, then drop the peer's routes                            |
| RI-Rsp / RI-Upd retransmit   | "a specified number"                                                     | 10 s, 5 tries, then close as sender                                    |
| Update interval              | ≥ 10 s, configurable                                                     | 10 s                                                                   |
| Reconnect to configured peer | —                                                                        | every 10 s while unconnected, at most one Open-Req per 10 min per peer |
| Tickle-before-data           | if LHF timeout > 2 min and idle that long, tickle before forwarding data | not implemented (LHF is 90 s)                                          |

The last-heard-from timer resets on RI-Rsp, RI-Upd, ZI-Rsp or Tickle-Ack
from the peer as sender. When the tickle retries are exhausted the receiver
closes its connection, drops every route learned from that peer, and — if it
is still sender on the other connection — sends a **null RI-Upd** there to
find out whether that direction is dead too (p. 40).

Retransmissions of Open-Req and RI-Req are fresh packets; RI-Rsp and RI-Upd
retransmissions are byte-identical repeats with the same sequence number.

## The two state machines

Per peer, per direction. jrouter's states, which follow the RFC's appendix
figures.

### As data receiver

```
Unconnected ──Open-Req sent──► WaitOpenRsp ──Open-Rsp ok──► Connected
     ▲                              │ error / 5 timeouts         │
     └──────────────────────────────┘                             │
     ▲                                                     RI-Req sent
     │                                                            ▼
     ├──── n+1 seq, or 10 tickle timeouts ─────────────── WaitRIRsp ──last RI-Rsp──► Connected
     │                                                                                   │
     └──── 10 tickle timeouts ◄──── WaitTickleAck ◄──── 90 s quiet ─────────────────────┘
                                          │
                                          └──Tickle-Ack──► Connected
```

In Connected: process RI-Upd (ack, apply events, SZI if any NA), ZI-Rsp
(add zones), RD (ack, drop routes, go Unconnected).

### As data sender

```
Unconnected ──Open-Req received, Open-Rsp sent──► Connected
     ▲                                                │ RI-Req: send RI-Rsp seq 1
     │                                                ▼
     │                                        WaitRIRspAck ──RI-Ack──► Connected
     │                                                                    │ pending events, ≥ 10 s since last
     │                                                                    ▼
     ├──── 5 timeouts ◄──────────────────────────────────────── WaitRIUpdAck ──RI-Ack──► Connected
     │
     └──── RD acked or timed out ◄── WaitRDAck ◄── shutting down
```

In WaitRIRspAck and WaitRIUpdAck, retransmit the outstanding packet every
10 s. Every RI-Ack with SZI set triggers a ZI-Rsp for the networks in the
packet just acked (all networks of an RI-Rsp; the NA events of an RI-Upd).
Route changes that happen while Unconnected are not queued.

## What to export: split horizon

An exterior router advertises **only its local internet**: networks reached
through its own cables, at the distance RTMP gave it. It never re-advertises a
network it learned over a tunnel, because every peer on the tunnel already
hears about that network from the peer it is behind (p. 8). This holds even
when the router has several separate tunnels — AURP assumes each tunnel is
fully connected and treats a router on two tunnels as two routers.

Concretely, in an RI-Rsp and in NA/NDC events, include a network if its
**best** route is via a local port (directly attached, or via an RTMP peer on
a local cable) and its distance is below 15. If the best route to a network
that was being exported moves to a tunnel, send **NRC** for it; when it moves
back, send **NA**.

Into the local cable, an exterior router advertises tunnel-learned networks
by RTMP at the stored distance (peer's distance + 1) like any other route, and
answers ZIP Queries for them from the zone lists received in ZI-Rsp.
GlobalTalk zone lists reach an emulator through jrouter this way, which is
what the bridge's live test in `CLAUDE.md` confirms.

Zone names are never modified in transit (p. 66). Two networks anywhere on the
internet with the same zone name are, as always in AppleTalk, one zone.

## Optional features

Chapter 4 of the RFC and most of its length: network hiding, device hiding,
network-number remapping with unique identifiers, clustering, hop-count
reduction, loop probes, hop-count weighting, backup paths. All optional; the
Open-Rsp environment flags tell a peer whether remapping or hop-count
reduction is on, and on GlobalTalk they are always 0.

They can be skipped because GlobalTalk **assigns every site a unique network
range and unique zone names by central agreement**. Remapping exists to
resolve numbering conflicts between independently administered internets;
with none, there is nothing to remap, and the loop-detection machinery that
remapping requires is moot. Hop-count reduction matters only when a path
would exceed 15 hops, which is far from the case.

Network hiding is the one worth remembering: export a subset of local
networks, and drop data packets arriving from a peer for networks hidden
from it. jrouter has `TODO`s for it and does not implement it.

## What a receiver must discard

| Condition                                                          | Reason                             |
|--------------------------------------------------------------------|------------------------------------|
| Shorter than two DIs plus 6 bytes                                  | No domain header                   |
| DI authority other than 0 or 1, or IP DI with length ≠ 7           | Unknown DI                         |
| Domain header version ≠ 1                                          | Unknown version                    |
| Packet type other than 2 or 3                                      | Unknown type                       |
| Type 3 body shorter than 8 bytes                                   | No routing header                  |
| Unknown command, or unknown subcode on 6 / 7                       | Undefined                          |
| Connection ID not ours (as receiver) or not the peer's (as sender) | Wrong connection                   |
| Sequenced packet with sequence 0, or transaction with sequence ≠ 0 | Malformed                          |
| Sequence n-1                                                       | Duplicate — re-ack, don't apply    |
| Sequence other than n or n-1                                       | Stale, or out of sync (n+1: close) |
| Network tuple cut short, or zone tuple whose name overruns         | Truncated                          |
| Optimized zone tuple whose offset lands outside the packet         | Malformed                          |
| Type 2 body shorter than 13 bytes, or DDP length ≠ body length     | Not one DDP datagram               |
| Data packet with DDP hop count 15                                  | Expired                            |
| Data packet for a network we have no route to                      | Unroutable                         |
| Packet from an IP not in the peer table, unless open peering       | Unknown peer                       |

Discard silently and keep reading. A tunnel peer is another organisation's
router; a wrong decode there is worse than a dropped packet.

## How to test it

Watch a tunnel:

```sh
sudo tcpdump -i any -n -X 'udp port 387'
```

The first 22 bytes of every payload are the domain header when both DIs are
IP; byte 21 (the last of the header) is 2 for data, 3 for routing. For routing
packets bytes 26–27 are the command code and `78 00` at bytes 28–29 mark an
Open-Req or RI-Req.

Ask jrouter what it thinks. With `monitoring_addr` set, `/status` shows every
peer's receiver and sender state, last-heard-from, and retry count, and
`/chatlog/<ip>` shows the last 200 routing packets exchanged with that
peer, decoded. That is the fastest way to see a handshake stall.

Hand-craft an Open-Req to a jrouter and expect an Open-Rsp back with
`00 01 00` (rate 1, no options) after the header. Connection ID `0x1234`
here; anything non-zero works:

```sh
printf '\x07\x01\x00\x00\xc0\x00\x02\x01\x07\x01\x00\x00\xc0\x00\x02\x02\x00\x01\x00\x00\x00\x03\x12\x34\x00\x00\x00\x08\x78\x00\x00\x01\x00' |
    socat -u - UDP4-DATAGRAM:192.0.2.1:387,sourceport=387
```

That single exchange proves the header, the DI format, the command layout and
the peer table. Follow it with an RI-Req on the same connection ID
(`... 12 34 00 00 00 01 78 00`) and the RI-Rsp that comes back is the peer's
whole exported internet in network tuples.

Two checks worth doing before trusting an implementation on a live tunnel:

- Restart it and confirm the peer resumes within one reconnect interval
  **with a different connection ID** in the new Open-Req. Reusing the ID is the
  classic stall: the peer answers the Open-Req and nothing else ever happens.
- Send it an RI-Upd with a sequence number two ahead of what it expects and
  confirm it closes and re-opens rather than acking.

## Where this stack stands

Nothing in `src/` speaks AURP yet, and the stack has no router at all:
`bridge` repeats frames between links at the link layer, and `node` is one
node on one cable. Becoming an exterior router means becoming a router first.
The pieces, in the order they are needed:

| Piece                 | Have                                   | Need                                                                                                                              |
|-----------------------|----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| RTMP parse and encode | Nothing — RTMP is still a hexdump      | Data, Request, Response packets (PDF 136–138); tuples are reused by AURP                                                          |
| Routing table         | Nothing                                | Per-network best route + alternatives, aging, split horizon per port, observers for AURP events                                   |
| Router core           | `bridge.rs` forwards at the link layer | DDP forwarding with hop count, `net.0` delivery to self, BrRq/FwdReq/LkUp translation, ZIP Query/Reply and GetNetInfo as a router |
| Port abstraction      | `capture.rs` (EtherTalk), `ltoudp.rs`  | One trait over EtherTalk, LToUDP and a tunnel peer — what tashrouter's `Port` and jrouter's `RouteTarget` are                     |
| AURP codec            | Nothing                                | `wire/aurp.rs`: domain header, routing header, every body above. Pure, testable from byte literals                                |
| AURP peer runtime     | Nothing                                | The two state machines, timers, UDP 387 socket, peer table                                                                        |

The codec is the same shape as every other `wire/` module and can be built
and tested against the layouts in this document alone. Everything else
depends on the router existing.

## References

- RFC 1504, *Appletalk Update-Based Routing Protocol: Enhanced Appletalk
  Routing*, A. Oppenheimer, Apple, August 1993. Chapter 3 is the required
  protocol; chapter 4 and the appendix are optional features.
- RFC 1378, *The PPP AppleTalk Control Protocol*, for AURP over PPP.
- jrouter, Josh Deprez — `gitea.drjosh.dev/josh/jrouter`, mirrored at
  `github.com/erichelgeson/jrouter`. Apache 2.0.
- tashrouter, lampmerchant — `github.com/lampmerchant/tashrouter`. The
  multi-port router model without AURP.
- *Inside AppleTalk*, 2nd ed.: RTMP Data packet PDF 136–138, ZIP Reply
  184–187, DDP header 116–119, NBP FwdReq/LkUp translation 169–172.
