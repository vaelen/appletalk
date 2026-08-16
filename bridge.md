# The bridge

`appletalk bridge udp` joins an EtherTalk cable to a LocalTalk link carried over
UDP multicast (see `LToUDP.md`) and repeats AppleTalk between them, so that
nodes on both sides behave as one network.

It is a **bridge, not a router**. There is one network number — the one it
claimed on the Ethernet cable — and one node-ID space shared by both sides. It
runs no routing or zone protocols of its own: no RTMP, no ZIP, no hop counting.
The cable's real router keeps that job, and its traffic reaches the LocalTalk
side because the bridge repeats it like anything else, so LocalTalk nodes learn
the network number and the zone from the router through the bridge. The bridge
claims one AppleTalk address for itself, defends it on both links, and is
otherwise invisible.

## Forwarding

Rows are checked top to bottom; the first match wins.

### Any frame arriving on Ethernet

| Condition                         | What happens                               |
|-----------------------------------|--------------------------------------------|
| Source MAC is the bridge's own    | Dropped — our own transmission, heard back |
| Not an 802.3/SNAP frame (Phase 1) | Dropped — see the limits below             |
| Neither AARP nor DDP              | Dropped                                    |

### AARP arriving on Ethernet

| Condition                                          | What happens                                               |
|----------------------------------------------------|------------------------------------------------------------|
| Request or Probe for the bridge's **own** address  | Answered — it defends its address like any node            |
| Response from an address on another network        | Its MAC is noted for routed traffic; nothing else          |
| Response from an address on this cable             | Sender placed on Ethernet; any waiting question settled    |
| **Request** for an ID believed to be on LocalTalk  | Answered from memory, giving the bridge's own MAC          |
| **Probe** for an ID believed to be on LocalTalk    | Not answered — LocalTalk is asked first; the reply is owed |
| Request or Probe for an ID known to be on Ethernet | Ignored — that node answers for itself                     |
| Request or Probe for an ID unknown or in doubt     | Node-ID enquiry to LocalTalk; the reply is owed            |
| Anything else                                      | Dropped — AARP never crosses to LocalTalk                  |

### DDP arriving on Ethernet

The source is dealt with **first**, before any decision about the destination.

| Condition                                        | What happens                                                  |
|--------------------------------------------------|---------------------------------------------------------------|
| Source is on this cable                          | Sender placed on the Ethernet side                            |
| Source is on another network                     | Its MAC is noted as the router's, not as a node               |
| Source contradicts the side we believed          | Nothing repeated; the entry is doubted and the old side asked |
| Addressed to the bridge itself                   | Not repeated                                                  |
| Unicast to another network                       | Dropped — the router's business                               |
| Addressed to node 255, even from another network | Crosses, payload byte for byte                                |
| Destination is on LocalTalk                      | Crosses, payload byte for byte                                |
| Destination is on Ethernet                       | Dropped — already where it needs to be                        |
| Destination is one we are unsure about           | Held — nothing crosses until the doubt clears                 |
| Destination is unknown                           | Crosses anyway, and **both** links are asked who holds the ID |

### Arriving on LocalTalk

| Frame                                       | What happens                                                           |
|---------------------------------------------|------------------------------------------------------------------------|
| DDP, either header form                     | Sender placed on LocalTalk, then sent to Ethernet                      |
| — source contradicts the table              | Nothing repeated; entry doubted, old side asked                        |
| — short header                              | Lifted to the extended form, filling in our network number             |
| — extended header                           | Sent on unchanged, so hop counts and checksum survive                  |
| — unparseable                               | Dropped                                                                |
| Node-ID enquiry for the bridge's **own** ID | Acknowledged at once — it is defending its address                     |
| Node-ID enquiry for any other ID            | AARP Probe to Ethernet; an acknowledgement is owed if Ethernet answers |
| Node-ID acknowledgement                     | Sender placed on LocalTalk; any waiting question settled               |
| Request-to-send / clear-to-send             | Dropped — they arbitrate a medium Ethernet has not got                 |
| Any other LLAP type                         | Dropped — only DDP is bridged                                          |

A datagram going out to Ethernet is addressed:

| Destination                                     | Ethernet address used            |
|-------------------------------------------------|----------------------------------|
| Node 255, in either the LLAP or the DDP header  | AppleTalk broadcast              |
| A node known to be on Ethernet                  | That node's MAC                  |
| A node on another network                       | The router's MAC, if it is known |
| Anything else — unknown, in doubt, or LocalTalk | AppleTalk broadcast              |

## Discovery and arbitration

The bridge configures nothing. It learns where nodes are by watching, and asks
when it does not know.

- A node is placed on the side it was last heard from — a Response, an
  acknowledgement, or a datagram it sourced.
- A destination nobody has claimed is asked about on **both** links at once,
  since either answer settles it. The datagram that raised the question crosses
  anyway: an answer could not have arrived in time to filter it.
- While an ID is in doubt, nothing is forwarded to it and no AARP is answered on
  its behalf.
- One question per ID: a second is suppressed while the first is outstanding.
- An AARP Request may be answered from memory — a resolve only routes traffic,
  and the data path re-checks. An AARP **Probe** may not, because a Probe is a
  claim, and denying a claim on the strength of a stale memory locks a returning
  node out of its own ID.
- A proxy answer is never sent when the table says, or merely suspects, that the
  node is somewhere else.

**Why a node-ID enquiry is never answered from memory.** An acknowledgement
tells a node "that ID is taken, pick another". Answering one out of the table
would let the memory of an Ethernet node that switched off long ago deny that ID
to whoever asked — and nothing would ever correct it, since no live node hears
the exchange. So the bridge asks Ethernet in real time and acknowledges only
once something has answered. The one exception is the bridge's **own** node ID,
which it acknowledges immediately and authoritatively: that is not a memory of
someone else, it is defending its own address.

## Aging and moves

| Behaviour                                                 | Timing |
|-----------------------------------------------------------|--------|
| An entry is forgotten if nothing confirms it              | 30 s   |
| A cross-link query is given this long to be answered      | 2 s    |
| The bridge wakes and re-checks both timers even when idle | 250 ms |

A node that moves between links is noticed when it next transmits: heard on the
side it should not be on, it is neither believed nor repeated. The bridge asks
the old side whether it is still there and waits out the query window.

| Outcome                   | Meaning                                                |
|---------------------------|--------------------------------------------------------|
| The old side stays silent | The node moved. The entry flips and traffic resumes    |
| The old side answers      | Both sides hold that ID. Reported, and neither trusted |

A contested entry is deliberately **not** kept alive by traffic: it ages out on
the normal 30-second clock and is learned again from scratch. A node that moves
and then stays silent is not noticed at all until its entry expires.

## Messages

Everything below goes to standard error. Silence is the normal state: apart from
the startup lines, every message means something wanted attention.

| Message                                                | Meaning                                                         |
|--------------------------------------------------------|-----------------------------------------------------------------|
| `listening on <interface>`                             | The capture started on that NIC                                 |
| `claimed <net.node>, zone "<zone>", router <net.node>` | Address claimed, router answered. A normal start                |
| `claimed <net.node>, no router on this network`        | Nothing answered; the network has no zones                      |
| `<net.node> is outside this cable's range …`           | `--node` pinned an address the router will not route replies to |
| `bridging <net.node> <-> LToUDP 239.192.76.84:1954`    | Running. Nothing more is printed in normal operation            |
| `bridge: node N moved to Ethernet` (or `to LocalTalk`) | N appeared on the other link and the old one went quiet         |
| `bridge: node N answered on both sides — …`            | Two nodes hold one ID, or a second bridge is reflecting         |
| `bridge: ethernet: <error>`, `bridge: ltoudp: <error>` | One frame could not be sent; the far end will retransmit        |
| `dropped N frames (queue full)`                        | It fell behind and lost N frames — a gap in forwarding          |
| `rx: <error>`                                          | A capture or socket read error                                  |

`answered on both sides` is the one that needs a human: two nodes really do hold
that ID, or a second bridge is repeating our own traffic back at us. Nothing is
forwarded to that ID until the entry ages out.

## Known limits

- **One bridge per pair.** Broadcasts flood both ways, so two bridges between
  the same cable and the same group will storm. The duplicate-ID report is the
  symptom.
- **One network number.** LocalTalk nodes live on the bridge's own net alone; a
  cable range spanning several nets bridges only into the first.
- **A silent move waits out the 30-second lifetime.** A move is only noticed
  when the moved node transmits.
- **A node-ID enquiry costs a round trip.** A node whose enquiry series is
  shorter than one AARP round trip could take an ID that is in fact held on
  Ethernet. The duplicate report then makes that loud rather than silent.
- **Phase 1 (non-SNAP) Ethernet frames are dropped**, not forwarded: such a
  frame has no length field to trim Ethernet's padding by, so repeating it would
  produce a packet that disagreed with its own length.
- **Every AARP Request for an unknown ID costs one node-ID enquiry** on the
  LocalTalk link, even when an Ethernet node was about to answer for itself.
- **Off-network MACs are remembered forever.** Only on-cable node entries age
  out.
