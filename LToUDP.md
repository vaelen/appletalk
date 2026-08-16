# LToUDP — LocalTalk over UDP multicast

LToUDP carries LocalTalk frames between hosts inside UDP multicast datagrams.
It exists because LocalTalk is a 230.4 kbps serial bus that almost nobody still
has: emulators, software routers and modern bridges need some way to exchange
LocalTalk traffic, and an IP multicast group on the local Ethernet is the
cheapest thing that behaves like a shared bus. Every station on the group hears
every frame, exactly as every node on a LocalTalk bus hears every frame, so no
addressing, discovery or connection setup has to be invented.

The protocol is deliberately tiny: a 4-byte sender ID, then a LocalTalk Link
Access Protocol (LLAP) packet with its frame check sequence removed. There is
no handshake, no version byte, no length field of its own, and no
acknowledgement. Anything richer than that lives in AppleTalk itself.

This document describes the protocol only. Byte layouts marked with a page
number are settled by *Inside AppleTalk*, 2nd ed. (Apple, 1990); the numbers
are PDF pages of the scanned second edition.

## The group

| Item            | Value           | Notes                                         |
|-----------------|-----------------|-----------------------------------------------|
| Multicast group | `239.192.76.84` | 76 and 84 are ASCII `L` and `T` — "LocalTalk" |
| UDP port        | `1954`          | Same port for sending and receiving           |
| Multicast TTL   | `1`             | This is a link, not an internet               |
| Address family  | IPv4 only       | No IPv6 group is defined                      |

`239.192.0.0/14` is the IPv4 organization-local scope, so the group never
leaves the site even if a router is misconfigured; the TTL of 1 keeps it on the
local segment regardless.

Both the source and destination port are 1954. A station sends to
`239.192.76.84:1954` and receives on `0.0.0.0:1954`; there is no unicast mode
and no "reply to the sender's port" convention.

## Socket setup

| Step                                 | Why it is required                              |
|--------------------------------------|-------------------------------------------------|
| Reuse address, **before** bind       | Two stations commonly share one host            |
| Reuse port, **before** bind          | What actually shares delivery on BSD and Linux  |
| Bind to `0.0.0.0:1954`               | A specific local address silently misses some   |
| Join the group on a named interface  | The kernel's default NIC is often the wrong one |
| Multicast TTL 1                      | This is a link, not an internet                 |
| **Leave multicast loopback enabled** | Peers on the same host must hear you            |

More than one LToUDP station on one host is the normal case, not the exception —
an emulator and a bridge, or two emulators. That is what the reuse options are
for, and they must be set **before** `bind`; setting them afterwards has no
effect. The failure mode is confusing: the first station on the host works and
the second cannot start.

Multicast loopback is enabled by default. **Leave it that way.** Turning it off
looks like an easy way to stop hearing yourself, but it also stops every peer on
the same host from hearing you — and that is the commonest deployment there is.
Filter your own datagrams by sender ID instead.

On a multi-homed host, name the local IPv4 address of the interface the peers
are on when joining, and set the outgoing multicast interface to match.

## Datagram layout

One datagram is exactly one LLAP packet. Datagrams are never fragmented,
concatenated or padded by the protocol.

| Offset | Size  | Field                                                       |
|--------|-------|-------------------------------------------------------------|
| 0      | 4     | Sender ID, big-endian. Discard datagrams carrying your own. |
| 4      | 1     | LLAP destination node ID                                    |
| 5      | 1     | LLAP source node ID                                         |
| 6      | 1     | LLAP type                                                   |
| 7      | 0–600 | LLAP data field, absent for control packets. No FCS.        |

The shortest legal datagram is 7 bytes (sender ID plus a control packet). The
longest is 607 (sender ID, 3-byte header, and the 600-byte maximum data field).

## The sender ID

The four leading octets are a sender ID, and they exist for exactly one
purpose: because multicast loopback is on, everything you send comes straight
back to you, and you must be able to throw your own datagrams away. Compare the
first four octets of every arriving datagram with your own ID and discard on a
match.

Its weaknesses, stated plainly:

- It is **not an address**. It cannot be used to reply to anyone, it does not
  identify a node, and nothing about it is registered or negotiated.
- Two stations **can** collide on the same value, and nothing detects that.
  When they do, each silently drops the other's traffic. Choosing a random
  32-bit value at startup makes a collision unlikely; choosing a constant makes
  it certain.
- The reference implementations use the **process ID**, written big-endian.
  That is fine on one host and collides readily across hosts, since low PIDs
  repeat everywhere.

Pick the value once at startup and never change it while running. Receivers
must not attribute any meaning to it beyond "mine" or "not mine".

## The payload: an LLAP packet with no FCS

Everything after offset 4 is an LLAP packet as it would appear on a real
LocalTalk bus, **minus the frame check sequence**. On the wire an LLAP frame
ends with a 2-byte CRC-CCITT computed over the destination node ID, source node
ID, type byte and data field (PDF 72). LToUDP strips it before sending and never
expects one back: UDP already carries a checksum, and the frame preamble, flag
bytes, bit stuffing and abort sequence of the real link are meaningless here.

A sender that leaves the FCS on produces datagrams two bytes too long, whose
data-field length check fails at every correct receiver. A bridge onto real
LocalTalk hardware must compute the FCS on the way out and strip it on the way
in.

### LLAP header

Three bytes, in this order (PDF 65–69):

| Offset | Size | Field               |
|--------|------|---------------------|
| 0      | 1    | Destination node ID |
| 1      | 1    | Source node ID      |
| 2      | 1    | LLAP type           |

### Node IDs

| Range         | Meaning                                           |
|---------------|---------------------------------------------------|
| `0` (`$00`)   | not allowed; treated as unknown                   |
| `1`–`127`     | user node IDs                                     |
| `128`–`254`   | server node IDs                                   |
| `255` (`$FF`) | broadcast ID — accepted by every node on the link |

Node IDs are not configured. A node guesses one at startup (from non-volatile
memory or at random) and verifies it by sending a series of lapENQ packets to
that ID; an lapACK from the current holder means the guess is taken and the node
must guess again. Silence means the ID is free. Both node bytes of an lapENQ and
of an lapACK carry the ID under discussion.

### LLAP type values

| Value             | Meaning                                        |
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

Types `$80`–`$FF` are control packets and carry **no data field at all**; a
control packet arriving with one is malformed. Types `$01`–`$7F` are data
packets, and the type byte names the client protocol the data belongs to.

lapRTS and lapCTS arbitrate access to a shared physical medium. UDP multicast
has no such contention, so they serve no purpose here — but they do turn up on
the group, because some senders repeat whatever they heard from a real link.
Receive them without complaint and ignore them.

### The data field

A data packet's data field is 2 to 600 bytes; a control packet has none. The
**low 10 bits of the first two bytes of the data field hold the length of the
data field itself, that length field included**, most significant bits first.
The high 6 bits belong to the client protocol and must be masked off before the
length is read — for DDP they carry the hop count and reserved bits (PDF 69).

So the smallest valid data packet is 5 bytes (3-byte header plus a 2-byte data
field), and the largest is 603.

The two DDP types differ only in header form (PDF 118): type `$01` carries the
5-byte short header, which omits the network numbers because both ends are
assumed to be on the same network, and type `$02` carries the 13-byte extended
header with full `net.node` addresses. Anything translating between LocalTalk
and a Phase 2 link must fill in the network number when lifting a short header
to an extended one.

## What a receiver must discard

| Condition                                                         | Reason                             |
|-------------------------------------------------------------------|------------------------------------|
| Fewer than 7 bytes                                                | No room for a sender ID and header |
| First four octets equal your own sender ID                        | Your own datagram, looped back     |
| More than 607 bytes                                               | Larger than any legal LLAP packet  |
| Type `$00`, or `$80`–`$FF` other than `$81 $82 $84 $85`           | Invalid or reserved (PDF 69)       |
| A control type carrying a data field                              | Control packets have no data field |
| A data field whose embedded length disagrees with what is present | Malformed                          |
| A data field longer than 600 bytes                                | Over the maximum                   |

Discard silently and keep reading. Never decode partially and never guess: on a
shared group you will see traffic from implementations that do not agree with
you, and a wrong decode is worse than an ignored datagram.

Size the read buffer **one byte larger** than the largest legal datagram. A
plain datagram receive truncates silently, so a read that exactly fills the
buffer is the only signal you get that something oversized arrived; without the
spare byte, an oversized datagram is indistinguishable from a legitimate
maximum-size frame.

## Interoperating implementations

| Implementation | What it is                                                    |
|----------------|---------------------------------------------------------------|
| Mini vMac      | Classic Macintosh emulator; speaks LToUDP as its network link |
| Snow           | Macintosh emulator with an LToUDP link                        |
| jrouter        | Software AppleTalk router                                     |
| tashrouter     | Software AppleTalk router                                     |
| tashtalkd      | Daemon bridging LToUDP to TashTalk LocalTalk hardware         |

All of them use the same group, port and framing described above. There is no
version negotiation, so compatibility rests entirely on getting these bytes
right.

## How to test it

Watch the group with `tcpdump`. The first four bytes of each payload are the
sender ID; the next three are the LLAP header:

```sh
sudo tcpdump -i any -n -X 'udp port 1954'
```

Join the group and dump whatever arrives, with `socat`:

```sh
socat -u UDP4-RECV:1954,reuseaddr,ip-add-membership=239.192.76.84:0.0.0.0 - | xxd
```

Send one lapENQ for node 42, from sender ID `$0000ABCD`:

```sh
printf '\x00\x00\xab\xcd\x2a\x2a\x81' |
    socat -u - UDP4-DATAGRAM:239.192.76.84:1954,ttl=1
```

If an emulator is holding node 42, it answers with a 7-byte datagram whose last
three bytes are `2a 2a 82` — an lapACK. If nothing holds it, nothing answers.
That single exchange proves the group, the port, the framing and the loopback
setting all at once.

Two useful checks beyond that:

- Run two receivers on one host. Both must see every datagram; if only one
  does, the reuse options were set after bind.
- Send from a host and confirm the sender itself does **not** log the datagram
  as inbound. If it does, self-echo filtering by sender ID is broken — and it
  will loop forever the first time it bridges to another link.

## References

*Inside AppleTalk*, 2nd ed., Apple Computer, 1990 — chapter 1 covers LLAP
in full.

| Topic                           | PDF pages |
|---------------------------------|-----------|
| LLAP node IDs and packet format | 65–69     |
| LLAP timing, framing, FCS       | 72–73     |
| Short vs extended DDP header    | 118       |
