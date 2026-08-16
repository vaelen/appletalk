# appletalk

An AppleTalk protocol stack in Rust: a passive EtherTalk sniffer, a node that
claims an address and asks the network questions, and a bridge that puts
emulated Macs onto your real AppleTalk network.

It speaks AppleTalk Phase 2 over Ethernet (802.3 + LLC + SNAP). Point it at a
NIC on a segment with vintage Macs, a Netatalk box, or an AppleTalk router, and
it will decode what it hears — or join in and ask.

```
$ appletalk zones
68k Mac Club *

$ appletalk nodes
Mini:AFPServer@* at 6800.150:249
Mini:Workstation@* at 6800.150:4
jrouter v0.0.21-dev:AppleRouter@68k Mac Club at 6800.1:253
raspberrypi:AFPServer@* at 6800.3:128

$ appletalk ping -c 2 6800.3
8 bytes from 6800.3: seq=0 time=1.42 ms
8 bytes from 6800.3: seq=1 time=0.98 ms

--- 6800.3 ping statistics ---
2 sent, 2 received, 0% loss, rtt min/avg/max 0.98/1.20/1.42 ms
```

## What it decodes

| Protocol | What it is                                         | Status              |
|----------|----------------------------------------------------|---------------------|
| ELAP     | AppleTalk over Ethernet framing, Phase 1 and 2     | Parsed and encoded  |
| LLAP     | AppleTalk over LocalTalk framing, and its node IDs | Parsed and encoded  |
| AARP     | Address resolution — claim, probe, defend          | Parsed and encoded  |
| DDP      | Datagrams, the layer everything else rides on      | Parsed and encoded  |
| NBP      | Name lookup: `object:type@zone` to an address      | Parsed and encoded  |
| ATP      | Request/response transactions, reassembled         | Parsed and encoded  |
| AEP      | Echo — the ping protocol                           | Parsed and encoded  |
| ZIP      | Zone names, and the cable range a node boots into  | Parsed and encoded  |
| RTMP     | Routing table maintenance                          | Identified only     |
| ADSP     | Reliable byte stream                               | Identified only     |

Protocols in the last group are recognised by their DDP type byte, so
`--hide rtmp` works on them even though their bodies fall through to a hexdump.
That matters in practice: routers beacon RTMP every ten seconds, and silencing
them shouldn't have to wait for a parser.

Every layout has been checked against *Inside AppleTalk, 2nd edition*, and a
parser that doesn't fully recognise its input returns nothing rather than
guessing — a wrong decode is worse than a hex dump.

## Building

Rust 1.85 or newer (the crate is edition 2024).

```sh
cargo build --release
```

## Running

Capturing and transmitting raw frames needs `CAP_NET_RAW`. Grant it to the
binary once rather than running the whole thing as root:

```sh
sudo setcap cap_net_raw+ep target/release/appletalk
```

By default it picks the first interface that is up, isn't loopback, and has a
MAC. Use `-i` to choose:

```sh
appletalk -i eth0 monitor
```

### monitor — watch traffic

The default command; `appletalk` on its own does this. One indented block per
packet: the Ethernet frame, the DDP datagram, then the decoded protocol.

```
12:04:22.115 00:05:02:aa:bb:cc > 09:00:07:ff:ff:ff  DDP (0x809b)  phase 2  20 bytes
  6800.99:6 > 0.255:6  type 6 (ZIP) hops 0 len 20 cksum none
    get-net-info zone
```

| Flag             | What it does                                      |
|------------------|---------------------------------------------------|
| `--hex`          | Hex dump payloads. Off by default                 |
| `--no-link`      | Hide the Ethernet frame line                      |
| `--no-net`       | Hide the DDP datagram line                        |
| `--only <list>`  | Show only these protocols, comma separated        |
| `--hide <list>`  | Hide these protocols, comma separated             |

`--only` and `--hide` are mutually exclusive. Filtering happens at display
time, so hidden traffic is still captured and reassembled.

Monitoring is entirely passive — it claims no address and transmits nothing.

### zones — list zones

```sh
appletalk zones
```

Asks a router for the internet's zone list over ATP, paging until the router
says it is done. Your own zone is marked with `*`. A network with no router has
no zones, and it says so rather than treating that as an error.

### nodes — list what's registered

```sh
appletalk nodes                  # the local zone
appletalk nodes "68k Mac Club"   # a named zone
appletalk nodes '*'              # this cable only
```

An NBP wildcard lookup, printing one line per registered entity. A single
machine usually registers several — a file server, a workstation, a printer
spooler — so expect its address to appear more than once. A trailing `#n` is
NBP's enumerator, distinguishing entities registered under one name on one
socket.

With a router, this is a broadcast request the router explodes across the zone,
which means naming a zone on the far side of a tunnel works exactly as well as
the local one:

```
$ appletalk nodes BabCom
claimed 6800.53, zone "68k Mac Club", router 6800.1
BabCom Gateway:Macintosh Quadra 800@* at 2905.50:251 #1
BabCom-PDF:LaserWriter@* at 2905.1:132
Sunny:LaserWriter@BabCom at 2905.217:128
```

Without a router, it falls back to a local broadcast on the cable.

### ping — echo a node

```sh
appletalk ping 6800.3
appletalk ping 'Mini:AFPServer@68k Mac Club'
appletalk ping -c 10 6800.3
```

A target containing `:` or `@` is looked up through NBP first; anything else is
parsed as `net.node`. AEP has no sequence number, so the round-trip time comes
from a marker planted in the echo data. Exits non-zero if nothing answers.

### bridge — put emulated Macs on the real network

```sh
appletalk bridge udp
```

Repeats AppleTalk between the Ethernet cable and LocalTalk-over-UDP-multicast
(LToUDP) — the transport Mini vMac, Snow, jrouter and tashrouter all speak.
Emulated Macs on the multicast group become ordinary nodes on your EtherTalk
network: they show up in the Chooser, answer a `nodes` run from another machine,
and can mount a real file server. Traffic goes both ways.

```
$ appletalk bridge udp
listening on eth0
claimed 6800.53, zone "68k Mac Club", router 6800.1
bridging 6800.53 <-> LToUDP 239.192.76.84:1954
```

It is a **bridge, not a router**: one network number, one node-ID space, and no
routing or zone protocols of its own. The cable's real router keeps that job,
and its RTMP and ZIP traffic reaches the LocalTalk side because the bridge
repeats it like anything else. That is what lets an emulator see zones on the
far side of an AURP tunnel — the router answers it directly.

The two sides arbitrate addresses differently, so the bridge translates rather
than repeats:

| Layer                        | What the bridge does                                    |
|------------------------------|---------------------------------------------------------|
| DDP datagrams                | Repeated both ways, extended headers byte for byte      |
| Short DDP headers            | Lifted to extended form on the way out to Ethernet      |
| AARP (Ethernet)              | Terminated. Answered on behalf of LocalTalk nodes       |
| LLAP ENQ/ACK (LocalTalk)     | Terminated. Answered on behalf of Ethernet nodes        |

It claims an AppleTalk address of its own, so it takes one node ID and accepts
the same `-i`, `--net` and `--node` flags as the query commands. Multicast needs
no special privilege, but the Ethernet side still wants `CAP_NET_RAW`.

Run **one bridge per Ethernet segment and group**. Broadcasts flood both ways,
and a second bridge on the same pair will storm — there is no spanning tree to
stop it.

`bridge.md` documents the forwarding rules, every message it prints, and the
known limits, for when something does not arrive and you need to know why.
`LToUDP.md` specifies the wire protocol itself, for implementing it elsewhere.

## Addressing

Everything except `monitor` needs an AppleTalk address, because a router can
only reply to a node it can resolve. On startup the node picks a provisional
address in the startup range, claims it with AARP probes, asks a router for the
real cable range and zone with ZIP GetNetInfo, and then answers AARP requests
for that address for as long as it runs.

You can short-circuit that:

| Flag                | Effect                                                    |
|---------------------|-----------------------------------------------------------|
| `--net <net>`       | Claim an address on this network; we pick the node number |
| `--node <net.node>` | Claim exactly this address                                |

Neither is second-guessed if the router disagrees about the cable range — it
says what it did and carries on. The address is claimed fresh each run and
dropped on exit; nothing is saved between invocations.

## Status

The wire layer is complete for AARP, DDP, NBP, ATP, AEP, ZIP and LLAP, with
round-trip tests built from byte literals. RTMP, ADSP, ASP, PAP and AFP are not
parsed yet.

Verified against a live AppleTalk internet — a seed router, a couple of vintage
Macs, and a second network reached over an AURP tunnel. The address claim, AARP
defense, ZIP GetNetInfo and all three query commands work against both the local
cable and a remote zone across the tunnel, and so does a routerless cable with
the router switched off.

The bridge is verified against real hardware too: emulators on the multicast
group and machines on the Ethernet cable reach each other in both directions,
and an emulator sees every zone on the internet, including those on the far side
of the tunnel.

Not yet exercised on real hardware: retrying after an address collision — as
opposed to detecting one, which works — zone lists long enough to need a second
page, and Phase 1 networks. On the bridge specifically: a node moving between
the two sides, a genuine duplicate node ID, and a second bridge on one pair.

The node asks questions but does not answer them. It registers no NBP name, so
it is invisible to a `nodes` run from another machine, and it does not reply to
echoes. The bridge is the exception: it answers AARP and LLAP enquiries on
behalf of the nodes it fronts.

## Development

```sh
cargo test
cargo clippy --all-targets
```

Both are expected to be clean before every commit. `CLAUDE.md` documents the
conventions; `appletalk.md` is the protocol reference and carries an index from
each section to its page in the book. `bridge.md` and `LToUDP.md` cover the
bridge's behaviour and the LToUDP wire protocol respectively.

## License

MIT. Copyright 2026 Andrew C. Young (andrew@vaelen.org). See `LICENSE`.
