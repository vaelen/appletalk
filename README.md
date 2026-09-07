# appletalk

An AppleTalk protocol stack in Rust: a passive EtherTalk sniffer, a node that
claims an address and asks the network questions, a bridge that puts emulated
Macs onto your real AppleTalk network, and a router that joins several links
and tunnels to other AppleTalk internets over AURP.

It speaks AppleTalk Phase 2 over Ethernet (802.3 + LLC + SNAP). Point it at a
NIC on a segment with vintage Macs, a Netatalk box, or an AppleTalk router, and
it will decode what it hears — or join in and ask.

```
$ appletalk zones
68k Mac Club *

$ appletalk nodes
Mini:AFPServer@* at 6800.150:249
Mini:Workstation@* at 6800.150:4
raspberrypi:AFPServer@* at 6800.3:128

$ appletalk ping -c 2 6800.3
8 bytes from 6800.3: seq=0 time=1.42 ms
8 bytes from 6800.3: seq=1 time=0.98 ms

--- 6800.3 ping statistics ---
2 sent, 2 received, 0% loss, rtt min/avg/max 0.98/1.20/1.42 ms
```

## What it decodes

| Protocol | What it is                                         | Status             |
|----------|----------------------------------------------------|--------------------|
| ELAP     | AppleTalk over Ethernet framing, Phase 1 and 2     | Parsed and encoded |
| LLAP     | AppleTalk over LocalTalk framing, and its node IDs | Parsed and encoded |
| AARP     | Address resolution — claim, probe, defend          | Parsed and encoded |
| DDP      | Datagrams, the layer everything else rides on      | Parsed and encoded |
| NBP      | Name lookup: `object:type@zone` to an address      | Parsed and encoded |
| ATP      | Request/response transactions, reassembled         | Parsed and encoded |
| AEP      | Echo — the ping protocol                           | Parsed and encoded |
| ZIP      | Zone names, and the cable range a node boots into  | Parsed and encoded |
| RTMP     | Routing table maintenance                          | Parsed and encoded |
| AURP     | Routing between internets, tunnelled over UDP      | Parsed and encoded |
| ADSP     | Reliable byte stream                               | Identified only    |

Anything still unparsed is recognised by its DDP type byte, so `--hide adsp`
works on it even though its body falls through to a hexdump — identity comes
from the type, not from having a parser.

Every layout has been checked against *Inside AppleTalk, 2nd edition*, and a
parser that doesn't fully recognise its input returns nothing rather than
guessing — a wrong decode is worse than a hex dump.

## Building

Rust 1.85 or newer (the crate is edition 2024). The TashTalk port uses the
`serialport` crate, which on Debian and Ubuntu needs `libudev-dev` at build
time:

```sh
sudo apt install libudev-dev     # Debian/Ubuntu only
cargo build --release
```

The binary is `target/release/appletalk`. Copy it wherever you like — it has no
runtime files, and the router looks for its config next to the working
directory or in `/etc/appletalk`, not next to the binary. A debug build
(`cargo build`, giving `target/debug/appletalk`) works the same way and is what
the test suite exercises.

## Running

Capturing and transmitting raw Ethernet frames needs `CAP_NET_RAW`, and the
router additionally binds UDP 387, which needs `CAP_NET_BIND_SERVICE`. Grant
them to the binary once rather than running the whole thing as root:

```sh
# everything except router
sudo setcap cap_net_raw+ep target/release/appletalk

# everything, including router
sudo setcap cap_net_raw,cap_net_bind_service+ep target/release/appletalk
```

`cargo build` writes a fresh file, so **re-run `setcap` after every rebuild**.
Running as root (`sudo ./target/release/appletalk ...`) works too, and is the
fallback on a filesystem that does not carry capabilities.

### Commands

| Command                 | What it does                                               | Needs                                 |
|-------------------------|------------------------------------------------------------|---------------------------------------|
| `monitor` (the default) | Print decoded AppleTalk traffic as it arrives              | `cap_net_raw`                         |
| `zones`                 | List the zones on the internet                             | `cap_net_raw`                         |
| `nodes [ZONE]`          | List the entities registered in a zone                     | `cap_net_raw`                         |
| `ping TARGET [-c N]`    | Echo a node by `net.node` or `object:type@zone`            | `cap_net_raw`                         |
| `bridge udp`            | Bridge LToUDP emulators onto this Ethernet, as one network | `cap_net_raw`                         |
| `router [FLAGS]`        | Route between links and AURP peers, from a config or flags | `cap_net_raw`, `cap_net_bind_service` |
| `peers import SOURCE`   | Merge a peer list, a file or HTTP(S) URL, into the config  | nothing                               |

`appletalk --help` lists them, `appletalk <command> --help` details one, and
`appletalk --version` prints the crate version.

### Global flags

These are accepted before or after the command name and apply to every
command that opens a NIC:

| Flag                  | Effect                                                                   |
|-----------------------|--------------------------------------------------------------------------|
| `-i, --interface NIC` | NIC to use. Default: the first one that is up, isn't loopback, has a MAC |
| `--net NET`           | Claim an address on this network; the node number is chosen for you      |
| `--node NET.NODE`     | Claim exactly this address                                               |
| `-h, --help`          | Usage, for the whole program or one command                              |
| `-V, --version`       | Print the version and exit                                               |

`--net` and `--node` are mutually exclusive, and `monitor` ignores both since
it never claims an address. The router does not use `-i`: each of its EtherTalk
ports names its own interface.

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

`--only` and `--hide` are mutually exclusive and take these names: `aarp`,
`rtmp`, `nbp`, `atp`, `aep`, `zip`, `adsp`, and `other` for any DDP type the
list does not name. Filtering happens at display time, so hidden traffic is
still captured and reassembled.

The flags may follow the command name or stand alone (`appletalk --hide rtmp`
means `appletalk monitor --hide rtmp`); they may not precede another command.

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
parsed as `net.node`. `-c, --count N` sets how many echoes to send (default 4,
minimum 1). AEP has no sequence number, so the round-trip time comes from a
marker planted in the echo data. Exits non-zero if nothing answers.

### bridge — put emulated Macs on the real network

```sh
appletalk bridge udp
```

Repeats AppleTalk between the Ethernet cable and LocalTalk-over-UDP-multicast
(LToUDP) — the transport that Mini vMac, Snow, jrouter and tashrouter all speak.
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

### router — route between links and tunnel peers

```sh
appletalk router --config appletalk.toml
```

Before the first run, grant the extra capability the AURP port needs (see
[Running](#running)):

```sh
cargo build --release
sudo setcap cap_net_raw,cap_net_bind_service+ep target/release/appletalk
```

Where `bridge` makes two links look like one network, `router` gives each link
its own network number and zones and routes between them — RTMP, ZIP, NBP and
DDP forwarding, the lot — and tunnels to distant AppleTalk internets over AURP
(UDP 387), the way GlobalTalk is stitched together. It is a **seed router**:
every port's network range and zones come from the config, nothing is learned
from a neighbour at startup.

Ports come in three kinds: EtherTalk on a NIC, LToUDP on a multicast group, and
TashTalk on a serial LocalTalk board. Each claims its own AppleTalk address and
defends it.

#### The config file

TOML, found at `--config PATH`, else `./appletalk.toml`, else
`/etc/appletalk/appletalk.toml`. Unknown keys are an error, so a typo cannot
silently disable a port.

```toml
[router]
name = "appletalk"            # NBP object name, type AppleRouter
public_ip = "203.0.113.5"     # our AURP domain identifier; needed behind NAT
listen = "0.0.0.0:387"
open_peering = true           # accept peers we did not configure, up to 256
peers = ["router.example.net", "192.0.2.7"]

[[ethertalk]]
interface = "eth0"
net = "6800-6800"             # a bare number is accepted too
zones = ["68k Mac Club"]      # the first is the port's default zone

[[ltoudp]]
net = 6801
zones = ["Emulators"]
interface = "192.168.1.5"     # optional; for a multi-homed host

[[tashtalk]]
device = "/dev/ttyAMA0"
net = 6802
zones = ["LocalTalk"]
```

Every port needs at least one zone, and zone names are 1 to 32 bytes. A
LocalTalk port — LToUDP or TashTalk — is one network, never a range. Two ports
may not share an interface or device, and their network ranges may not overlap.
At least one port is required; zero peers is fine.

#### The command line

Every setting is reachable without a file, so a one-off run needs no config:

```sh
appletalk router --ethertalk 'eth0:6800-6800:68k Mac Club' --ltoudp 6801:Emulators
```

| Flag                                                | Meaning                                                                |
|-----------------------------------------------------|------------------------------------------------------------------------|
| `--config PATH`                                     | Config file to load; an explicit one that does not exist is an error   |
| `--name NAME`                                       | Our NBP object name, registered as type `AppleRouter`                  |
| `--public-ip IP`                                    | Our AURP domain identifier. Needed behind NAT                          |
| `--listen ADDR:PORT`                                | UDP address for AURP; default `0.0.0.0:387`                            |
| `--no-open-peering`                                 | Refuse AURP packets from addresses the config does not name            |
| `--peer HOST`                                       | Peer, by IP or hostname. Repeatable; **replaces** the file's list      |
| `--add-peer HOST`                                   | Repeatable; appends to the file's list                                 |
| `--no-peers`                                        | Empty the peer list. Open peering is separate                          |
| `--ethertalk SPEC`                                  | `IFACE:NET[-NET]:ZONE[,ZONE...]`. Repeatable; replaces the file's list |
| `--ltoudp SPEC`                                     | `[IFACE_IP:]NET:ZONE[,ZONE...]`. Same                                  |
| `--tashtalk SPEC`                                   | `DEVICE:NET:ZONE[,ZONE...]`. Same                                      |
| `--add-ethertalk`, `--add-ltoudp`, `--add-tashtalk` | Append one port instead of replacing the list                          |
| `--no-ethertalk`, `--no-ltoudp`, `--no-tashtalk`    | Drop every port of that kind                                           |

Per list, the replace, `--add-*` and `--no-*` flags are mutually exclusive. A
zone name containing a colon cannot go in a spec — the colon is the field
separator — so put that port in the config file. Flags override the file: a
scalar flag replaces the file's value, and each list follows the rule above.
The global `-i`, `--net` and `--node` flags are ignored by `router`.

| Setting        | File key              | Flag                | Default                       |
|----------------|-----------------------|---------------------|-------------------------------|
| Router name    | `router.name`         | `--name`            | `appletalk`                   |
| Public IP      | `router.public_ip`    | `--public-ip`       | the socket's, else a NIC's IP |
| AURP listen    | `router.listen`       | `--listen`          | `0.0.0.0:387`                 |
| Open peering   | `router.open_peering` | `--no-open-peering` | `true`                        |
| Peers          | `router.peers`        | `--peer` and kin    | none                          |
| EtherTalk port | `[[ethertalk]]`       | `--ethertalk`       | none                          |
| LToUDP port    | `[[ltoudp]]`          | `--ltoudp`          | none                          |
| TashTalk port  | `[[tashtalk]]`        | `--tashtalk`        | none                          |

#### peers import — merge a peer list

```sh
appletalk peers import globaltalk-peers.txt
appletalk peers import https://example.net/globaltalk/peers.txt
appletalk peers import peers.txt --config /etc/appletalk/appletalk.toml
```

The argument is a file path, or an `http://` or `https://` URL that is fetched
with a plain GET; a non-2xx status is an error and nothing is written. One
IPv4 literal or hostname per line; blank lines and `#` comments are skipped. Every bad line is reported at once and nothing is written. New entries
are appended to `router.peers`, compared case-insensitively against what is
already there, and the file is rewritten with `toml_edit` so its comments and
formatting survive. A missing config file is created. It prints
`added N, M already present`. Names are not resolved, and a running router is
not disturbed.

#### While it runs

It opens every port, binds the AURP socket, settles on a domain identifier and
says so, then routes:

```
router: appletalk on 2 port(s), AURP on 0.0.0.0:387 as 203.0.113.5
```

If that identifier is private, loopback or unset it says so too — such an
address peers two routers on one LAN and nothing further, so set `public_ip`.
Every line after that is on stderr and prefixed `router:`: ports claiming an
address, peer connections opening and closing with the reason, routes added,
dropped or changed, zones learned, plus `rx:` for a read error, `send failed:`
for a frame that would not go out, and `dropped N events (queue full)` if the
router falls behind its links.

Configured peer names are re-resolved every 10 seconds, so a peer on a dynamic
address reconnects on its own once DNS catches up.

`SIGUSR1` dumps three things to stderr, in order: the routing and zone table,
the peer table, then a line per port with its kind, name, network range,
claimed node and zones. All in aligned columns.

```sh
kill -USR1 $(pidof appletalk)
```

`SIGINT` or `SIGTERM` shuts it down politely: it sends an RD to every peer it
is data sender to, keeps running for up to two seconds so those can be
acknowledged, and exits. Peers therefore drop our routes at once rather than
waiting out their tickle timer. A second `SIGINT` during those two seconds
exits immediately.

Open peering holds at most 256 peers, and an unconfigured one with neither
connection up is dropped after 90 seconds quiet: UDP 387 faces the internet,
and a stranger's packet must not buy permanent memory. Configured peers are
exempt from both.

AURP listens on UDP 387, which is privileged, so the router wants one more
capability than the rest of the stack:

```sh
sudo setcap cap_net_raw,cap_net_bind_service+ep target/release/appletalk
```

#### Running as a service

`contrib/appletalk-router.service` is a systemd unit that runs the router as an
unprivileged dynamic user with the two capabilities granted by systemd, so the
installed binary needs no `setcap`. It expects the binary at
`/usr/local/bin/appletalk` and the config at `/etc/appletalk/appletalk.toml`:

```sh
sudo install -m 755 target/release/appletalk /usr/local/bin/appletalk
sudo install -d /etc/appletalk
sudo install -m 644 appletalk.toml /etc/appletalk/appletalk.toml
sudo install -m 644 contrib/appletalk-router.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now appletalk-router
```

Logs go to the journal (`journalctl -u appletalk-router -f`), `systemctl stop`
sends the `SIGTERM` the router shuts down politely on, and the dump is
`systemctl kill -s USR1 appletalk-router`. A TashTalk port needs the serial
device let through; the unit has the two lines to uncomment. Edit the peer
list with `sudo appletalk peers import ... --config
/etc/appletalk/appletalk.toml` and restart the service to pick it up.

`docs/AURP.md` is the tunnel protocol itself — the dialog, the packet layouts
and what this stack implements of it.

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

The wire layer is complete for AARP, DDP, NBP, ATP, AEP, ZIP, LLAP, RTMP and
AURP, with round-trip tests built from byte literals. ADSP, ASP, PAP and AFP
are not parsed yet.

Verified against a live AppleTalk internet — a seed router, a couple of vintage
Macs, and a second network reached over an AURP tunnel. The address claim, AARP
defense, ZIP GetNetInfo and all three query commands work against both the local
cable and a remote zone across the tunnel, and so does a routerless cable with
the router switched off.

The bridge is verified against real hardware too: emulators on the multicast
group and machines on the Ethernet cable reach each other in both directions,
and an emulator sees every zone on the internet, including those on the far side
of the tunnel.

Router mode has run live on a real internet: an EtherTalk port and an LToUDP
port, the GlobalTalk peer list, and traffic routed to remote zones over the
AURP tunnel. Not yet measured on a wire: the hop-count rule (one hop per
cable, none for the tunnel) and a second seed router. The TashTalk port is 
furthest out — the hardware has not arrived, so its serial framing has only 
ever been tested against byte literals. A Phase 1 EtherTalk frame is dropped 
by the router rather than routed: Phase 1 carries no length field to trim 
Ethernet's padding by, so the datagram disagrees with its own length and fails 
closed.

Not yet exercised on real hardware: retrying after an address collision — as
opposed to detecting one, which works — zone lists long enough to need a second
page, and Phase 1 networks. On the bridge specifically: a node moving between
the two sides, a genuine duplicate node ID, and a second bridge on one pair.

The node asks questions but does not answer them. It registers no NBP name, so
it is invisible to a `nodes` run from another machine, and it does not reply to
echoes. The bridge and the router are the exceptions: the bridge answers AARP
and LLAP enquiries on behalf of the nodes it fronts, and the router answers the
services a router owes its cables.

## Development

```sh
cargo test
cargo clippy --all-targets
```

Both are expected to be clean before every commit. `CLAUDE.md` documents the
conventions; `appletalk.md` is the protocol reference and carries an index from
each section to its page in the book. `bridge.md`, `LToUDP.md` and
`docs/AURP.md` cover the bridge's behaviour, the LToUDP wire protocol and the
AURP tunnel protocol respectively.

## License

MIT. Copyright 2026 Andrew C. Young (andrew@vaelen.org). See `LICENSE`.
