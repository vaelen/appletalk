# appletalk

A Rust implementation of the AppleTalk protocol stack. It dumps EtherTalk
traffic passively by default, and can also claim an AppleTalk address and act
as a node: `zones`, `nodes`, `ping` and `bridge`. `router` goes further and
routes between several links and AURP tunnel peers. `appletalk.md` has the
protocol overview and the planned build order.

## Layout

| File                  | Holds                                                                                              |
|-----------------------|----------------------------------------------------------------------------------------------------|
| `src/wire/`           | Protocol parsers, one file per protocol; `decode()`. No I/O.                                       |
| `src/session.rs`      | Reassembles multi-packet ATP transactions. The only stateful module, driven by the frontend.       |
| `src/capture.rs`      | Capture thread: NIC to `Event`s on a bounded channel.                                              |
| `src/node.rs`         | Node runtime: claims an address, defends it, sends requests, awaits replies.                       |
| `src/ltoudp.rs`       | LToUDP transport: the multicast socket and its reader thread.                                      |
| `src/tashtalk.rs`     | TashTalk transport: LocalTalk over a serial port — FCS, escapes, node bitmap, reader thread.       |
| `src/bridge.rs`       | Bridge runtime: repeats AppleTalk between EtherTalk and a LocalTalk link.                          |
| `src/config.rs`       | Router config: the TOML file, the `router` flags, their merge, and `peers import`.                 |
| `src/router/mod.rs`   | Router runtime: the `Target`/`Dest`/`Emit`/`Action` types the parts below speak, and the run loop. |
| `src/router/table.rs` | Routing and zone tables: best route per network, the book's aging, split horizon per port.         |
| `src/router/ports.rs` | One router port: its link kind, network range, zones, address claim and framing.                   |
| `src/router/local.rs` | The services a router owes its own cables: RTMP, ZIP, NBP and echo. Pure.                          |
| `src/router/aurp.rs`  | The AURP peers: two one-way connections each, their state machines and timers.                     |
| `src/text.rs`         | Plain-text frontend. Timestamps and hexdump.                                                       |
| `src/cli.rs`          | `clap` command line: subcommands, and the output/filter flags a frontend obeys.                    |
| `src/main.rs`         | Glue: pick an interface, pick a frontend, start it.                                                |
| `appletalk.md`        | Protocol reference: layers, addressing, Phase 1 vs 2.                                              |
| `LToUDP.md`           | The LToUDP protocol, for someone implementing it elsewhere.                                        |
| `bridge.md`           | The bridge's behaviour, for whoever has to debug it.                                               |
| `docs/AURP.md`        | The AURP tunnel protocol (RFC 1504) as GlobalTalk runs it, and what this stack implements.         |
| `repos/`              | Reference clones of jrouter and tashrouter. Gitignored; re-clone if missing.                       |
| `contrib/`            | A systemd unit for `router`: dynamic user, ambient capabilities, config in `/etc/appletalk`.       |

Keep parsing pure and in `wire/` — it stays testable without a NIC.

Frontends consume `Receiver<capture::Event>` and nothing else; they never touch
pnet. `wire::Packet` is fully owned so it can cross that channel — pnet lends
out a buffer that dies on the next read, so parsers copy their payloads.

Filtering (`--only`/`--hide`) happens **at display time only**. Hidden packets
are still captured, decoded and reassembled — filtering upstream would mean a
hidden protocol never reassembles, and would stop a TUI toggling filters live.

The queue is bounded and the capture thread **drops** rather than blocking when
a frontend falls behind, reporting the count via `Event::Dropped`. A frontend
that ignores it shows a gap with no explanation.

## Conventions

- Every wire type gets `fn parse(&[u8]) -> Option<Self>`, `impl Display`, and
  `impl Encode`. Use `Display`, not bespoke `to_str` helpers, so `{}` and
  `format!` work.
- **Fail closed.** A parser that does not fully recognise its input returns
  `None`; the caller falls back to a hexdump. Never decode partially or guess —
  a wrong decode is worse than a hex dump.
- **Recompute derived fields at encode time** — lengths, counts, padding —
  rather than trusting what's stored on the struct. A parsed packet whose
  length field disagreed with its data must not be able to re-transmit that
  disagreement; `encode` derives it fresh from the data every time.
- Slice with `.get()` and `?`, never index into untrusted wire bytes.
- All AppleTalk fields are big-endian.
- Comment the byte layout where it is not obvious (bit-packed fields,
  length-prefixed strings, anything where the wire disagrees with intuition).
- Prefer accessors over duplicating the wire: store the raw control byte and
  read bits from it rather than exploding it into bools.
- Mark deliberate shortcuts with a `ponytail:` comment naming the ceiling and
  the upgrade path.

## Tests

`#[cfg(test)] mod tests` next to the code. Build packets from byte literals and
assert on **both** the parsed fields and the rendered `Display` string — that
pins the wire layout and the output together.

Cover the rejects too: truncated headers, reserved/unknown function codes,
length fields that overrun the buffer.

Before committing: `cargo test && cargo clippy --all-targets` — both clean.

## Commits

Short — one or two sentences. No body paragraphs restating the diff, no
`Co-Authored-By` or session trailers.

## Verifying layouts

`inside-appletalk-second-edition.pdf` in the repo root is the authority. It is
gitignored — 57MB, and Apple's copyright. It has an OCR text layer, so grep it
instead of reading page images:

```sh
pdftotext -f 209 -l 212 inside-appletalk-second-edition.pdf -
```

`appletalk.md` has a section-to-PDF-page index. **Check the book before writing
a parser, not after.** Every layout in `wire/` has been verified against it;
keep it that way.

## What a live network has confirmed

Verified 2026-08-16 against a real internet: a `jrouter v0.0.21-dev` seed router
at `6800.1`, cable range 6800-6800, zone `68k Mac Club`, with a Mac and a
Netatalk box — and, over an AURP tunnel to the USA, a second network (2905,
zone `BabCom`) with a Quadra 800, a LaserWriter and more.

Confirmed working:

- The whole startup sequence unaided, including the interesting branch: the
  provisional startup-range address falls outside the 6800-6800 cable range, so
  `NetInfo::Repick` fires and `claim_in_range` claims a fresh address on the
  real cable.
- Defending the address — peers resolve us by AARP and their replies arrive.
- ZIP GetNetInfo, including a **broadcast** reply and adopting the default zone.
- Refusing a taken address: `--node` at an address another node holds gets an
  AARP Response and fails with "is taken" rather than stealing it.
- `zones`, `nodes` and `ping` on the local cable. The internet has 36 zones,
  which is 435 bytes of length-prefixed names — inside one ATP response, so
  this has still never paged.
- `nodes <zone>` against a **remote** zone: the router explodes our BrRq into
  FwdReqs across the internet and replies come back from the far network.
- `ping` to a node on a remote network, routed over the tunnel.
- `bridge udp` against emulators on a real LToUDP group: unicast reaches them
  from the Ethernet cable and reaches back the other way, so the address
  translation works in both directions. An emulator also sees the **whole**
  zone list, including zones across the AURP tunnel — which means RTMP and ZIP
  cross intact and the router answers a LocalTalk node through the bridge.
  That is the load-bearing confirmation: the bridge is transparent, not merely
  moving packets.

Also confirmed: `--net`, both on and off the cable range; and the **routerless
branch**, by switching the router off — the node keeps its provisional address
and `zones` reports that the network has none.

Not yet exercised, so do not assume these work: retrying after a collision (as
opposed to detecting one, which is confirmed), a zone list long enough to page
more than once, a reply with no zone multicast address, and Phase 1. On the
bridge specifically, still unconfirmed: a node **moving** between the two links,
a genuine duplicate node ID across the bridge, a second bridge on the same pair,
entry aging after a node goes quiet, and that Ethernet-to-Ethernet traffic stays
off the LToUDP group. The book settles byte layouts, not behavior — cross-check
with `tcpdump -e -x` before trusting anything on that second list. The router
adds one known drop to that list: a Phase 1 EtherTalk frame fails `arrived`'s
DDP length check, because Phase 1 carries its Ethernet padding into the payload.

**Router mode: confirmed live on 2026-09-08**, in jrouter's place rather than
beside it. The config was translated from the jrouter config (an EtherTalk port
on `br0`, net 6800, zone `68k Mac Club`, a public IP, open peering and the seven
GlobalTalk peers) plus an LToUDP port. Both ports came up, the AURP peers
connected, and traffic was routed to the remote zones over the tunnel. That is
the load-bearing result: ports, claims, tables, ZIP and AURP all work together
on a real internet. Still unmeasured, so do not assume them: the hop-count
check (`tcpdump -e -x` showing hops one higher on the cable than on the tunnel,
never two), the second-seed-router-beside-jrouter arrangement, and an emulator
on the LToUDP port listing the whole zone list through us. Two things to know
before reading the logs: every line it prints is prefixed `router:`, and
`SIGUSR1` prints the routing and zone table, the peer table and a per-port
summary, in that order, as one log line; `SIGUSR2` tickles every connected
peer and logs a round-trip table two seconds later. Never probe the peers
from a second process behind the same NAT: they key peers by IP alone, so an
Open-Req from us with a fresh connection ID reads as a restart and breaks the
live connection. `SIGINT`/`SIGTERM` send RD to every
peer we are data sender to and drain for two seconds before exiting.

| Live check                                                                                                                                             | State                                |
|--------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------|
| EtherTalk and LToUDP ports up, GlobalTalk peers connected over UDP 387, traffic routed to remote zones across the tunnel                               | Confirmed 2026-09-08                 |
| Second seed router beside the live one, with a TashTalk port on its own net: the neighbours learn our net's zone and a Mac lists every zone through us | Confirmed 2026-09-18                 |
| `tcpdump -e -x` shows hop counts one higher on the cable than on the tunnel, never two                                                                 | Pending                              |
| TashTalk board with an empty cable: opens at 1 Mbaud with CTS asserted; init, ENQs, node bitmap and RTMP go out with a correct FCS; clean SIGTERM      | Confirmed 2026-09-15                 |
| TashTalk with a Mac on the cable: RTS/CTS both ways, frames decoded with a good FCS, GetMyZone and GetLocalZones answered, BrRq turned into a LkUp     | Confirmed 2026-09-18                 |
| TashTalk beside an EtherTalk port: the Mac's Chooser lookup for a remote zone leaves us as a zone-multicast LkUp on the Ethernet cable                 | Confirmed 2026-09-18                 |
| On `vaelen` with all three port kinds: a LocalTalk Mac behind TashTalk mounted a share from a remote network across the tunnel                         | Confirmed 2026-09-18                 |
| The firmware answering an ENQ for our node ID                                                                                                          | Pending, needs a Mac to probe our ID |

One deployment lesson from that run: under systemd, `RestrictAddressFamilies`
must include `AF_NETLINK` or interface enumeration returns nothing and every
NIC is "not found". `contrib/appletalk-router.service` has it.

```sh
sudo setcap cap_net_raw+ep target/debug/appletalk   # or run as root
# router only: UDP 387 is privileged
sudo setcap cap_net_raw,cap_net_bind_service+ep target/debug/appletalk
./target/debug/appletalk [-i interface] [--hex] [--hide rtmp,...]   # monitor, the default
./target/debug/appletalk zones                                      # list zones on the internet
./target/debug/appletalk nodes [zone]                               # list entities in a zone
./target/debug/appletalk ping <net.node | object:type@zone>         # echo a node
./target/debug/appletalk bridge udp                                 # join LToUDP and bridge it
./target/debug/appletalk router [--config appletalk.toml]           # route between links and peers
./target/debug/appletalk peers import <file | url>                 # merge a peer list into the config
kill -USR1 $(pidof appletalk)                                       # dump the router's tables
kill -USR2 $(pidof appletalk)                                       # tickle every peer, report two seconds later
```
