# appletalk

A Rust implementation of the AppleTalk protocol stack. It dumps EtherTalk
traffic passively by default, and can also claim an AppleTalk address and act
as a node: `zones`, `nodes` and `ping`. `appletalk.md` has the protocol
overview and the planned build order.

## Layout

| File             | Holds                                                                                        |
|------------------|----------------------------------------------------------------------------------------------|
| `src/wire/`      | Protocol parsers, one file per protocol; `decode()`. No I/O.                                 |
| `src/session.rs` | Reassembles multi-packet ATP transactions. The only stateful module, driven by the frontend. |
| `src/capture.rs` | Capture thread: NIC to `Event`s on a bounded channel.                                        |
| `src/node.rs`    | Node runtime: claims an address, defends it, sends requests, awaits replies.                 |
| `src/text.rs`    | Plain-text frontend. Timestamps and hexdump.                                                 |
| `src/cli.rs`     | `clap` command line: subcommands, and the output/filter flags a frontend obeys.              |
| `src/main.rs`    | Glue: pick an interface, pick a frontend, start it.                                          |
| `appletalk.md`   | Protocol reference: layers, addressing, Phase 1 vs 2.                                        |

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

Not yet exercised, so do not assume these work: retrying after a collision (as
opposed to detecting one, which is confirmed), the routerless branch, a zone
list long enough to page more than once, a reply with no zone multicast
address, `--net`, and Phase 1. The book settles
byte layouts, not behavior — cross-check with `tcpdump -e -x` before trusting
anything on that second list.

```sh
sudo setcap cap_net_raw+ep target/debug/appletalk   # or run as root
./target/debug/appletalk [-i interface] [--hex] [--hide rtmp,...]   # monitor, the default
./target/debug/appletalk zones                                     # list zones on the internet
./target/debug/appletalk nodes [zone]                               # list entities in a zone
./target/debug/appletalk ping <net.node | object:type@zone>         # echo a node
```
