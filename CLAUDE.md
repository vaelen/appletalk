# appletalk

A Rust implementation of the AppleTalk protocol stack. Currently a passive
EtherTalk frame dumper; the intent is a working node. `appletalk.md` has the
protocol overview and the planned build order.

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

Still untested against a live AppleTalk network — the book settles the byte
layouts, not our behavior. Cross-check with `tcpdump -e -x` before trusting a
decode of real traffic.

```sh
sudo setcap cap_net_raw+ep target/debug/appletalk   # or run as root
./target/debug/appletalk [-i interface] [--hex] [--hide rtmp,...]
```
