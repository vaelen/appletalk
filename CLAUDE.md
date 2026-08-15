# appletalk

A Rust implementation of the AppleTalk protocol stack. Currently a passive
EtherTalk frame dumper; the intent is a working node. `appletalk.md` has the
protocol overview and the planned build order.

## Layout

| File           | Holds                                                      |
|----------------|-------------------------------------------------------------|
| `src/wire.rs`  | Protocol parsers and their `Display` impls. No I/O.          |
| `src/main.rs`  | Capture loop, interface selection, hexdump.                  |
| `appletalk.md` | Protocol reference: layers, addressing, Phase 1 vs 2.        |

Keep parsing pure and in `wire.rs` — it stays testable without a NIC.

## Conventions

- Every wire type gets `fn parse(&[u8]) -> Option<Self>` and `impl Display`.
  Use `Display`, not bespoke `to_str` helpers, so `{}` and `format!` work.
- **Fail closed.** A parser that does not fully recognise its input returns
  `None`; the caller falls back to a hexdump. Never decode partially or guess —
  a wrong decode is worse than a hex dump.
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

## Verifying against real traffic

Nothing here has been tested against a live AppleTalk network. Layouts written
from *Inside AppleTalk* are marked where they are worth confirming. Cross-check
with `tcpdump -e -x` before trusting a decode.

```sh
sudo setcap cap_net_raw+ep target/debug/appletalk   # or run as root
./target/debug/appletalk [interface]
```
