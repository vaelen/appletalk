# TODO

Things deliberately deferred, kept here so they are not lost. Nothing in this
file is blocking — the dumper and the three query commands work. Items are
grouped by what would prompt you to pick them up.

## Verify against real hardware

The node has met a real internet: a `jrouter v0.0.21-dev` seed router at
`6800.1` with zone `68k Mac Club`, and a second network (2905, zone `BabCom`)
reached over an AURP tunnel. That confirmed the full startup sequence including
the re-pick into the cable range, AARP defense, ZIP GetNetInfo, `zones`, and
both `nodes` and `ping` against local *and* remote networks.

These paths remain unexercised, and each one has already proven to be where the
bugs hide:

| Path | Why it matters |
|----------------------------------------|------------------------------------------------------------|
| Retrying after a collision              | Detection works — `--node` at a taken address correctly refuses. But that path errors out by design; the *pick another and probe again* loop in `claim_any`/`claim_in_range` only runs when a random pick collides, which has not happened |
| A network with no router                | Only ever run by accident, while a bug made a routed network look routerless |
| A zone list needing more than one page  | Still book-only. The live internet has 36 zones, but as length-prefixed strings that is 435 bytes — inside the 578 an ATP response carries, so the router answers in one packet. Roughly 50 zones would force a second page |
| A reply with no zone multicast address  | Accepted since the `Option<MacAddr>` change, never seen |
| `--net`                                 | Every live run so far used `--node` or no flag at all |
| A Phase 1 network                       | We only ever transmit Phase 2 |

## Protocols not yet parsed

Each needs its chapter read before writing the parser, per `CLAUDE.md`. Page
numbers are PDF pages in *Inside AppleTalk, 2nd ed.*; `appletalk.md` has the
full index.

| Protocol | Pages     | Notes                                                        |
|----------|-----------|--------------------------------------------------------------|
| RTMP     | 136-138   | Routers beacon every 10s, so it is the noisiest thing on the wire and currently a hexdump. Would also give a second route to router discovery, which today comes only from a GetNetInfo reply. |
| ADSP     | 297       | Reliable byte stream straight over DDP; needs its own reassembly, unlike the ATP-based protocols. |
| ASP, PAP | ch. 11, 236-239 | Both ride ATP, so `session.rs` already delivers their reassembled transactions as `Message::Unclassified`. Classifying them is the next step. |
| AFP      | 329-371   | The reason anyone ran AppleTalk. Large; needs ASP first. |

## Node runtime

- **Save the claimed address between runs.** The book wants the last address
  kept and retried as a hint at startup; we claim fresh every time.
- **Answer, don't just ask.** We register no NBP name and do not reply to
  echoes, so we are invisible to a `nodes` run from another machine and cannot
  be pinged back. Registering a name is the smallest useful step.
- **Revisit the capture queue's drop policy.** Dropping is right for a sniffer
  and wrong for a node that serves. Every request today retries, so it does not
  bite yet.
- **A TUI frontend.** The filter design already permits live toggling — it
  filters at display time precisely so a TUI can change filters without
  disturbing capture or reassembly.

## Wire layer

Raised during review of the encoder work, triaged as non-blocking.

### Encoders

| Where | Gap |
|-------|-----|
| `wire/mod.rs` `Frame::encode` | Emits the DDP SNAP discriminator for any `proto` that is not AARP, so a hand-built frame with an unrelated proto goes out mislabelled as AppleTalk. Now that a node transmits, this deserves a `debug_assert!` or a real proto-to-discriminator table. |
| `wire/mod.rs` `Frame::encode` | Phase 1 (`snap: false`) does not round-trip: `encode` pads to 60 bytes and the raw-EtherType parse branch has no length field to trim with, so the payload returns with trailing zeros. Marked with a `ponytail:` comment. |
| `wire/zip.rs` `NetInfoReply` | The encoder gates default-zone emission on `default_zone.is_some()` rather than the `flags & 0x80` bit. Equivalent for anything `parse` produced, but the two fields are independently settable. |
| `wire/nbp.rs`, `wire/zip.rs` | `tuples.len().min(15)` and `.min(255)` clamp silently, so 16 tuples emit behind a count of 15 — a fail-open on the send side. `ddp.rs` marks the same hazard with a `ponytail:` comment; these do not. |
| `wire/ddp.rs` | `checksum` is the one wire field echoed from the struct rather than recomputed. Spec-compliant, since generation is optional, but mutating `data` on a parsed `Ddp` and re-encoding emits a stale checksum that looks valid. Wants a note on the field. |

### Parsers

| Where | Gap |
|-------|-----|
| `wire/mod.rs` `pstring` / `put_pstring` | Asymmetric: `pstring` accepts up to 255 bytes, `put_pstring` truncates at the protocol's 32, so an over-long parsed name silently shortens on re-encode. Either reject `len > 32` on parse, which is the house rule, or document it. |
| `wire/zip.rs` `ZipAtp::parse_reply` | Ignores unconsumed trailing bytes: a reply declaring one zone but carrying three names parses one and discards the rest. Consistent with `Nbp::parse` and `Zip::parse`, but "never decode partially" is the stated rule. |
| `wire/zip.rs` `ZipAtp` | The reserved byte in the ATP user bytes is read but never validated as zero. |

### Reassembly

| Where | Gap |
|-------|-----|
| `session.rs` `expire` | O(n log n) per packet once the map saturates: under a flood of distinct `TxnKey`s — trivially spoofable by varying `tid` — every packet sorts a 512-element `Vec` to evict one entry. Degrades into queue backpressure, which is the sniffer's designed-for failure mode. Wants a `ponytail:` comment, or a `BTreeMap`/insertion-order deque. |
| `session.rs` `expire` | Backward-clock handling is correct but undocumented at the point of decision, so a future reader could "fix" it into an `unwrap()`. |
| `session.rs` `expire` | The eviction boundary is `< TXN_TIMEOUT`, so exactly 30s evicts while the doc says "quiet for longer than this". Wording nit. |

### Node runtime, from the whole-branch review

| Where | Gap |
|-------|-----|
| `node.rs` `Target::from_str` | A name with `@` but no `:` (`Server@Zone`) maps to the wildcard type `=`. Plausible NBP semantics, untested. |
| `node.rs` `Node::ping` | The pacing computes `Instant::now()` twice, so the gap between probes can drift slightly past 1s. `self.wait(sent + PING_INTERVAL, ...)` is shorter and drift-free. |
| `node.rs` `wait` | The `MAX_MESSAGES` trim is a pure operation that could be extracted and unit-tested against a plain `Vec`, the way `next_start` and `zone_reply_matches` were. |
| `node.rs` `zone_list` | Once `zone_reply_matches` passes, the drain still scans all of `messages` for any `ZipAtp::Reply` rather than the one derived from that packet, because `Message::Zip` carries no tid or source. Benign within a page; fixing it means changing `session.rs`. |
| `node.rs` | `LOOKUP_TRIES`/`LOOKUP_INTERVAL` carry no book citation, unlike their siblings — the book gives no exact count for NBP retries, which is worth saying in the comment. |
| `src/node.rs` | 1000+ lines, a third of it tests. Coherent for now. The seams if it grows: tests into their own file first, then address claim and defense apart from the query operations. |

### Test coverage

| Where | Gap |
|-------|-----|
| `wire/aarp.rs` | `aarp_encodes_known_bytes` is structurally a round-trip against a shared fixture rather than an independent byte literal. It catches pad-byte and field-order bugs only because the fixture's values happen to be asymmetric. |
| `wire/mod.rs` | `frame_rejects_foreign_snap_discriminators` covers OUI `00:00:00` with proto `809B` but not the mirror case, `08:00:07` with proto `80F3`. Correct by construction, unpinned by test. |
| `session.rs` | No test for the "socket is ZIS but the user bytes fail to parse" fallthrough in `Session::push`. Correct by inspection. |

## Repository

- `Cargo.toml` has no `description`, `repository`, or `keywords`, which is what
  crates.io and GitHub search key off.
- `CLAUDE.md` and `README.md` both name the test network specifically — the
  router, the zone, the net number. Fine, but it is real detail about a real
  LAN on a public repo.
