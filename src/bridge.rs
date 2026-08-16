// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Repeats AppleTalk between the EtherTalk cable and a LocalTalk link, as one
//! network with one node-ID space.
//!
//! Not a router: no RTMP, no ZIP, no hop counting. The cable's real router
//! keeps that job, and its traffic reaches LocalTalk because the bridge
//! repeats it like anything else. `bridge.md` describes the behaviour.
//!
//! All decisions live in `Bridge::step`, which is pure — it takes what
//! arrived and the time, and returns what to send. `run` is the only part
//! that touches a socket.
//!
//! ponytail: broadcasts flood both ways. Two bridges between the same
//! Ethernet and the same group will storm on broadcast traffic — the
//! contradiction check only catches unicast reflections. One bridge per pair;
//! a real answer needs a spanning tree.
//!
//! ponytail: one network number. LocalTalk nodes live on our own net alone, so
//! a cable range spanning several nets bridges only into the first. Split this
//! into a half-router if that ever matters.
//!
//! ponytail: every AARP Request for an ID we do not know costs one lapENQ,
//! even when an Ethernet node is about to answer it itself. Hold the query
//! briefly and see if Ethernet answers first, if the group ever gets noisy.
//!
//! ponytail: an ENQ is answered a round trip late, never from cache, so a
//! LocalTalk node whose ENQ series is shorter than one AARP round trip could
//! take an ID that is in fact held on Ethernet. The contradiction check then
//! reports it, so it is loud rather than silent. Cache fresh entries if a real
//! emulator turns out to give up that fast.
//!
//! ponytail: a move is only noticed when the moved node transmits. One that
//! moves and stays silent waits out ENTRY_TTL. Nothing cheaper exists; the TTL
//! is the backstop.

use std::collections::HashMap;
use std::io;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use pnet::util::MacAddr;

use crate::capture::{Event, Tx};
use crate::ltoudp::Ltoudp;
use crate::node::{aarp_action, aarp_request, aarp_response, frame, mac_for, probe, AarpAction, BROADCAST_MAC};
use crate::wire::{
    Aarp, Addr, Body, Ddp, Encode, Frame, Llap, Packet, AARP, DDP, LLAP_ACK, LLAP_ENQ,
    LLAP_LONG_DDP, LLAP_SHORT_DDP,
};

/// How long a node stays believed-in without being heard from. PDF 87 ages
/// AMT entries the same way — confirm on traffic, delete on expiry,
/// re-resolve on demand — so there is no refresh timer here, just expiry.
///
/// ponytail: fixed rather than adaptive. Make it a flag if a real network
/// wants otherwise.
const ENTRY_TTL: Duration = Duration::from_secs(30);

/// How long a cross-side query waits for its answer. Matches how long a
/// requester on either side keeps retrying — `node.rs` probes 10 times at
/// 200ms — so a debt is never settled after the creditor gave up.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Which link a node lives on. `Ether` carries the MAC because that is what
/// makes the entry useful for sending; `Local` needs no address beyond the
/// node ID the map is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Ether(MacAddr),
    Local,
}

impl Side {
    /// Same link, whatever MAC. Two `Ether` values with different MACs are the
    /// same side — a node changing NIC has not crossed the bridge.
    fn same_as(self, other: Side) -> bool {
        matches!(
            (self, other),
            (Side::Ether(_), Side::Ether(_)) | (Side::Local, Side::Local)
        )
    }

    fn name(self) -> &'static str {
        match self {
            Side::Ether(_) => "Ethernet",
            Side::Local => "LocalTalk",
        }
    }

    fn link(self) -> Ask {
        match self {
            Side::Ether(_) => Ask::Ether,
            Side::Local => Ask::Local,
        }
    }
}

/// Which link to put a question to. Distinct from `Side` because a question
/// carries no MAC — that is exactly what it is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ask {
    Ether,
    Local,
    Both,
}

/// What is owed to whom when a query is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owed {
    /// A LocalTalk node is claiming this ID; ACK it if Ethernet holds it.
    LocalAck,
    /// An Ethernet node is asking after this ID; answer for it if LocalTalk
    /// holds it.
    EtherResponse { to: Addr, to_mac: MacAddr },
    /// Nobody is waiting; the answer only updates the table.
    Nothing,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    side: Side,
    confirmed: Instant,
    /// Set when the node turned up on the other side, or when both sides
    /// claimed it. A doubted entry is not live: nothing is forwarded to it and
    /// no AARP is answered on its behalf.
    doubted: bool,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    asked: Instant,
    owed: Owed,
    /// Set when this query exists to settle a contradiction. If it goes
    /// unanswered, the node moved to this side.
    moved_to: Option<Side>,
}

/// Something for `run` to do. Pure data, so the whole decision table can be
/// asserted on without a socket.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    ToEther(Frame),
    ToLocal(Llap),
    /// Something an operator needs to know. Rare by construction.
    Report(String),
}

/// What arrived, or a bare tick when nothing did.
pub enum In<'a> {
    Ether(&'a Packet),
    Local(&'a Llap),
    Tick,
}

pub struct Bridge {
    addr: Addr,
    mac: MacAddr,
    /// Which side each node ID on our own net lives on.
    nodes: HashMap<u8, Entry>,
    /// Gleaned address-to-MAC for addresses on *other* networks — the router
    /// and everything beyond it. On-net MACs come from `nodes`.
    ///
    /// ponytail: grows without bound — every off-net address ever heard stays
    /// forever, unlike `nodes` there is no TTL. Fine for one router's worth of
    /// traffic; age it out (and give `node::mac_for` a clock) if a busy
    /// network ever makes this map large.
    amt: HashMap<Addr, MacAddr>,
    pending: HashMap<u8, Pending>,
}

impl Bridge {
    pub fn new(addr: Addr, mac: MacAddr, amt: HashMap<Addr, MacAddr>) -> Bridge {
        let now = Instant::now();
        // Everything already gleaned on our own net is an Ethernet resident:
        // it was heard over ELAP, which is proof enough to start with. Node 0
        // and 255 are never real nodes (PDF 66), the same check `confirm`
        // makes at its own entry point into the table.
        let nodes = amt
            .iter()
            .filter(|(a, _)| a.net == addr.net && a.node != addr.node && a.node != 0 && a.node != 255)
            .map(|(a, m)| (a.node, Entry { side: Side::Ether(*m), confirmed: now, doubted: false }))
            .collect();
        // `amt` holds only off-net addresses; on-net MACs live in `nodes`.
        let amt = amt.into_iter().filter(|(a, _)| a.net != addr.net).collect();
        Bridge { addr, mac, nodes, amt, pending: HashMap::new() }
    }

    /// The side a node is known to be on, or None when we do not know, do not
    /// trust what we have, or it has aged out.
    fn live(&self, node: u8) -> Option<Side> {
        let e = self.nodes.get(&node)?;
        if e.doubted { None } else { Some(e.side) }
    }

    /// Records that `node` was heard from on `side`, and says what that means.
    fn confirm(&mut self, node: u8, side: Side, now: Instant) -> Vec<Action> {
        // Node 0 is not allowed and 255 is the broadcast ID (PDF 66); neither
        // is a node. Our own ID is ours and needs no entry.
        if node == 0 || node == 255 || node == self.addr.node {
            return Vec::new();
        }
        let Some(&Entry { side: believed, doubted, .. }) = self.nodes.get(&node) else {
            self.nodes.insert(node, Entry { side, confirmed: now, doubted: false });
            return Vec::new();
        };

        if !believed.same_as(side) {
            // Heard on the side we did not expect. A move and a reflection are
            // identical in the frame, so believe neither and ask the side we
            // believed; silence from it is the answer.
            if doubted {
                return Vec::new();
            }
            self.nodes.insert(node, Entry { side: believed, confirmed: now, doubted: true });
            // A contradiction needs its own move-check; let it displace a
            // query already in flight rather than being suppressed by it —
            // otherwise the node stays dark for ENTRY_TTL instead of the
            // much shorter QUERY_TIMEOUT.
            self.pending.remove(&node);
            return self.ask(node, believed.link(), Owed::Nothing, Some(side), now);
        }

        // The believed side spoke. If that answers an outstanding
        // move-check, both sides really do hold this ID.
        if matches!(self.pending.get(&node), Some(q) if q.moved_to.is_some()) {
            self.pending.remove(&node);
            return vec![Action::Report(format!(
                "node {node} answered on both sides — a duplicate ID, or a second bridge on this pair"
            ))];
        }
        // A contested entry is deliberately not refreshed: letting traffic
        // keep it alive would make a stale contest permanent. It ages out and
        // is learned again from scratch.
        if doubted {
            return Vec::new();
        }
        self.nodes.insert(node, Entry { side, confirmed: now, doubted: false });
        Vec::new()
    }

    /// Puts a question to one link, or both. `pending` doubles as the rate
    /// limit: a second query while one is in flight is suppressed.
    fn ask(
        &mut self,
        node: u8,
        link: Ask,
        owed: Owed,
        moved_to: Option<Side>,
        now: Instant,
    ) -> Vec<Action> {
        // Node 0 and 255 are never real nodes (PDF 66); a wire byte naming
        // one must not drive an AARP Request/Probe or an ENQ onto either
        // link. Same guard `confirm` makes at its own entry point.
        if node == 0 || node == 255 || self.pending.contains_key(&node) {
            return Vec::new();
        }
        self.pending.insert(node, Pending { asked: now, owed, moved_to });
        let target = Addr { net: self.addr.net, node };
        match link {
            Ask::Ether => {
                // A Probe when someone is claiming the ID, because a node
                // suppresses AARP answers while it is itself probing (PDF 86)
                // and a Request would draw silence from one mid-claim. A
                // Request otherwise, which claims nothing.
                let a = match owed {
                    Owed::LocalAck => probe(target, self.mac),
                    _ => aarp_request(self.addr, self.mac, target),
                };
                vec![Action::ToEther(frame(self.mac, BROADCAST_MAC, AARP, a.to_bytes()))]
            }
            // An ENQ we never act on is inert: only receipt of an ACK makes a
            // node give up an ID (PDF 65), so this asks without claiming.
            Ask::Local => vec![Action::ToLocal(Llap::control(node, node, LLAP_ENQ))],
            // A destination nobody has claimed: ask both links at once,
            // since either answer settles the question.
            Ask::Both => {
                let a = aarp_request(self.addr, self.mac, target);
                vec![
                    Action::ToEther(frame(self.mac, BROADCAST_MAC, AARP, a.to_bytes())),
                    Action::ToLocal(Llap::control(node, node, LLAP_ENQ)),
                ]
            }
        }
    }

    /// Pays whatever was owed on `node` now that a side has answered.
    fn settle(&mut self, node: u8, answered: Side) -> Vec<Action> {
        let Some(q) = self.pending.get(&node).copied() else {
            return Vec::new();
        };
        // A move-check is settled by `confirm`, which is the only place that
        // knows whether the answer contradicts the table.
        if q.moved_to.is_some() {
            return Vec::new();
        }
        match q.owed {
            Owed::LocalAck if matches!(answered, Side::Ether(_)) => {
                self.pending.remove(&node);
                // Ethernet holds it, so tell the claimant it is taken. Both
                // node bytes carry the ID, as an ACK always does.
                vec![Action::ToLocal(Llap::control(node, node, LLAP_ACK))]
            }
            Owed::EtherResponse { to, to_mac } if answered == Side::Local => {
                self.pending.remove(&node);
                // Never proxy against evidence. `live()` collapses "no entry
                // at all" and "entry doubted" into the same `None`, but they
                // must not be treated alike here: no entry means this answer
                // is the first word on the node, and is trusted; an entry
                // that exists and is doubted or confirmed elsewhere is
                // contested, and proxying over that gap would be exactly the
                // hijack this guards against.
                if self.nodes.contains_key(&node) && self.live(node) != Some(Side::Local) {
                    return Vec::new();
                }
                // Answer as the LocalTalk node, giving our own MAC — which is
                // exactly where its traffic should go.
                let src = Addr { net: self.addr.net, node };
                let a = aarp_response(src, self.mac, to, to_mac);
                vec![Action::ToEther(frame(self.mac, to_mac, AARP, a.to_bytes()))]
            }
            // Answered by the side that proves the opposite, or nothing owed.
            // Either way the table has already been updated by `confirm`.
            _ => Vec::new(),
        }
    }

    /// Drops entries nobody has confirmed lately and resolves queries nobody
    /// answered. An unanswered move-check *is* the answer: the node moved.
    fn expire(&mut self, now: Instant) -> Vec<Action> {
        self.nodes.retain(|_, e| now.duration_since(e.confirmed) < ENTRY_TTL);
        let done: Vec<u8> = self
            .pending
            .iter()
            .filter(|(_, q)| now.duration_since(q.asked) >= QUERY_TIMEOUT)
            .map(|(&n, _)| n)
            .collect();
        let mut out = Vec::new();
        for n in done {
            let Some(q) = self.pending.remove(&n) else { continue };
            if let Some(side) = q.moved_to {
                out.push(Action::Report(format!("node {n} moved to {}", side.name())));
                self.nodes.insert(n, Entry { side, confirmed: now, doubted: false });
            }
        }
        out
    }

    /// A destination nobody has claimed: ask both links at once, under one
    /// pending entry. Thin wrapper so `ask` stays the only owner of the
    /// pending insert, the rate limit, and the reserved-ID guard.
    fn ask_both(&mut self, node: u8, now: Instant) -> Vec<Action> {
        self.ask(node, Ask::Both, Owed::Nothing, None, now)
    }

    /// What arrived, or nothing at all. `Tick` exists so entries expire and
    /// unanswered questions resolve on a quiet link as well as a busy one.
    pub fn step(&mut self, input: In, now: Instant) -> Vec<Action> {
        let mut out = self.expire(now);
        match input {
            In::Tick => {}
            In::Ether(p) => out.extend(self.on_ether(p, now)),
            In::Local(l) => out.extend(self.on_local(l, now)),
        }
        out
    }

    // Named `on_ether`/`on_local`, not `from_ether`/`from_local` as the brief
    // spelled them: clippy's `wrong_self_convention` reads a `from_*` method
    // as a conversion constructor and flags one that takes `&mut self`.
    fn on_ether(&mut self, p: &Packet, now: Instant) -> Vec<Action> {
        // A promiscuous capture hears our own transmissions.
        if p.frame.src == self.mac {
            return Vec::new();
        }
        // Phase 1 has no length field to trim Ethernet's padding by
        // (wire::Frame's own ponytail note), so a DDP payload forwarded
        // verbatim would carry trailing pad bytes and disagree with its own
        // length field once parsed on the other side. We only ever transmit
        // Phase 2 (CLAUDE.md); drop rather than emit a malformed frame.
        if !p.frame.snap {
            return Vec::new();
        }
        match &p.body {
            Body::Aarp(a) => self.ether_aarp(p, a, now),
            Body::Ddp(d, _) => self.ether_ddp(p, d, now),
            Body::Unknown => Vec::new(),
        }
    }

    fn ether_aarp(&mut self, p: &Packet, a: &Aarp, now: Instant) -> Vec<Action> {
        // Defend our own address exactly as a node does.
        if let AarpAction::AnswerTo(to) = aarp_action(p, self.addr, self.mac, false) {
            let r = aarp_response(self.addr, self.mac, a.src, to);
            return vec![Action::ToEther(frame(self.mac, to, AARP, r.to_bytes()))];
        }
        // A Response proves where its sender is. A Probe proves nothing: its
        // source address is only tentative (PDF 87).
        if a.op == 2 {
            if a.src.net != self.addr.net {
                self.amt.insert(a.src, a.src_hw);
                return Vec::new();
            }
            let side = Side::Ether(a.src_hw);
            let mut out = self.confirm(a.src.node, side, now);
            out.extend(self.settle(a.src.node, side));
            return out;
        }
        // Requests and Probes, for an address on our own cable.
        if (a.op == 1 || a.op == 3) && a.dst.net == self.addr.net && a.dst.node != self.addr.node {
            let n = a.dst.node;
            let owed = Owed::EtherResponse { to: a.src, to_mac: a.src_hw };
            return match self.live(n) {
                // A resolve only routes traffic, and the data path re-verifies,
                // so the table is good enough to answer from.
                Some(Side::Local) if a.op == 1 => {
                    let src = Addr { net: self.addr.net, node: n };
                    let r = aarp_response(src, self.mac, a.src, a.src_hw);
                    vec![Action::ToEther(frame(self.mac, a.src_hw, AARP, r.to_bytes()))]
                }
                // A claim denies an address, so it is never answered from
                // memory: that is how a returning node gets locked out of its
                // own ID forever.
                Some(Side::Local) => self.ask(n, Ask::Local, owed, None, now),
                // Demonstrably on Ethernet: it will answer for itself.
                Some(Side::Ether(_)) => Vec::new(),
                None => self.ask(n, Ask::Local, owed, None, now),
            };
        }
        Vec::new()
    }

    fn ether_ddp(&mut self, p: &Packet, d: &Ddp, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        if d.src.net == self.addr.net {
            out.extend(self.confirm(d.src.node, Side::Ether(p.frame.src), now));
            // A datagram from a node we believed was on LocalTalk is either a
            // reflection or a node that moved. Repeat nothing until we know.
            if self.live(d.src.node).is_none() && self.nodes.contains_key(&d.src.node) {
                return out;
            }
        } else {
            // The router relaying for a distant network: a MAC we may need,
            // but not a node on this cable.
            self.amt.insert(d.src, p.frame.src);
        }

        // Ours, not something to repeat.
        if d.dst.net == self.addr.net && d.dst.node == self.addr.node {
            return out;
        }
        // Off-cable unicast is the router's business. A broadcast is not:
        // every node on the cable is meant to hear one.
        if d.dst.net != self.addr.net && d.dst.node != 255 {
            return out;
        }

        let cross = |out: &mut Vec<Action>| {
            // `Ddp::parse` deliberately does not check `d.length` against what
            // actually arrived (fail-closed parsers reject a short buffer, not
            // a dishonest length field), so a node on the cable can claim a
            // small length while its frame carries far more payload. Forwarding
            // that verbatim would emit an LToUDP datagram no conformant
            // receiver — including our own `inbound` — accepts: an LLAP data
            // field is legal only at 13..=600 bytes here, and only when it
            // agrees with DDP's own length field. Fail closed, same reasoning
            // as dropping Phase 1 above.
            let len = p.frame.payload.len();
            if !(13..=600).contains(&len) || d.length as usize != len {
                return;
            }
            out.push(Action::ToLocal(Llap {
                dst: d.dst.node,
                src: d.src.node,
                typ: LLAP_LONG_DDP,
                // Verbatim: re-encoding would put the hop count and any
                // checksum at risk for no gain.
                data: p.frame.payload.clone(),
            }));
        };

        if d.dst.node == 255 {
            cross(&mut out);
            return out;
        }
        match self.live(d.dst.node) {
            Some(Side::Local) => cross(&mut out),
            Some(Side::Ether(_)) => {}
            None if self.nodes.contains_key(&d.dst.node) => {} // doubted; hold off
            None => {
                // Forward optimistically — an answer cannot arrive before the
                // datagram it would have filtered — then find out for next time.
                cross(&mut out);
                let q = self.ask_both(d.dst.node, now);
                out.extend(q);
            }
        }
        out
    }

    fn on_local(&mut self, l: &Llap, now: Instant) -> Vec<Action> {
        match l.typ {
            LLAP_SHORT_DDP | LLAP_LONG_DDP => self.local_ddp(l, now),
            // Defend our own address exactly as the Ethernet side does (row
            // 2). This is not the cached-ENQ shortcut we refuse below: our
            // own ID is not a memory of some other node, it is authoritative.
            LLAP_ENQ if l.dst == self.addr.node => {
                vec![Action::ToLocal(Llap::control(l.dst, l.dst, LLAP_ACK))]
            }
            // Never answered from cache: an ACK denies an address, and a
            // memory of a node that has since left would deny it wrongly.
            LLAP_ENQ => self.ask(l.dst, Ask::Ether, Owed::LocalAck, None, now),
            LLAP_ACK => {
                let mut out = self.confirm(l.src, Side::Local, now);
                out.extend(self.settle(l.src, Side::Local));
                out
            }
            // RTS and CTS arbitrate a shared medium Ethernet does not have,
            // and any other data type belongs to another LLAP client.
            _ => Vec::new(),
        }
    }

    fn local_ddp(&mut self, l: &Llap, now: Instant) -> Vec<Action> {
        let mut out = self.confirm(l.src, Side::Local, now);
        // A frame from a node we believed was on Ethernet is either a
        // reflection or a node that moved. Repeat nothing until we know.
        if self.live(l.src).is_none() && self.nodes.contains_key(&l.src) {
            return out;
        }
        let (dst, bytes) = match l.typ {
            // LocalTalk omits the network numbers when both ends share a net;
            // the bridge's own net is what was being omitted (PDF 118).
            LLAP_SHORT_DDP => match Ddp::from_short(&l.data, self.addr.net, l.dst, l.src) {
                Some(d) => (d.dst, d.to_bytes()),
                None => return out,
            },
            // Already extended: pass the bytes through untouched.
            _ => match Ddp::parse(&l.data) {
                Some(d) => (d.dst, l.data.clone()),
                None => return out,
            },
        };
        let mac = if l.dst == 255 || dst.node == 255 {
            Some(BROADCAST_MAC)
        } else if dst.net == self.addr.net {
            match self.live(dst.node) {
                Some(Side::Ether(m)) => Some(m),
                // LToUDP is a shared bus: everyone on the group, including a
                // destination we believe is on LocalTalk, already received
                // this datagram directly. Repeating it onto Ethernet's
                // broadcast MAC would interrupt every real node on the cable
                // for traffic that was never theirs — mirrors the
                // `Some(Side::Ether(_)) => {}` guard in `ether_ddp`.
                Some(Side::Local) => None,
                // Unknown or doubted: broadcast and let the cable sort it out.
                None => Some(BROADCAST_MAC),
            }
        } else {
            // Off-cable: the router's MAC, if we have gleaned it.
            Some(mac_for(&self.amt, dst))
        };
        if let Some(mac) = mac {
            out.push(Action::ToEther(frame(self.mac, mac, DDP, bytes)));
        }
        out
    }
}

/// How often the loop wakes with nothing to do, so entries expire and
/// unanswered questions resolve on a quiet link too.
const TICK: Duration = Duration::from_millis(250);

/// Runs until the capture thread goes away.
///
/// A send failure is reported and the loop continues: one unsendable frame is
/// not a reason to take the whole bridge down, and on a link this old the
/// far end will retransmit.
pub fn run(
    mut tx: Tx,
    rx: Receiver<Event>,
    lt: Ltoudp,
    addr: Addr,
    amt: HashMap<Addr, MacAddr>,
) -> io::Result<()> {
    let mut b = Bridge::new(addr, tx.mac, amt);
    loop {
        // Sampled after the blocking receive, not before: taken any earlier,
        // `now` could be up to TICK stale by the time an event is actually
        // handled, and a query answer arriving right at its timeout would be
        // (wrongly) treated as late.
        let event = rx.recv_timeout(TICK);
        let now = Instant::now();
        let actions = match event {
            Ok(Event::Packet { packet, .. }) => b.step(In::Ether(&packet), now),
            Ok(Event::Ltoudp { llap, .. }) => b.step(In::Local(&llap), now),
            Ok(Event::Dropped(n)) => {
                eprintln!("dropped {n} frames (queue full)");
                b.step(In::Tick, now)
            }
            Ok(Event::Error(e)) => {
                eprintln!("rx: {e}");
                b.step(In::Tick, now)
            }
            Err(RecvTimeoutError::Timeout) => b.step(In::Tick, now),
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        };
        for a in actions {
            match a {
                Action::ToEther(f) => {
                    if let Err(e) = tx.send(&f) {
                        eprintln!("bridge: ethernet: {e}");
                    }
                }
                Action::ToLocal(l) => {
                    if let Err(e) = lt.send(&l) {
                        eprintln!("bridge: ltoudp: {e}");
                    }
                }
                Action::Report(m) => eprintln!("bridge: {m}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: u16 = 6800;
    fn us() -> Addr { Addr { net: NET, node: 7 } }
    fn our_mac() -> MacAddr { MacAddr::new(2, 0, 0, 0, 0, 1) }
    fn peer_mac() -> MacAddr { MacAddr::new(2, 0, 0, 0, 0, 42) }
    fn bridge() -> Bridge { Bridge::new(us(), our_mac(), HashMap::new()) }

    /// A time base the tests can move forward deliberately.
    fn t0() -> Instant { Instant::now() }

    #[test]
    fn seeds_the_table_from_what_the_node_already_gleaned() {
        let mut amt = HashMap::new();
        amt.insert(Addr { net: NET, node: 3 }, peer_mac());
        // An address on another network is the router relaying, not a node on
        // our cable, so it stays in the MAC table and out of the node table.
        amt.insert(Addr { net: 2905, node: 9 }, peer_mac());
        let b = Bridge::new(us(), our_mac(), amt);
        assert_eq!(b.live(3), Some(Side::Ether(peer_mac())));
        assert_eq!(b.live(9), None);
    }

    #[test]
    fn seeding_never_makes_an_entry_for_a_reserved_node() {
        let mut amt = HashMap::new();
        amt.insert(Addr { net: NET, node: 0 }, peer_mac());
        amt.insert(Addr { net: NET, node: 255 }, peer_mac());
        let b = Bridge::new(us(), our_mac(), amt);
        assert_eq!(b.live(0), None);
        assert_eq!(b.live(255), None);
    }

    #[test]
    fn a_first_sighting_is_believed() {
        let mut b = bridge();
        assert!(b.confirm(12, Side::Local, t0()).is_empty());
        assert_eq!(b.live(12), Some(Side::Local));
    }

    #[test]
    fn our_own_id_and_the_reserved_ones_are_never_entries() {
        let mut b = bridge();
        for n in [0, 255, us().node] {
            assert!(b.confirm(n, Side::Local, t0()).is_empty());
            assert_eq!(b.live(n), None, "node {n}");
        }
    }

    #[test]
    fn hearing_a_node_on_the_wrong_side_asks_the_side_we_believed() {
        let mut b = bridge();
        b.confirm(12, Side::Local, t0());
        // Now it turns up on Ethernet.
        let out = b.confirm(12, Side::Ether(peer_mac()), t0());
        // An ENQ goes to LocalTalk, asking whether it is still there.
        assert_eq!(out, vec![Action::ToLocal(Llap::control(12, 12, LLAP_ENQ))]);
        // And nothing is trusted about it meanwhile.
        assert_eq!(b.live(12), None);
    }

    #[test]
    fn silence_from_the_old_side_means_the_node_moved() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        b.confirm(12, Side::Ether(peer_mac()), t);
        // Nothing answers within the window.
        let out = b.expire(t + QUERY_TIMEOUT);
        assert_eq!(out, vec![Action::Report("node 12 moved to Ethernet".into())]);
        assert_eq!(b.live(12), Some(Side::Ether(peer_mac())));
    }

    #[test]
    fn the_move_works_in_the_other_direction_too() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Ether(peer_mac()), t);
        let out = b.confirm(12, Side::Local, t);
        // A Request, not a Probe: this is a resolve, nobody is claiming.
        match &out[..] {
            [Action::ToEther(f)] => {
                let a = crate::wire::Aarp::parse(&f.payload).unwrap();
                assert_eq!(a.op, 1);
                assert_eq!(a.dst, Addr { net: NET, node: 12 });
            }
            other => panic!("expected one AARP Request, got {other:?}"),
        }
        assert_eq!(b.expire(t + QUERY_TIMEOUT), vec![Action::Report("node 12 moved to LocalTalk".into())]);
        assert_eq!(b.live(12), Some(Side::Local));
    }

    #[test]
    fn an_answer_from_the_old_side_means_a_real_duplicate() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        b.confirm(12, Side::Ether(peer_mac()), t);
        // LocalTalk answers the move-check: both sides hold the ID.
        let out = b.confirm(12, Side::Local, t);
        assert_eq!(
            out,
            vec![Action::Report(
                "node 12 answered on both sides — a duplicate ID, or a second bridge on this pair"
                    .into()
            )]
        );
        // Nothing is trusted about a contested ID.
        assert_eq!(b.live(12), None);
    }

    #[test]
    fn a_contested_entry_ages_out_instead_of_being_refreshed() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        b.confirm(12, Side::Ether(peer_mac()), t);
        b.confirm(12, Side::Local, t);
        // Traffic keeps arriving, but a contest must not be kept alive by it.
        b.confirm(12, Side::Local, t + ENTRY_TTL / 2);
        b.expire(t + ENTRY_TTL);
        assert_eq!(b.live(12), None);
        // And the ID is learnable again from scratch.
        b.confirm(12, Side::Local, t + ENTRY_TTL);
        assert_eq!(b.live(12), Some(Side::Local));
    }

    #[test]
    fn an_entry_nobody_confirms_ages_out() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        b.expire(t + ENTRY_TTL - Duration::from_secs(1));
        assert_eq!(b.live(12), Some(Side::Local));
        b.expire(t + ENTRY_TTL);
        assert_eq!(b.live(12), None);
    }

    #[test]
    fn traffic_keeps_an_uncontested_entry_alive() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        b.confirm(12, Side::Local, t + ENTRY_TTL - Duration::from_secs(1));
        b.expire(t + ENTRY_TTL);
        assert_eq!(b.live(12), Some(Side::Local));
    }

    #[test]
    fn a_second_query_while_one_is_in_flight_is_suppressed() {
        let mut b = bridge();
        let t = t0();
        assert_eq!(b.ask(12, Ask::Local, Owed::Nothing, None, t).len(), 1);
        assert!(b.ask(12, Ask::Local, Owed::Nothing, None, t).is_empty());
        // Once it times out, asking again is allowed.
        b.expire(t + QUERY_TIMEOUT);
        assert_eq!(b.ask(12, Ask::Local, Owed::Nothing, None, t + QUERY_TIMEOUT).len(), 1);
    }

    #[test]
    fn asking_ethernet_on_behalf_of_a_claim_uses_a_probe() {
        let mut b = bridge();
        let out = b.ask(12, Ask::Ether, Owed::LocalAck, None, t0());
        match &out[..] {
            [Action::ToEther(f)] => {
                let a = crate::wire::Aarp::parse(&f.payload).unwrap();
                // Op 3. A Request would draw silence from a node mid-claim of
                // the same ID (PDF 86) and both would end up on it.
                assert_eq!(a.op, 3);
                assert_eq!(a.src, Addr { net: NET, node: 12 });
                assert_eq!(f.dst, BROADCAST_MAC);
            }
            other => panic!("expected one AARP Probe, got {other:?}"),
        }
    }

    #[test]
    fn ethernet_confirming_pays_a_localtalk_node_its_ack() {
        let mut b = bridge();
        let t = t0();
        b.ask(12, Ask::Ether, Owed::LocalAck, None, t);
        let out = b.settle(12, Side::Ether(peer_mac()));
        assert_eq!(out, vec![Action::ToLocal(Llap::control(12, 12, LLAP_ACK))]);
    }

    #[test]
    fn localtalk_confirming_pays_an_ethernet_node_its_response() {
        let mut b = bridge();
        let t = t0();
        let asker = Addr { net: NET, node: 3 };
        b.ask(12, Ask::Local, Owed::EtherResponse { to: asker, to_mac: peer_mac() }, None, t);
        let out = b.settle(12, Side::Local);
        match &out[..] {
            [Action::ToEther(f)] => {
                let a = crate::wire::Aarp::parse(&f.payload).unwrap();
                assert_eq!(a.op, 2);
                // We answer *as* the LocalTalk node, giving our own MAC.
                assert_eq!(a.src, Addr { net: NET, node: 12 });
                assert_eq!(a.src_hw, our_mac());
                assert_eq!(a.dst, asker);
            }
            other => panic!("expected one AARP Response, got {other:?}"),
        }
    }

    #[test]
    fn a_debt_is_never_paid_by_the_wrong_side() {
        let mut b = bridge();
        let t = t0();
        // Owed an ACK if *Ethernet* holds the ID; LocalTalk answering proves
        // the opposite and settles nothing.
        b.ask(12, Ask::Ether, Owed::LocalAck, None, t);
        assert!(b.settle(12, Side::Local).is_empty());
    }

    #[test]
    fn a_debt_is_never_paid_after_the_creditor_gave_up() {
        let mut b = bridge();
        let t = t0();
        b.ask(12, Ask::Ether, Owed::LocalAck, None, t);
        b.expire(t + QUERY_TIMEOUT);
        assert!(b.settle(12, Side::Ether(peer_mac())).is_empty());
    }

    #[test]
    fn a_proxy_response_is_never_sent_against_evidence() {
        let mut b = bridge();
        let t = t0();
        let asker = Addr { net: NET, node: 3 };
        b.ask(12, Ask::Local, Owed::EtherResponse { to: asker, to_mac: peer_mac() }, None, t);
        // Ethernet answers for the ID while the question is still out.
        b.confirm(12, Side::Ether(peer_mac()), t);
        // Answering as the LocalTalk node now would hijack an Ethernet node's
        // address, so the debt is cancelled rather than paid.
        assert!(b.settle(12, Side::Local).is_empty());
    }

    #[test]
    fn a_proxy_response_is_never_sent_for_a_doubted_entry() {
        let mut b = bridge();
        let t = t0();
        // Drive node 12 into the doubted state via a resolved duplicate
        // contest: LocalTalk first, Ethernet contradicts it, then LocalTalk
        // itself answers the move-check — both sides really hold the ID.
        b.confirm(12, Side::Local, t);
        b.confirm(12, Side::Ether(peer_mac()), t);
        b.confirm(12, Side::Local, t);
        assert_eq!(b.live(12), None);

        // Only now does Ethernet ask after the (still-doubted) ID.
        let asker = Addr { net: NET, node: 3 };
        b.ask(12, Ask::Local, Owed::EtherResponse { to: asker, to_mac: peer_mac() }, None, t);
        // LocalTalk answers, but a doubted entry is neither confirmed Ether
        // nor confirmed Local — it is `live() == None`, same as no entry at
        // all. The old guard (`live() != Some(Ether(_))`) let that gap
        // through and proxied anyway; the fix tells the two `None`s apart.
        assert!(b.settle(12, Side::Local).is_empty());
    }

    // `Body`, `Ddp`, `Packet` and `DDP` already arrive through `use super::*`
    // once Step 3 extends the module's imports; only `DdpBody` is new here.
    use crate::wire::DdpBody;

    /// An Ethernet frame carrying a DDP datagram, as it would arrive.
    fn ether_ddp(src_mac: MacAddr, src: Addr, dst: Addr, typ: u8) -> Packet {
        let d = Ddp {
            hops: 0,
            length: 17,
            checksum: 0,
            dst,
            dst_socket: 253,
            src,
            src_socket: 252,
            typ,
            data: vec![1, 2, 3, 4],
        };
        let payload = d.to_bytes();
        Packet {
            frame: Frame { dst: BROADCAST_MAC, src: src_mac, proto: DDP, snap: true, payload },
            body: Body::Ddp(d, DdpBody::Unknown),
        }
    }

    /// An Ethernet frame carrying AARP.
    fn ether_aarp(src_mac: MacAddr, op: u16, src: Addr, dst: Addr) -> Packet {
        let a = crate::wire::Aarp { op, src_hw: src_mac, src, dst_hw: MacAddr::zero(), dst };
        let payload = a.to_bytes();
        Packet {
            frame: Frame { dst: BROADCAST_MAC, src: src_mac, proto: AARP, snap: true, payload },
            body: Body::Aarp(a),
        }
    }

    /// An LLAP long-DDP frame, as it would arrive off the group.
    fn local_ddp(src: u8, dst: u8) -> Llap {
        let d = Ddp {
            hops: 0,
            length: 17,
            checksum: 0,
            dst: Addr { net: NET, node: dst },
            dst_socket: 253,
            src: Addr { net: NET, node: src },
            src_socket: 252,
            typ: 3,
            data: vec![1, 2, 3, 4],
        };
        Llap { dst, src, typ: LLAP_LONG_DDP, data: d.to_bytes() }
    }

    #[test]
    fn our_own_frames_are_never_repeated() {
        let mut b = bridge();
        let p = ether_ddp(our_mac(), Addr { net: NET, node: 3 }, Addr { net: NET, node: 12 }, 3);
        assert!(b.step(In::Ether(&p), t0()).is_empty());
    }

    #[test]
    fn an_ethernet_broadcast_reaches_localtalk_verbatim() {
        let mut b = bridge();
        let src = Addr { net: NET, node: 3 };
        let p = ether_ddp(peer_mac(), src, Addr { net: NET, node: 255 }, 3);
        let out = b.step(In::Ether(&p), t0());
        assert_eq!(
            out,
            vec![Action::ToLocal(Llap {
                dst: 255,
                src: 3,
                typ: LLAP_LONG_DDP,
                data: p.frame.payload.clone(),
            })]
        );
    }

    #[test]
    fn traffic_between_two_ethernet_nodes_stays_on_ethernet() {
        let mut b = bridge();
        let t = t0();
        // Both ends demonstrably on Ethernet.
        b.confirm(3, Side::Ether(peer_mac()), t);
        b.confirm(12, Side::Ether(peer_mac()), t);
        let p = ether_ddp(peer_mac(), Addr { net: NET, node: 3 }, Addr { net: NET, node: 12 }, 3);
        assert!(b.step(In::Ether(&p), t).is_empty());
    }

    #[test]
    fn traffic_for_a_localtalk_node_crosses() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        let p = ether_ddp(peer_mac(), Addr { net: NET, node: 3 }, Addr { net: NET, node: 12 }, 3);
        let out = b.step(In::Ether(&p), t);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Action::ToLocal(l) if l.dst == 12 && l.typ == LLAP_LONG_DDP));
    }

    #[test]
    fn a_payload_that_disagrees_with_its_own_ddp_length_is_dropped_not_crossed() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        // The DDP header still says length 17 (13 + 4 data bytes), but the
        // Ethernet frame actually carries far more — the length field cannot
        // be trusted (`Ddp::parse` never checks it), so this must not reach
        // LToUDP as an oversized, malformed datagram.
        let mut p = ether_ddp(peer_mac(), Addr { net: NET, node: 3 }, Addr { net: NET, node: 12 }, 3);
        p.frame.payload.resize(601, 0);
        assert!(b.step(In::Ether(&p), t).is_empty());
    }

    #[test]
    fn a_payload_within_bounds_but_shorter_than_its_own_length_field_is_dropped() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        // Still a legal LLAP data-field size (13..=600), but the bytes present
        // do not match what the DDP header claims — equally untrustworthy.
        let mut p = ether_ddp(peer_mac(), Addr { net: NET, node: 3 }, Addr { net: NET, node: 12 }, 3);
        p.frame.payload.truncate(15);
        assert!(b.step(In::Ether(&p), t).is_empty());
    }

    #[test]
    fn an_unknown_destination_is_forwarded_and_asked_about() {
        let mut b = bridge();
        let p = ether_ddp(peer_mac(), Addr { net: NET, node: 3 }, Addr { net: NET, node: 12 }, 3);
        let out = b.step(In::Ether(&p), t0());
        // Forwarded optimistically — the answer cannot arrive before the datagram
        // it would have filtered — then both links are asked.
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], Action::ToLocal(_)));
        assert!(matches!(out[1], Action::ToEther(_)));
        assert!(matches!(out[2], Action::ToLocal(_)));
    }

    #[test]
    fn datagrams_addressed_to_the_bridge_are_not_repeated() {
        let mut b = bridge();
        let p = ether_ddp(peer_mac(), Addr { net: NET, node: 3 }, us(), 3);
        let out = b.step(In::Ether(&p), t0());
        assert!(out.iter().all(|a| !matches!(a, Action::ToLocal(_))));
    }

    #[test]
    fn a_localtalk_long_ddp_crosses_byte_for_byte() {
        let mut b = bridge();
        let t = t0();
        b.confirm(3, Side::Ether(peer_mac()), t);
        let l = local_ddp(12, 3);
        let out = b.step(In::Local(&l), t);
        match &out[..] {
            [Action::ToEther(f)] => {
                // Verbatim: a re-encode would risk the hop count and any checksum.
                assert_eq!(f.payload, l.data);
                assert_eq!(f.dst, peer_mac());
                assert_eq!(f.src, our_mac());
                assert_eq!(f.proto, DDP);
            }
            other => panic!("expected one Ethernet frame, got {other:?}"),
        }
    }

    #[test]
    fn a_localtalk_short_ddp_is_lifted_to_the_extended_form() {
        let mut b = bridge();
        let t = t0();
        // Short header: length 9, sockets 253/252, DDP type 3, 4 bytes of data.
        let l = Llap {
            dst: 3,
            src: 12,
            typ: LLAP_SHORT_DDP,
            data: vec![0x00, 0x09, 253, 252, 3, 0xde, 0xad, 0xbe, 0xef],
        };
        b.confirm(3, Side::Ether(peer_mac()), t);
        let out = b.step(In::Local(&l), t);
        match &out[..] {
            [Action::ToEther(f)] => {
                let d = Ddp::parse(&f.payload).unwrap();
                // The net comes from the cable the bridge sits on; the nodes from
                // the LLAP header.
                assert_eq!(d.src, Addr { net: NET, node: 12 });
                assert_eq!(d.dst, Addr { net: NET, node: 3 });
                assert_eq!(d.data, [0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("expected one Ethernet frame, got {other:?}"),
        }
    }

    #[test]
    fn a_localtalk_broadcast_goes_to_the_appletalk_multicast() {
        let mut b = bridge();
        let l = local_ddp(12, 255);
        match &b.step(In::Local(&l), t0())[..] {
            [Action::ToEther(f)] => assert_eq!(f.dst, BROADCAST_MAC),
            other => panic!("expected one Ethernet frame, got {other:?}"),
        }
    }

    #[test]
    fn localtalk_to_localtalk_unicast_is_never_repeated_onto_ethernet() {
        let mut b = bridge();
        let t = t0();
        // Both ends already live on LocalTalk — the shared bus already
        // delivered this to node 3 directly, so nothing should cross.
        b.confirm(3, Side::Local, t);
        let l = local_ddp(12, 3);
        assert!(b.step(In::Local(&l), t).is_empty());
    }

    #[test]
    fn an_enq_is_probed_for_rather_than_answered_from_memory() {
        let mut b = bridge();
        let t = t0();
        // Even with the ID sitting in the table as an Ethernet resident.
        b.confirm(12, Side::Ether(peer_mac()), t);
        let out = b.step(In::Local(&Llap::control(12, 12, LLAP_ENQ)), t);
        match &out[..] {
            [Action::ToEther(f)] => {
                assert_eq!(crate::wire::Aarp::parse(&f.payload).unwrap().op, 3);
            }
            other => panic!("expected one AARP Probe, got {other:?}"),
        }
        // And the ACK only follows once Ethernet actually answers.
        let resp = ether_aarp(peer_mac(), 2, Addr { net: NET, node: 12 }, us());
        let out = b.step(In::Ether(&resp), t);
        assert!(out.contains(&Action::ToLocal(Llap::control(12, 12, LLAP_ACK))));
    }

    #[test]
    fn a_request_for_a_localtalk_node_is_proxied_from_cache() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        let asker = Addr { net: NET, node: 3 };
        let req = ether_aarp(peer_mac(), 1, asker, Addr { net: NET, node: 12 });
        match &b.step(In::Ether(&req), t)[..] {
            [Action::ToEther(f)] => {
                let a = crate::wire::Aarp::parse(&f.payload).unwrap();
                assert_eq!(a.op, 2);
                assert_eq!(a.src, Addr { net: NET, node: 12 });
                assert_eq!(a.src_hw, our_mac());
            }
            other => panic!("expected one AARP Response, got {other:?}"),
        }
    }

    #[test]
    fn a_probe_for_a_localtalk_node_is_re_verified_first() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        let probe_pkt = ether_aarp(peer_mac(), 3, Addr { net: NET, node: 12 }, Addr { net: NET, node: 12 });
        // No Response yet: a claim is never answered from memory, or a returning
        // node would be locked out of its own ID forever.
        let out = b.step(In::Ether(&probe_pkt), t);
        assert_eq!(out, vec![Action::ToLocal(Llap::control(12, 12, LLAP_ENQ))]);
        // The ACK from LocalTalk proves it is still there, and only then do we
        // answer the prober.
        let out = b.step(In::Local(&Llap::control(12, 12, LLAP_ACK)), t);
        match &out[..] {
            [Action::ToEther(f)] => assert_eq!(crate::wire::Aarp::parse(&f.payload).unwrap().op, 2),
            other => panic!("expected one AARP Response, got {other:?}"),
        }
    }

    #[test]
    fn we_still_defend_our_own_address() {
        let mut b = bridge();
        let p = ether_aarp(peer_mac(), 3, us(), us());
        match &b.step(In::Ether(&p), t0())[..] {
            [Action::ToEther(f)] => {
                let a = crate::wire::Aarp::parse(&f.payload).unwrap();
                assert_eq!(a.op, 2);
                assert_eq!(a.src, us());
            }
            other => panic!("expected one AARP Response, got {other:?}"),
        }
    }

    #[test]
    fn a_node_heard_on_the_wrong_side_is_dropped_until_re_verified() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        // 12 turns up sourcing traffic on Ethernet.
        let p = ether_ddp(peer_mac(), Addr { net: NET, node: 12 }, Addr { net: NET, node: 3 }, 3);
        let out = b.step(In::Ether(&p), t);
        // The frame is not repeated; only the question goes out.
        assert_eq!(out, vec![Action::ToLocal(Llap::control(12, 12, LLAP_ENQ))]);
    }

    #[test]
    fn a_moved_node_resumes_forwarding_once_the_old_side_stays_quiet() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        let p = ether_ddp(peer_mac(), Addr { net: NET, node: 12 }, Addr { net: NET, node: 3 }, 3);
        b.step(In::Ether(&p), t);
        let out = b.step(In::Tick, t + QUERY_TIMEOUT);
        assert_eq!(out, vec![Action::Report("node 12 moved to Ethernet".into())]);
        // And traffic *to* it now stays on Ethernet rather than crossing.
        let to12 = ether_ddp(peer_mac(), Addr { net: NET, node: 3 }, Addr { net: NET, node: 12 }, 3);
        assert!(b.step(In::Ether(&to12), t + QUERY_TIMEOUT).is_empty());
    }

    #[test]
    fn a_doubted_node_is_not_proxied_for() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        let p = ether_ddp(peer_mac(), Addr { net: NET, node: 12 }, Addr { net: NET, node: 3 }, 3);
        b.step(In::Ether(&p), t);
        // While in doubt we answer no AARP on its behalf: a returning node must be
        // able to claim its own ID.
        let req = ether_aarp(peer_mac(), 1, Addr { net: NET, node: 3 }, Addr { net: NET, node: 12 });
        let out = b.step(In::Ether(&req), t);
        assert!(!out.iter().any(|a| matches!(a, Action::ToEther(_))));
    }

    #[test]
    fn control_frames_never_cross_to_ethernet() {
        let mut b = bridge();
        for typ in [0x84u8, 0x85] {
            assert!(b.step(In::Local(&Llap::control(1, 2, typ)), t0()).is_empty());
        }
    }

    #[test]
    fn another_llap_client_is_not_our_business() {
        let mut b = bridge();
        // Type $10 is a data packet for some other client entirely.
        let l = Llap { dst: 3, src: 12, typ: 0x10, data: vec![0x00, 0x02] };
        assert!(b.step(In::Local(&l), t0()).is_empty());
    }

    #[test]
    fn an_unknown_destination_is_asked_about_on_both_links_at_once() {
        let mut b = bridge();
        let out = b.ask_both(12, t0());
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], Action::ToEther(_)));
        assert_eq!(out[1], Action::ToLocal(Llap::control(12, 12, LLAP_ENQ)));
    }

    #[test]
    fn off_net_unicast_is_the_routers_business_not_ours() {
        let mut b = bridge();
        let t = t0();
        b.confirm(12, Side::Local, t);
        // Addressed to a node on the far side of the router.
        let p = ether_ddp(peer_mac(), Addr { net: NET, node: 3 }, Addr { net: 2905, node: 9 }, 3);
        assert!(b.step(In::Ether(&p), t).is_empty());
    }

    #[test]
    fn we_still_defend_our_own_address_on_localtalk() {
        let mut b = bridge();
        let n = us().node;
        let out = b.step(In::Local(&Llap::control(n, n, LLAP_ENQ)), t0());
        // Authoritative, not the cached-ENQ shortcut: it is our own address.
        assert_eq!(out, vec![Action::ToLocal(Llap::control(n, n, LLAP_ACK))]);
    }

    #[test]
    fn an_off_cable_broadcast_still_crosses_to_localtalk() {
        let mut b = bridge();
        // Off-cable, but node 255: the router-relayed broadcast every node on
        // the cable is meant to hear, not the off-cable unicast that guard
        // also has to reject.
        let p = ether_ddp(peer_mac(), Addr { net: 2905, node: 9 }, Addr { net: 2905, node: 255 }, 3);
        let out = b.step(In::Ether(&p), t0());
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], Action::ToLocal(l) if l.dst == 255 && l.typ == LLAP_LONG_DDP));
    }

    #[test]
    fn a_malformed_short_header_is_dropped() {
        let mut b = bridge();
        // Length field says 9; only 7 bytes actually follow.
        let l = Llap {
            dst: 3,
            src: 12,
            typ: LLAP_SHORT_DDP,
            data: vec![0x00, 0x09, 253, 252, 3, 0xde, 0xad],
        };
        assert!(b.step(In::Local(&l), t0()).is_empty());
    }
}
