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

use std::collections::HashMap;
use std::time::{Duration, Instant};

use pnet::util::MacAddr;

use crate::node::{aarp_request, aarp_response, frame, probe, BROADCAST_MAC};
use crate::wire::{Addr, Encode, Frame, Llap, AARP, LLAP_ACK, LLAP_ENQ};

/// How long a node stays believed-in without being heard from. PDF 2-10 ages
/// AMT entries the same way — confirm on traffic, delete on expiry,
/// re-resolve on demand — so there is no refresh timer here, just expiry.
///
/// ponytail: fixed rather than adaptive. Make it a flag if a real network
/// wants otherwise.
// ponytail: only `expire` reads this, and nothing constructs a Bridge to
// call it until Task 8 wires the bridge in.
#[allow(dead_code)]
const ENTRY_TTL: Duration = Duration::from_secs(30);

/// How long a cross-side query waits for its answer. Matches how long a
/// requester on either side keeps retrying — `node.rs` probes 10 times at
/// 200ms — so a debt is never settled after the creditor gave up.
// ponytail: only `ask` and `expire` read this, and nothing constructs a
// Bridge to call them until Task 8 wires the bridge in.
#[allow(dead_code)]
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Which link a node lives on. `Ether` carries the MAC because that is what
/// makes the entry useful for sending; `Local` needs no address beyond the
/// node ID the map is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// ponytail: nothing constructs a Bridge until Task 8 wires the bridge in.
#[allow(dead_code)]
pub enum Side {
    Ether(MacAddr),
    Local,
}

#[allow(dead_code)]
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
// ponytail: nothing constructs a Bridge until Task 8 wires the bridge in.
#[allow(dead_code)]
enum Ask {
    Ether,
    Local,
}

/// What is owed to whom when a query is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// ponytail: nothing constructs a Bridge until Task 8 wires the bridge in.
#[allow(dead_code)]
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
// ponytail: nothing constructs a Bridge until Task 8 wires the bridge in.
#[allow(dead_code)]
struct Entry {
    side: Side,
    confirmed: Instant,
    /// Set when the node turned up on the other side, or when both sides
    /// claimed it. A doubted entry is not live: nothing is forwarded to it and
    /// no AARP is answered on its behalf.
    doubted: bool,
}

#[derive(Debug, Clone, Copy)]
// ponytail: nothing constructs a Bridge until Task 8 wires the bridge in.
#[allow(dead_code)]
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
// ponytail: nothing constructs a Bridge until Task 8 wires the bridge in.
#[allow(dead_code)]
pub enum Action {
    ToEther(Frame),
    ToLocal(Llap),
    /// Something an operator needs to know. Rare by construction.
    Report(String),
}

// ponytail: nothing constructs a Bridge until Task 8 wires the bridge in.
#[allow(dead_code)]
pub struct Bridge {
    addr: Addr,
    mac: MacAddr,
    /// Which side each node ID on our own net lives on.
    nodes: HashMap<u8, Entry>,
    /// Gleaned address-to-MAC for addresses on *other* networks — the router
    /// and everything beyond it. On-net MACs come from `nodes`.
    amt: HashMap<Addr, MacAddr>,
    pending: HashMap<u8, Pending>,
}

// ponytail: nothing calls into Bridge until Task 8 wires the bridge in.
#[allow(dead_code)]
impl Bridge {
    pub fn new(addr: Addr, mac: MacAddr, amt: HashMap<Addr, MacAddr>) -> Bridge {
        let now = Instant::now();
        // Everything already gleaned on our own net is an Ethernet resident:
        // it was heard over ELAP, which is proof enough to start with.
        let nodes = amt
            .iter()
            .filter(|(a, _)| a.net == addr.net && a.node != addr.node)
            .map(|(a, m)| (a.node, Entry { side: Side::Ether(*m), confirmed: now, doubted: false }))
            .collect();
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

    /// Puts a question to one link. `pending` doubles as the rate limit: a
    /// second query while one is in flight is suppressed.
    fn ask(
        &mut self,
        node: u8,
        link: Ask,
        owed: Owed,
        moved_to: Option<Side>,
        now: Instant,
    ) -> Vec<Action> {
        if self.pending.contains_key(&node) {
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
        }
    }

    /// Pays whatever was owed on `node` now that a side has answered.
    fn settle(&mut self, node: u8, answered: Side, _now: Instant) -> Vec<Action> {
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
                // Never proxy against evidence: if Ethernet answered for the
                // ID while the question was out, answering as the LocalTalk
                // node would hijack an Ethernet node's address.
                if matches!(self.live(node), Some(Side::Ether(_))) {
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
        let out = b.settle(12, Side::Ether(peer_mac()), t);
        assert_eq!(out, vec![Action::ToLocal(Llap::control(12, 12, LLAP_ACK))]);
    }

    #[test]
    fn localtalk_confirming_pays_an_ethernet_node_its_response() {
        let mut b = bridge();
        let t = t0();
        let asker = Addr { net: NET, node: 3 };
        b.ask(12, Ask::Local, Owed::EtherResponse { to: asker, to_mac: peer_mac() }, None, t);
        let out = b.settle(12, Side::Local, t);
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
        assert!(b.settle(12, Side::Local, t).is_empty());
    }

    #[test]
    fn a_debt_is_never_paid_after_the_creditor_gave_up() {
        let mut b = bridge();
        let t = t0();
        b.ask(12, Ask::Ether, Owed::LocalAck, None, t);
        b.expire(t + QUERY_TIMEOUT);
        assert!(b.settle(12, Side::Ether(peer_mac()), t + QUERY_TIMEOUT).is_empty());
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
        assert!(b.settle(12, Side::Local, t).is_empty());
    }
}
