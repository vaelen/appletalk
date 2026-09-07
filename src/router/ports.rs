// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! A router port: one physical link, its network range, its zones, and the
//! address mapping the link needs.
//!
//! A port owns its own address: it claims one at start-up, defends it for the
//! life of the process, and refuses to carry anything until it holds one
//! (spec, "Bring-up"). Everything else here is framing — the same datagram
//! looks different on Ethernet, on LToUDP and on a TashTalk UART, and the
//! router upstream should not have to know which.
//!
//! stub: Task 11 is the first caller.
#![allow(dead_code)]

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use pnet::util::MacAddr;

use crate::capture::PortId;
use crate::node::{
    self, aarp_action, aarp_response, glean, mac_for, probe, AarpAction, BROADCAST_MAC,
};
use crate::router::{Action, Dest};
use crate::wire::{
    zone_multicast, Addr, Body, Ddp, Encode, Llap, Packet, AARP, DDP, LLAP_ACK, LLAP_ENQ,
    LLAP_LONG_DDP, LLAP_SHORT_DDP,
};

/// AARP probes, and the gap between them (PDF 85). The same numbers `node.rs`
/// uses; its own copies are private to the node runtime.
pub const PROBE_TRIES: u32 = 10;
pub const PROBE_INTERVAL: Duration = Duration::from_millis(200);
/// lapENQs, and the gap between them (PDF 71).
pub const ENQ_TRIES: u32 = 8;
pub const ENQ_INTERVAL: Duration = Duration::from_millis(250);

/// What sort of link this is — which decides the framing, the node-ID range
/// and who answers an ENQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ether { mac: MacAddr },
    Ltoudp,
    Tashtalk,
}

/// The claim in progress. Once `Port::node` is `Some` this is history.
#[derive(Debug)]
struct Claim {
    node: u8,
    /// Probes or ENQs sent so far in this round.
    tries: u32,
    /// When the next one is due.
    next: Instant,
    /// Which candidate this is, so a restart seeds differently.
    attempt: u32,
}

pub struct Port {
    pub id: PortId,
    /// "eth0", "ltoudp", "/dev/ttyAMA0" — whatever the config called it.
    pub name: String,
    pub kind: Kind,
    pub range: (u16, u16),
    /// `zones[0]` is the port's default zone.
    pub zones: Vec<String>,
    /// The claimed node ID; `None` while claiming.
    pub node: Option<u8>,
    /// Address-to-MAC mappings gleaned from the cable. Ethernet only —
    /// LocalTalk's node ID *is* its hardware address.
    pub amt: HashMap<Addr, MacAddr>,
    claim: Claim,
}

/// What a port made of an incoming frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Inbound {
    /// A datagram for the router to route or deliver, already lifted to the
    /// extended header.
    Ddp(Ddp),
    /// Consumed by the port (AARP, ENQ/ACK, claim traffic).
    Handled,
    Ignore,
}

impl Port {
    pub fn new(
        id: PortId,
        name: String,
        kind: Kind,
        range: (u16, u16),
        zones: Vec<String>,
        now: Instant,
    ) -> Port {
        let node = candidate(kind, seed(id, kind, now, 0));
        Port {
            id,
            name,
            kind,
            range,
            zones,
            node: None,
            amt: HashMap::new(),
            claim: Claim { node, tries: 0, next: now, attempt: 0 },
        }
    }

    /// Only EtherTalk carries the extended DDP header, so only an EtherTalk
    /// port may span a range of networks.
    pub fn extended(&self) -> bool {
        matches!(self.kind, Kind::Ether { .. })
    }

    /// Our own address on this link, once we hold one. A port's own node
    /// always sits on the first network of its range.
    pub fn addr(&self) -> Option<Addr> {
        self.node.map(|node| Addr { net: self.range.0, node })
    }

    pub fn default_zone(&self) -> &str {
        self.zones.first().map(String::as_str).unwrap_or("")
    }

    pub fn has_zone(&self, z: &str) -> bool {
        self.zones.iter().any(|ours| ours.eq_ignore_ascii_case(z))
    }

    /// Drives the claim: a probe or ENQ per interval, then the address, once
    /// a whole interval has passed after the last one in silence. Call on
    /// every tick; it does nothing once the port is claimed.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        if self.node.is_some() || now < self.claim.next {
            return Vec::new();
        }
        let (tries, interval) = self.schedule();
        if self.claim.tries >= tries {
            return self.claimed();
        }
        self.claim.tries += 1;
        self.claim.next = now + interval;
        let node = self.claim.node;
        match self.kind {
            Kind::Ether { mac } => {
                let a = probe(Addr { net: self.range.0, node }, mac);
                vec![Action::ToEther {
                    port: self.id,
                    frame: node::frame(mac, BROADCAST_MAC, AARP, a.to_bytes()),
                }]
            }
            // ENQ and ACK both carry the ID under discussion in both node
            // bytes (PDF 71).
            _ => vec![Action::ToLlap {
                port: self.id,
                llap: Llap::control(node, node, LLAP_ENQ),
            }],
        }
    }

    /// Ethernet input: glean, defend, and pass datagrams up.
    pub fn inbound_ether(&mut self, p: &Packet, now: Instant) -> (Inbound, Vec<Action>) {
        let Kind::Ether { mac } = self.kind else { return (Inbound::Ignore, Vec::new()) };
        glean(&mut self.amt, p);
        match &p.body {
            Body::Aarp(a) => {
                let probing = self.node.is_none();
                let ours = Addr { net: self.range.0, node: self.claiming_node() };
                let out = match aarp_action(p, ours, mac, probing) {
                    // While probing, both sides give way (PDF 86). Once
                    // claimed a conflict means someone took the address from
                    // under us, which `aarp_action` only reports for a
                    // Response naming it — there is nothing to do but say so.
                    AarpAction::Conflict if probing => {
                        self.restart(now);
                        Vec::new()
                    }
                    AarpAction::Conflict => {
                        vec![Action::Log(format!("port {}: {ours} claimed by {}", self.name, a.src_hw))]
                    }
                    AarpAction::AnswerTo(to) => {
                        let r = aarp_response(ours, mac, a.src, to);
                        vec![Action::ToEther {
                            port: self.id,
                            frame: node::frame(mac, to, AARP, r.to_bytes()),
                        }]
                    }
                    AarpAction::Ignore => Vec::new(),
                };
                (Inbound::Handled, out)
            }
            // Our own frame heard back off the cable.
            Body::Ddp(..) if p.frame.src == mac => (Inbound::Ignore, Vec::new()),
            // Both header forms reach Ethernet as extended, so there is
            // nothing to lift.
            Body::Ddp(d, _) => (Inbound::Ddp(d.clone()), Vec::new()),
            Body::Unknown => (Inbound::Ignore, Vec::new()),
        }
    }

    /// LocalTalk input: answer ENQs for our own ID, watch for a conflict
    /// while claiming, and lift short headers onto this port's network.
    pub fn inbound_llap(&mut self, l: &Llap, now: Instant) -> (Inbound, Vec<Action>) {
        let ours = self.claiming_node();
        // Someone else holds, or is also claiming, the ID we are asking for.
        if self.node.is_none() && matches!(l.typ, LLAP_ENQ | LLAP_ACK) && l.dst == ours {
            self.restart(now);
            return (Inbound::Handled, Vec::new());
        }
        // An ENQ names the ID under discussion in *both* node bytes, so this
        // has to come before the own-frame filter below: an ENQ for our own
        // address arrives looking like one of ours.
        match l.typ {
            LLAP_ENQ if self.node == Some(l.dst) => match self.kind {
                // TashTalk's firmware answers every ID in its node bitmap; a
                // second ACK from us would be a duplicate on the wire.
                Kind::Tashtalk => (Inbound::Handled, Vec::new()),
                _ => (
                    Inbound::Handled,
                    vec![Action::ToLlap {
                        port: self.id,
                        llap: Llap::control(l.dst, l.dst, LLAP_ACK),
                    }],
                ),
            },
            // Another node's ID is not ours to deny.
            LLAP_ENQ => (Inbound::Handled, Vec::new()),
            // Our own frame heard back: LToUDP filters its own datagrams by
            // sender ID, but TashTalk echoes what its firmware answered on
            // our behalf, and a data frame can be reflected too.
            _ if l.src == ours && self.node.is_some() => (Inbound::Ignore, Vec::new()),
            // An ACK for someone else settles someone else's claim.
            LLAP_ACK => (Inbound::Handled, Vec::new()),
            // A short header omits what LLAP already said: the node IDs, and
            // the single network both ends share (PDF 118).
            LLAP_SHORT_DDP => match Ddp::from_short(&l.data, self.range.0, l.dst, l.src) {
                Some(d) => (Inbound::Ddp(d), Vec::new()),
                None => (Inbound::Ignore, Vec::new()),
            },
            LLAP_LONG_DDP => match Ddp::parse(&l.data) {
                Some(d) => (Inbound::Ddp(d), Vec::new()),
                None => (Inbound::Ignore, Vec::new()),
            },
            _ => (Inbound::Ignore, Vec::new()),
        }
    }

    /// Frames a datagram for this link. `None` until the port holds a node:
    /// a port with no address has no legal source to send from.
    pub fn emit(&self, dest: &Dest, ddp: &Ddp) -> Option<Action> {
        let node = self.node?;
        match self.kind {
            Kind::Ether { mac } => {
                let dst = match dest {
                    // ponytail: the AMT is keyed by full address, and a
                    // `Dest::Node` names only the node — so a next hop on
                    // another network of our range misses and broadcasts,
                    // which still delivers. Key the map by node ID per port
                    // if the extra broadcasts ever matter.
                    Dest::Node(n) => mac_for(&self.amt, Addr { net: ddp.dst.net, node: *n }),
                    Dest::Broadcast => BROADCAST_MAC,
                    Dest::Zone(z) => zone_multicast(z),
                };
                Some(Action::ToEther {
                    port: self.id,
                    frame: node::frame(mac, dst, DDP, ddp.to_bytes()),
                })
            }
            // LocalTalk has one multicast and it is the broadcast node ID, so
            // a zone-directed datagram goes to the whole cable.
            _ => {
                let dst = match dest {
                    Dest::Node(n) => *n,
                    Dest::Broadcast | Dest::Zone(_) => 255,
                };
                // The short header is only legal when both ends are on the
                // one network it leaves unsaid. Net 0 means "this cable".
                let short = ddp.src.net == self.range.0
                    && (ddp.dst.net == self.range.0 || ddp.dst.net == 0);
                let (typ, data) = match short {
                    true => (LLAP_SHORT_DDP, ddp.to_short_bytes()),
                    false => (LLAP_LONG_DDP, ddp.to_bytes()),
                };
                Some(Action::ToLlap { port: self.id, llap: Llap { dst, src: node, typ, data } })
            }
        }
    }

    /// The node ID we hold, or the one we are asking for.
    fn claiming_node(&self) -> u8 {
        self.node.unwrap_or(self.claim.node)
    }

    fn schedule(&self) -> (u32, Duration) {
        match self.kind {
            Kind::Ether { .. } => (PROBE_TRIES, PROBE_INTERVAL),
            _ => (ENQ_TRIES, ENQ_INTERVAL),
        }
    }

    fn claimed(&mut self) -> Vec<Action> {
        let node = self.claim.node;
        self.node = Some(node);
        let addr = Addr { net: self.range.0, node };
        let mut out = vec![Action::Log(format!("port {}: claimed {addr}", self.name))];
        // TashTalk answers ENQ and RTS for every ID in its node bitmap, so
        // the claim is the moment to put ours in it — and not before.
        if matches!(self.kind, Kind::Tashtalk) {
            out.push(Action::SetNode { port: self.id, node: Some(node) });
        }
        out
    }

    /// The address is taken: pick another and start the round over.
    fn restart(&mut self, now: Instant) {
        let attempt = self.claim.attempt + 1;
        let mut node = candidate(self.kind, seed(self.id, self.kind, now, attempt));
        if node == self.claim.node {
            node = next_node(self.kind, node);
        }
        self.claim = Claim { node, tries: 0, next: now, attempt };
    }
}

/// The node IDs a port may claim: EtherTalk 1–253 (254 and 255 are reserved),
/// LocalTalk 128–254, the server range (PDF 68).
fn id_range(kind: Kind) -> (u8, u64) {
    match kind {
        Kind::Ether { .. } => (1, 253),
        _ => (128, 127),
    }
}

fn candidate(kind: Kind, seed: u64) -> u8 {
    let (lo, span) = id_range(kind);
    lo + (seed % span) as u8
}

/// The next ID up, wrapping — used only to guarantee a restart moves off the
/// address that was just refused.
fn next_node(kind: Kind, node: u8) -> u8 {
    let (lo, span) = id_range(kind);
    lo + ((u64::from(node - lo) + 1) % span) as u8
}

/// ponytail: the seed is the monotonic clock mixed with the port and its MAC
/// rather than a real RNG — the same trade as `node::pick_address`. A
/// collision costs one more probe round, which is what the probes are for.
fn seed(id: PortId, kind: Kind, now: Instant, attempt: u32) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    now.hash(&mut h);
    id.hash(&mut h);
    attempt.hash(&mut h);
    if let Kind::Ether { mac } = kind {
        mac.octets().hash(&mut h);
    }
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Aarp, DdpBody, Frame, DDP};

    const OURS: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 1);
    const THEIRS: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 2);
    const NET: u16 = 6800;
    const ZONE: &str = "68k Mac Club";

    fn port(kind: Kind, now: Instant) -> Port {
        let name = match kind {
            Kind::Ether { .. } => "eth0",
            Kind::Ltoudp => "ltoudp",
            Kind::Tashtalk => "/dev/ttyAMA0",
        };
        Port::new(1, name.to_string(), kind, (NET, NET), vec![ZONE.to_string()], now)
    }

    /// The AARP packet inside a `ToEther` action, or a panic naming what came
    /// out instead.
    fn aarp(a: &Action) -> Aarp {
        match a {
            Action::ToEther { frame, .. } => Aarp::parse(&frame.payload).expect("AARP"),
            other => panic!("expected an Ethernet frame, got {other:?}"),
        }
    }

    fn llap(a: &Action) -> &Llap {
        match a {
            Action::ToLlap { llap, .. } => llap,
            other => panic!("expected an LLAP frame, got {other:?}"),
        }
    }

    /// The node the port is currently probing for, read off its own probe.
    fn candidate(p: &mut Port, now: Instant) -> u8 {
        match p.kind {
            Kind::Ether { .. } => aarp(&p.tick(now)[0]).src.node,
            _ => llap(&p.tick(now)[0]).dst,
        }
    }

    fn ether_packet(body: Body, src: MacAddr) -> Packet {
        let proto = if matches!(body, Body::Aarp(_)) { AARP } else { DDP };
        let payload = match &body {
            Body::Aarp(a) => a.to_bytes(),
            Body::Ddp(d, _) => d.to_bytes(),
            Body::Unknown => Vec::new(),
        };
        Packet { frame: Frame { dst: BROADCAST_MAC, src, proto, snap: true, payload }, body }
    }

    fn ddp(src: Addr, dst: Addr) -> Ddp {
        crate::node::datagram(src, 128, dst, 129, 4, vec![1, 2, 3, 4])
    }

    #[test]
    fn ether_claim_completes_after_ten_quiet_probes_and_logs_once() {
        let t = Instant::now();
        let mut p = port(Kind::Ether { mac: OURS }, t);
        let node = candidate(&mut p, t);
        // The first tick already sent probe 1; nine more finish the round.
        for i in 1..PROBE_TRIES {
            let out = p.tick(t + PROBE_INTERVAL * i);
            assert_eq!(out.len(), 1, "probe {i}");
            let a = aarp(&out[0]);
            assert_eq!((a.op, a.src, a.src_hw), (3, Addr { net: NET, node }, OURS));
            assert!(p.node.is_none(), "claimed before the last probe was answered for");
        }
        // The interval after the tenth probe passes in silence: claimed.
        let out = p.tick(t + PROBE_INTERVAL * PROBE_TRIES);
        assert_eq!(p.node, Some(node));
        assert_eq!(p.addr(), Some(Addr { net: NET, node }));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Action::Log(_)), "{:?}", out[0]);
        // And it stays claimed: no more probes, no second log.
        assert_eq!(p.tick(t + PROBE_INTERVAL * 20), Vec::new());
    }

    #[test]
    fn a_probe_response_for_the_candidate_restarts_with_a_different_node() {
        let t = Instant::now();
        let mut p = port(Kind::Ether { mac: OURS }, t);
        let node = candidate(&mut p, t);
        let taken = Aarp {
            op: 2,
            src_hw: THEIRS,
            src: Addr { net: NET, node },
            dst_hw: OURS,
            dst: Addr { net: NET, node },
        };
        let (r, out) = p.inbound_ether(&ether_packet(Body::Aarp(taken), THEIRS), t);
        assert_eq!(r, Inbound::Handled);
        assert_eq!(out, Vec::new());
        // A fresh candidate, and the probe round starts over.
        let next = candidate(&mut p, t);
        assert_ne!(next, node);
        for i in 1..PROBE_TRIES {
            assert_eq!(aarp(&p.tick(t + PROBE_INTERVAL * i)[0]).src.node, next);
        }
        assert!(p.node.is_none());
        p.tick(t + PROBE_INTERVAL * PROBE_TRIES);
        assert_eq!(p.node, Some(next));
    }

    #[test]
    fn ltoudp_claim_completes_after_eight_enqs() {
        let t = Instant::now();
        let mut p = port(Kind::Ltoudp, t);
        let node = candidate(&mut p, t);
        assert!((128..=254).contains(&node), "{node} is outside the server range");
        for i in 1..ENQ_TRIES {
            let out = p.tick(t + ENQ_INTERVAL * i);
            assert_eq!(llap(&out[0]), &Llap::control(node, node, LLAP_ENQ));
            assert!(p.node.is_none());
        }
        let out = p.tick(t + ENQ_INTERVAL * ENQ_TRIES);
        assert_eq!(p.node, Some(node));
        // LToUDP programs no firmware: the claim is a log and nothing else.
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Action::Log(_)), "{:?}", out[0]);
    }

    #[test]
    fn an_enq_for_the_candidate_restarts_the_ltoudp_claim() {
        let t = Instant::now();
        let mut p = port(Kind::Ltoudp, t);
        let node = candidate(&mut p, t);
        let (r, out) = p.inbound_llap(&Llap::control(node, node, LLAP_ENQ), t);
        assert_eq!(r, Inbound::Handled);
        // We are still probing, so we neither answer nor keep the ID.
        assert_eq!(out, Vec::new());
        let next = candidate(&mut p, t);
        assert_ne!(next, node);
        for i in 1..ENQ_TRIES {
            p.tick(t + ENQ_INTERVAL * i);
        }
        p.tick(t + ENQ_INTERVAL * ENQ_TRIES);
        assert_eq!(p.node, Some(next));
    }

    #[test]
    fn tashtalk_claim_emits_set_node() {
        let t = Instant::now();
        let mut p = port(Kind::Tashtalk, t);
        let node = candidate(&mut p, t);
        for i in 1..ENQ_TRIES {
            p.tick(t + ENQ_INTERVAL * i);
        }
        let out = p.tick(t + ENQ_INTERVAL * ENQ_TRIES);
        assert_eq!(p.node, Some(node));
        assert!(matches!(out[0], Action::Log(_)), "{:?}", out[0]);
        assert_eq!(out[1], Action::SetNode { port: 1, node: Some(node) });
    }

    #[test]
    fn emit_picks_short_or_long_header() {
        let t = Instant::now();
        let mut p = port(Kind::Ltoudp, t);
        let node = claim(&mut p, t);

        // Both ends on this port's one network: the short header, whose bytes
        // omit exactly what the LLAP header just said.
        let d = ddp(Addr { net: NET, node }, Addr { net: NET, node: 42 });
        let short = p.emit(&Dest::Node(42), &d).unwrap();
        assert_eq!(
            llap(&short),
            &Llap { dst: 42, src: node, typ: LLAP_SHORT_DDP, data: d.to_short_bytes() }
        );

        // A datagram from another network cannot drop its network numbers.
        let far = ddp(Addr { net: 2905, node: 7 }, Addr { net: NET, node: 42 });
        let long = p.emit(&Dest::Node(42), &far).unwrap();
        assert_eq!(llap(&long), &Llap { dst: 42, src: node, typ: LLAP_LONG_DDP, data: far.to_bytes() });

        // Network 0 means "this cable", so it is short too.
        let unnumbered = ddp(Addr { net: NET, node }, Addr { net: 0, node: 42 });
        assert_eq!(llap(&p.emit(&Dest::Node(42), &unnumbered).unwrap()).typ, LLAP_SHORT_DDP);
    }

    #[test]
    fn emit_needs_a_node_and_maps_the_destination() {
        let t = Instant::now();
        let mut p = port(Kind::Ether { mac: OURS }, t);
        let d = ddp(Addr { net: NET, node: 9 }, Addr { net: NET, node: 42 });
        // Nothing goes out before the claim.
        assert_eq!(p.emit(&Dest::Node(42), &d), None);
        let node = claim(&mut p, t);

        // Unknown address: broadcast, and the cable sorts it out.
        let Action::ToEther { frame, port } = p.emit(&Dest::Node(42), &d).unwrap() else {
            panic!("expected an Ethernet frame");
        };
        assert_eq!(port, 1);
        assert_eq!((frame.dst, frame.src, frame.proto), (BROADCAST_MAC, OURS, DDP));
        assert_eq!(frame.payload, d.to_bytes());

        // Once gleaned from that node's own traffic, it goes direct.
        let their = ddp(Addr { net: NET, node: 42 }, Addr { net: NET, node });
        p.inbound_ether(&ether_packet(Body::Ddp(their, DdpBody::Unknown), THEIRS), t);
        let a = p.emit(&Dest::Node(42), &d).unwrap();
        let Action::ToEther { frame, .. } = a else { panic!("expected an Ethernet frame") };
        assert_eq!(frame.dst, THEIRS);
    }

    #[test]
    fn emit_uses_the_zone_multicast_on_ether_and_broadcast_on_localtalk() {
        let t = Instant::now();
        let mut e = port(Kind::Ether { mac: OURS }, t);
        let node = claim(&mut e, t);
        let d = ddp(Addr { net: NET, node }, Addr { net: NET, node: 255 });
        let Action::ToEther { frame, .. } = e.emit(&Dest::Zone(ZONE.to_string()), &d).unwrap()
        else {
            panic!("expected an Ethernet frame");
        };
        assert_eq!(frame.dst, zone_multicast(ZONE));
        let Action::ToEther { frame, .. } = e.emit(&Dest::Broadcast, &d).unwrap() else {
            panic!("expected an Ethernet frame");
        };
        assert_eq!(frame.dst, BROADCAST_MAC);

        // LocalTalk has one multicast, and it is the broadcast node ID.
        let mut l = port(Kind::Ltoudp, t);
        let node = claim(&mut l, t);
        let d = ddp(Addr { net: NET, node }, Addr { net: NET, node: 255 });
        assert_eq!(llap(&l.emit(&Dest::Zone(ZONE.to_string()), &d).unwrap()).dst, 255);
        assert_eq!(llap(&l.emit(&Dest::Broadcast, &d).unwrap()).dst, 255);
    }

    #[test]
    fn inbound_llap_answers_enq_on_ltoudp_but_not_on_tashtalk() {
        let t = Instant::now();
        let mut l = port(Kind::Ltoudp, t);
        let node = claim(&mut l, t);
        let (r, out) = l.inbound_llap(&Llap::control(node, node, LLAP_ENQ), t);
        assert_eq!(r, Inbound::Handled);
        assert_eq!(out, vec![Action::ToLlap { port: 1, llap: Llap::control(node, node, LLAP_ACK) }]);
        // Someone else's ID is not ours to deny.
        let other = if node == 200 { 201 } else { 200 };
        assert_eq!(l.inbound_llap(&Llap::control(other, other, LLAP_ENQ), t).1, Vec::new());

        // TashTalk's firmware answers from its node bitmap; a second ACK would
        // be a duplicate on the wire.
        let mut tt = port(Kind::Tashtalk, t);
        let node = claim(&mut tt, t);
        let (r, out) = tt.inbound_llap(&Llap::control(node, node, LLAP_ENQ), t);
        assert_eq!(r, Inbound::Handled);
        assert_eq!(out, Vec::new());
    }

    #[test]
    fn inbound_ether_answers_an_aarp_request_for_our_address_only_after_the_claim() {
        let t = Instant::now();
        let mut p = port(Kind::Ether { mac: OURS }, t);
        let node = candidate(&mut p, t);
        let ours = Addr { net: NET, node };
        let req = || {
            let a = Aarp {
                op: 1,
                src_hw: THEIRS,
                src: Addr { net: NET, node: 42 },
                dst_hw: MacAddr::zero(),
                dst: ours,
            };
            ether_packet(Body::Aarp(a), THEIRS)
        };
        // A probing node answers nothing (PDF 86).
        assert_eq!(p.inbound_ether(&req(), t), (Inbound::Handled, Vec::new()));

        for i in 1..=PROBE_TRIES {
            p.tick(t + PROBE_INTERVAL * i);
        }
        assert_eq!(p.node, Some(node));
        let (r, out) = p.inbound_ether(&req(), t);
        assert_eq!(r, Inbound::Handled);
        let Action::ToEther { frame, .. } = &out[0] else { panic!("expected an Ethernet frame") };
        assert_eq!(frame.dst, THEIRS);
        let a = aarp(&out[0]);
        assert_eq!((a.op, a.src, a.src_hw), (2, ours, OURS));
        assert_eq!((a.dst, a.dst_hw), (Addr { net: NET, node: 42 }, THEIRS));
    }

    #[test]
    fn our_own_frames_are_ignored() {
        let t = Instant::now();
        let mut e = port(Kind::Ether { mac: OURS }, t);
        let node = claim(&mut e, t);
        let d = ddp(Addr { net: NET, node }, Addr { net: NET, node: 42 });
        // Heard back off our own cable: the source MAC is ours.
        assert_eq!(
            e.inbound_ether(&ether_packet(Body::Ddp(d, DdpBody::Unknown), OURS), t).0,
            Inbound::Ignore
        );
        // Somebody else's datagram is the router's business.
        let theirs = ddp(Addr { net: NET, node: 42 }, Addr { net: NET, node });
        let (r, out) = e.inbound_ether(&ether_packet(Body::Ddp(theirs, DdpBody::Unknown), THEIRS), t);
        assert!(matches!(r, Inbound::Ddp(_)), "{r:?}");
        assert_eq!(out, Vec::new());

        // On LocalTalk it is the node ID, and our own echoed ACK with it.
        let mut l = port(Kind::Tashtalk, t);
        let node = claim(&mut l, t);
        assert_eq!(l.inbound_llap(&Llap::control(node, node, LLAP_ACK), t).0, Inbound::Ignore);
        let mine = ddp(Addr { net: NET, node }, Addr { net: NET, node: 42 });
        let echo = Llap { dst: 42, src: node, typ: LLAP_SHORT_DDP, data: mine.to_short_bytes() };
        assert_eq!(l.inbound_llap(&echo, t).0, Inbound::Ignore);
    }

    #[test]
    fn inbound_llap_lifts_both_header_forms_and_rejects_the_unparseable() {
        let t = Instant::now();
        let mut p = port(Kind::Ltoudp, t);
        let node = claim(&mut p, t);
        // A short header names no networks: this port's own supplies them.
        let d = ddp(Addr { net: NET, node: 42 }, Addr { net: NET, node });
        let short = Llap { dst: node, src: 42, typ: LLAP_SHORT_DDP, data: d.to_short_bytes() };
        // The lifted header carries the extended length the short one implied.
        let lifted = Ddp { length: 17, ..d };
        assert_eq!(p.inbound_llap(&short, t).0, Inbound::Ddp(lifted));

        let far = ddp(Addr { net: 2905, node: 7 }, Addr { net: NET, node });
        let long = Llap { dst: node, src: 42, typ: LLAP_LONG_DDP, data: far.to_bytes() };
        assert_eq!(p.inbound_llap(&long, t).0, Inbound::Ddp(Ddp { length: 17, ..far }));

        // Fail closed rather than guess at a header we cannot read.
        let runt = Llap { dst: node, src: 42, typ: LLAP_LONG_DDP, data: vec![0, 5, 1, 2, 3] };
        assert_eq!(p.inbound_llap(&runt, t).0, Inbound::Ignore);
    }

    #[test]
    fn zones_are_matched_case_insensitively() {
        let t = Instant::now();
        let p = port(Kind::Ether { mac: OURS }, t);
        assert_eq!(p.default_zone(), ZONE);
        assert!(p.has_zone("68K MAC CLUB"));
        assert!(!p.has_zone("BabCom"));
        assert!(p.extended());
        assert!(!port(Kind::Ltoudp, t).extended());
    }

    /// Ticks a port through its whole claim and returns the node it took.
    fn claim(p: &mut Port, t: Instant) -> u8 {
        let (tries, interval) = match p.kind {
            Kind::Ether { .. } => (PROBE_TRIES, PROBE_INTERVAL),
            _ => (ENQ_TRIES, ENQ_INTERVAL),
        };
        for i in 0..=tries {
            p.tick(t + interval * i);
        }
        p.node.expect("claimed")
    }
}
