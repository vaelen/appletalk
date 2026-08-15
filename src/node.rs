// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! The node runtime: claim an AppleTalk address, defend it, ask questions.
//!
//! Everything that decides something is a free function over a `&Packet`, so
//! it can be tested without a NIC. The `Node` methods are the socket-and-timer
//! glue around them.
//!
//! Nothing here is reachable from `main` yet, and some of it depends on
//! pieces added in later tasks. Drop the allow below once Task 6 wires it in.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pnet::util::MacAddr;

use crate::capture::{Event, Tx};
use crate::session::Session;
use crate::wire::{Aarp, Addr, Body, Ddp, DdpBody, Encode, Frame, Packet, Zip, AARP, DDP, DDP_ZIP};

/// Where ELAP sends AppleTalk broadcasts, and where AARP probes and requests
/// belong too (PDF 98). Non-AppleTalk nodes never register on it.
pub const BROADCAST_MAC: MacAddr = MacAddr(0x09, 0x00, 0x07, 0xff, 0xff, 0xff);

/// The bottom of the dynamic socket range. One conversation at a time means
/// one socket is enough.
pub const OUR_SOCKET: u8 = 128;

/// A datagram with its derived fields left for `encode`: the length is
/// recomputed there, and a zero checksum means "sender computed none", which
/// is legal and what we want.
pub fn datagram(
    src: Addr,
    src_socket: u8,
    dst: Addr,
    dst_socket: u8,
    typ: u8,
    data: Vec<u8>,
) -> Ddp {
    Ddp { hops: 0, length: 0, checksum: 0, dst, dst_socket, src, src_socket, typ, data }
}

/// Always Phase 2 — 802.3 + LLC + SNAP. Every network this is likely to meet
/// is Phase 2, and `Frame::encode` handles the framing when `snap` is set.
pub fn frame(src: MacAddr, dst: MacAddr, proto: u16, payload: Vec<u8>) -> Frame {
    Frame { dst, src, proto, snap: true, payload }
}

/// Picks a provisional address. The node ID is random and the network number
/// comes from the startup range $FF00–$FFFE (PDF 111). Node IDs 0, $FE and
/// $FF are reserved on Ethernet and token ring (PDF 98).
///
/// ponytail: the seed is the clock mixed with the NIC's MAC rather than a real
/// RNG. Collisions are what the probe is for, so a weak seed costs at most one
/// extra round of probing. Reach for a real RNG only if probing starts failing.
pub fn pick_address(seed: u64) -> Addr {
    Addr {
        net: 0xff00 + (seed % 0xff) as u16,
        node: 1 + ((seed >> 16) % 253) as u8,
    }
}

/// An AARP Probe: "is anyone using this address?". The target hardware
/// address is zero because that is exactly what we are asking for.
pub fn probe(addr: Addr, mac: MacAddr) -> Aarp {
    Aarp { op: 3, src_hw: mac, src: addr, dst_hw: MacAddr::zero(), dst: addr }
}

/// "Yes, that address is mine, at this MAC."
pub fn aarp_response(ours: Addr, our_mac: MacAddr, to: Addr, to_mac: MacAddr) -> Aarp {
    Aarp { op: 2, src_hw: our_mac, src: ours, dst_hw: to_mac, dst: to }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AarpAction {
    /// Someone else holds, or is also claiming, the address we want.
    Conflict,
    /// A request for our address, to be answered at this MAC.
    AnswerTo(MacAddr),
    Ignore,
}

/// What an incoming packet means for our address. `probing` is true until the
/// address is claimed — a probing node answers nothing (PDF 86).
pub fn aarp_action(p: &Packet, ours: Addr, our_mac: MacAddr, probing: bool) -> AarpAction {
    let Body::Aarp(a) = &p.body else { return AarpAction::Ignore };
    match a.op {
        // A response for the address means it is taken.
        2 if a.src == ours => AarpAction::Conflict,
        // Someone else probing for the same address. While we are probing too,
        // both sides give up (PDF 86). Once claimed, we defend it by answering
        // — that response is how the prober learns the address is taken (PDF 85).
        3 if a.src == ours && a.src_hw != our_mac => {
            if probing { AarpAction::Conflict } else { AarpAction::AnswerTo(a.src_hw) }
        }
        1 if a.dst == ours && !probing => AarpAction::AnswerTo(a.src_hw),
        _ => AarpAction::Ignore,
    }
}

/// Records the sender's address-to-MAC mapping, so a later directed frame has
/// somewhere to go. Gleaning is optional in the book and deliberately excludes
/// Probes, whose source address is only tentative (PDF 87).
pub fn glean(amt: &mut HashMap<Addr, MacAddr>, p: &Packet) {
    match &p.body {
        Body::Aarp(a) if a.op != 3 => {
            amt.insert(a.src, a.src_hw);
        }
        Body::Ddp(d, _) => {
            amt.insert(d.src, p.frame.src);
        }
        _ => {}
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NetInfo {
    /// Our provisional network number is valid on this cable.
    Keep,
    /// It is not; pick again inside this range.
    Repick { range: (u16, u16) },
}

/// Reads a ZIP GetNetInfo reply: whether our provisional address survives, the
/// zone name to adopt, and the address of the router that answered — which is
/// the only way we learn of a router (PDF 181).
pub fn netinfo_verdict(p: &Packet, provisional: Addr) -> Option<(NetInfo, String, Addr)> {
    let Body::Ddp(d, DdpBody::Zip(Zip::NetInfoReply { range, zone, default_zone, .. })) = &p.body
    else {
        return None;
    };
    // A range whose end precedes its start is not something we recognise, and
    // the span arithmetic downstream would underflow on it. Fail closed: with
    // no verdict the caller falls through to the routerless path and keeps its
    // provisional address, exactly as if no router had answered.
    if range.1 < range.0 {
        return None;
    }
    // The reply echoes the zone we asked for; a default zone means that one
    // was not valid here and this is the name to use instead.
    let zone = default_zone.clone().unwrap_or_else(|| zone.clone());
    let verdict = if (range.0..=range.1).contains(&provisional.net) {
        NetInfo::Keep
    } else {
        NetInfo::Repick { range: *range }
    };
    Some((verdict, zone, d.src))
}

/// PDF 98: ten retransmissions, one fifth of a second apart.
const PROBE_TRIES: u32 = 10;
const PROBE_INTERVAL: Duration = Duration::from_millis(200);
/// How many different addresses to try before giving up entirely.
const ADDRESS_TRIES: u32 = 5;
/// PDF 181: "retransmitted several times to insure that a response is received".
const NETINFO_TRIES: u32 = 3;
const NETINFO_INTERVAL: Duration = Duration::from_secs(1);

pub struct Node {
    tx: Tx,
    rx: Receiver<Event>,
    addr: Addr,
    /// None means no router answered: no zone, and `*` in every lookup.
    zone: Option<String>,
    router: Option<Addr>,
    /// Address-to-MAC mappings gleaned from traffic.
    amt: HashMap<Addr, MacAddr>,
    /// Reused wholesale for ATP reassembly.
    session: Session,
    /// True until the address is claimed; suppresses AARP answers.
    probing: bool,
    next_id: u16,
}

impl Node {
    /// Runs the book's two-step startup and returns a node ready to ask
    /// questions. Narrates to stderr, because stdout is for results.
    pub fn claim(tx: Tx, rx: Receiver<Event>, want: Option<Addr>) -> io::Result<Node> {
        let mut n = Node {
            tx,
            rx,
            addr: Addr { net: 0, node: 0 },
            zone: None,
            router: None,
            amt: HashMap::new(),
            session: Session::new(),
            probing: true,
            next_id: 1,
        };

        n.addr = match want {
            Some(a) => {
                n.claim_one(a)?;
                a
            }
            None => n.claim_any()?,
        };

        // Step two: ask a router what this cable actually is.
        if let Some((verdict, zone, router)) = n.get_net_info() {
            n.router = Some(router);
            n.zone = Some(zone);
            if let NetInfo::Repick { range } = verdict {
                let addr = n.claim_in_range(range)?;
                n.addr = addr;
            }
            eprintln!(
                "claimed {}, zone {:?}, router {}",
                n.addr,
                n.zone.as_deref().unwrap_or("*"),
                router
            );
        } else {
            // PDF 181: no reply means no router. The provisional address is
            // final and `*` is the only zone name valid in lookups.
            eprintln!("claimed {}, no router on this network", n.addr);
        }
        n.probing = false;
        Ok(n)
    }

    fn claim_any(&mut self) -> io::Result<Addr> {
        for attempt in 0..ADDRESS_TRIES {
            let addr = pick_address(self.seed(attempt));
            if self.claim_one(addr).is_ok() {
                return Ok(addr);
            }
        }
        Err(io::Error::new(io::ErrorKind::AddrInUse, "could not claim an address"))
    }

    fn claim_in_range(&mut self, range: (u16, u16)) -> io::Result<Addr> {
        for attempt in 0..ADDRESS_TRIES {
            let seed = self.seed(attempt);
            let span = (range.1 - range.0) as u64 + 1;
            let addr = Addr {
                net: range.0 + (seed % span) as u16,
                node: pick_address(seed).node,
            };
            if self.claim_one(addr).is_ok() {
                return Ok(addr);
            }
        }
        Err(io::Error::new(io::ErrorKind::AddrInUse, "could not claim an address in range"))
    }

    /// Probes one address. Ok means nobody objected.
    fn claim_one(&mut self, addr: Addr) -> io::Result<()> {
        let our_mac = self.tx.mac;
        for _ in 0..PROBE_TRIES {
            let p = probe(addr, our_mac);
            let f = frame(our_mac, BROADCAST_MAC, AARP, p.to_bytes());
            self.tx.send(&f)?;
            let taken = self.wait(Instant::now() + PROBE_INTERVAL, |_, pkt| {
                match aarp_action(pkt, addr, our_mac, true) {
                    AarpAction::Conflict => Some(()),
                    _ => None,
                }
            });
            if taken.is_some() {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("{addr} is taken")));
            }
        }
        Ok(())
    }

    fn get_net_info(&mut self) -> Option<(NetInfo, String, Addr)> {
        // An empty zone name is the "no saved zone" case (PDF 181).
        let body = Zip::GetNetInfo { zone: String::new() }.to_bytes();
        let provisional = self.addr;
        for _ in 0..NETINFO_TRIES {
            // ZIP is a socket-6 protocol at both ends.
            self.send_from(6, Addr { net: 0, node: 255 }, 6, DDP_ZIP, body.clone()).ok()?;
            let got = self.wait(Instant::now() + NETINFO_INTERVAL, move |_, p| {
                netinfo_verdict(p, provisional)
            });
            if got.is_some() {
                return got;
            }
        }
        None
    }

    /// The clock mixed with the NIC's MAC. See `pick_address` for why this is
    /// enough.
    fn seed(&self, attempt: u32) -> u64 {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        let m = self.tx.mac;
        let mac = u64::from(m.3) << 16 | u64::from(m.4) << 8 | u64::from(m.5);
        u64::from(nanos) ^ (mac << 8) ^ u64::from(attempt) << 32
    }

    pub fn addr(&self) -> Addr {
        self.addr
    }

    pub fn zone(&self) -> &str {
        self.zone.as_deref().unwrap_or("*")
    }

    pub fn router(&self) -> Option<Addr> {
        self.router
    }

    /// Transaction and lookup identifiers, so a late reply to a previous
    /// request cannot be mistaken for an answer to this one.
    pub fn next_id(&mut self) -> u16 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    fn mac_for(&self, addr: Addr) -> MacAddr {
        // Unknown means broadcast: everyone on the cable hears it, and the one
        // it is for answers. Costs an interrupt on other AppleTalk nodes only.
        self.amt.get(&addr).copied().unwrap_or(BROADCAST_MAC)
    }

    fn send_ddp(&mut self, dst: Addr, dst_socket: u8, typ: u8, data: Vec<u8>) -> io::Result<()> {
        self.send_from(OUR_SOCKET, dst, dst_socket, typ, data)
    }

    fn send_from(
        &mut self,
        src_socket: u8,
        dst: Addr,
        dst_socket: u8,
        typ: u8,
        data: Vec<u8>,
    ) -> io::Result<()> {
        let d = datagram(self.addr, src_socket, dst, dst_socket, typ, data);
        // A broadcast node number always goes to the multicast address.
        let mac = if dst.node == 255 { BROADCAST_MAC } else { self.mac_for(dst) };
        let f = frame(self.tx.mac, mac, DDP, d.to_bytes());
        self.tx.send(&f)
    }

    /// Drains capture events until `f` yields a value or `deadline` passes.
    /// Answers AARP for our address, gleans mappings, and feeds `Session`
    /// along the way — this is the only loop in the program.
    fn wait<T>(
        &mut self,
        deadline: Instant,
        mut f: impl FnMut(&mut Node, &Packet) -> Option<T>,
    ) -> Option<T> {
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            match self.rx.recv_timeout(left) {
                Ok(Event::Packet { at, packet }) => {
                    glean(&mut self.amt, &packet);
                    self.session.push(at, &packet);
                    if let AarpAction::AnswerTo(mac) =
                        aarp_action(&packet, self.addr, self.tx.mac, self.probing)
                        && let Body::Aarp(a) = &packet.body
                    {
                        let r = aarp_response(self.addr, self.tx.mac, a.src, mac);
                        let out = frame(self.tx.mac, mac, AARP, r.to_bytes());
                        let _ = self.tx.send(&out);
                    }
                    if let Some(v) = f(self, &packet) {
                        return Some(v);
                    }
                }
                Ok(Event::Dropped(_)) => self.session.flush(),
                Ok(Event::Error(e)) => eprintln!("rx: {e}"),
                Err(RecvTimeoutError::Timeout) => return None,
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use pnet::util::MacAddr;

    use crate::wire::{Aarp, Body, DdpBody, Encode, Packet, Zip, AARP, DDP, DDP_ZIP};

    fn aarp_packet(op: u16, src: Addr, src_hw: MacAddr, dst: Addr) -> Packet {
        let body = Body::Aarp(Aarp {
            op,
            src_hw,
            src,
            // A request leaves the target hardware address unknown.
            dst_hw: MacAddr::zero(),
            dst,
        });
        Packet { frame: frame(src_hw, BROADCAST_MAC, AARP, Vec::new()), body }
    }

    const OURS: Addr = Addr { net: 0xff00, node: 137 };
    const OUR_MAC: MacAddr = MacAddr(0x00, 0x05, 0x02, 0xaa, 0xbb, 0xcc);
    const THEIR_MAC: MacAddr = MacAddr(0x08, 0x00, 0x07, 0x11, 0x22, 0x33);

    #[test]
    fn picked_addresses_stay_inside_the_startup_range() {
        // Node IDs 0, $FE and $FF are reserved on Ethernet; nets come from the
        // startup range. Sweep enough seeds to catch an off-by-one at either end.
        for seed in 0..2000u64 {
            let a = pick_address(seed.wrapping_mul(2_654_435_761));
            assert!((0xff00..=0xfffe).contains(&a.net), "net {:#06x}", a.net);
            assert!((1..=253).contains(&a.node), "node {}", a.node);
        }
    }

    #[test]
    fn a_probe_carries_a_zero_target_hardware_address() {
        let p = probe(OURS, OUR_MAC);
        assert_eq!(p.op, 3);
        assert_eq!(p.src, OURS);
        assert_eq!(p.dst, OURS);
        assert_eq!(p.dst_hw, MacAddr::zero());
        let b = p.to_bytes();
        assert_eq!(&b[..6], &[0x00, 0x01, 0x80, 0x9b, 6, 4]);
        assert_eq!(&b[6..8], &[0x00, 0x03]);
    }

    #[test]
    fn a_response_for_our_tentative_address_is_a_conflict() {
        let p = aarp_packet(2, OURS, THEIR_MAC, OURS);
        assert!(matches!(aarp_action(&p, OURS, OUR_MAC, true), AarpAction::Conflict));
    }

    #[test]
    fn another_nodes_probe_for_the_same_address_is_a_conflict() {
        // Two nodes probing at once: the book has the receiver give up too.
        let p = aarp_packet(3, OURS, THEIR_MAC, OURS);
        assert!(matches!(aarp_action(&p, OURS, OUR_MAC, true), AarpAction::Conflict));
    }

    #[test]
    fn a_probe_for_our_claimed_address_is_answered_not_conceded() {
        // Once claimed, a Probe for our address must be defended (PDF 85) —
        // conceding it here would let the newcomer take our address.
        let p = aarp_packet(3, OURS, THEIR_MAC, OURS);
        match aarp_action(&p, OURS, OUR_MAC, false) {
            AarpAction::AnswerTo(m) => assert_eq!(m, THEIR_MAC),
            other => panic!("expected AnswerTo, got {other:?}"),
        }
    }

    #[test]
    fn our_own_probe_coming_back_is_not_a_conflict() {
        let p = aarp_packet(3, OURS, OUR_MAC, OURS);
        assert!(matches!(aarp_action(&p, OURS, OUR_MAC, true), AarpAction::Ignore));
    }

    #[test]
    fn we_answer_requests_for_our_address_only_once_claimed() {
        let asking = aarp_packet(1, Addr { net: 3, node: 1 }, THEIR_MAC, OURS);
        // While probing, a node responds to nothing.
        assert!(matches!(aarp_action(&asking, OURS, OUR_MAC, true), AarpAction::Ignore));
        match aarp_action(&asking, OURS, OUR_MAC, false) {
            AarpAction::AnswerTo(m) => assert_eq!(m, THEIR_MAC),
            other => panic!("expected AnswerTo, got {other:?}"),
        }
        // Someone else's address is not our business.
        let other = aarp_packet(1, Addr { net: 3, node: 1 }, THEIR_MAC, Addr { net: 3, node: 9 });
        assert!(matches!(aarp_action(&other, OURS, OUR_MAC, false), AarpAction::Ignore));
    }

    #[test]
    fn a_response_names_us_as_the_source_and_the_asker_as_the_target() {
        let them = Addr { net: 3, node: 1 };
        let r = aarp_response(OURS, OUR_MAC, them, THEIR_MAC);
        assert_eq!((r.op, r.src, r.src_hw), (2, OURS, OUR_MAC));
        assert_eq!((r.dst, r.dst_hw), (them, THEIR_MAC));
    }

    #[test]
    fn gleaning_takes_mappings_from_data_and_responses_but_never_probes() {
        let mut amt = HashMap::new();
        let them = Addr { net: 3, node: 1 };

        // A probe's source address is tentative and must not be cached (PDF 98).
        glean(&mut amt, &aarp_packet(3, them, THEIR_MAC, them));
        assert!(amt.is_empty());

        glean(&mut amt, &aarp_packet(2, them, THEIR_MAC, OURS));
        assert_eq!(amt.get(&them), Some(&THEIR_MAC));

        // A DDP datagram carries both addresses too.
        let mut amt = HashMap::new();
        let d = datagram(them, 6, OURS, 128, DDP_ZIP, vec![1]);
        let p = Packet {
            frame: frame(THEIR_MAC, OUR_MAC, DDP, Vec::new()),
            body: Body::Ddp(d, DdpBody::Unknown),
        };
        glean(&mut amt, &p);
        assert_eq!(amt.get(&them), Some(&THEIR_MAC));
    }

    #[test]
    fn datagram_recomputes_its_length_and_orders_the_addresses() {
        // A ZIP GetNetInfo request: 7 bytes of data from 65280.128:6 to 0.255:6.
        let d = datagram(
            Addr { net: 0xff00, node: 128 },
            6,
            Addr { net: 0, node: 255 },
            6,
            DDP_ZIP,
            vec![5, 0, 0, 0, 0, 0, 0],
        );
        let b = d.to_bytes();
        assert_eq!(b[0], 0); // hops 0, and the top 2 bits of a length below 256
        assert_eq!(b[1], 20); // 13 header + 7 data, recomputed
        // Both network numbers come before either node number.
        assert_eq!(&b[4..8], &[0x00, 0x00, 0xff, 0x00]);
        assert_eq!((b[8], b[9]), (255, 128));
        assert_eq!((b[10], b[11], b[12]), (6, 6, DDP_ZIP));
    }

    /// A ZIP GetNetInfo reply from router 3.1, for cable range 3–5, zone
    /// "Engineering", optionally correcting an invalid requested zone.
    fn netinfo(range: (u16, u16), zone: &str, default_zone: Option<&str>) -> Packet {
        let z = Zip::NetInfoReply {
            flags: 0,
            range,
            zone: zone.to_string(),
            multicast: MacAddr(0x09, 0x00, 0x07, 0x00, 0x00, 0x0f),
            default_zone: default_zone.map(str::to_string),
        };
        let d = datagram(
            Addr { net: 3, node: 1 },
            6,
            Addr { net: 0xff00, node: 137 },
            6,
            DDP_ZIP,
            z.to_bytes(),
        );
        Packet {
            frame: frame(THEIR_MAC, OUR_MAC, DDP, Vec::new()),
            body: Body::Ddp(d, DdpBody::Zip(z)),
        }
    }

    #[test]
    fn a_provisional_net_inside_the_cable_range_is_kept() {
        let p = netinfo((0xff00, 0xff0a), "Engineering", None);
        let (verdict, zone, router) = netinfo_verdict(&p, OURS).unwrap();
        assert_eq!(verdict, NetInfo::Keep);
        assert_eq!(zone, "Engineering");
        assert_eq!(router, Addr { net: 3, node: 1 });
    }

    #[test]
    fn a_provisional_net_at_the_top_of_the_cable_range_is_kept() {
        // range.0..range.1 alone would exclude this end; pin it explicitly.
        // OURS.net is 0xff00, placed at range.1 here rather than range.0.
        let p = netinfo((0xfef0, 0xff00), "Engineering", None);
        let (verdict, _, _) = netinfo_verdict(&p, OURS).unwrap();
        assert_eq!(verdict, NetInfo::Keep);
    }

    #[test]
    fn a_provisional_net_outside_the_cable_range_forces_a_repick() {
        let p = netinfo((3, 5), "Engineering", None);
        let (verdict, _, _) = netinfo_verdict(&p, OURS).unwrap();
        assert_eq!(verdict, NetInfo::Repick { range: (3, 5) });
    }

    #[test]
    fn an_inverted_cable_range_is_rejected_rather_than_underflowing() {
        let p = netinfo((0xff0a, 0xff00), "Engineering", None);
        assert!(netinfo_verdict(&p, OURS).is_none());
    }

    #[test]
    fn an_invalid_requested_zone_is_replaced_by_the_default_zone() {
        // The reply echoes the zone we asked for and appends the real default.
        let p = netinfo((3, 5), "Nonesuch", Some("Engineering"));
        let (_, zone, _) = netinfo_verdict(&p, OURS).unwrap();
        assert_eq!(zone, "Engineering");
    }

    #[test]
    fn other_zip_traffic_is_not_a_netinfo_verdict() {
        let z = Zip::Query { nets: vec![3] };
        let d = datagram(Addr { net: 3, node: 1 }, 6, OURS, 6, DDP_ZIP, z.to_bytes());
        let p = Packet {
            frame: frame(THEIR_MAC, OUR_MAC, DDP, Vec::new()),
            body: Body::Ddp(d, DdpBody::Zip(z)),
        };
        assert!(netinfo_verdict(&p, OURS).is_none());
    }

    #[test]
    fn frames_go_out_as_phase_2_snap() {
        let f = frame(
            MacAddr::new(0x00, 0x05, 0x02, 0xaa, 0xbb, 0xcc),
            BROADCAST_MAC,
            DDP,
            vec![1, 2, 3],
        );
        assert!(f.snap);
        assert_eq!(f.dst, MacAddr::new(0x09, 0x00, 0x07, 0xff, 0xff, 0xff));
        let b = f.to_bytes();
        assert_eq!(&b[14..22], &[0xaa, 0xaa, 0x03, 0x08, 0x00, 0x07, 0x80, 0x9b]);
    }
}
