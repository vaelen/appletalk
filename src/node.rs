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

use pnet::util::MacAddr;

use crate::wire::{Aarp, Addr, Body, Ddp, Frame, Packet};

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
/// address is claimed — a probing node answers nothing (PDF 98).
pub fn aarp_action(p: &Packet, ours: Addr, our_mac: MacAddr, probing: bool) -> AarpAction {
    let Body::Aarp(a) = &p.body else { return AarpAction::Ignore };
    match a.op {
        // A response for the address means it is taken.
        2 if a.src == ours => AarpAction::Conflict,
        // Someone else probing for the same address: both sides give up.
        3 if a.src == ours && a.src_hw != our_mac => AarpAction::Conflict,
        1 if a.dst == ours && !probing => AarpAction::AnswerTo(a.src_hw),
        _ => AarpAction::Ignore,
    }
}

/// Records the sender's address-to-MAC mapping, so a later directed frame has
/// somewhere to go. Gleaning is optional in the book and deliberately excludes
/// Probes, whose source address is only tentative (PDF 98).
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use pnet::util::MacAddr;

    use crate::wire::{Aarp, Body, DdpBody, Encode, Packet, AARP, DDP, DDP_ZIP};

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
