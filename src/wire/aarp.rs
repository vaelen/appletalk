// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! AppleTalk Address Resolution Protocol — ARP's layout with AppleTalk
//! addresses.

use std::fmt;

use pnet::util::MacAddr;

use super::{mac, mac_bytes, Addr, Encode};

/// An AARP packet: ARP's layout with AppleTalk addresses. Ethernet AARP is
/// always 28 bytes and carries no payload.
#[derive(Debug, PartialEq, Eq)]
pub struct Aarp {
    pub op: u16,
    pub src_hw: MacAddr,
    pub src: Addr,
    pub dst_hw: MacAddr,
    pub dst: Addr,
}

impl Aarp {
    pub fn parse(p: &[u8]) -> Option<Self> {
        let h = p.get(..28)?;
        // Hardware type 1 (Ethernet), protocol 0x809b (AppleTalk), 6-byte MAC,
        // 4-byte AppleTalk address. Anything else is not ours to decode.
        if h[..6] != [0x00, 0x01, 0x80, 0x9b, 6, 4] {
            return None;
        }
        // A protocol address is a zero pad byte, a 16-bit net, then the node.
        let addr = |a: &[u8]| Addr { net: u16::from_be_bytes([a[1], a[2]]), node: a[3] };
        Some(Aarp {
            op: u16::from_be_bytes([h[6], h[7]]),
            src_hw: mac(&h[8..14])?,
            src: addr(&h[14..18]),
            dst_hw: mac(&h[18..24])?,
            dst: addr(&h[24..28]),
        })
    }

    pub fn op_name(&self) -> &'static str {
        match self.op {
            1 => "request",
            2 => "response",
            3 => "probe",
            _ => "?",
        }
    }
}

impl fmt::Display for Aarp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}  {} ({}) > {} ({})",
            self.op_name(),
            self.src,
            self.src_hw,
            self.dst,
            self.dst_hw
        )
    }
}

impl Encode for Aarp {
    fn encode(&self, out: &mut Vec<u8>) {
        // Hardware type 1 (Ethernet), protocol 0x809b, 6-byte MAC, 4-byte
        // AppleTalk address — the only combination this parser accepts.
        out.extend([0x00, 0x01, 0x80, 0x9b, 6, 4]);
        out.extend(self.op.to_be_bytes());
        let addr = |out: &mut Vec<u8>, a: &Addr| {
            out.push(0); // the pad byte before the network number
            out.extend(a.net.to_be_bytes());
            out.push(a.node);
        };
        out.extend(mac_bytes(self.src_hw));
        addr(out, &self.src);
        out.extend(mac_bytes(self.dst_hw));
        addr(out, &self.dst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testkit::*;

    #[test]
    fn aarp_request() {
        let a = Aarp::parse(&aarp(1, &[])).unwrap();
        assert_eq!(a.dst, Addr { net: 65280, node: 42 });
        assert_eq!(
            a.to_string(),
            "request  65280.128 (00:05:02:aa:bb:cc) > 65280.42 (00:00:00:00:00:00)"
        );
    }

    #[test]
    fn aarp_probe_ignores_trailing_padding() {
        let a = Aarp::parse(&aarp(3, &[0; 20])).unwrap();
        assert_eq!(a.op_name(), "probe");
    }

    #[test]
    fn aarp_rejects_short_and_foreign() {
        assert!(Aarp::parse(&aarp(1, &[])[..27]).is_none()); // truncated
        let mut token_ring = aarp(1, &[]);
        token_ring[1] = 0x02; // hardware type != Ethernet
        assert!(Aarp::parse(&token_ring).is_none());
    }

    #[test]
    fn aarp_encodes_known_bytes() {
        let a = Aarp::parse(&crate::wire::testkit::aarp(3, &[])).unwrap();
        assert_eq!(a.to_bytes(), crate::wire::testkit::aarp(3, &[]));
    }

    #[test]
    fn aarp_round_trips_each_opcode() {
        for op in [1, 2, 3] {
            let a = Aarp::parse(&crate::wire::testkit::aarp(op, &[])).unwrap();
            assert_eq!(Aarp::parse(&a.to_bytes()), Some(a), "opcode {op}");
        }
    }
}
