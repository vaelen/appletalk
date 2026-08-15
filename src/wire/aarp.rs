// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! AppleTalk Address Resolution Protocol — ARP's layout with AppleTalk
//! addresses.

use std::fmt;

use pnet::util::MacAddr;

use super::{mac, Addr};

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
}
