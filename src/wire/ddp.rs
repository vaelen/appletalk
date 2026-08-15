// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Datagram Delivery Protocol — the AppleTalk network layer.

use std::fmt;

use super::{Addr, DDP_AEP, DDP_ATP, DDP_NBP, DDP_ZIP};

/// A DDP datagram with the 13-byte extended (long) header — the only form
/// EtherTalk carries. The 5-byte short header is LocalTalk-only, where LLAP's
/// type field tells the two apart.
#[derive(Debug, PartialEq, Eq)]
pub struct Ddp {
    pub hops: u8,
    /// Header + data, per the wire. Compare against `data` to spot truncation.
    pub length: u16,
    /// 0 means the sender computed no checksum.
    pub checksum: u16,
    pub dst: Addr,
    pub dst_socket: u8,
    pub src: Addr,
    pub src_socket: u8,
    pub typ: u8,
    pub data: Vec<u8>,
}

impl Ddp {
    pub fn parse(p: &[u8]) -> Option<Self> {
        let h = p.get(..13)?;
        Some(Ddp {
            // byte 0: 2 bits reserved, 4 bits hop count, then the top 2 of a
            // 10-bit length.
            hops: (h[0] >> 2) & 0x0f,
            length: u16::from_be_bytes([h[0] & 0x03, h[1]]),
            checksum: u16::from_be_bytes([h[2], h[3]]),
            dst: Addr { net: u16::from_be_bytes([h[4], h[5]]), node: h[8] },
            dst_socket: h[10],
            src: Addr { net: u16::from_be_bytes([h[6], h[7]]), node: h[9] },
            src_socket: h[11],
            typ: h[12],
            data: p[13..].to_vec(),
        })
    }

    pub fn type_name(&self) -> &'static str {
        match self.typ {
            1 => "RTMP-data",
            DDP_NBP => "NBP",
            DDP_ATP => "ATP",
            DDP_AEP => "AEP",
            5 => "RTMP-req",
            DDP_ZIP => "ZIP",
            7 => "ADSP",
            _ => "?",
        }
    }
}

impl fmt::Display for Ddp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{} > {}:{}  type {} ({}) hops {} len {}",
            self.src,
            self.src_socket,
            self.dst,
            self.dst_socket,
            self.typ,
            self.type_name(),
            self.hops,
            self.length
        )?;
        // The length field covers the header, so it should match what arrived.
        let wire = 13 + self.data.len();
        if self.length as usize != wire {
            write!(f, " (wire {wire})")?;
        }
        match self.checksum {
            0 => write!(f, " cksum none"),
            c => write!(f, " cksum {c:#06x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddp_long_header() {
        let dgram = [
            0x00, 17, // hops 0, length 17 (13 header + 4 data)
            0x00, 0x00, // no checksum
            0x00, 0x00, 0xff, 0x00, // dst net 0, src net 65280
            255, 128, // dst node, src node
            2, 253, // dst socket, src socket
            2,  // DDP type: NBP
            1, 2, 3, 4,
        ];
        let d = Ddp::parse(&dgram).unwrap();
        assert_eq!(d.src, Addr { net: 65280, node: 128 });
        assert_eq!(d.data, [1, 2, 3, 4]);
        assert_eq!(
            d.to_string(),
            "65280.128:253 > 0.255:2  type 2 (NBP) hops 0 len 17 cksum none"
        );
    }

    #[test]
    fn ddp_hops_and_10_bit_length() {
        // hops 5, length 600 -> byte 0 = 5<<2 | 600>>8, byte 1 = 600 & 0xff
        let mut dgram = vec![(5 << 2) | 0x02, 88, 0x12, 0x34];
        dgram.resize(13, 0);
        let d = Ddp::parse(&dgram).unwrap();
        assert_eq!((d.hops, d.length, d.checksum), (5, 600, 0x1234));
        assert!(d.to_string().ends_with("hops 5 len 600 (wire 13) cksum 0x1234"));
    }

    #[test]
    fn ddp_rejects_short_header() {
        assert!(Ddp::parse(&[0; 12]).is_none());
    }
}
