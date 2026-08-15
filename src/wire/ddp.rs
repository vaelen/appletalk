// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Datagram Delivery Protocol — the AppleTalk network layer.

use std::fmt;

use super::{Addr, Encode, DDP_AEP, DDP_ATP, DDP_NBP, DDP_ZIP};

/// The DDP checksum (Inside AppleTalk, PDF 120): add each byte, rotate the
/// running total left one bit, and substitute $FFFF for a zero result because
/// a zero checksum on the wire means "not computed".
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u16 = 0;
    for &b in bytes {
        sum = sum.wrapping_add(b as u16).rotate_left(1);
    }
    if sum == 0 { 0xffff } else { sum }
}

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

    /// Checksum over everything following the checksum field — destination
    /// network through the last data byte.
    pub fn compute_checksum(&self) -> u16 {
        checksum(&self.to_bytes()[4..])
    }
}

impl Encode for Ddp {
    fn encode(&self, out: &mut Vec<u8>) {
        let len = (13 + self.data.len()) as u16;
        // byte 0: 2 bits reserved, 4 bits hops, top 2 bits of a 10-bit length.
        out.push(((self.hops & 0x0f) << 2) | ((len >> 8) as u8 & 0x03));
        out.push(len as u8);
        out.extend(self.checksum.to_be_bytes());
        out.extend(self.dst.net.to_be_bytes());
        out.extend(self.src.net.to_be_bytes());
        out.push(self.dst.node);
        out.push(self.src.node);
        out.push(self.dst_socket);
        out.push(self.src_socket);
        out.push(self.typ);
        out.extend(&self.data);
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

    #[test]
    fn ddp_encodes_known_bytes() {
        let d = Ddp {
            hops: 0,
            length: 0, // deliberately wrong; encode must ignore it
            checksum: 0,
            dst: Addr { net: 0, node: 255 },
            dst_socket: 2,
            src: Addr { net: 65280, node: 128 },
            src_socket: 253,
            typ: 2,
            data: vec![1, 2, 3, 4],
        };
        assert_eq!(
            d.to_bytes(),
            vec![
                0x00, 17, // hops 0, recomputed length 13 + 4
                0x00, 0x00, // checksum
                0x00, 0x00, 0xff, 0x00, // dst net 0, src net 65280
                255, 128, // dst node, src node
                2, 253, // dst socket, src socket
                2, // type
                1, 2, 3, 4,
            ]
        );
    }

    #[test]
    fn ddp_encodes_hops_and_10_bit_length() {
        let mut d = Ddp::parse(&[0x00, 13, 0, 0, 0, 3, 0, 5, 1, 2, 6, 7, 3]).unwrap();
        d.hops = 5;
        d.data = vec![0; 587 - 13]; // 574 bytes -> length 587
        let out = d.to_bytes();
        assert_eq!(out[0], (5 << 2) | 0x02); // hops 5, length bit 9 set
        assert_eq!(out[1], 587u16 as u8 & 0xff);
    }

    #[test]
    fn ddp_round_trips() {
        let d = Ddp::parse(&[
            0x14, 17, 0x12, 0x34, 0x00, 0x03, 0xff, 0x00, 42, 128, 253, 6, 3, 9, 9, 9, 9,
        ])
        .unwrap();
        assert_eq!(Ddp::parse(&d.to_bytes()), Some(d));
    }

    #[test]
    fn ddp_checksum_matches_the_book_algorithm() {
        // Add each byte then rotate left one bit; $FFFF if the result is zero.
        // For [0x01]: 0 + 1 = 1, rotate -> 2.
        assert_eq!(checksum(&[0x01]), 2);
        // For [0x01, 0x02]: 1 -> 2, 2 + 2 = 4, rotate -> 8.
        assert_eq!(checksum(&[0x01, 0x02]), 8);
        // A zero result becomes all ones, since 0 means "not computed".
        assert_eq!(checksum(&[0x00]), 0xffff);
    }

    #[test]
    fn ddp_computes_checksum_over_bytes_after_the_field() {
        let d = Ddp::parse(&[0x00, 14, 0, 0, 0, 3, 0, 5, 1, 2, 6, 7, 3, 0xaa]).unwrap();
        let bytes = d.to_bytes();
        assert_eq!(d.compute_checksum(), checksum(&bytes[4..]));
        // Prove the offset matters: checksum over wrong range must differ
        assert_ne!(d.compute_checksum(), checksum(&bytes));
    }
}
