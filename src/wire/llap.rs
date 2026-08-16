// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! LocalTalk Link Access Protocol — LocalTalk's link layer, and the payload
//! LToUDP carries.
//!
//! A 3-byte header and a data field (PDF 65–69). Node IDs are 8 bits: 0 is
//! not allowed, 1–127 are user nodes, 128–254 server nodes, and 255 is the
//! broadcast ID.

use std::fmt;

use super::Encode;

// ponytail: only this module's own tests use these until a later task wires
// the bridge in.
#[allow(dead_code)]
pub const LLAP_SHORT_DDP: u8 = 0x01;
#[allow(dead_code)]
pub const LLAP_LONG_DDP: u8 = 0x02;
#[allow(dead_code)]
pub const LLAP_ENQ: u8 = 0x81;
#[allow(dead_code)]
pub const LLAP_ACK: u8 = 0x82;
#[allow(dead_code)]
pub const LLAP_RTS: u8 = 0x84;
#[allow(dead_code)]
pub const LLAP_CTS: u8 = 0x85;

/// The largest LLAP data field (PDF 68). The header is not counted.
#[allow(dead_code)]
const MAX_DATA: usize = 600;

/// An LLAP packet: the 3-byte header and its data field.
///
/// No frame check sequence. A real LocalTalk frame ends with a CRC-CCITT over
/// the header and data, but LToUDP strips it before transmission and never
/// expects one back.
///
/// ponytail: so this cannot drive real LocalTalk hardware. Add the CRC
/// (Appendix B) when a link that wants one appears.
#[allow(dead_code)] // only this module's own tests construct one until a later task wires the bridge in
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Llap {
    pub dst: u8,
    pub src: u8,
    pub typ: u8,
    /// Empty for control packets, which have no data field at all.
    pub data: Vec<u8>,
}

#[allow(dead_code)] // only this module's own tests call these until a later task wires the bridge in
impl Llap {
    pub fn parse(p: &[u8]) -> Option<Self> {
        let h = p.get(..3)?;
        let data = &p[3..];
        match h[2] {
            // Control packets carry no data field (PDF 68).
            LLAP_ENQ | LLAP_ACK | LLAP_RTS | LLAP_CTS => {
                if !data.is_empty() {
                    return None;
                }
            }
            // $00 is invalid, and every other $80–$FF value "must be
            // discarded" (PDF 69). Types $03–$7F are other LLAP clients:
            // we parse them, and it is the caller's business whether it
            // has any use for one.
            0x00 | 0x80..=0xff => return None,
            _ => {
                if data.len() > MAX_DATA {
                    return None;
                }
                // The low 10 bits of the data field's first 2 bytes hold its
                // own length, that length field included. The high 6 bits
                // belong to the higher-level protocol (PDF 69).
                let l = data.get(..2)?;
                let len = u16::from_be_bytes([l[0] & 0x03, l[1]]) as usize;
                if len != data.len() {
                    return None;
                }
            }
        }
        Some(Llap { dst: h[0], src: h[1], typ: h[2], data: data.to_vec() })
    }

    /// A control packet. ENQ and ACK both carry the ID under discussion in
    /// *both* node bytes — `(id, id, $81)` and `(id, id, $82)`.
    pub fn control(dst: u8, src: u8, typ: u8) -> Llap {
        Llap { dst, src, typ, data: Vec::new() }
    }

    pub fn type_name(&self) -> &'static str {
        match self.typ {
            LLAP_SHORT_DDP => "short-DDP",
            LLAP_LONG_DDP => "long-DDP",
            LLAP_ENQ => "lapENQ",
            LLAP_ACK => "lapACK",
            LLAP_RTS => "lapRTS",
            LLAP_CTS => "lapCTS",
            _ => "?",
        }
    }
}

impl Encode for Llap {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.dst);
        out.push(self.src);
        out.push(self.typ);
        out.extend(&self.data);
    }
}

impl fmt::Display for Llap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} > {}  {} (${:02X})", self.src, self.dst, self.type_name(), self.typ)?;
        if !self.data.is_empty() {
            write!(f, "  {} bytes", self.data.len())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A short-header DDP data packet: node 3 to node 12, 8 bytes of data
    /// whose first two bytes carry that length.
    fn short_ddp() -> Vec<u8> {
        vec![12, 3, LLAP_SHORT_DDP, 0x00, 0x08, 4, 2, 0, 1, 2, 3]
    }

    #[test]
    fn parses_a_short_ddp_packet() {
        let l = Llap::parse(&short_ddp()).unwrap();
        assert_eq!(l.dst, 12);
        assert_eq!(l.src, 3);
        assert_eq!(l.typ, LLAP_SHORT_DDP);
        assert_eq!(l.data, [0x00, 0x08, 4, 2, 0, 1, 2, 3]);
        assert_eq!(l.to_string(), "3 > 12  short-DDP ($01)  8 bytes");
    }

    #[test]
    fn parses_a_long_ddp_packet() {
        // A 13-byte extended DDP header and no data. Byte 0 carries the hop
        // count and the top 2 bits of the length; byte 1 the rest of it.
        let mut p = vec![255, 42, LLAP_LONG_DDP];
        p.extend([0x00, 13, 0, 0, 0x1a, 0x90, 0x1a, 0x90, 1, 42, 128, 128, 4]);
        let l = Llap::parse(&p).unwrap();
        assert_eq!((l.dst, l.src, l.typ), (255, 42, LLAP_LONG_DDP));
        assert_eq!(l.data.len(), 13);
        assert_eq!(l.to_string(), "42 > 255  long-DDP ($02)  13 bytes");
    }

    #[test]
    fn parses_the_control_packets() {
        let enq = Llap::parse(&[42, 42, LLAP_ENQ]).unwrap();
        assert_eq!(enq, Llap::control(42, 42, LLAP_ENQ));
        assert_eq!(enq.to_string(), "42 > 42  lapENQ ($81)");

        let ack = Llap::parse(&[42, 42, LLAP_ACK]).unwrap();
        assert_eq!(ack.to_string(), "42 > 42  lapACK ($82)");

        assert_eq!(Llap::parse(&[9, 8, 0x84]).unwrap().to_string(), "8 > 9  lapRTS ($84)");
        assert_eq!(Llap::parse(&[9, 8, 0x85]).unwrap().to_string(), "8 > 9  lapCTS ($85)");
    }

    #[test]
    fn encodes_without_an_fcs() {
        // LToUDP carries no frame check sequence, so encode is exactly the
        // three header bytes and the data.
        assert_eq!(Llap::parse(&short_ddp()).unwrap().to_bytes(), short_ddp());
        assert_eq!(Llap::control(42, 42, LLAP_ENQ).to_bytes(), vec![42, 42, LLAP_ENQ]);
    }

    #[test]
    fn round_trips_every_type_we_accept() {
        for p in [short_ddp(), vec![1, 2, LLAP_ENQ], vec![1, 2, LLAP_ACK]] {
            let l = Llap::parse(&p).unwrap();
            assert_eq!(Llap::parse(&l.to_bytes()), Some(l), "{p:?}");
        }
    }

    #[test]
    fn rejects_a_runt() {
        assert!(Llap::parse(&[]).is_none());
        assert!(Llap::parse(&[1, 2]).is_none());
    }

    #[test]
    fn rejects_a_control_packet_carrying_data() {
        // Control packets have no data field (PDF 68).
        assert!(Llap::parse(&[42, 42, LLAP_ENQ, 0x00, 0x02]).is_none());
    }

    #[test]
    fn rejects_reserved_control_types() {
        // "must be discarded" (PDF 69) — $83 and $86 are not among the four.
        assert!(Llap::parse(&[1, 2, 0x83]).is_none());
        assert!(Llap::parse(&[1, 2, 0x86]).is_none());
        assert!(Llap::parse(&[1, 2, 0xff]).is_none());
    }

    #[test]
    fn rejects_type_zero() {
        assert!(Llap::parse(&[1, 2, 0x00, 0x00, 0x02]).is_none());
    }

    #[test]
    fn rejects_a_length_field_that_disagrees() {
        // Says 9 bytes of data field, carries 8.
        assert!(Llap::parse(&[12, 3, LLAP_SHORT_DDP, 0x00, 0x09, 4, 2, 0, 1, 2, 3]).is_none());
        // Says 2, carries 8.
        assert!(Llap::parse(&[12, 3, LLAP_SHORT_DDP, 0x00, 0x02, 4, 2, 0, 1, 2, 3]).is_none());
    }

    #[test]
    fn rejects_a_data_field_that_is_too_short_or_too_long() {
        // A data packet must carry at least its own 2-byte length field.
        assert!(Llap::parse(&[12, 3, LLAP_SHORT_DDP, 0x00]).is_none());
        // 601 bytes, one over the maximum (PDF 68).
        let mut big = vec![12, 3, LLAP_SHORT_DDP];
        big.extend((601u16).to_be_bytes());
        big.resize(3 + 601, 0);
        assert!(Llap::parse(&big).is_none());
    }

    #[test]
    fn ignores_the_high_six_bits_of_the_length() {
        // They belong to the higher-level protocol — for DDP, its reserved
        // bits and hop count — and must not be read as length.
        let p = vec![12, 3, LLAP_SHORT_DDP, 0xfc, 0x08, 4, 2, 0, 1, 2, 3];
        assert_eq!(Llap::parse(&p).unwrap().data.len(), 8);
    }
}
