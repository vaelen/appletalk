// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! RTMP: the Routing Table Maintenance Protocol, DDP types 1 and 5.
//!
//! Layouts from Inside AppleTalk, PDF 138-139 (Data) and 140-142 (tuples,
//! Request, Response and RDR).
#![allow(dead_code)]

use std::fmt;

use super::{Addr, Encode};

/// One network range and its distance in hops. Extended tuples are six bytes
/// and carry a trailer byte whose value differs between RTMP and AURP;
/// nonextended tuples are three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkTuple {
    pub range: (u16, u16),
    pub extended: bool,
    /// Hops. 31 means the sender believes the entry is bad and wants its
    /// neighbours to notice (PDF 137).
    pub distance: u8,
}

impl NetworkTuple {
    /// Returns the tuple and the bytes after it. The high bit of the distance
    /// byte tells the two forms apart: set means a six-byte extended tuple
    /// <start, distance|0x80, end, trailer>, clear a three-byte <net, distance>.
    pub fn parse(p: &[u8]) -> Option<(Self, &[u8])> {
        let b = p.get(..3)?;
        let start = u16::from_be_bytes([b[0], b[1]]);
        if b[2] & 0x80 == 0 {
            let t = NetworkTuple { range: (start, start), extended: false, distance: b[2] };
            return Some((t, &p[3..]));
        }
        let b = p.get(..6)?;
        // b[5] is the trailer: the RTMP version marker 0x82, unused in AURP.
        let end = u16::from_be_bytes([b[3], b[4]]);
        let t = NetworkTuple { range: (start, end), extended: true, distance: b[2] & 0x7f };
        Some((t, &p[6..]))
    }

    /// `trailer` is the sixth byte of an extended tuple: 0x82 in RTMP, 0x00 in
    /// AURP. A nonextended tuple has no trailer, so the argument is ignored.
    pub fn encode_with(&self, out: &mut Vec<u8>, trailer: u8) {
        out.extend(self.range.0.to_be_bytes());
        if !self.extended {
            out.push(self.distance & 0x7f);
            return;
        }
        out.push(self.distance | 0x80);
        out.extend(self.range.1.to_be_bytes());
        out.push(trailer);
    }
}

/// The trailer byte RTMP puts on an extended tuple: also its version marker.
const RTMP_TRAILER: u8 = 0x82;

/// The three-byte version marker that stands in for the first tuple on a
/// nonextended network (PDF 139).
const VERSION_MARKER: [u8; 3] = [0x00, 0x00, RTMP_TRAILER];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rtmp {
    /// DDP type 1. `range` is Some on an extended network (the first tuple) and None on a
    /// nonextended one (the 00 00 82 version marker). An RTMP Response is a Data with no tuples.
    Data { sender: Addr, range: Option<(u16, u16)>, tuples: Vec<NetworkTuple> },
    /// DDP type 5, function 1.
    Request,
    /// DDP type 5, function 2 (split horizon) or 3 (whole table).
    Rdr { split_horizon: bool },
}

impl Rtmp {
    pub fn parse(ddp_type: u8, p: &[u8]) -> Option<Self> {
        match ddp_type {
            super::DDP_RTMP_DATA => Self::parse_data(p),
            super::DDP_RTMP_REQ => match p {
                [1] => Some(Rtmp::Request),
                [2] => Some(Rtmp::Rdr { split_horizon: true }),
                [3] => Some(Rtmp::Rdr { split_horizon: false }),
                _ => None,
            },
            _ => None,
        }
    }

    fn parse_data(p: &[u8]) -> Option<Self> {
        let h = p.get(..4)?;
        // The sender ID is length-prefixed in *bits*; on AppleTalk it is always 8.
        if h[2] != 8 {
            return None;
        }
        let sender = Addr { net: u16::from_be_bytes([h[0], h[1]]), node: h[3] };
        let mut rest = p.get(4..)?;
        let range = if rest.get(..3) == Some(&VERSION_MARKER[..]) {
            rest = &rest[3..];
            None
        } else {
            let (first, tail) = NetworkTuple::parse(rest)?;
            if !first.extended {
                return None;
            }
            rest = tail;
            Some(first.range)
        };
        let mut tuples = Vec::new();
        while !rest.is_empty() {
            let (t, tail) = NetworkTuple::parse(rest)?;
            tuples.push(t);
            rest = tail;
        }
        Some(Rtmp::Data { sender, range, tuples })
    }

    /// The DDP protocol type this variant travels as.
    pub fn ddp_type(&self) -> u8 {
        match self {
            Rtmp::Data { .. } => super::DDP_RTMP_DATA,
            Rtmp::Request | Rtmp::Rdr { .. } => super::DDP_RTMP_REQ,
        }
    }
}

impl fmt::Display for Rtmp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Rtmp::Data { sender, range, tuples } => {
                write!(f, "rtmp-data from {sender}")?;
                if let Some((start, end)) = range {
                    write!(f, " range {start}-{end}")?;
                }
                for (i, t) in tuples.iter().enumerate() {
                    f.write_str(if i == 0 { ": " } else { ", " })?;
                    if t.extended {
                        write!(f, "{}-{} d{}", t.range.0, t.range.1, t.distance)?;
                    } else {
                        write!(f, "{} d{}", t.range.0, t.distance)?;
                    }
                }
                Ok(())
            }
            Rtmp::Request => f.write_str("rtmp-request"),
            Rtmp::Rdr { split_horizon: true } => f.write_str("rtmp-rdr split-horizon"),
            Rtmp::Rdr { split_horizon: false } => f.write_str("rtmp-rdr full"),
        }
    }
}

impl Encode for Rtmp {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Rtmp::Data { sender, range, tuples } => {
                out.extend(sender.net.to_be_bytes());
                out.push(8); // sender ID length, in bits
                out.push(sender.node);
                match *range {
                    Some((start, end)) => {
                        let first =
                            NetworkTuple { range: (start, end), extended: true, distance: 0 };
                        first.encode_with(out, RTMP_TRAILER);
                    }
                    None => out.extend(VERSION_MARKER),
                }
                for t in tuples {
                    t.encode_with(out, RTMP_TRAILER);
                }
            }
            Rtmp::Request => out.push(1),
            Rtmp::Rdr { split_horizon } => out.push(if *split_horizon { 2 } else { 3 }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Addr, Encode};

    #[test]
    fn data_on_an_extended_network() {
        let p = [
            0x1a, 0x90, 8, 1,                      // sender 6800.1
            0x1a, 0x90, 0x80, 0x1a, 0x90, 0x82,    // first tuple: range 6800-6800, distance 0
            0x1a, 0x91, 0x01,                      // 6801 at 1 hop, nonextended
            0x0b, 0x59, 0x82, 0x0b, 0x59, 0x82,    // 2905-2905 at 2 hops
        ];
        let r = Rtmp::parse(1, &p).unwrap();
        let Rtmp::Data { sender, range, tuples } = &r else { panic!() };
        assert_eq!(*sender, Addr { net: 6800, node: 1 });
        assert_eq!(*range, Some((6800, 6800)));
        assert_eq!(tuples.len(), 2);
        assert_eq!(tuples[0], NetworkTuple { range: (6801, 6801), extended: false, distance: 1 });
        assert_eq!(tuples[1], NetworkTuple { range: (2905, 2905), extended: true, distance: 2 });
        assert_eq!(r.to_string(), "rtmp-data from 6800.1 range 6800-6800: 6801 d1, 2905-2905 d2");
        assert_eq!(r.to_bytes(), p);
    }

    #[test]
    fn data_on_a_nonextended_network_carries_the_version_marker() {
        let p = [0x00, 0x05, 8, 0x80, 0x00, 0x00, 0x82, 0x00, 0x07, 0x1f];
        let r = Rtmp::parse(1, &p).unwrap();
        let Rtmp::Data { sender, range, tuples } = &r else { panic!() };
        assert_eq!((*sender, *range), (Addr { net: 5, node: 128 }, None));
        assert_eq!(tuples, &[NetworkTuple { range: (7, 7), extended: false, distance: 31 }]);
        assert_eq!(r.to_string(), "rtmp-data from 5.128: 7 d31");
        assert_eq!(r.to_bytes(), p);
    }

    #[test]
    fn response_is_a_data_with_no_tuples() {
        let p = [0x1a, 0x90, 8, 1, 0x1a, 0x90, 0x80, 0x1a, 0x90, 0x82];
        let r = Rtmp::parse(1, &p).unwrap();
        assert!(matches!(&r, Rtmp::Data { tuples, .. } if tuples.is_empty()));
        assert_eq!(r.to_bytes(), p);
    }

    #[test]
    fn request_and_rdr() {
        assert_eq!(Rtmp::parse(5, &[1]).unwrap(), Rtmp::Request);
        assert_eq!(Rtmp::parse(5, &[2]).unwrap(), Rtmp::Rdr { split_horizon: true });
        assert_eq!(Rtmp::parse(5, &[3]).unwrap().to_string(), "rtmp-rdr full");
        assert_eq!(Rtmp::Request.to_bytes(), [1]);
        assert_eq!(Rtmp::Request.ddp_type(), 5);
        assert_eq!(Rtmp::Data { sender: Addr { net: 1, node: 1 }, range: None, tuples: vec![] }.ddp_type(), 1);
    }

    #[test]
    fn rejects() {
        assert!(Rtmp::parse(5, &[4]).is_none());          // unknown function
        assert!(Rtmp::parse(5, &[1, 0]).is_none());       // trailing byte
        assert!(Rtmp::parse(5, &[]).is_none());
        assert!(Rtmp::parse(2, &[1]).is_none());          // not an RTMP type
        assert!(Rtmp::parse(1, &[0x1a, 0x90, 8]).is_none());               // no node
        assert!(Rtmp::parse(1, &[0x1a, 0x90, 16, 1, 0, 0, 0x82]).is_none()); // id length not 8
        assert!(Rtmp::parse(1, &[0x1a, 0x90, 8, 1, 0x1a, 0x90, 0x80, 0x1a]).is_none()); // extended tuple cut short
        assert!(Rtmp::parse(1, &[0x1a, 0x90, 8, 1, 0x1a, 0x90, 0x80, 0x1a, 0x90, 0x82, 0x00]).is_none()); // dangling byte
    }

    #[test]
    fn tuple_trailer_is_a_parameter() {
        let t = NetworkTuple { range: (3, 4), extended: true, distance: 5 };
        let mut out = Vec::new();
        t.encode_with(&mut out, 0x00);
        assert_eq!(out, [0, 3, 0x85, 0, 4, 0]);
        // A nonextended tuple has no trailer at all.
        let mut out = Vec::new();
        NetworkTuple { range: (3, 3), extended: false, distance: 5 }.encode_with(&mut out, 0x82);
        assert_eq!(out, [0, 3, 5]);
    }
}
