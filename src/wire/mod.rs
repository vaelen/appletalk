// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Parsers for the AppleTalk protocols, bottom up: ELAP, AARP, DDP, then the
//! protocols DDP carries. Every `parse` takes a byte slice and returns None
//! rather than decoding something it does not recognise.

use std::fmt;

use pnet::util::MacAddr;

/// Serialises a wire type. Derived fields — lengths, counts, padding — are
/// recomputed here rather than read from the struct, so a parsed packet whose
/// length field disagreed with its data cannot be re-transmitted that way.
///
/// Implemented by Tasks 3-6 for the remaining protocols; nothing consumes it yet.
#[allow(dead_code)]
pub trait Encode {
    /// Appends to `out` so nested layers share one allocation.
    fn encode(&self, out: &mut Vec<u8>);

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }
}

mod aarp;
mod aep;
mod atp;
mod ddp;
mod nbp;
mod zip;

pub use aarp::Aarp;
// Nothing in this crate names Echo/Func/NbpFunc/NbpTuple directly yet — they
// are matched through Display and the Body/DdpBody enums instead — so the
// re-export otherwise trips unused_imports.
#[allow(unused_imports)]
pub use aep::{Aep, Echo};
#[allow(unused_imports)]
pub use atp::{Atp, Func};
pub use ddp::Ddp;
#[allow(unused_imports)]
pub use nbp::{Nbp, NbpFunc, NbpTuple};
pub use zip::Zip;

pub const DDP: u16 = 0x809b; // AppleTalk Datagram Delivery Protocol
pub const AARP: u16 = 0x80f3; // AppleTalk Address Resolution Protocol

// DDP protocol types.
pub const DDP_NBP: u8 = 2;
pub const DDP_ATP: u8 = 3;
pub const DDP_AEP: u8 = 4;
pub const DDP_ZIP: u8 = 6;

pub(crate) fn mac(b: &[u8]) -> Option<MacAddr> {
    Some(MacAddr::from(<[u8; 6]>::try_from(b).ok()?))
}

/// Reads a length-prefixed (Pascal) string, returning it and the rest.
///
/// ponytail: AppleTalk names are Mac OS Roman; non-ASCII bytes become '.'
/// rather than mangling them. Swap in encoding_rs::MACINTOSH if accented zone
/// names start mattering.
fn pstring(p: &[u8]) -> Option<(String, &[u8])> {
    let len = *p.first()? as usize;
    let s = p.get(1..1 + len)?;
    let text = s
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect();
    Some((text, &p[1 + len..]))
}

/// An AppleTalk network address: 16-bit network, 8-bit node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addr {
    pub net: u16,
    pub node: u8,
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.net, self.node)
    }
}

// ---------------------------------------------------------------- link layer

/// An Ethernet frame carrying AppleTalk (ELAP).
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub dst: MacAddr,
    pub src: MacAddr,
    /// EtherType, or the SNAP protocol when `snap` is set.
    pub proto: u16,
    /// True for Phase 2: IEEE 802.3 + 802.2 LLC + SNAP.
    pub snap: bool,
    /// Owned, so a decoded packet can cross a channel to a frontend. pnet
    /// hands out a borrow of its own buffer that dies on the next read.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Phase 2 EtherTalk is 802.3 (the type field is a *length*) + LLC + SNAP,
    /// so the real protocol number sits 8 bytes further in. Phase 1 used a
    /// plain EtherType. Non-SNAP LLC frames return None.
    pub fn parse(b: &[u8]) -> Option<Self> {
        let (dst, src) = (mac(b.get(..6)?)?, mac(b.get(6..12)?)?);
        let typelen = u16::from_be_bytes([b[12], b[13]]);
        let body = b.get(14..)?;
        if typelen > 1500 {
            let payload = body.to_vec();
            return Some(Frame { dst, src, proto: typelen, snap: false, payload });
        }
        // 802.3: trim the padding Ethernet added to reach the 60-byte minimum.
        match body.get(..typelen as usize)? {
            // DSAP AA, SSAP AA, control 03, 3-byte OUI, 2-byte protocol.
            [0xaa, 0xaa, 0x03, _, _, _, hi, lo, rest @ ..] => Some(Frame {
                dst,
                src,
                proto: u16::from_be_bytes([*hi, *lo]),
                snap: true,
                payload: rest.to_vec(),
            }),
            _ => None,
        }
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self.proto {
            DDP => "DDP",
            AARP => "AARP",
            _ => "?",
        };
        write!(
            f,
            "{} > {}  {name} ({:#06x})  phase {}  {} bytes",
            self.src,
            self.dst,
            self.proto,
            // ponytail: SNAP presence stands in for phase detection; good
            // enough unless you meet a Phase 1 net that also uses SNAP.
            if self.snap { 2 } else { 1 },
            self.payload.len()
        )
    }
}

// ------------------------------------------------------------- decode tree

/// One captured frame, decoded as far down the stack as its bytes could be
/// followed. Owned throughout, so it can be sent to a frontend.
#[derive(Debug, PartialEq, Eq)]
pub struct Packet {
    pub frame: Frame,
    pub body: Body,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Body {
    Aarp(Aarp),
    Ddp(Ddp, DdpBody),
    /// A header we could not follow. The bytes are in `Frame::payload`.
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DdpBody {
    Atp(Atp),
    Aep(Aep),
    Nbp(Nbp),
    Zip(Zip),
    /// A DDP type we do not decode, or a body we could not follow. The bytes
    /// are in `Ddp::data`.
    Unknown,
}

/// Decodes one Ethernet frame. Returns None for anything that is not
/// AppleTalk — the capture thread uses this to filter before queueing.
///
/// Note that a *recognised* protocol whose body fails to parse still yields a
/// Packet, with `Unknown` at the layer that stopped: the caller can fall back
/// to hexdumping the enclosing layer's bytes.
pub fn decode(bytes: &[u8]) -> Option<Packet> {
    let frame = Frame::parse(bytes)?;
    let body = match frame.proto {
        AARP => Aarp::parse(&frame.payload).map_or(Body::Unknown, Body::Aarp),
        DDP => match Ddp::parse(&frame.payload) {
            Some(d) => {
                let inner = match d.typ {
                    DDP_NBP => Nbp::parse(&d.data).map_or(DdpBody::Unknown, DdpBody::Nbp),
                    DDP_ATP => Atp::parse(&d.data).map_or(DdpBody::Unknown, DdpBody::Atp),
                    DDP_AEP => Aep::parse(&d.data).map_or(DdpBody::Unknown, DdpBody::Aep),
                    DDP_ZIP => Zip::parse(&d.data).map_or(DdpBody::Unknown, DdpBody::Zip),
                    _ => DdpBody::Unknown,
                };
                Body::Ddp(d, inner)
            }
            None => Body::Unknown,
        },
        _ => return None,
    };
    Some(Packet { frame, body })
}

/// Fixture builders shared by the protocol modules' tests.
#[cfg(test)]
pub(crate) mod testkit {
    /// dst, src, then body; padded to the 60-byte Ethernet minimum.
    pub fn frame(typelen: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 12];
        f.extend(typelen.to_be_bytes());
        f.extend(body);
        f.resize(60, 0);
        f
    }

    /// A length-prefixed string, as it appears in NBP and ZIP.
    pub fn ps(s: &str) -> Vec<u8> {
        let mut v = vec![s.len() as u8];
        v.extend(s.bytes());
        v
    }

    /// An ATP header with tid 4660 and user bytes 01 02 03 04.
    pub fn atp(control: u8, bitmap: u8, data: &[u8]) -> Vec<u8> {
        let mut p = vec![control, bitmap, 0x12, 0x34, 1, 2, 3, 4];
        p.extend(data);
        p
    }

    /// A 28-byte AARP packet: src 65280.128 at 00:05:02:aa:bb:cc,
    /// dst 65280.42 with an unknown MAC.
    pub fn aarp(op: u16, extra: &[u8]) -> Vec<u8> {
        let mut p = vec![0x00, 0x01, 0x80, 0x9b, 6, 4];
        p.extend(op.to_be_bytes());
        p.extend([0x00, 0x05, 0x02, 0xaa, 0xbb, 0xcc]);
        p.extend([0x00, 0xff, 0x00, 128]);
        p.extend([0; 6]);
        p.extend([0x00, 0xff, 0x00, 42]);
        p.extend(extra);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::testkit::*;

    #[test]
    fn phase2_ddp() {
        let body = [
            0xaa, 0xaa, 0x03, 0x08, 0x00, 0x07, 0x80, 0x9b, // LLC + SNAP
            1, 2, 3, 4,
        ];
        let bytes = frame(body.len() as u16, &body);
        let f = Frame::parse(&bytes).unwrap();
        assert_eq!((f.proto, f.snap), (DDP, true));
        assert_eq!(f.payload, [1, 2, 3, 4]);
        assert_eq!(
            f.to_string(),
            "ff:ff:ff:ff:ff:ff > ff:ff:ff:ff:ff:ff  DDP (0x809b)  phase 2  4 bytes"
        );
    }

    #[test]
    fn phase2_aarp() {
        let body = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x80, 0xf3, 9];
        let bytes = frame(body.len() as u16, &body);
        let f = Frame::parse(&bytes).unwrap();
        assert_eq!((f.proto, f.snap), (AARP, true));
        assert_eq!(f.payload, [9]);
    }

    #[test]
    fn phase1_raw_ethertype() {
        let bytes = frame(DDP, &[1, 2, 3]);
        let f = Frame::parse(&bytes).unwrap();
        assert_eq!((f.proto, f.snap), (DDP, false));
        assert_eq!(f.payload[..3], [1, 2, 3]); // no length field: padding included
    }

    #[test]
    fn frame_ignores_non_snap_and_short() {
        assert!(Frame::parse(&frame(3, &[0x42, 0x42, 0x03])).is_none()); // plain LLC
        assert!(Frame::parse(&[0; 10]).is_none()); // runt
        assert!(Frame::parse(&frame(1400, &[0xaa; 8])).is_none()); // length > frame
    }

    #[test]
    fn decode_walks_the_whole_stack() {
        // Ethernet + SNAP -> DDP type 3 -> ATP TReq.
        let mut dgram = vec![
            0x00, 0, // hops 0, length patched below
            0x00, 0x00, // no checksum
            0x00, 0x03, 0xff, 0x00, // dst net 3, src net 65280
            42, 128, // dst node, src node
            253, 6, // dst socket, src socket
            DDP_ATP,
        ];
        dgram.extend(atp(0x40, 0x01, &[7]));
        dgram[1] = dgram.len() as u8;

        let mut body = vec![0xaa, 0xaa, 0x03, 0x08, 0x00, 0x07, 0x80, 0x9b];
        body.extend(&dgram);
        let p = decode(&frame(body.len() as u16, &body)).unwrap();

        assert_eq!(p.frame.proto, DDP);
        match p.body {
            Body::Ddp(d, DdpBody::Atp(a)) => {
                assert_eq!((d.typ, d.dst), (DDP_ATP, Addr { net: 3, node: 42 }));
                assert_eq!((a.func, a.tid), (Func::Req, 4660));
                assert_eq!(a.data, [7]);
            }
            other => panic!("expected ATP over DDP, got {other:?}"),
        }
    }

    #[test]
    fn decode_skips_non_appletalk() {
        assert!(decode(&frame(0x0800, &[0; 20])).is_none()); // IPv4
        assert!(decode(&[0; 10]).is_none()); // runt
    }

    #[test]
    fn decode_keeps_bytes_for_layers_it_cannot_follow() {
        // DDP type 7 (ADSP) — recognised as DDP, but we have no ADSP parser,
        // so the datagram still decodes and its body stays available as bytes.
        let mut dgram = vec![0x00, 17, 0x00, 0x00, 0x00, 0x03, 0xff, 0x00, 42, 128, 253, 6, 7];
        dgram.extend([1, 2, 3, 4]);
        let mut body = vec![0xaa, 0xaa, 0x03, 0x08, 0x00, 0x07, 0x80, 0x9b];
        body.extend(&dgram);
        let p = decode(&frame(body.len() as u16, &body)).unwrap();
        match p.body {
            Body::Ddp(d, DdpBody::Unknown) => assert_eq!(d.data, [1, 2, 3, 4]),
            other => panic!("expected undecoded DDP body, got {other:?}"),
        }
    }
}
