// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! AURP: the AppleTalk Update-Based Routing Protocol tunnelled over UDP 387.
//! `docs/AURP.md` has the layouts, the worked examples and the discard table.
//!
//! stub: Task 10 gives these types their first caller; until then nothing in
//! the binary parses an AURP packet.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

use super::{pstring, put_pstring, Encode, NetworkTuple};

/// A domain identifier: the four-byte IP form, or the null form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Di {
    Null,
    Ip(Ipv4Addr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainHeader {
    pub dst: Di,
    pub src: Di,
}

/// code 0 = null: tuple ignored
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventTuple {
    pub code: u8,
    pub tuple: NetworkTuple,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    RiReq { sui: u16 },                          // flags & 0x7800
    RiRsp { last: bool, tuples: Vec<NetworkTuple> },
    RiAck { szi: bool },
    RiUpd { events: Vec<EventTuple> },
    Rd { code: i16 },
    ZiReq { nets: Vec<u16> },
    /// `extended` is Some(total tuples in the whole list) for subcode 2, None for subcode 1.
    ZiRsp { extended: Option<u16>, zones: Vec<(u16, String)> },
    GznReq { zone: String },
    /// `tuples` None = not supported (count -1).
    GznRsp { zone: String, tuples: Option<Vec<NetworkTuple>> },
    GdzlReq { start: u16 },
    /// `start` -1 = not supported. Zone names are length-prefixed (jrouter's reading; the RFC does not say).
    GdzlRsp { last: bool, start: i16, zones: Vec<String> },
    OpenReq { sui: u16, version: u16, options: Vec<(u8, Vec<u8>)> },
    OpenRsp { env: u16, rate_or_err: i16, options: Vec<(u8, Vec<u8>)> },
    Tickle,
    TickleAck,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Aurp {
    Data { dh: DomainHeader, ddp: Vec<u8> },
    Routing { dh: DomainHeader, conn: u16, seq: u16, cmd: Cmd },
}

/// The only version of the domain header, and of AURP itself.
const VERSION: u16 = 1;
const TYPE_DATA: u16 = 2;
const TYPE_ROUTING: u16 = 3;

/// The environment flags of an Open-Rsp: remapping active, hop-count reduction
/// on. The rest of that field is reserved, so it is masked off on parse.
const ENV: u16 = 0x6000;

/// The placeholder in a null event, which is one byte and carries no tuple.
const NO_TUPLE: NetworkTuple = NetworkTuple { range: (0, 0), extended: false, distance: 0 };

/// Where an optimized zone tuple's offset is measured from: the length byte of
/// the first zone name in the body, which follows the subcode, the count and
/// that first tuple's network number. The first name is always spelled out.
const ZONE_BASE: usize = 6;

impl Cmd {
    /// All four "send update information" flags: what every Open-Req and
    /// RI-Req on GlobalTalk carries.
    pub const ALL_SUI: u16 = 0x7800;
    /// On an RI-Ack: also send the zones of the networks just acked.
    pub const SZI: u16 = 0x4000;
    /// Last packet of a sequence, in RI-Rsp and GDZL-Rsp.
    pub const LAST: u16 = 0x8000;

    /// The command code this variant travels as. Subcodes live in the body.
    fn code(&self) -> u16 {
        match self {
            Cmd::RiReq { .. } => 1,
            Cmd::RiRsp { .. } => 2,
            Cmd::RiAck { .. } => 3,
            Cmd::RiUpd { .. } => 4,
            Cmd::Rd { .. } => 5,
            Cmd::ZiReq { .. } | Cmd::GznReq { .. } | Cmd::GdzlReq { .. } => 6,
            Cmd::ZiRsp { .. } | Cmd::GznRsp { .. } | Cmd::GdzlRsp { .. } => 7,
            Cmd::OpenReq { .. } => 8,
            Cmd::OpenRsp { .. } => 9,
            Cmd::Tickle => 14,
            Cmd::TickleAck => 15,
        }
    }

    /// The flags word. Everything not listed here is reserved and written 0.
    fn flags(&self) -> u16 {
        match self {
            Cmd::RiReq { sui } | Cmd::OpenReq { sui, .. } => sui & Cmd::ALL_SUI,
            Cmd::RiRsp { last: true, .. } | Cmd::GdzlRsp { last: true, .. } => Cmd::LAST,
            Cmd::RiAck { szi: true } => Cmd::SZI,
            Cmd::OpenRsp { env, .. } => env & ENV,
            _ => 0,
        }
    }

    fn parse(code: u16, flags: u16, b: &[u8]) -> Option<Self> {
        match code {
            1 => b.is_empty().then_some(Cmd::RiReq { sui: flags & Cmd::ALL_SUI }),
            2 => Some(Cmd::RiRsp { last: flags & Cmd::LAST != 0, tuples: parse_tuples(b)? }),
            3 => b.is_empty().then_some(Cmd::RiAck { szi: flags & Cmd::SZI != 0 }),
            4 => {
                let mut events = Vec::new();
                let mut rest = b;
                while !rest.is_empty() {
                    let (e, tail) = parse_event(rest)?;
                    events.push(e);
                    rest = tail;
                }
                Some(Cmd::RiUpd { events })
            }
            5 => {
                let &[hi, lo] = b else { return None };
                Some(Cmd::Rd { code: i16::from_be_bytes([hi, lo]) })
            }
            6 | 7 => Self::parse_sub(code, flags, b),
            8 => {
                let h = b.get(..3)?;
                Some(Cmd::OpenReq {
                    sui: flags & Cmd::ALL_SUI,
                    version: u16::from_be_bytes([h[0], h[1]]),
                    options: parse_options(b.get(3..)?, h[2])?,
                })
            }
            9 => {
                let h = b.get(..3)?;
                Some(Cmd::OpenRsp {
                    env: flags & ENV,
                    rate_or_err: i16::from_be_bytes([h[0], h[1]]),
                    options: parse_options(b.get(3..)?, h[2])?,
                })
            }
            14 => b.is_empty().then_some(Cmd::Tickle),
            15 => b.is_empty().then_some(Cmd::TickleAck),
            _ => None, // 10-13 and above 15 are undefined
        }
    }

    /// Commands 6 and 7 carry a two-byte subcode as the first field of the body.
    fn parse_sub(code: u16, flags: u16, b: &[u8]) -> Option<Self> {
        let sub = u16::from_be_bytes([*b.first()?, *b.get(1)?]);
        let rest = b.get(2..)?;
        match (code, sub) {
            (6, 1) => {
                if rest.len() % 2 != 0 {
                    return None;
                }
                let nets = rest.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Some(Cmd::ZiReq { nets })
            }
            (7, 1) | (7, 2) => parse_zi_rsp(sub, b),
            (6, 3) => {
                let (zone, tail) = pstring(rest)?;
                tail.is_empty().then_some(Cmd::GznReq { zone })
            }
            (7, 3) => {
                let (zone, tail) = pstring(rest)?;
                let h = tail.get(..2)?;
                let count = i16::from_be_bytes([h[0], h[1]]);
                if count < 0 {
                    // -1 is "not supported"; nothing may follow it.
                    return (count == -1 && tail.len() == 2).then_some(Cmd::GznRsp { zone, tuples: None });
                }
                let mut tuples = Vec::new();
                let mut rest = tail.get(2..)?;
                for _ in 0..count {
                    let (t, tail) = NetworkTuple::parse(rest)?;
                    tuples.push(t);
                    rest = tail;
                }
                rest.is_empty().then_some(Cmd::GznRsp { zone, tuples: Some(tuples) })
            }
            (6, 4) => {
                let &[hi, lo] = rest else { return None };
                Some(Cmd::GdzlReq { start: u16::from_be_bytes([hi, lo]) })
            }
            (7, 4) => {
                let h = rest.get(..2)?;
                let mut zones = Vec::new();
                let mut rest = rest.get(2..)?;
                while !rest.is_empty() {
                    let (z, tail) = pstring(rest)?;
                    zones.push(z);
                    rest = tail;
                }
                Some(Cmd::GdzlRsp {
                    last: flags & Cmd::LAST != 0,
                    start: i16::from_be_bytes([h[0], h[1]]),
                    zones,
                })
            }
            _ => None,
        }
    }

    /// The body after the routing header, subcode included.
    fn encode_body(&self, out: &mut Vec<u8>) {
        match self {
            Cmd::RiReq { .. } | Cmd::RiAck { .. } | Cmd::Tickle | Cmd::TickleAck => {}
            Cmd::RiRsp { tuples, .. } => {
                for t in tuples {
                    // AURP's extended tuple ends in 0x00 where RTMP's carries 0x82.
                    t.encode_with(out, 0x00);
                }
            }
            Cmd::RiUpd { events } => {
                for e in events {
                    encode_event(out, e);
                }
            }
            Cmd::Rd { code } => out.extend(code.to_be_bytes()),
            Cmd::ZiReq { nets } => {
                out.extend(1u16.to_be_bytes());
                for n in nets {
                    out.extend(n.to_be_bytes());
                }
            }
            Cmd::ZiRsp { extended, zones } => encode_zi_rsp(out, *extended, zones),
            Cmd::GznReq { zone } => {
                out.extend(3u16.to_be_bytes());
                put_pstring(out, zone);
            }
            Cmd::GznRsp { zone, tuples } => {
                out.extend(3u16.to_be_bytes());
                put_pstring(out, zone);
                match tuples {
                    None => out.extend((-1i16).to_be_bytes()),
                    Some(tuples) => {
                        out.extend((tuples.len() as u16).to_be_bytes());
                        for t in tuples {
                            t.encode_with(out, 0x00);
                        }
                    }
                }
            }
            Cmd::GdzlReq { start } => {
                out.extend(4u16.to_be_bytes());
                out.extend(start.to_be_bytes());
            }
            Cmd::GdzlRsp { start, zones, .. } => {
                out.extend(4u16.to_be_bytes());
                out.extend(start.to_be_bytes());
                for z in zones {
                    put_pstring(out, z);
                }
            }
            Cmd::OpenReq { version, options, .. } => {
                out.extend(version.to_be_bytes());
                encode_options(out, options);
            }
            Cmd::OpenRsp { rate_or_err, options, .. } => {
                out.extend(rate_or_err.to_be_bytes());
                encode_options(out, options);
            }
        }
    }
}

/// A domain identifier: a length byte, an authority byte, then the authority's
/// own bytes. The length counts everything after itself and is always odd, so
/// the whole DI is an even number of bytes.
fn parse_di(p: &[u8]) -> Option<(Di, &[u8])> {
    let h = p.get(..2)?;
    match (h[1], h[0]) {
        (0, 1) => Some((Di::Null, &p[2..])),
        // Two reserved bytes, then the address. They are ignored on receive.
        (1, 7) => {
            let b = p.get(4..8)?;
            Some((Di::Ip(Ipv4Addr::new(b[0], b[1], b[2], b[3])), &p[8..]))
        }
        _ => None, // unknown authority, or a known one with the wrong length
    }
}

fn encode_di(out: &mut Vec<u8>, di: &Di) {
    match di {
        Di::Null => out.extend([0x01, 0x00]),
        Di::Ip(a) => {
            out.extend([0x07, 0x01, 0x00, 0x00]);
            out.extend(a.octets());
        }
    }
}

fn parse_tuples(mut rest: &[u8]) -> Option<Vec<NetworkTuple>> {
    let mut tuples = Vec::new();
    while !rest.is_empty() {
        let (t, tail) = NetworkTuple::parse(rest)?;
        tuples.push(t);
        rest = tail;
    }
    Some(tuples)
}

/// An event tuple is a network tuple behind an event code, with one difference
/// that matters: the extended form is six bytes with **no** trailing zero. The
/// null event (code 0) is a single byte.
fn parse_event(p: &[u8]) -> Option<(EventTuple, &[u8])> {
    let code = *p.first()?;
    if code == 0 {
        return Some((EventTuple { code, tuple: NO_TUPLE }, &p[1..]));
    }
    let b = p.get(1..4)?;
    let start = u16::from_be_bytes([b[0], b[1]]);
    if b[2] & 0x80 == 0 {
        let tuple = NetworkTuple { range: (start, start), extended: false, distance: b[2] };
        return Some((EventTuple { code, tuple }, &p[4..]));
    }
    let e = p.get(4..6)?;
    let end = u16::from_be_bytes([e[0], e[1]]);
    let tuple = NetworkTuple { range: (start, end), extended: true, distance: b[2] & 0x7f };
    Some((EventTuple { code, tuple }, &p[6..]))
}

fn encode_event(out: &mut Vec<u8>, e: &EventTuple) {
    out.push(e.code);
    if e.code == 0 {
        return;
    }
    out.extend(e.tuple.range.0.to_be_bytes());
    if !e.tuple.extended {
        out.push(e.tuple.distance & 0x7f);
        return;
    }
    out.push(e.tuple.distance | 0x80);
    out.extend(e.tuple.range.1.to_be_bytes());
}

/// `b` is the whole body, subcode included, because an optimized tuple's offset
/// is measured from a fixed place in it.
fn parse_zi_rsp(sub: u16, b: &[u8]) -> Option<Cmd> {
    let h = b.get(2..4)?;
    let count = u16::from_be_bytes([h[0], h[1]]);
    let mut zones = Vec::new();
    let mut rest = b.get(4..)?;
    while !rest.is_empty() {
        let t = rest.get(..3)?;
        let net = u16::from_be_bytes([t[0], t[1]]);
        if t[2] & 0x80 == 0 {
            // Long tuple: the name is spelled out here.
            let (name, tail) = pstring(&rest[2..])?;
            zones.push((net, name));
            rest = tail;
        } else {
            // Optimized tuple: an offset to a name already in this packet.
            let off = (u16::from_be_bytes([t[2], *rest.get(3)?]) & 0x7fff) as usize;
            let at = b.get(ZONE_BASE + off..)?;
            if at.first()? & 0x80 != 0 {
                return None; // points at another offset, not a name
            }
            let (name, _) = pstring(at)?;
            zones.push((net, name));
            rest = &rest[4..];
        }
    }
    // The count is the whole list's on subcode 2 and cannot be recomputed; the
    // RFC says process every tuple present regardless of it either way.
    Some(Cmd::ZiRsp { extended: (sub == 2).then_some(count), zones })
}

fn encode_zi_rsp(out: &mut Vec<u8>, extended: Option<u16>, zones: &[(u16, String)]) {
    let (sub, count) = match extended {
        Some(total) => (2u16, total),
        None => (1, zones.len() as u16),
    };
    out.extend(sub.to_be_bytes());
    out.extend(count.to_be_bytes());
    // Offset of each name's length byte, measured as a receiver measures it.
    let base = out.len() + 2;
    let mut seen: HashMap<&str, u16> = HashMap::new();
    for (net, name) in zones {
        out.extend(net.to_be_bytes());
        match seen.get(name.as_str()) {
            Some(&off) => out.extend((off | 0x8000).to_be_bytes()),
            None => {
                // ponytail: exact match only, so "Zone" and "zone" each get
                // spelled out. Lowercase the key if the saved bytes ever matter.
                seen.insert(name.as_str(), (out.len() - base) as u16);
                put_pstring(out, name);
            }
        }
    }
}

fn parse_options(p: &[u8], count: u8) -> Option<Vec<(u8, Vec<u8>)>> {
    let mut options = Vec::new();
    let mut rest = p;
    for _ in 0..count {
        // The length counts the type byte and the data, so it is never 0.
        let len = *rest.first()? as usize;
        if len == 0 {
            return None;
        }
        let t = rest.get(1..1 + len)?;
        options.push((t[0], t[1..].to_vec()));
        rest = &rest[1 + len..];
    }
    rest.is_empty().then_some(options)
}

fn encode_options(out: &mut Vec<u8>, options: &[(u8, Vec<u8>)]) {
    out.push(options.len() as u8);
    for (t, data) in options {
        out.push((1 + data.len()) as u8);
        out.push(*t);
        out.extend(data);
    }
}

impl Aurp {
    pub fn parse(p: &[u8]) -> Option<Self> {
        let (dst, rest) = parse_di(p)?;
        let (src, rest) = parse_di(rest)?;
        let h = rest.get(..6)?;
        if u16::from_be_bytes([h[0], h[1]]) != VERSION {
            return None;
        }
        // h[2..4] is reserved and ignored.
        let dh = DomainHeader { dst, src };
        let body = &rest[6..];
        match u16::from_be_bytes([h[4], h[5]]) {
            // One whole DDP datagram with the 13-byte extended header.
            TYPE_DATA => (body.len() >= 13).then(|| Aurp::Data { dh, ddp: body.to_vec() }),
            TYPE_ROUTING => {
                let h = body.get(..8)?;
                let cmd = Cmd::parse(
                    u16::from_be_bytes([h[4], h[5]]),
                    u16::from_be_bytes([h[6], h[7]]),
                    &body[8..],
                )?;
                Some(Aurp::Routing {
                    dh,
                    conn: u16::from_be_bytes([h[0], h[1]]),
                    seq: u16::from_be_bytes([h[2], h[3]]),
                    cmd,
                })
            }
            _ => None,
        }
    }
}

impl fmt::Display for Di {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Di::Null => f.write_str("null"),
            Di::Ip(a) => write!(f, "{a}"),
        }
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Cmd::RiReq { .. } => f.write_str("ri-req"),
            Cmd::RiRsp { last, tuples } => {
                write!(f, "ri-rsp{} {} nets", if *last { " last" } else { "" }, tuples.len())
            }
            Cmd::RiAck { szi } => write!(f, "ri-ack{}", if *szi { " szi" } else { "" }),
            Cmd::RiUpd { events } => write!(f, "ri-upd {} events", events.len()),
            Cmd::Rd { code } => write!(f, "rd {code}"),
            Cmd::ZiReq { nets } => {
                f.write_str("zi-req")?;
                nets.iter().try_for_each(|n| write!(f, " {n}"))
            }
            Cmd::ZiRsp { zones, .. } => write!(f, "zi-rsp {} zones", zones.len()),
            Cmd::GznReq { zone } => write!(f, "gzn-req \"{zone}\""),
            Cmd::GznRsp { .. } => f.write_str("gzn-rsp"),
            Cmd::GdzlReq { start } => write!(f, "gdzl-req {start}"),
            Cmd::GdzlRsp { .. } => f.write_str("gdzl-rsp"),
            Cmd::OpenReq { sui, version, .. } => write!(f, "open-req sui {sui:04x} v{version}"),
            Cmd::OpenRsp { rate_or_err, .. } => {
                if *rate_or_err < 0 {
                    write!(f, "open-rsp error {rate_or_err}")
                } else {
                    write!(f, "open-rsp rate {rate_or_err}")
                }
            }
            Cmd::Tickle => f.write_str("tickle"),
            Cmd::TickleAck => f.write_str("tickle-ack"),
        }
    }
}

impl fmt::Display for Aurp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Aurp::Data { dh, ddp } => {
                write!(f, "aurp-data {} > {} {} bytes", dh.src, dh.dst, ddp.len())
            }
            Aurp::Routing { dh, conn, seq, cmd } => {
                write!(f, "aurp {} > {} conn {conn} seq {seq} {cmd}", dh.src, dh.dst)
            }
        }
    }
}

impl Encode for Aurp {
    fn encode(&self, out: &mut Vec<u8>) {
        let (dh, typ) = match self {
            Aurp::Data { dh, .. } => (dh, TYPE_DATA),
            Aurp::Routing { dh, .. } => (dh, TYPE_ROUTING),
        };
        encode_di(out, &dh.dst);
        encode_di(out, &dh.src);
        out.extend(VERSION.to_be_bytes());
        out.extend([0, 0]); // reserved
        out.extend(typ.to_be_bytes());
        match self {
            Aurp::Data { ddp, .. } => out.extend(ddp),
            Aurp::Routing { conn, seq, cmd, .. } => {
                out.extend(conn.to_be_bytes());
                out.extend(seq.to_be_bytes());
                out.extend(cmd.code().to_be_bytes());
                out.extend(cmd.flags().to_be_bytes());
                cmd.encode_body(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Encode;
    use std::net::Ipv4Addr;

    fn dh() -> Vec<u8> {
        vec![7, 1, 0, 0, 192, 0, 2, 1, 7, 1, 0, 0, 192, 0, 2, 2, 0, 1, 0, 0, 0, 3]
    }
    fn hdr() -> DomainHeader { DomainHeader { dst: Di::Ip(Ipv4Addr::new(192, 0, 2, 1)), src: Di::Ip(Ipv4Addr::new(192, 0, 2, 2)) } }
    fn routing(conn: u16, seq: u16, cmd: u16, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut p = dh();
        p.extend(conn.to_be_bytes()); p.extend(seq.to_be_bytes());
        p.extend(cmd.to_be_bytes()); p.extend(flags.to_be_bytes());
        p.extend(body);
        p
    }

    #[test]
    fn open_req_from_the_doc() {
        let p = routing(0x1234, 0, 8, 0x7800, &[0, 1, 0]);
        let a = Aurp::parse(&p).unwrap();
        assert_eq!(a, Aurp::Routing { dh: hdr(), conn: 0x1234, seq: 0, cmd: Cmd::OpenReq { sui: 0x7800, version: 1, options: vec![] } });
        assert_eq!(a.to_string(), "aurp 192.0.2.2 > 192.0.2.1 conn 4660 seq 0 open-req sui 7800 v1");
        assert_eq!(a.to_bytes(), p);
    }

    #[test]
    fn open_rsp_rate_and_error() {
        let ok = Aurp::parse(&routing(1, 0, 9, 0, &[0, 1, 0])).unwrap();
        assert!(matches!(ok, Aurp::Routing { cmd: Cmd::OpenRsp { rate_or_err: 1, .. }, .. }));
        let err = Aurp::parse(&routing(1, 0, 9, 0, &[0xff, 0xfb, 0])).unwrap();
        assert!(matches!(err, Aurp::Routing { cmd: Cmd::OpenRsp { rate_or_err: -5, .. }, .. }));
        assert!(err.to_string().ends_with("open-rsp error -5"));
    }

    #[test]
    fn options_round_trip_and_overrun_rejects() {
        let p = routing(1, 0, 8, 0x7800, &[0, 1, 1, 3, 1, 0xaa, 0xbb]);
        let a = Aurp::parse(&p).unwrap();
        assert!(matches!(&a, Aurp::Routing { cmd: Cmd::OpenReq { options, .. }, .. } if options == &[(1u8, vec![0xaa, 0xbb])]));
        assert_eq!(a.to_bytes(), p);
        assert!(Aurp::parse(&routing(1, 0, 8, 0x7800, &[0, 1, 1, 9, 1, 0xaa])).is_none());
    }

    #[test]
    fn ri_rsp_tuples_use_the_zero_trailer() {
        let p = routing(1, 1, 2, 0x8000, &[0x1a, 0x90, 0x80, 0x1a, 0x90, 0x00, 0x00, 0x05, 0x02]);
        let a = Aurp::parse(&p).unwrap();
        let Aurp::Routing { seq, cmd: Cmd::RiRsp { last, tuples }, .. } = &a else { panic!() };
        assert_eq!((*seq, *last), (1, true));
        assert_eq!(tuples[0], NetworkTuple { range: (6800, 6800), extended: true, distance: 0 });
        assert_eq!(tuples[1], NetworkTuple { range: (5, 5), extended: false, distance: 2 });
        assert_eq!(a.to_bytes(), p);
        assert_eq!(a.to_string(), "aurp 192.0.2.2 > 192.0.2.1 conn 1 seq 1 ri-rsp last 2 nets");
    }

    #[test]
    fn ri_upd_event_tuples_have_no_trailer() {
        let p = routing(1, 2, 4, 0, &[1, 0x1a, 0x90, 0x80, 0x1a, 0x90, 2, 0, 5, 0, 0]);
        let a = Aurp::parse(&p).unwrap();
        let Aurp::Routing { cmd: Cmd::RiUpd { events }, .. } = &a else { panic!() };
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].code, 1);
        assert_eq!(events[0].tuple.range, (6800, 6800));
        assert_eq!((events[1].code, events[1].tuple.range), (2, (5, 5)));
        assert_eq!(events[2].code, 0); // the null event is one byte
        assert_eq!(a.to_bytes(), p);
    }

    #[test]
    fn ri_ack_and_rd() {
        let a = Aurp::parse(&routing(1, 1, 3, 0x4000, &[])).unwrap();
        assert!(matches!(a, Aurp::Routing { cmd: Cmd::RiAck { szi: true }, .. }));
        let a = Aurp::parse(&routing(1, 3, 5, 0, &[0xff, 0xff])).unwrap();
        assert!(matches!(a, Aurp::Routing { cmd: Cmd::Rd { code: -1 }, .. }));
        assert!(Aurp::parse(&routing(1, 1, 3, 0, &[0])).is_none()); // ri-ack has no body
    }

    #[test]
    fn zi_rsp_optimized_tuple_from_the_doc() {
        let mut body = vec![0, 1, 0, 2, 0x1a, 0x90, 0x0c];
        body.extend(b"68k Mac Club");
        body.extend([0x0b, 0x59, 0x80, 0x00]);
        let p = routing(1, 0, 7, 0, &body);
        let a = Aurp::parse(&p).unwrap();
        let Aurp::Routing { cmd: Cmd::ZiRsp { extended, zones }, .. } = &a else { panic!() };
        assert_eq!(*extended, None);
        assert_eq!(zones, &[(6800, "68k Mac Club".to_string()), (2905, "68k Mac Club".to_string())]);
        // Encoding optimizes the repeat back into the same bytes.
        assert_eq!(a.to_bytes(), p);
        // An offset past the end of the packet is rejected.
        let mut bad = vec![0, 1, 0, 2, 0x1a, 0x90, 0x0c];
        bad.extend(b"68k Mac Club");
        bad.extend([0x0b, 0x59, 0x80, 0x40]);
        assert!(Aurp::parse(&routing(1, 0, 7, 0, &bad)).is_none());
    }

    #[test]
    fn zi_req_gzn_gdzl_tickle() {
        let a = Aurp::parse(&routing(1, 0, 6, 0, &[0, 1, 0x1a, 0x90, 0x0b, 0x59])).unwrap();
        assert!(matches!(&a, Aurp::Routing { cmd: Cmd::ZiReq { nets }, .. } if nets == &[6800, 2905]));
        assert!(Aurp::parse(&routing(1, 0, 6, 0, &[0, 1, 0x1a])).is_none()); // odd byte
        let a = Aurp::parse(&routing(1, 0, 6, 0, &[0, 3, 1, b'Z'])).unwrap();
        assert!(matches!(&a, Aurp::Routing { cmd: Cmd::GznReq { zone }, .. } if zone == "Z"));
        let a = Aurp::parse(&routing(1, 0, 7, 0, &[0, 3, 1, b'Z', 0xff, 0xff])).unwrap();
        assert!(matches!(a, Aurp::Routing { cmd: Cmd::GznRsp { tuples: None, .. }, .. }));
        let a = Aurp::parse(&routing(1, 0, 6, 0, &[0, 4, 0, 0])).unwrap();
        assert!(matches!(a, Aurp::Routing { cmd: Cmd::GdzlReq { start: 0 }, .. }));
        let a = Aurp::parse(&routing(1, 0, 7, 0x8000, &[0, 4, 0xff, 0xff])).unwrap();
        assert!(matches!(a, Aurp::Routing { cmd: Cmd::GdzlRsp { last: true, start: -1, .. }, .. }));
        assert!(Aurp::parse(&routing(1, 0, 6, 0, &[0, 9])).is_none()); // unknown subcode
        assert!(matches!(Aurp::parse(&routing(1, 0, 14, 0, &[])).unwrap(), Aurp::Routing { cmd: Cmd::Tickle, .. }));
        assert!(matches!(Aurp::parse(&routing(1, 0, 15, 0, &[])).unwrap(), Aurp::Routing { cmd: Cmd::TickleAck, .. }));
        assert!(Aurp::parse(&routing(1, 0, 10, 0, &[])).is_none()); // undefined command
    }

    #[test]
    fn data_packet_and_null_di() {
        let mut p = vec![1, 0, 7, 1, 0, 0, 10, 0, 0, 1, 0, 1, 0, 0, 0, 2];
        let ddp = [0x00, 13, 0, 0, 0x1a, 0x90, 0x0b, 0x59, 1, 2, 4, 4, 4];
        p.extend(ddp);
        let a = Aurp::parse(&p).unwrap();
        let Aurp::Data { dh, ddp: got } = &a else { panic!() };
        assert_eq!(dh.dst, Di::Null);
        assert_eq!(dh.src, Di::Ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(got, &ddp);
        assert_eq!(a.to_bytes(), p);
        assert_eq!(a.to_string(), "aurp-data 10.0.0.1 > null 13 bytes");
        assert!(Aurp::parse(&p[..p.len() - 1]).is_none()); // shorter than a DDP header
    }

    #[test]
    fn domain_header_rejects() {
        let mut p = dh(); p[16] = 2;                      // version 2
        assert!(Aurp::parse(&p).is_none());
        let mut p = dh(); p[21] = 4;                      // packet type 4
        assert!(Aurp::parse(&p).is_none());
        let mut p = dh(); p[1] = 2;                       // authority 2
        assert!(Aurp::parse(&p).is_none());
        let mut p = dh(); p[0] = 5;                       // IP DI with the wrong length
        assert!(Aurp::parse(&p).is_none());
        assert!(Aurp::parse(&dh()).is_none());            // routing header missing
        assert!(Aurp::parse(&dh()[..10]).is_none());
    }

    /// The paths the doc's worked examples do not reach: subcode 2 carries a
    /// whole-list count that survives a round trip, and the two optional
    /// commands can be answered rather than refused.
    #[test]
    fn extended_zi_rsp_and_the_optional_commands() {
        let p = routing(1, 0, 7, 0, &[0, 2, 0, 5, 0x1a, 0x90, 1, b'Z']);
        let a = Aurp::parse(&p).unwrap();
        let Aurp::Routing { cmd: Cmd::ZiRsp { extended, zones }, .. } = &a else { panic!() };
        assert_eq!((*extended, zones.len()), (Some(5), 1));
        assert_eq!(a.to_bytes(), p); // the count is the list's, not this packet's
        assert!(a.to_string().ends_with("zi-rsp 1 zones"));

        let p = routing(1, 0, 7, 0, &[0, 3, 1, b'Z', 0, 1, 0x1a, 0x90, 0x80, 0x1a, 0x90, 0x00]);
        let a = Aurp::parse(&p).unwrap();
        let Aurp::Routing { cmd: Cmd::GznRsp { tuples: Some(tuples), .. }, .. } = &a else { panic!() };
        assert_eq!(tuples[0].range, (6800, 6800));
        assert_eq!(a.to_bytes(), p);

        let p = routing(1, 0, 7, 0x8000, &[0, 4, 0, 0, 1, b'A', 1, b'B']);
        let a = Aurp::parse(&p).unwrap();
        let Aurp::Routing { cmd: Cmd::GdzlRsp { last, start, zones }, .. } = &a else { panic!() };
        assert_eq!((*last, *start), (true, 0));
        assert_eq!(zones, &["A".to_string(), "B".to_string()]);
        assert_eq!(a.to_bytes(), p);
        assert!(a.to_string().ends_with("gdzl-rsp"));

        // A zone name that runs off the end of the packet, and a count that
        // claims a tuple the body does not hold.
        assert!(Aurp::parse(&routing(1, 0, 7, 0, &[0, 1, 0, 1, 0x1a, 0x90, 0x20, b'Z'])).is_none());
        assert!(Aurp::parse(&routing(1, 0, 7, 0, &[0, 3, 1, b'Z', 0, 2, 0x1a, 0x90, 0])).is_none());
    }
}
