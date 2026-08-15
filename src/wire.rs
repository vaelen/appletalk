//! Parsers for the AppleTalk protocols, bottom up: ELAP, AARP, DDP, then the
//! protocols DDP carries. Every `parse` takes a byte slice and returns None
//! rather than decoding something it does not recognise.

use std::fmt;

use pnet::util::MacAddr;

pub const DDP: u16 = 0x809b; // AppleTalk Datagram Delivery Protocol
pub const AARP: u16 = 0x80f3; // AppleTalk Address Resolution Protocol

// DDP protocol types.
pub const DDP_NBP: u8 = 2;
pub const DDP_ATP: u8 = 3;
pub const DDP_AEP: u8 = 4;
pub const DDP_ZIP: u8 = 6;

fn mac(b: &[u8]) -> Option<MacAddr> {
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
pub struct Frame<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    /// EtherType, or the SNAP protocol when `snap` is set.
    pub proto: u16,
    /// True for Phase 2: IEEE 802.3 + 802.2 LLC + SNAP.
    pub snap: bool,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Phase 2 EtherTalk is 802.3 (the type field is a *length*) + LLC + SNAP,
    /// so the real protocol number sits 8 bytes further in. Phase 1 used a
    /// plain EtherType. Non-SNAP LLC frames return None.
    pub fn parse(b: &'a [u8]) -> Option<Self> {
        let (dst, src) = (mac(b.get(..6)?)?, mac(b.get(6..12)?)?);
        let typelen = u16::from_be_bytes([b[12], b[13]]);
        let body = b.get(14..)?;
        if typelen > 1500 {
            return Some(Frame { dst, src, proto: typelen, snap: false, payload: body });
        }
        // 802.3: trim the padding Ethernet added to reach the 60-byte minimum.
        match body.get(..typelen as usize)? {
            // DSAP AA, SSAP AA, control 03, 3-byte OUI, 2-byte protocol.
            [0xaa, 0xaa, 0x03, _, _, _, hi, lo, rest @ ..] => Some(Frame {
                dst,
                src,
                proto: u16::from_be_bytes([*hi, *lo]),
                snap: true,
                payload: rest,
            }),
            _ => None,
        }
    }
}

impl fmt::Display for Frame<'_> {
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

// ------------------------------------------------------------- address layer

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

// ------------------------------------------------------------- network layer

/// A DDP datagram with the 13-byte extended (long) header — the only form
/// EtherTalk carries. The 5-byte short header is LocalTalk-only, where LLAP's
/// type field tells the two apart.
#[derive(Debug, PartialEq, Eq)]
pub struct Ddp<'a> {
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
    pub data: &'a [u8],
}

impl<'a> Ddp<'a> {
    pub fn parse(p: &'a [u8]) -> Option<Self> {
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
            data: &p[13..],
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

impl fmt::Display for Ddp<'_> {
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

// --------------------------------------------------------- transaction layer

/// ATP function code, from the top two bits of the control byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Func {
    /// Transaction request.
    Req,
    /// Transaction response — up to 8 per request, sequence-numbered.
    Resp,
    /// Transaction release, closing an exactly-once transaction.
    Rel,
}

impl fmt::Display for Func {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Func::Req => "TReq",
            Func::Resp => "TResp",
            Func::Rel => "TRel",
        })
    }
}

/// An ATP packet: an 8-byte header over DDP, carrying up to 578 bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct Atp<'a> {
    pub func: Func,
    /// The raw control byte; the flag accessors read their bits from it.
    pub control: u8,
    /// TReq: bitmap of the responses being asked for. TResp: this packet's
    /// sequence number. Unused in TRel.
    pub bitmap: u8,
    pub tid: u16,
    /// Four bytes ATP does not interpret — ASP and PAP put their own headers
    /// here rather than in the data.
    pub user_bytes: [u8; 4],
    pub data: &'a [u8],
}

impl<'a> Atp<'a> {
    pub fn parse(p: &'a [u8]) -> Option<Self> {
        let h = p.get(..8)?;
        Some(Atp {
            func: match h[0] & 0xc0 {
                0x40 => Func::Req,
                0x80 => Func::Resp,
                0xc0 => Func::Rel,
                _ => return None, // 00 is reserved
            },
            control: h[0],
            bitmap: h[1],
            tid: u16::from_be_bytes([h[2], h[3]]),
            user_bytes: h[4..8].try_into().ok()?,
            data: &p[8..],
        })
    }

    /// Exactly-once service: the responder must hold the reply until released.
    pub fn xo(&self) -> bool {
        self.control & 0x20 != 0
    }

    /// End of message — this is the last response in the set.
    pub fn eom(&self) -> bool {
        self.control & 0x10 != 0
    }

    /// Send transaction status: the requester should retransmit its bitmap.
    pub fn sts(&self) -> bool {
        self.control & 0x08 != 0
    }

    /// How long the responder holds exactly-once state without a TRel. A
    /// Phase 2 addition; earlier senders leave the field zero.
    pub fn trel_timeout(&self) -> &'static str {
        match self.control & 0x07 {
            0 => "30s",
            1 => "1m",
            2 => "2m",
            3 => "4m",
            4 => "8m",
            _ => "reserved",
        }
    }
}

impl fmt::Display for Atp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} tid {}", self.func, self.tid)?;
        match self.func {
            Func::Req => {
                write!(f, " bitmap {:#04x}", self.bitmap)?;
                if self.xo() {
                    write!(f, " XO({})", self.trel_timeout())?;
                }
            }
            Func::Resp => {
                write!(f, " seq {}", self.bitmap)?;
                if self.eom() {
                    f.write_str(" EOM")?;
                }
                if self.sts() {
                    f.write_str(" STS")?;
                }
            }
            Func::Rel => {}
        }
        let user: String = self.user_bytes.iter().map(|b| format!("{b:02x}")).collect();
        write!(f, " user {user}")
    }
}

// -------------------------------------------------------------------- echoes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Echo {
    Request,
    Reply,
}

impl fmt::Display for Echo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Echo::Request => "request",
            Echo::Reply => "reply",
        })
    }
}

/// An AEP packet: a function code, then data the replier echoes back
/// unchanged. There is no sequence number — a pinger matches replies to
/// requests by putting its own marker in the data.
#[derive(Debug, PartialEq, Eq)]
pub struct Aep<'a> {
    pub func: Echo,
    pub data: &'a [u8],
}

impl<'a> Aep<'a> {
    pub fn parse(p: &'a [u8]) -> Option<Self> {
        Some(Aep {
            func: match p.first()? {
                1 => Echo::Request,
                2 => Echo::Reply,
                _ => return None,
            },
            data: &p[1..],
        })
    }
}

impl fmt::Display for Aep<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} bytes", self.func, self.data.len())
    }
}

// ---------------------------------------------------------------------- NBP

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NbpFunc {
    /// Broadcast request: "someone find this name for me".
    BrRq,
    /// Lookup, sent to a network's NBP socket.
    LkUp,
    LkUpReply,
    /// Forward request: a router passing a BrRq to another network.
    FwdReq,
}

impl fmt::Display for NbpFunc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            NbpFunc::BrRq => "BrRq",
            NbpFunc::LkUp => "LkUp",
            NbpFunc::LkUpReply => "LkUp-Reply",
            NbpFunc::FwdReq => "FwdReq",
        })
    }
}

/// One name-to-address binding: `object:type@zone` living at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbpTuple {
    pub addr: Addr,
    pub socket: u8,
    /// Distinguishes entities registered under the same name on one socket.
    pub enumerator: u8,
    pub object: String,
    pub typ: String,
    pub zone: String,
}

impl NbpTuple {
    fn parse(p: &[u8]) -> Option<(Self, &[u8])> {
        let h = p.get(..5)?;
        let (object, rest) = pstring(&p[5..])?;
        let (typ, rest) = pstring(rest)?;
        let (zone, rest) = pstring(rest)?;
        Some((
            NbpTuple {
                addr: Addr { net: u16::from_be_bytes([h[0], h[1]]), node: h[2] },
                socket: h[3],
                enumerator: h[4],
                object,
                typ,
                zone,
            },
            rest,
        ))
    }
}

impl fmt::Display for NbpTuple {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}@{} at {}:{}",
            self.object, self.typ, self.zone, self.addr, self.socket
        )?;
        if self.enumerator != 0 {
            write!(f, " #{}", self.enumerator)?;
        }
        Ok(())
    }
}

/// An NBP packet: a function, a transaction id, and one or more tuples. A
/// lookup carries the name being asked about; a reply carries what answered.
#[derive(Debug, PartialEq, Eq)]
pub struct Nbp {
    pub func: NbpFunc,
    pub id: u8,
    pub tuples: Vec<NbpTuple>,
}

impl Nbp {
    pub fn parse(p: &[u8]) -> Option<Self> {
        // High nibble is the function, low nibble the tuple count.
        let (b0, id) = (*p.first()?, *p.get(1)?);
        let func = match b0 >> 4 {
            1 => NbpFunc::BrRq,
            2 => NbpFunc::LkUp,
            3 => NbpFunc::LkUpReply,
            4 => NbpFunc::FwdReq,
            _ => return None,
        };
        let mut rest = &p[2..];
        let mut tuples = Vec::new();
        for _ in 0..(b0 & 0x0f) {
            let (t, r) = NbpTuple::parse(rest)?;
            tuples.push(t);
            rest = r;
        }
        Some(Nbp { func, id, tuples })
    }
}

impl fmt::Display for Nbp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} id {}", self.func, self.id)?;
        for t in &self.tuples {
            write!(f, "  {t}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------- ZIP

/// A ZIP packet sent directly over DDP. The GetZoneList / GetLocalZones /
/// GetMyZone calls are a separate thing entirely — those ride on ATP with the
/// function in the user bytes, so they surface as ATP, not here.
#[derive(Debug, PartialEq, Eq)]
pub enum Zip {
    /// "Which zones are on these networks?"
    Query { nets: Vec<u16> },
    /// Network-to-zone-name answers. `extended` marks command 8, used when one
    /// network's zone list does not fit in a single reply.
    Reply { zones: Vec<(u16, String)>, extended: bool },
    /// A booting node asking a router for its cable range and zone.
    GetNetInfo { zone: String },
    NetInfoReply {
        flags: u8,
        range: (u16, u16),
        zone: String,
        multicast: MacAddr,
        /// Sent when the requested zone was not valid on this cable.
        default_zone: Option<String>,
    },
    /// Zone name change. ponytail: body left undecoded — rare, and the layout
    /// is worth confirming against a real capture before trusting it.
    Notify,
}

impl Zip {
    pub fn parse(p: &[u8]) -> Option<Self> {
        let count = *p.get(1)? as usize;
        match *p.first()? {
            1 => {
                let nets = p
                    .get(2..2 + count * 2)?
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Some(Zip::Query { nets })
            }
            cmd @ (2 | 8) => {
                let mut rest = p.get(2..)?;
                let mut zones = Vec::with_capacity(count);
                for _ in 0..count {
                    let net = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
                    let (name, r) = pstring(rest.get(2..)?)?;
                    zones.push((net, name));
                    rest = r;
                }
                Some(Zip::Reply { zones, extended: cmd == 8 })
            }
            // Command, flags, then 4 zero bytes, then the zone being asked about.
            5 => Some(Zip::GetNetInfo { zone: pstring(p.get(6..)?)?.0 }),
            6 => {
                let h = p.get(..6)?;
                let (zone, rest) = pstring(&p[6..])?;
                let mclen = *rest.first()? as usize;
                let multicast = mac(rest.get(1..1 + mclen)?)?;
                let rest = rest.get(1 + mclen..)?;
                let flags = h[1];
                Some(Zip::NetInfoReply {
                    flags,
                    range: (
                        u16::from_be_bytes([h[2], h[3]]),
                        u16::from_be_bytes([h[4], h[5]]),
                    ),
                    zone,
                    multicast,
                    // Only present when the router rejected the requested zone.
                    default_zone: (flags & 0x80 != 0).then(|| pstring(rest)).flatten().map(|(s, _)| s),
                })
            }
            7 => Some(Zip::Notify),
            _ => None,
        }
    }
}

impl fmt::Display for Zip {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Zip::Query { nets } => {
                let list: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
                write!(f, "query nets {}", list.join(", "))
            }
            Zip::Reply { zones, extended } => {
                let list: Vec<String> = zones.iter().map(|(n, z)| format!("{n}={z}")).collect();
                let kind = if *extended { "ext-reply" } else { "reply" };
                write!(f, "{kind} {}", list.join(", "))
            }
            Zip::GetNetInfo { zone } => write!(f, "get-net-info zone {zone}"),
            Zip::NetInfoReply { flags, range, zone, multicast, default_zone } => {
                write!(f, "net-info-reply nets {}-{} zone {zone} mcast {multicast}", range.0, range.1)?;
                if flags & 0x80 != 0 {
                    f.write_str(" zone-invalid")?;
                }
                if flags & 0x40 != 0 {
                    f.write_str(" use-broadcast")?;
                }
                if flags & 0x20 != 0 {
                    f.write_str(" one-zone")?;
                }
                match default_zone {
                    Some(z) => write!(f, " default {z}"),
                    None => Ok(()),
                }
            }
            Zip::Notify => f.write_str("notify"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dst, src, then body; padded to the 60-byte Ethernet minimum.
    fn frame(typelen: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 12];
        f.extend(typelen.to_be_bytes());
        f.extend(body);
        f.resize(60, 0);
        f
    }

    fn aarp(op: u16, extra: &[u8]) -> Vec<u8> {
        let mut p = vec![0x00, 0x01, 0x80, 0x9b, 6, 4];
        p.extend(op.to_be_bytes());
        p.extend([0x00, 0x05, 0x02, 0xaa, 0xbb, 0xcc]); // src MAC
        p.extend([0x00, 0xff, 0x00, 128]); // src 65280.128
        p.extend([0; 6]); // dst MAC unknown
        p.extend([0x00, 0xff, 0x00, 42]); // dst 65280.42
        p.extend(extra);
        p
    }

    fn atp(control: u8, bitmap: u8, data: &[u8]) -> Vec<u8> {
        let mut p = vec![control, bitmap, 0x12, 0x34, 1, 2, 3, 4]; // tid 4660
        p.extend(data);
        p
    }

    /// A length-prefixed string, as it appears in NBP and ZIP.
    fn ps(s: &str) -> Vec<u8> {
        let mut v = vec![s.len() as u8];
        v.extend(s.bytes());
        v
    }

    #[test]
    fn phase2_ddp() {
        let body = [
            0xaa, 0xaa, 0x03, 0x08, 0x00, 0x07, 0x80, 0x9b, // LLC + SNAP
            1, 2, 3, 4,
        ];
        let bytes = frame(body.len() as u16, &body);
        let f = Frame::parse(&bytes).unwrap();
        assert_eq!((f.proto, f.snap, f.payload), (DDP, true, &[1, 2, 3, 4][..]));
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
        assert_eq!((f.proto, f.snap, f.payload), (AARP, true, &[9][..]));
    }

    #[test]
    fn phase1_raw_ethertype() {
        let bytes = frame(DDP, &[1, 2, 3]);
        let f = Frame::parse(&bytes).unwrap();
        assert_eq!((f.proto, f.snap), (DDP, false));
        assert_eq!(&f.payload[..3], &[1, 2, 3]); // no length field: padding included
    }

    #[test]
    fn frame_ignores_non_snap_and_short() {
        assert!(Frame::parse(&frame(3, &[0x42, 0x42, 0x03])).is_none()); // plain LLC
        assert!(Frame::parse(&[0; 10]).is_none()); // runt
        assert!(Frame::parse(&frame(1400, &[0xaa; 8])).is_none()); // length > frame
    }

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
        assert_eq!(d.data, &[1, 2, 3, 4]);
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
    fn atp_treq_exactly_once() {
        // 0x40 TReq | 0x20 XO | timeout 0 (30s)
        let p = atp(0x60, 0x07, &[9, 9]);
        let a = Atp::parse(&p).unwrap();
        assert_eq!((a.func, a.tid, a.bitmap), (Func::Req, 4660, 0x07));
        assert!(a.xo() && !a.eom());
        assert_eq!(a.data, &[9, 9]);
        assert_eq!(a.to_string(), "TReq tid 4660 bitmap 0x07 XO(30s) user 01020304");
    }

    #[test]
    fn atp_tresp_flags() {
        // 0x80 TResp | 0x10 EOM | 0x08 STS, sequence number 2
        let p = atp(0x98, 2, &[]);
        let a = Atp::parse(&p).unwrap();
        assert_eq!(a.func, Func::Resp);
        assert_eq!(a.to_string(), "TResp tid 4660 seq 2 EOM STS user 01020304");
    }

    #[test]
    fn atp_trel_omits_bitmap() {
        let p = atp(0xc0, 0, &[]);
        let a = Atp::parse(&p).unwrap();
        assert_eq!(a.to_string(), "TRel tid 4660 user 01020304");
    }

    #[test]
    fn atp_rejects_reserved_func_and_short() {
        assert!(Atp::parse(&atp(0x00, 0, &[])).is_none()); // function code 00
        assert!(Atp::parse(&atp(0x40, 0, &[])[..7]).is_none()); // truncated header
    }

    #[test]
    fn aep_request_and_reply() {
        let req = Aep::parse(&[1, 0xde, 0xad, 0xbe, 0xef]).unwrap();
        assert_eq!(req.func, Echo::Request);
        assert_eq!(req.data, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(req.to_string(), "request 4 bytes");

        let reply = Aep::parse(&[2]).unwrap();
        assert_eq!((reply.func, reply.data), (Echo::Reply, &[][..]));
        assert_eq!(reply.to_string(), "reply 0 bytes");
    }

    #[test]
    fn aep_rejects_unknown_func_and_empty() {
        assert!(Aep::parse(&[0]).is_none());
        assert!(Aep::parse(&[]).is_none());
    }

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
    fn nbp_lookup_one_tuple() {
        let mut p = vec![(2 << 4) | 1, 42]; // LkUp, 1 tuple, id 42
        p.extend([0xff, 0x00, 128, 253, 0]); // 65280.128 socket 253
        p.extend(ps("="));
        p.extend(ps("AFPServer"));
        p.extend(ps("*"));
        let n = Nbp::parse(&p).unwrap();
        assert_eq!((n.func, n.id, n.tuples.len()), (NbpFunc::LkUp, 42, 1));
        assert_eq!(n.to_string(), "LkUp id 42  =:AFPServer@* at 65280.128:253");
    }

    #[test]
    fn nbp_reply_two_tuples_with_enumerator() {
        let mut p = vec![(3 << 4) | 2, 7];
        for (node, enumerator, name) in [(128u8, 0u8, "Mac IIci"), (129, 3, "SE/30")] {
            p.extend([0xff, 0x00, node, 253, enumerator]);
            p.extend(ps(name));
            p.extend(ps("AFPServer"));
            p.extend(ps("Engineering"));
        }
        let n = Nbp::parse(&p).unwrap();
        assert_eq!(n.tuples.len(), 2);
        assert_eq!(n.tuples[1].enumerator, 3);
        assert_eq!(
            n.to_string(),
            "LkUp-Reply id 7  Mac IIci:AFPServer@Engineering at 65280.128:253  \
             SE/30:AFPServer@Engineering at 65280.129:253 #3"
        );
    }

    #[test]
    fn nbp_rejects_bad_function_and_truncated_tuple() {
        assert!(Nbp::parse(&[0x00, 1]).is_none()); // function 0
        assert!(Nbp::parse(&[(2 << 4) | 1, 1, 0xff, 0x00]).is_none()); // tuple cut short
    }

    #[test]
    fn zip_query() {
        let z = Zip::parse(&[1, 2, 0, 3, 0, 5]).unwrap();
        assert_eq!(z, Zip::Query { nets: vec![3, 5] });
        assert_eq!(z.to_string(), "query nets 3, 5");
    }

    #[test]
    fn zip_reply_pairs_nets_with_zones() {
        let mut p = vec![2, 2];
        p.extend([0, 3]);
        p.extend(ps("Engineering"));
        p.extend([0, 5]);
        p.extend(ps("Marketing"));
        let z = Zip::parse(&p).unwrap();
        assert_eq!(z.to_string(), "reply 3=Engineering, 5=Marketing");
    }

    #[test]
    fn zip_get_net_info_round_trip() {
        let mut req = vec![5, 0, 0, 0, 0, 0];
        req.extend(ps("Engineering"));
        assert_eq!(
            Zip::parse(&req).unwrap().to_string(),
            "get-net-info zone Engineering"
        );

        // Reply: flags "only one zone", cable range 3-5, plus the multicast
        // address a node in that zone should listen on.
        let mut reply = vec![6, 0x20, 0, 3, 0, 5];
        reply.extend(ps("Engineering"));
        reply.extend([6, 0x09, 0x00, 0x07, 0x00, 0x00, 0x01]);
        let z = Zip::parse(&reply).unwrap();
        assert_eq!(
            z.to_string(),
            "net-info-reply nets 3-5 zone Engineering mcast 09:00:07:00:00:01 one-zone"
        );
    }

    #[test]
    fn zip_net_info_reply_carries_default_zone_when_invalid() {
        let mut reply = vec![6, 0x80, 0, 3, 0, 5]; // 0x80 = requested zone invalid
        reply.extend(ps("Nonexistent"));
        reply.extend([6, 0x09, 0x00, 0x07, 0x00, 0x00, 0x01]);
        reply.extend(ps("Engineering"));
        let z = Zip::parse(&reply).unwrap();
        assert!(z.to_string().ends_with("zone-invalid default Engineering"), "{z}");
    }

    #[test]
    fn zip_rejects_unknown_command_and_short() {
        assert!(Zip::parse(&[99, 0]).is_none());
        assert!(Zip::parse(&[1]).is_none()); // no count byte
        assert!(Zip::parse(&[1, 4, 0, 3]).is_none()); // count exceeds body
    }
}
