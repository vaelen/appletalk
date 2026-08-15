// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Name Binding Protocol — maps `object:type@zone` names to addresses.

use std::fmt;

use super::{put_pstring, pstring, Addr, Encode};

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

impl Encode for NbpTuple {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend(self.addr.net.to_be_bytes());
        out.push(self.addr.node);
        out.push(self.socket);
        out.push(self.enumerator);
        put_pstring(out, &self.object);
        put_pstring(out, &self.typ);
        put_pstring(out, &self.zone);
    }
}

impl Encode for Nbp {
    fn encode(&self, out: &mut Vec<u8>) {
        let func = match self.func {
            NbpFunc::BrRq => 1,
            NbpFunc::LkUp => 2,
            NbpFunc::LkUpReply => 3,
            NbpFunc::FwdReq => 4,
        };
        // High nibble function, low nibble the recomputed tuple count.
        out.push((func << 4) | (self.tuples.len().min(15) as u8));
        out.push(self.id);
        for t in &self.tuples {
            t.encode(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testkit::*;

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
    fn nbp_encodes_known_bytes() {
        use crate::wire::testkit::ps;
        let n = Nbp {
            func: NbpFunc::LkUp,
            id: 42,
            tuples: vec![NbpTuple {
                addr: Addr { net: 65280, node: 128 },
                socket: 253,
                enumerator: 0,
                object: "=".into(),
                typ: "AFPServer".into(),
                zone: "*".into(),
            }],
        };
        let mut want = vec![(2 << 4) | 1, 42, 0xff, 0x00, 128, 253, 0];
        want.extend(ps("="));
        want.extend(ps("AFPServer"));
        want.extend(ps("*"));
        assert_eq!(n.to_bytes(), want);
    }

    #[test]
    fn nbp_recomputes_the_tuple_count() {
        use crate::wire::testkit::ps;
        let mut p = vec![(3 << 4) | 2, 7];
        for node in [128u8, 129] {
            p.extend([0xff, 0x00, node, 253, 0]);
            p.extend(ps("Mac"));
            p.extend(ps("AFPServer"));
            p.extend(ps("Eng"));
        }
        let mut n = Nbp::parse(&p).unwrap();
        n.tuples.pop(); // one tuple left; the count nibble must follow
        assert_eq!(n.to_bytes()[0], (3 << 4) | 1);
    }

    #[test]
    fn nbp_round_trips() {
        use crate::wire::testkit::ps;
        let mut p = vec![(2 << 4) | 1, 42, 0xff, 0x00, 128, 253, 3];
        p.extend(ps("Mac IIci"));
        p.extend(ps("AFPServer"));
        p.extend(ps("Engineering"));
        let n = Nbp::parse(&p).unwrap();
        assert_eq!(Nbp::parse(&n.to_bytes()), Some(n));
    }
}
