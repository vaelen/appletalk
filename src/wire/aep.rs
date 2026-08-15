// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! AppleTalk Echo Protocol.

use std::fmt;

use super::Encode;

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
pub struct Aep {
    pub func: Echo,
    pub data: Vec<u8>,
}

impl Aep {
    pub fn parse(p: &[u8]) -> Option<Self> {
        Some(Aep {
            func: match p.first()? {
                1 => Echo::Request,
                2 => Echo::Reply,
                _ => return None,
            },
            data: p[1..].to_vec(),
        })
    }
}

impl fmt::Display for Aep {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} bytes", self.func, self.data.len())
    }
}

impl Encode for Aep {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(match self.func {
            Echo::Request => 1,
            Echo::Reply => 2,
        });
        out.extend(&self.data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aep_request_and_reply() {
        let req = Aep::parse(&[1, 0xde, 0xad, 0xbe, 0xef]).unwrap();
        assert_eq!(req.func, Echo::Request);
        assert_eq!(req.data, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(req.to_string(), "request 4 bytes");

        let reply = Aep::parse(&[2]).unwrap();
        assert_eq!(reply.func, Echo::Reply);
        assert!(reply.data.is_empty());
        assert_eq!(reply.to_string(), "reply 0 bytes");
    }

    #[test]
    fn aep_rejects_unknown_func_and_empty() {
        assert!(Aep::parse(&[0]).is_none());
        assert!(Aep::parse(&[]).is_none());
    }

    #[test]
    fn aep_encodes_and_round_trips() {
        let a = Aep { func: Echo::Request, data: vec![0xde, 0xad] };
        assert_eq!(a.to_bytes(), vec![1, 0xde, 0xad]);
        assert_eq!(Aep::parse(&a.to_bytes()), Some(a));

        let r = Aep { func: Echo::Reply, data: Vec::new() };
        assert_eq!(r.to_bytes(), vec![2]);
        assert_eq!(Aep::parse(&r.to_bytes()), Some(r));
    }
}
