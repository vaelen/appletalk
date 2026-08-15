// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! AppleTalk Transaction Protocol — the transaction layer over DDP.

use std::fmt;

use super::Encode;

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

/// The five legal ATP release-timer values. Encodings 5-7 are reserved by the
/// book, so they are unrepresentable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Task 7's reassembler tests consume this
pub enum TrelTimeout {
    S30,
    M1,
    M2,
    M4,
    M8,
}

impl TrelTimeout {
    fn bits(self) -> u8 {
        match self {
            TrelTimeout::S30 => 0,
            TrelTimeout::M1 => 1,
            TrelTimeout::M2 => 2,
            TrelTimeout::M4 => 3,
            TrelTimeout::M8 => 4,
        }
    }
}

/// An ATP packet: an 8-byte header over DDP, carrying up to 578 bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct Atp {
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
    pub data: Vec<u8>,
}

impl Atp {
    pub fn parse(p: &[u8]) -> Option<Self> {
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
            data: p[8..].to_vec(),
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

    /// `xo` carries the release timer; Phase 1 nodes ignore it and always use
    /// 30 seconds.
    #[allow(dead_code)] // Task 7's reassembler tests consume this
    pub fn request(
        tid: u16,
        bitmap: u8,
        xo: Option<TrelTimeout>,
        user_bytes: [u8; 4],
        data: Vec<u8>,
    ) -> Self {
        let mut control = 0x40;
        if let Some(t) = xo {
            control |= 0x20 | t.bits();
        }
        Atp { func: Func::Req, control, bitmap, tid, user_bytes, data }
    }

    #[allow(dead_code)] // Task 7's reassembler tests consume this
    pub fn response(
        tid: u16,
        seq: u8,
        eom: bool,
        sts: bool,
        user_bytes: [u8; 4],
        data: Vec<u8>,
    ) -> Self {
        let mut control = 0x80;
        if eom {
            control |= 0x10;
        }
        if sts {
            control |= 0x08;
        }
        Atp { func: Func::Resp, control, bitmap: seq, tid, user_bytes, data }
    }

    /// The book notes a TRel's user bytes are not significant.
    #[allow(dead_code)] // Task 7's reassembler tests consume this
    pub fn release(tid: u16) -> Self {
        Atp {
            func: Func::Rel,
            control: 0xc0,
            bitmap: 0,
            tid,
            user_bytes: [0; 4],
            data: Vec::new(),
        }
    }
}

impl fmt::Display for Atp {
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

impl Encode for Atp {
    fn encode(&self, out: &mut Vec<u8>) {
        // The control byte IS the wire field; func/xo/eom/sts are views onto
        // it, so there is nothing to recompute.
        out.push(self.control);
        out.push(self.bitmap);
        out.extend(self.tid.to_be_bytes());
        out.extend(self.user_bytes);
        out.extend(&self.data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testkit::*;

    #[test]
    fn atp_treq_exactly_once() {
        // 0x40 TReq | 0x20 XO | timeout 0 (30s)
        let p = atp(0x60, 0x07, &[9, 9]);
        let a = Atp::parse(&p).unwrap();
        assert_eq!((a.func, a.tid, a.bitmap), (Func::Req, 4660, 0x07));
        assert!(a.xo() && !a.eom());
        assert_eq!(a.data, [9, 9]);
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
    fn atp_request_builds_its_control_byte() {
        let a = Atp::request(4660, 0x07, Some(TrelTimeout::S30), [1, 2, 3, 4], vec![9, 9]);
        assert_eq!(a.control, 0x60); // 0x40 TReq | 0x20 XO | 000 timeout
        assert_eq!(a.func, Func::Req);
        assert!(a.xo());
        assert_eq!(a.trel_timeout(), "30s");

        let plain = Atp::request(1, 0x01, None, [0; 4], Vec::new());
        assert_eq!(plain.control, 0x40);
        assert!(!plain.xo());
    }

    #[test]
    fn atp_request_encodes_each_trel_timeout() {
        for (t, bits) in [
            (TrelTimeout::S30, 0),
            (TrelTimeout::M1, 1),
            (TrelTimeout::M2, 2),
            (TrelTimeout::M4, 3),
            (TrelTimeout::M8, 4),
        ] {
            let a = Atp::request(1, 1, Some(t), [0; 4], Vec::new());
            assert_eq!(a.control & 0x07, bits, "{t:?}");
        }
    }

    #[test]
    fn atp_response_sets_eom_and_sts() {
        let a = Atp::response(4660, 2, true, true, [1, 2, 3, 4], Vec::new());
        assert_eq!(a.control, 0x98); // 0x80 TResp | 0x10 EOM | 0x08 STS
        assert_eq!(a.bitmap, 2);
        assert_eq!(a.to_string(), "TResp tid 4660 seq 2 EOM STS user 01020304");
    }

    #[test]
    fn atp_release_carries_no_data() {
        let a = Atp::release(4660);
        assert_eq!(a.control, 0xc0);
        assert!(a.data.is_empty());
        assert_eq!(a.to_string(), "TRel tid 4660 user 00000000");
    }

    #[test]
    fn atp_encodes_known_bytes() {
        let a = Atp::request(4660, 0x07, None, [1, 2, 3, 4], vec![9, 9]);
        assert_eq!(a.to_bytes(), vec![0x40, 0x07, 0x12, 0x34, 1, 2, 3, 4, 9, 9]);
    }

    #[test]
    fn atp_round_trips() {
        let a = Atp::response(4660, 2, true, false, [0xde, 0xad, 0xbe, 0xef], vec![1, 2, 3]);
        assert_eq!(Atp::parse(&a.to_bytes()), Some(a));
    }
}
