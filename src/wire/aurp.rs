// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! AURP: the AppleTalk Update-Based Routing Protocol tunnelled over UDP 387.
//! `docs/AURP.md` has the layouts.
//!
//! stub: Task 3 fills in the parser, `Display` and `Encode`. The types are
//! here now so the tasks that build on them can compile.
#![allow(dead_code)]

use std::fmt;
use std::net::Ipv4Addr;

use super::{Encode, NetworkTuple};

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

impl Aurp {
    // stub: Task 3.
    pub fn parse(_p: &[u8]) -> Option<Self> {
        None
    }
}

impl fmt::Display for Aurp {
    // stub: Task 3.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            Aurp::Data { .. } => "aurp-data",
            Aurp::Routing { .. } => "aurp",
        };
        f.write_str(name)
    }
}

impl Encode for Aurp {
    // stub: Task 3.
    fn encode(&self, _out: &mut Vec<u8>) {}
}
