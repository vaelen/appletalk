// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! RTMP: the Routing Table Maintenance Protocol, DDP types 1 and 5.
//!
//! stub: Task 2 fills in the parser, `Display` and `Encode`. The types are
//! here now so the tasks that build on them can compile.
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
    pub distance: u8,
}

impl NetworkTuple {
    /// `trailer` is the sixth byte of an extended tuple: 0x82 in RTMP, 0x00 in AURP.
    // stub: Task 2.
    pub fn parse(_p: &[u8]) -> Option<(Self, &[u8])> {
        None
    }

    // stub: Task 2. The empty body is why clippy wants a slice here; the real
    // one appends.
    #[allow(clippy::ptr_arg)]
    pub fn encode_with(&self, _out: &mut Vec<u8>, _trailer: u8) {}
}

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
    // stub: Task 2.
    pub fn parse(_ddp_type: u8, _p: &[u8]) -> Option<Self> {
        None
    }
}

impl fmt::Display for Rtmp {
    // stub: Task 2.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            Rtmp::Data { .. } => "rtmp-data",
            Rtmp::Request => "rtmp-request",
            Rtmp::Rdr { .. } => "rtmp-rdr",
        };
        f.write_str(name)
    }
}

impl Encode for Rtmp {
    // stub: Task 2.
    fn encode(&self, _out: &mut Vec<u8>) {}
}
