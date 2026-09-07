// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! The router: forwards DDP between ports and AURP peers, and runs the
//! routing, zone and name services a router owes its cables.
//!
//! stub: Task 11 fills in `run`; the types are here now so the service tasks
//! can compile against them.
#![allow(dead_code)]

pub mod aurp;
pub mod local;
pub mod ports;
pub mod table;

use std::io;
use std::net::Ipv4Addr;

use crate::capture::PortId;
use crate::config::Config;
use crate::wire::{Ddp, Frame, Llap};

/// Where a datagram goes: out one of our own ports, or down a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    Port(PortId),
    Peer(Ipv4Addr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dest {
    Node(u8),
    Broadcast,
    Zone(String),
}

/// A datagram a service wants sent. `On` names a port; `Route` asks the router
/// to forward it as if it originated here (hop count untouched, best route
/// chosen).
#[derive(Debug, PartialEq, Eq)]
pub enum Emit {
    On { port: PortId, dest: Dest, ddp: Ddp },
    Route(Ddp),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    ToEther { port: PortId, frame: Frame },
    ToLlap { port: PortId, llap: Llap },
    ToPeer { peer: Ipv4Addr, bytes: Vec<u8> },
    /// TashTalk only: program the firmware's node-ID bitmap.
    SetNode { port: PortId, node: Option<u8> },
    Log(String),
}

// stub: Task 11.
pub fn run(_cfg: Config) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "router: not implemented yet"))
}
