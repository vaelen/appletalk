// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Router configuration: the TOML file, the command line, and their merge.
//!
//! stub: Task 5 fills in `load` and `import_peers`.
#![allow(dead_code)]
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtherPort {
    pub interface: String,
    pub net: (u16, u16),
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtoudpPort {
    pub interface: Option<Ipv4Addr>,
    pub net: u16,
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TashtalkPort {
    pub device: String,
    pub net: u16,
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub name: String,
    pub public_ip: Option<Ipv4Addr>,
    pub listen: SocketAddrV4,
    pub open_peering: bool,
    pub peers: Vec<String>,
    pub ethertalk: Vec<EtherPort>,
    pub ltoudp: Vec<LtoudpPort>,
    pub tashtalk: Vec<TashtalkPort>,
}

// stub: Task 5.
pub fn load(_args: &crate::cli::RouterArgs) -> io::Result<Config> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "config: not implemented yet"))
}

/// Returns (added, already present).
// stub: Task 5.
pub fn import_peers(_config: Option<&Path>, _list: &Path) -> io::Result<(usize, usize)> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "peers import: not implemented yet"))
}
