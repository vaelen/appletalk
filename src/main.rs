// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Dump EtherTalk (AppleTalk-over-Ethernet) frames off the wire.
//!
//! Usage: sudo ./appletalk [-i interface] [monitor] [flags]

mod capture;
mod cli;
mod node;
mod session;
mod text;
mod wire;

use clap::Parser;

fn main() {
    let args = cli::Cli::parse();
    let (iface, _tx, events) = match capture::spawn(args.interface.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("appletalk: {e}");
            std::process::exit(1);
        }
    };
    println!("listening on {iface}");
    // Only `monitor` exists, implicit or not; both land here.
    text::run(events, args.output());
}
