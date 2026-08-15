// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Dump EtherTalk (AppleTalk-over-Ethernet) frames off the wire.
//!
//! Usage: sudo ./appletalk [interface]

mod capture;
mod text;
mod wire;

fn main() {
    let want = std::env::args().nth(1);
    let (iface, events) = match capture::spawn(want.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("appletalk: {e}");
            std::process::exit(1);
        }
    };
    println!("listening on {iface}");
    text::run(events);
}
