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
    let (iface, tx, events) = match capture::spawn(args.interface.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("appletalk: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("listening on {iface}");

    match &args.command {
        // Only the passive path; a dumper needs no address.
        None | Some(cli::Command::Monitor { .. }) => text::run(events, args.output()),
        Some(cmd) => {
            if let Err(e) = run_node(cmd, tx, events, args.node.as_deref()) {
                eprintln!("appletalk: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Everything that needs a claimed address.
fn run_node(
    cmd: &cli::Command,
    tx: capture::Tx,
    events: std::sync::mpsc::Receiver<capture::Event>,
    want: Option<&str>,
) -> std::io::Result<()> {
    let want = match want {
        Some(s) => Some(node::parse_addr(s)?),
        None => None,
    };
    let mut n = node::Node::claim(tx, events, want)?;
    match cmd {
        cli::Command::Nodes { zone } => {
            let zone = zone.clone().unwrap_or_else(|| n.zone().to_string());
            let found = n.lookup("=", "=", &zone)?;
            if found.is_empty() {
                eprintln!("no entities answered in zone {zone:?}");
            }
            for t in found {
                println!("{t}");
            }
            Ok(())
        }
        cli::Command::Ping { target, count } => {
            let addr = match target.parse::<node::Target>()? {
                node::Target::Addr(a) => a,
                node::Target::Name { object, typ, zone } => {
                    let zone = zone.unwrap_or_else(|| n.zone().to_string());
                    let found = n.lookup(&object, &typ, &zone)?;
                    let first = found.first().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("no answer for {object}:{typ}@{zone}"),
                        )
                    })?;
                    if found.len() > 1 {
                        eprintln!("{} answered; pinging {first}", found.len());
                    }
                    first.addr
                }
            };
            // No reply at all is a failure, the same as any other ping.
            if n.ping(addr, *count)? { Ok(()) } else { std::process::exit(1) }
        }
        cli::Command::Zones => {
            if n.router().is_none() {
                // Not a failure: a routerless network genuinely has no zones.
                eprintln!("no router: this network has no zones");
                return Ok(());
            }
            let ours = n.zone().to_string();
            for z in n.zone_list()? {
                // Mark the zone we are actually in.
                let mark = if z == ours { " *" } else { "" };
                println!("{z}{mark}");
            }
            Ok(())
        }
        cli::Command::Monitor { .. } => unreachable!("handled by the passive path"),
    }
}
