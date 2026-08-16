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
    if args.conflicting_output() {
        eprintln!("appletalk: output flags before a subcommand name are ambiguous; put them after it");
        std::process::exit(2);
    }
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
            if let Err(e) = run_node(cmd, tx, events, args.node.as_deref(), args.net) {
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
    node_arg: Option<&str>,
    net_arg: Option<u16>,
) -> std::io::Result<()> {
    // clap already rejects --node alongside --net, so at most one is set.
    let want = match (node_arg, net_arg) {
        (Some(s), _) => node::Want::Addr(node::parse_addr(s)?),
        (None, Some(net)) => node::Want::Net(net),
        (None, None) => node::Want::Discover,
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
            let Some(router) = n.router() else {
                // Not a failure: a routerless network genuinely has no zones.
                eprintln!("no router: this network has no zones");
                return Ok(());
            };
            let ours = n.zone().to_string();
            let zones = n.zone_list()?;
            if zones.is_empty() {
                // A router that answers but lists nothing is a real answer, and
                // saying so beats printing nothing and exiting successfully.
                eprintln!("router {router} answered with an empty zone list");
            }
            for z in zones {
                // Mark the zone we are actually in.
                let mark = if z == ours { " *" } else { "" };
                println!("{z}{mark}");
            }
            Ok(())
        }
        cli::Command::Monitor { .. } => unreachable!("handled by the passive path"),
    }
}
