// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Command line: subcommands, and the flags controlling what gets printed.

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::wire::{Body, Packet};

/// Dump EtherTalk (AppleTalk-over-Ethernet) traffic.
#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    /// NIC to capture on; defaults to the first up, non-loopback one with a MAC
    #[arg(short, long, global = true)]
    pub interface: Option<String>,

    /// Claim this address instead of discovering one, as `net.node`
    #[arg(long, global = true, value_name = "NET.NODE")]
    pub node: Option<String>,

    /// Claim an address on this network, choosing the node number for you
    #[arg(long, global = true, value_name = "NET", conflicts_with = "node")]
    pub net: Option<u16>,

    /// Flags for the implicit `monitor`; conflict with naming a subcommand.
    #[command(flatten)]
    output: Output,

    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// The output flags in force, whichever side of the subcommand they came
    /// from. `main` rejects combining a top-level flag with a subcommand
    /// other than `monitor`, so in practice only one side is ever set.
    pub fn output(&self) -> &Output {
        match &self.command {
            Some(Command::Monitor { output }) => output,
            _ => &self.output,
        }
    }

    /// Whether an output flag was given before a subcommand name — ambiguous,
    /// since a flag there could mean either "implicit monitor" or "meant for
    /// the subcommand that follows". Clap can no longer reject this for us:
    /// `global = true` is what lets `-i`/`--node` precede a subcommand, and
    /// clap 4.6 has no way to say "these globals may precede a subcommand,
    /// but these flattened args may not".
    pub fn conflicting_output(&self) -> bool {
        self.command.is_some() && self.output != Output::default()
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Print AppleTalk traffic as it arrives. The default.
    Monitor {
        #[command(flatten)]
        output: Output,
    },
    /// List the entities registered in a zone. Defaults to the local zone.
    Nodes {
        /// Zone to look in; `*` means this cable only.
        zone: Option<String>,
    },
    /// Echo a node, by address or by NBP name.
    Ping {
        /// `net.node`, or `object:type@zone`
        target: String,
        /// Number of echoes to send
        #[arg(short, long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..))]
        count: u16,
    },
    /// List the zones on the internet.
    Zones,
    /// Bridge another AppleTalk link onto this Ethernet, as one network.
    Bridge {
        #[command(subcommand)]
        link: Link,
    },
}

/// Which other link to bridge. A subcommand rather than a flag because each
/// one will want its own options.
#[derive(Subcommand, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// LocalTalk over UDP multicast (LToUDP), as Mini vMac, Snow, jrouter and
    /// tashrouter speak it.
    Udp,
}

#[derive(Args, Clone, Default, PartialEq)]
pub struct Output {
    /// Hex dump payloads
    #[arg(long)]
    pub hex: bool,
    /// Hide the Ethernet frame line
    #[arg(long)]
    pub no_link: bool,
    /// Hide the DDP datagram line
    #[arg(long)]
    pub no_net: bool,
    /// Show only these protocols
    #[arg(long, value_delimiter = ',', conflicts_with = "hide")]
    pub only: Vec<Proto>,
    /// Hide these protocols
    #[arg(long, value_delimiter = ',')]
    pub hide: Vec<Proto>,
}

impl Output {
    /// Whether this packet is printed at all. Empty lists show everything.
    pub fn shows(&self, p: &Packet) -> bool {
        let proto = Proto::of(p);
        if !self.only.is_empty() {
            return self.only.contains(&proto);
        }
        !self.hide.contains(&proto)
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Aarp,
    Rtmp,
    Nbp,
    Atp,
    Aep,
    Zip,
    Adsp,
    Other,
}

impl Proto {
    /// Identity comes from the DDP type byte, not from whether we have a
    /// parser — so `--hide rtmp` works before RTMP decodes. Same type numbers
    /// as `Ddp::type_name`.
    fn of(p: &Packet) -> Proto {
        match &p.body {
            Body::Aarp(_) => Proto::Aarp,
            Body::Ddp(d, _) => match d.typ {
                1 | 5 => Proto::Rtmp, // RTMP-data, RTMP-req
                2 => Proto::Nbp,
                3 => Proto::Atp,
                4 => Proto::Aep,
                6 => Proto::Zip,
                7 => Proto::Adsp,
                _ => Proto::Other,
            },
            Body::Unknown => Proto::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use pnet::util::MacAddr;

    use crate::wire::{Aarp, Addr, Body, Ddp, DdpBody, Frame, Packet, DDP};

    fn packet(body: Body) -> Packet {
        let mac = MacAddr::zero();
        let frame = Frame { dst: mac, src: mac, proto: DDP, snap: true, payload: Vec::new() };
        Packet { frame, body }
    }

    /// A DDP datagram of the given type, body undecoded — which is the point:
    /// protocol identity comes from the type byte, not from having a parser.
    fn ddp(typ: u8) -> Packet {
        let addr = Addr { net: 0, node: 0 };
        let d = Ddp {
            hops: 0,
            length: 0,
            checksum: 0,
            dst: addr,
            dst_socket: 0,
            src: addr,
            src_socket: 0,
            typ,
            data: Vec::new(),
        };
        packet(Body::Ddp(d, DdpBody::Unknown))
    }

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn derive_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_flags_mean_implicit_monitor() {
        let cli = parse(&["appletalk", "--hex"]);
        assert!(cli.command.is_none());
        assert!(cli.output().hex);
    }

    #[test]
    fn explicit_monitor_takes_the_same_flags() {
        let cli = parse(&["appletalk", "monitor", "--hex", "--no-link", "--no-net"]);
        let out = cli.output();
        assert!(out.hex && out.no_link && out.no_net);
    }

    #[test]
    fn interface_is_global() {
        assert_eq!(parse(&["appletalk", "-i", "eth0"]).interface.as_deref(), Some("eth0"));
        assert_eq!(
            parse(&["appletalk", "monitor", "--interface", "eth0"]).interface.as_deref(),
            Some("eth0")
        );
    }

    #[test]
    fn defaults_print_no_hexdump() {
        let out = parse(&["appletalk"]).output().clone();
        assert!(!out.hex && !out.no_link && !out.no_net);
        assert!(out.only.is_empty() && out.hide.is_empty());
    }

    #[test]
    fn only_and_hide_are_comma_separated() {
        assert_eq!(parse(&["appletalk", "--only", "atp,nbp"]).output().only, [Proto::Atp, Proto::Nbp]);
        assert_eq!(parse(&["appletalk", "--hide", "rtmp"]).output().hide, [Proto::Rtmp]);
    }

    #[test]
    fn top_level_flags_before_a_subcommand_parse_but_are_flagged_conflicting() {
        // clap itself accepts this now — `global = true` requires it — but
        // `Cli::conflicting_output` (checked in `main`) still rejects it.
        let cli = parse(&["appletalk", "--hex", "monitor"]);
        assert!(cli.conflicting_output());
    }

    #[test]
    fn global_flags_survive_in_either_position_around_a_subcommand() {
        for args in [
            &["appletalk", "-i", "eth0", "zones"][..],
            &["appletalk", "--node", "3.4", "zones"][..],
            &["appletalk", "-i", "eth0", "monitor"][..],
            &["appletalk", "zones", "--node", "3.4"][..],
            &["appletalk", "ping", "-i", "eth0", "3.4"][..],
        ] {
            let cli = Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
            assert!(!cli.conflicting_output(), "{args:?} should not be flagged conflicting");
        }
    }

    #[test]
    fn ping_count_must_be_at_least_one() {
        assert!(Cli::try_parse_from(["appletalk", "ping", "-c", "0", "1.2"]).is_err());
        assert!(Cli::try_parse_from(["appletalk", "ping", "-c", "1", "1.2"]).is_ok());
    }

    #[test]
    fn net_claims_a_node_number_for_you() {
        assert_eq!(parse(&["appletalk", "--net", "6800", "zones"]).net, Some(6800));
        assert_eq!(parse(&["appletalk", "zones", "--net", "6800"]).net, Some(6800));
        // Naming the whole address and naming only the net are alternatives.
        assert!(
            Cli::try_parse_from(["appletalk", "--net", "6800", "--node", "6800.99", "zones"])
                .is_err()
        );
    }

    #[test]
    fn only_and_hide_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["appletalk", "--only", "atp", "--hide", "nbp"]).is_err());
    }

    #[test]
    fn interface_name_is_no_longer_positional() {
        assert!(Cli::try_parse_from(["appletalk", "eth0"]).is_err());
    }

    #[test]
    fn bridge_takes_a_named_link() {
        let cli = parse(&["appletalk", "bridge", "udp"]);
        assert!(matches!(cli.command, Some(Command::Bridge { link: Link::Udp })));
    }

    #[test]
    fn bridge_needs_a_link() {
        // The link is what says *which* other network; there is no default.
        assert!(Cli::try_parse_from(["appletalk", "bridge"]).is_err());
        assert!(Cli::try_parse_from(["appletalk", "bridge", "tashtalk"]).is_err());
    }

    #[test]
    fn bridge_takes_the_global_flags() {
        for args in [
            &["appletalk", "-i", "eth0", "bridge", "udp"][..],
            &["appletalk", "bridge", "udp", "--node", "6800.7"][..],
            &["appletalk", "--net", "6800", "bridge", "udp"][..],
        ] {
            let cli = Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
            assert!(!cli.conflicting_output(), "{args:?}");
        }
    }

    #[test]
    fn protocol_identity_comes_from_the_ddp_type() {
        let cases = [
            (1, Proto::Rtmp), // RTMP-data
            (2, Proto::Nbp),
            (3, Proto::Atp),
            (4, Proto::Aep),
            (5, Proto::Rtmp), // RTMP-req
            (6, Proto::Zip),
            (7, Proto::Adsp), // no parser yet, still identifiable
            (11, Proto::Other),
        ];
        for (typ, want) in cases {
            assert_eq!(Proto::of(&ddp(typ)), want, "DDP type {typ}");
        }

        let aarp = Aarp {
            op: 1,
            src_hw: MacAddr::zero(),
            src: Addr { net: 0, node: 0 },
            dst_hw: MacAddr::zero(),
            dst: Addr { net: 0, node: 0 },
        };
        assert_eq!(Proto::of(&packet(Body::Aarp(aarp))), Proto::Aarp);
        assert_eq!(Proto::of(&packet(Body::Unknown)), Proto::Other);
    }

    #[test]
    fn no_filters_shows_everything() {
        let out = Output::default();
        assert!(out.shows(&ddp(3)));
        assert!(out.shows(&packet(Body::Unknown)));
    }

    #[test]
    fn only_shows_just_the_listed_protocols() {
        let out = Output { only: vec![Proto::Atp], ..Output::default() };
        assert!(out.shows(&ddp(3)));
        assert!(!out.shows(&ddp(2)));
        assert!(!out.shows(&packet(Body::Unknown)));
    }

    #[test]
    fn hide_drops_just_the_listed_protocols() {
        let out = Output { hide: vec![Proto::Rtmp, Proto::Adsp], ..Output::default() };
        assert!(!out.shows(&ddp(1)));
        assert!(!out.shows(&ddp(5)));
        assert!(!out.shows(&ddp(7)));
        assert!(out.shows(&ddp(3)));
    }
}
