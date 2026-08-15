// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Zone Information Protocol.

use std::fmt;

use pnet::util::MacAddr;

use super::{mac, mac_bytes, put_pstring, pstring, Encode};

/// A ZIP packet sent directly over DDP. The GetZoneList / GetLocalZones /
/// GetMyZone calls are a separate thing entirely — those ride on ATP with the
/// function in the user bytes, so they surface as ATP, not here.
#[derive(Debug, PartialEq, Eq)]
pub enum Zip {
    /// "Which zones are on these networks?"
    Query { nets: Vec<u16> },
    /// Network-to-zone-name answers. `extended` marks command 8, used when one
    /// network's zone list does not fit in a single reply.
    Reply { zones: Vec<(u16, String)>, extended: bool },
    /// A booting node asking a router for its cable range and zone.
    GetNetInfo { zone: String },
    NetInfoReply {
        flags: u8,
        range: (u16, u16),
        zone: String,
        multicast: MacAddr,
        /// Sent when the requested zone was not valid on this cable.
        default_zone: Option<String>,
    },
    /// Zone name change. ponytail: body left undecoded — rare, and the layout
    /// is worth confirming against a real capture before trusting it.
    Notify,
}

impl Zip {
    pub fn parse(p: &[u8]) -> Option<Self> {
        let count = *p.get(1)? as usize;
        match *p.first()? {
            1 => {
                let nets = p
                    .get(2..2 + count * 2)?
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Some(Zip::Query { nets })
            }
            cmd @ (2 | 8) => {
                let mut rest = p.get(2..)?;
                let mut zones = Vec::with_capacity(count);
                for _ in 0..count {
                    let net = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
                    let (name, r) = pstring(rest.get(2..)?)?;
                    zones.push((net, name));
                    rest = r;
                }
                Some(Zip::Reply { zones, extended: cmd == 8 })
            }
            // Command, flags, then 4 zero bytes, then the zone being asked about.
            5 => Some(Zip::GetNetInfo { zone: pstring(p.get(6..)?)?.0 }),
            6 => {
                let h = p.get(..6)?;
                let (zone, rest) = pstring(&p[6..])?;
                let mclen = *rest.first()? as usize;
                let multicast = mac(rest.get(1..1 + mclen)?)?;
                let rest = rest.get(1 + mclen..)?;
                let flags = h[1];
                Some(Zip::NetInfoReply {
                    flags,
                    range: (
                        u16::from_be_bytes([h[2], h[3]]),
                        u16::from_be_bytes([h[4], h[5]]),
                    ),
                    zone,
                    multicast,
                    // Only present when the router rejected the requested zone.
                    default_zone: (flags & 0x80 != 0).then(|| pstring(rest)).flatten().map(|(s, _)| s),
                })
            }
            7 => Some(Zip::Notify),
            _ => None,
        }
    }
}

impl fmt::Display for Zip {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Zip::Query { nets } => {
                let list: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
                write!(f, "query nets {}", list.join(", "))
            }
            Zip::Reply { zones, extended } => {
                let list: Vec<String> = zones.iter().map(|(n, z)| format!("{n}={z}")).collect();
                let kind = if *extended { "ext-reply" } else { "reply" };
                write!(f, "{kind} {}", list.join(", "))
            }
            Zip::GetNetInfo { zone } => write!(f, "get-net-info zone {zone}"),
            Zip::NetInfoReply { flags, range, zone, multicast, default_zone } => {
                write!(f, "net-info-reply nets {}-{} zone {zone} mcast {multicast}", range.0, range.1)?;
                if flags & 0x80 != 0 {
                    f.write_str(" zone-invalid")?;
                }
                if flags & 0x40 != 0 {
                    f.write_str(" use-broadcast")?;
                }
                if flags & 0x20 != 0 {
                    f.write_str(" one-zone")?;
                }
                match default_zone {
                    Some(z) => write!(f, " default {z}"),
                    None => Ok(()),
                }
            }
            Zip::Notify => f.write_str("notify"),
        }
    }
}

impl Encode for Zip {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Zip::Query { nets } => {
                out.push(1);
                out.push(nets.len().min(255) as u8);
                for n in nets {
                    out.extend(n.to_be_bytes());
                }
            }
            Zip::Reply { zones, extended } => {
                out.push(if *extended { 8 } else { 2 });
                out.push(zones.len().min(255) as u8);
                for (net, name) in zones {
                    out.extend(net.to_be_bytes());
                    put_pstring(out, name);
                }
            }
            Zip::GetNetInfo { zone } => {
                out.push(5);
                out.extend([0; 5]); // flags byte plus 4 reserved zero bytes
                put_pstring(out, zone);
            }
            Zip::NetInfoReply { flags, range, zone, multicast, default_zone } => {
                out.push(6);
                out.push(*flags);
                out.extend(range.0.to_be_bytes());
                out.extend(range.1.to_be_bytes());
                put_pstring(out, zone);
                out.push(6);
                out.extend(mac_bytes(*multicast));
                if let Some(z) = default_zone {
                    put_pstring(out, z);
                }
            }
            Zip::Notify => out.push(7),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testkit::*;

    #[test]
    fn zip_query() {
        let z = Zip::parse(&[1, 2, 0, 3, 0, 5]).unwrap();
        assert_eq!(z, Zip::Query { nets: vec![3, 5] });
        assert_eq!(z.to_string(), "query nets 3, 5");
    }

    #[test]
    fn zip_reply_pairs_nets_with_zones() {
        let mut p = vec![2, 2];
        p.extend([0, 3]);
        p.extend(ps("Engineering"));
        p.extend([0, 5]);
        p.extend(ps("Marketing"));
        let z = Zip::parse(&p).unwrap();
        assert_eq!(z.to_string(), "reply 3=Engineering, 5=Marketing");
    }

    #[test]
    fn zip_get_net_info_round_trip() {
        let mut req = vec![5, 0, 0, 0, 0, 0];
        req.extend(ps("Engineering"));
        assert_eq!(
            Zip::parse(&req).unwrap().to_string(),
            "get-net-info zone Engineering"
        );

        // Reply: flags "only one zone", cable range 3-5, plus the multicast
        // address a node in that zone should listen on.
        let mut reply = vec![6, 0x20, 0, 3, 0, 5];
        reply.extend(ps("Engineering"));
        reply.extend([6, 0x09, 0x00, 0x07, 0x00, 0x00, 0x01]);
        let z = Zip::parse(&reply).unwrap();
        assert_eq!(
            z.to_string(),
            "net-info-reply nets 3-5 zone Engineering mcast 09:00:07:00:00:01 one-zone"
        );
    }

    #[test]
    fn zip_net_info_reply_carries_default_zone_when_invalid() {
        let mut reply = vec![6, 0x80, 0, 3, 0, 5]; // 0x80 = requested zone invalid
        reply.extend(ps("Nonexistent"));
        reply.extend([6, 0x09, 0x00, 0x07, 0x00, 0x00, 0x01]);
        reply.extend(ps("Engineering"));
        let z = Zip::parse(&reply).unwrap();
        assert!(z.to_string().ends_with("zone-invalid default Engineering"), "{z}");
    }

    #[test]
    fn zip_rejects_unknown_command_and_short() {
        assert!(Zip::parse(&[99, 0]).is_none());
        assert!(Zip::parse(&[1]).is_none()); // no count byte
        assert!(Zip::parse(&[1, 4, 0, 3]).is_none()); // count exceeds body
    }

    #[test]
    fn zip_encodes_query_and_recomputes_count() {
        let mut z = Zip::parse(&[1, 2, 0, 3, 0, 5]).unwrap();
        assert_eq!(z.to_bytes(), vec![1, 2, 0, 3, 0, 5]);
        if let Zip::Query { nets } = &mut z {
            nets.push(9);
        }
        assert_eq!(z.to_bytes(), vec![1, 3, 0, 3, 0, 5, 0, 9]);
    }

    #[test]
    fn zip_round_trips_reply_and_net_info() {
        use crate::wire::testkit::ps;

        let mut reply = vec![2, 2];
        reply.extend([0, 3]);
        reply.extend(ps("Engineering"));
        reply.extend([0, 5]);
        reply.extend(ps("Marketing"));
        let z = Zip::parse(&reply).unwrap();
        assert_eq!(Zip::parse(&z.to_bytes()), Some(z));

        let mut info = vec![6, 0x20, 0, 3, 0, 5];
        info.extend(ps("Engineering"));
        info.extend([6, 0x09, 0x00, 0x07, 0x00, 0x00, 0x01]);
        let z = Zip::parse(&info).unwrap();
        assert_eq!(Zip::parse(&z.to_bytes()), Some(z));
    }

    #[test]
    fn zip_round_trips_net_info_with_default_zone() {
        use crate::wire::testkit::ps;
        let mut info = vec![6, 0x80, 0, 3, 0, 5];
        info.extend(ps("Nonexistent"));
        info.extend([6, 0x09, 0x00, 0x07, 0x00, 0x00, 0x01]);
        info.extend(ps("Engineering"));
        let z = Zip::parse(&info).unwrap();
        assert_eq!(Zip::parse(&z.to_bytes()), Some(z));
    }
}
