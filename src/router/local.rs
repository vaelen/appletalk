// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! The services a router owes its own cables: RTMP, ZIP, NBP and echo.
//!
//! Everything here is pure: `handle` and `tick` take what they need, read and
//! update the tables, and hand back datagrams for the runtime to send. No I/O,
//! no clock of their own.
//!
//! stub: Task 11 is the first caller.
#![allow(dead_code)]

use std::time::{Duration, Instant};

use super::ports::Port;
use super::table::{RouteChange, Tables};
use super::{Dest, Emit, Target};
use crate::capture::PortId;
use crate::node::datagram;
use crate::wire::{
    zone_multicast, Addr, Aep, Atp, Ddp, DdpBody, Echo, Encode, Func, Nbp, NbpFunc, NbpTuple,
    NetworkTuple, Rtmp, Zip, ZipAtp, DDP_AEP, DDP_ATP, DDP_NBP, DDP_ZIP,
};

/// How often a router broadcasts its routing table on each port (PDF 143).
pub const RTMP_INTERVAL: Duration = Duration::from_secs(10);
/// How often we ask the next router for the zones of a network we lack.
pub const ZIP_QUERY_INTERVAL: Duration = Duration::from_secs(10);

pub const RTMP_SOCKET: u8 = 1;
pub const NBP_SOCKET: u8 = 2;
pub const AEP_SOCKET: u8 = 4;
pub const ZIP_SOCKET: u8 = 6;

/// The most data one DDP datagram carries.
const DDP_MAX: usize = 586;
/// What is left for an ATP response's data once its 8-byte header is on.
const ATP_MAX: usize = 578;
/// A ZIP Reply's function and network-count bytes.
const ZIP_HEAD: usize = 2;

/// The NBP type a router registers itself under, and the socket it answers
/// lookups from.
const ROUTER_TYPE: &str = "AppleRouter";
const ROUTER_SOCKET: u8 = 253;

/// The router's own name, and the state its two timers keep.
pub struct Local {
    name: String,
    last_beacon: Option<Instant>,
    last_query: Option<Instant>,
}

impl Local {
    pub fn new(name: String) -> Local {
        Local { name, last_beacon: None, last_query: None }
    }

    /// A datagram delivered to this router (dst node ours, 0, or 255 on one of
    /// our nets) on `port`.
    pub fn handle(
        &mut self,
        port: &Port,
        ports: &[Port],
        ddp: &Ddp,
        body: &DdpBody,
        tables: &mut Tables,
        now: Instant,
    ) -> (Vec<Emit>, Vec<RouteChange>) {
        match body {
            DdpBody::Rtmp(r) => self.rtmp(port, ports, ddp, r, tables, now),
            DdpBody::Zip(z) => self.zip(port, ddp, z, tables),
            DdpBody::Atp(a) => (zone_list(port, ddp, a, tables).into_iter().collect(), Vec::new()),
            DdpBody::Nbp(n) => (self.nbp(port, ports, ddp, n, tables), Vec::new()),
            DdpBody::Aep(a) => (echo(port, ddp, a).into_iter().collect(), Vec::new()),
            DdpBody::Unknown => (Vec::new(), Vec::new()),
        }
    }

    /// Every tick: an RTMP beacon on each claimed port every 10 s, and a ZIP
    /// Query for every RTMP-learned network still missing its zones.
    pub fn tick(&mut self, _ports: &[Port], _tables: &Tables, _now: Instant) -> Vec<Emit> {
        Vec::new()
    }

    // ------------------------------------------------------------------ RTMP

    fn rtmp(
        &mut self,
        port: &Port,
        ports: &[Port],
        ddp: &Ddp,
        r: &Rtmp,
        tables: &mut Tables,
        now: Instant,
    ) -> (Vec<Emit>, Vec<RouteChange>) {
        match r {
            // Our own beacon heard back off the cable teaches us nothing.
            Rtmp::Data { sender, .. } if Some(*sender) == port.addr() => {
                (Vec::new(), Vec::new())
            }
            Rtmp::Data { sender, tuples, .. } => {
                let changes = tuples
                    .iter()
                    .flat_map(|t| tables.learn(t, Target::Port(port.id), *sender, now))
                    .collect();
                (Vec::new(), changes)
            }
            // A Response is a Data with the port's range and no tuples at all
            // (PDF 143).
            Rtmp::Request => (self.data_to(port, ddp, &[]), Vec::new()),
            Rtmp::Rdr { split_horizon } => {
                let tuples = match split_horizon {
                    true => tables.tuples_for(port.id),
                    false => tables.tuples_for(no_port(ports)),
                };
                (self.data_to(port, ddp, &advertisable(tables, ports, tuples)), Vec::new())
            }
        }
    }

    /// RTMP Data back to whoever asked, on the port it asked over.
    fn data_to(&self, port: &Port, ddp: &Ddp, tuples: &[NetworkTuple]) -> Vec<Emit> {
        let dest = Dest::Node(ddp.src.node);
        rtmp_data(port, dest, ddp.src, ddp.src_socket, tuples)
    }

    // ------------------------------------------------------------------- ZIP

    fn zip(
        &self,
        port: &Port,
        ddp: &Ddp,
        z: &Zip,
        tables: &mut Tables,
    ) -> (Vec<Emit>, Vec<RouteChange>) {
        match z {
            Zip::Query { nets } => (query_reply(port, ddp, nets, tables), Vec::new()),
            Zip::Reply { zones, extended } => (Vec::new(), learn_zones(zones, *extended, tables)),
            Zip::GetNetInfo { zone } => (net_info(port, ddp, zone).into_iter().collect(), Vec::new()),
            // A NetInfoReply is somebody else's answer, and Notify is not
            // decoded; neither is ours to act on.
            Zip::NetInfoReply { .. } | Zip::Notify => (Vec::new(), Vec::new()),
        }
    }

    // ------------------------------------------------------------------- NBP

    fn nbp(&self, port: &Port, ports: &[Port], ddp: &Ddp, n: &Nbp, tables: &Tables) -> Vec<Emit> {
        let Some(t) = n.tuples.first() else { return Vec::new() };
        // `*` and an empty zone both mean "wherever this cable is". The far
        // end has no way to work that out, so it is resolved here (PDF 191).
        let zone = match t.zone.as_str() {
            "" | "*" => port.default_zone().to_string(),
            z => z.to_string(),
        };
        let mut out = Vec::new();
        match n.func {
            NbpFunc::BrRq => {
                for (start, target) in tables.nets_in_zone(&zone) {
                    match direct_port(ports, target, start) {
                        Some(q) => out.extend(lkup(q, n, &zone)),
                        // Somebody else's cable: the first router on it is the
                        // one that turns this into a LkUp (PDF 191).
                        None => out.push(fwd_req(ddp, n, start, &zone)),
                    }
                }
            }
            NbpFunc::FwdReq => {
                for q in ports.iter().filter(|q| q.has_zone(&zone)) {
                    out.extend(lkup(q, n, &zone));
                }
            }
            NbpFunc::LkUp => {}
            // Somebody's answer to somebody's lookup: forwarded like any
            // datagram, never answered here.
            NbpFunc::LkUpReply => return Vec::new(),
        }
        out.extend(self.reply(port, n, t));
        out
    }

    /// Our own LkUp-Reply, when the lookup names this router.
    fn reply(&self, port: &Port, n: &Nbp, t: &NbpTuple) -> Option<Emit> {
        let object = t.object == "=" || t.object.eq_ignore_ascii_case(&self.name);
        let typ = t.typ == "=" || t.typ.eq_ignore_ascii_case(ROUTER_TYPE);
        let zone = t.zone.is_empty() || t.zone == "*" || port.has_zone(&t.zone);
        if !(object && typ && zone) {
            return None;
        }
        let body = Nbp {
            func: NbpFunc::LkUpReply,
            id: n.id,
            tuples: vec![NbpTuple {
                addr: port.addr()?,
                socket: ROUTER_SOCKET,
                enumerator: 0,
                object: self.name.clone(),
                typ: ROUTER_TYPE.to_string(),
                zone: port.default_zone().to_string(),
            }],
        };
        // The requester's address comes from the tuple, not from DDP: the
        // router that relayed the lookup is not the one waiting (PDF 192).
        Some(Emit::Route(from(port, NBP_SOCKET, t.addr, t.socket, DDP_NBP, &body)?))
    }
}

/// The port a network is directly attached to, if it is a cable of ours. A
/// `Target::Port` whose range does not start where the port's does is a route
/// learned through that port, not one of our own networks.
fn direct_port(ports: &[Port], target: Target, start: u16) -> Option<&Port> {
    match target {
        Target::Port(id) => ports.iter().find(|p| p.id == id && p.range.0 == start),
        Target::Peer(_) => None,
    }
}

/// The same lookup, addressed at the whole cable through its zone multicast.
fn lkup(q: &Port, n: &Nbp, zone: &str) -> Option<Emit> {
    let body = retarget(n, NbpFunc::LkUp, zone);
    // Network 0, node 255: every node on the cable, narrowed to the zone by
    // the multicast address the link carries it on (PDF 192).
    let ddp = from(q, NBP_SOCKET, Addr { net: 0, node: 255 }, NBP_SOCKET, DDP_NBP, &body)?;
    Some(Emit::On { port: q.id, dest: Dest::Zone(zone.to_string()), ddp })
}

/// The same lookup, on its way to the first router of network `start`.
fn fwd_req(ddp: &Ddp, n: &Nbp, start: u16, zone: &str) -> Emit {
    let body = retarget(n, NbpFunc::FwdReq, zone);
    // Node 0 of the range start means "the first router on that network"
    // (PDF 191). The requester's own source address rides along untouched.
    Emit::Route(datagram(
        ddp.src,
        ddp.src_socket,
        Addr { net: start, node: 0 },
        NBP_SOCKET,
        DDP_NBP,
        body.to_bytes(),
    ))
}

/// The same tuples under a different function code, with the wildcard zone
/// resolved: the only two things a router changes on the way through.
fn retarget(n: &Nbp, func: NbpFunc, zone: &str) -> Nbp {
    Nbp {
        func,
        id: n.id,
        tuples: n
            .tuples
            .iter()
            .map(|t| NbpTuple { zone: zone.to_string(), ..t.clone() })
            .collect(),
    }
}

/// AEP: the same data straight back to whoever asked.
fn echo(port: &Port, ddp: &Ddp, a: &Aep) -> Option<Emit> {
    if a.func != Echo::Request {
        return None;
    }
    let body = Aep { func: Echo::Reply, data: a.data.clone() };
    // Routed rather than pinned to this port: a ping can come from a network
    // away, and the router already knows the way back.
    Some(Emit::Route(from(port, AEP_SOCKET, ddp.src, ddp.src_socket, DDP_AEP, &body)?))
}

/// Answers a ZIP Query with the zones of every network named that we hold a
/// complete list for. Nothing known means no reply at all (PDF 184).
fn query_reply(port: &Port, ddp: &Ddp, nets: &[u16], tables: &Tables) -> Vec<Emit> {
    let mut replies: Vec<Zip> = Vec::new();
    let mut batch: Vec<(u16, String)> = Vec::new();
    let mut size = ZIP_HEAD;
    for &net in nets {
        let Some(list) = tables.zones(net).filter(|z| z.complete()) else { continue };
        let pairs: Vec<(u16, String)> = list.names.iter().map(|n| (net, n.clone())).collect();
        let bytes: usize = pairs.iter().map(|(_, n)| pair_bytes(n)).sum();
        let alone = ZIP_HEAD + bytes > DDP_MAX;
        // A network's zones list has to be whole inside one Reply, so flush
        // before starting a network that will not fit alongside it (PDF 184).
        if !batch.is_empty() && (alone || size + bytes > DDP_MAX) {
            replies.push(Zip::Reply { zones: std::mem::take(&mut batch), extended: false });
            size = ZIP_HEAD;
        }
        if alone {
            replies.extend(pages(pairs));
            continue;
        }
        batch.extend(pairs);
        size += bytes;
    }
    if !batch.is_empty() {
        replies.push(Zip::Reply { zones: batch, extended: false });
    }
    replies
        .into_iter()
        .filter_map(|r| {
            let ddp = from(port, ZIP_SOCKET, ddp.src, ddp.src_socket, DDP_ZIP, &r)?;
            Some(Emit::On { port: port.id, dest: Dest::Node(ddp.dst.node), ddp })
        })
        .collect()
}

/// One network's list split across Extended Replies.
///
/// ponytail: the book's network count on an Extended Reply is the size of the
/// *whole* list, not of this packet, but `Zip::Reply` derives the count from
/// the pairs it carries and `Zip::parse` reads exactly that many back. A
/// receiver therefore sees each page as a complete list. Carry the total on
/// `Zip::Reply` if a network ever really has more than a packet of zones.
fn pages(pairs: Vec<(u16, String)>) -> Vec<Zip> {
    let mut out = Vec::new();
    let mut batch: Vec<(u16, String)> = Vec::new();
    let mut size = ZIP_HEAD;
    for p in pairs {
        let n = pair_bytes(&p.1);
        if size + n > DDP_MAX && !batch.is_empty() {
            out.push(Zip::Reply { zones: std::mem::take(&mut batch), extended: true });
            size = ZIP_HEAD;
        }
        size += n;
        batch.push(p);
    }
    if !batch.is_empty() {
        out.push(Zip::Reply { zones: batch, extended: true });
    }
    out
}

/// A network number and a length-prefixed zone name, as a Reply carries them.
fn pair_bytes(name: &str) -> usize {
    2 + 1 + name.len().min(32)
}

/// A ZIP Reply fills in the zone table. The names for one network are
/// contiguous, so they are gathered per network before being stored.
fn learn_zones(zones: &[(u16, String)], extended: bool, tables: &mut Tables) -> Vec<RouteChange> {
    let mut by_net: Vec<(u16, Vec<String>)> = Vec::new();
    for (net, name) in zones {
        match by_net.iter_mut().find(|(n, _)| n == net) {
            Some((_, names)) => names.push(name.clone()),
            None => by_net.push((*net, vec![name.clone()])),
        }
    }
    let mut changes = Vec::new();
    for (net, names) in by_net {
        let expected = extended.then_some(names.len());
        changes.extend(tables.add_zones(net, &names, expected));
    }
    changes
}

/// The answer a booting node needs: this cable's range, whether the zone it
/// asked for is valid here, and the multicast address to listen on (PDF 190).
fn net_info(port: &Port, ddp: &Ddp, zone: &str) -> Option<Emit> {
    let valid = !zone.is_empty() && port.has_zone(zone);
    let mut flags = 0u8;
    if !valid {
        flags |= 0x80; // the requested zone is not on this cable
    }
    if port.zones.len() == 1 {
        flags |= 0x20; // one zone, so there is no point asking for the list
    }
    // An invalid request is answered with the default zone's multicast
    // address, and the default zone's name after it.
    let effective = if valid { zone } else { port.default_zone() };
    let multicast = match port.extended() {
        true => Some(zone_multicast(effective)),
        false => {
            flags |= 0x40; // this data link has no multicast: use broadcast
            None
        }
    };
    let body = Zip::NetInfoReply {
        flags,
        range: port.range,
        // Always a copy of the name from the request, so a node that hears a
        // broadcast reply can tell whether it is the one it asked for.
        zone: zone.to_string(),
        multicast,
        default_zone: (!valid).then(|| port.default_zone().to_string()),
    };
    // A requester whose network is not this cable's has no reachable node
    // address, so the reply goes to the whole cable (PDF 190).
    let dest = match (port.range.0..=port.range.1).contains(&ddp.src.net) {
        true => Dest::Node(ddp.src.node),
        false => Dest::Broadcast,
    };
    Some(Emit::On {
        port: port.id,
        dest,
        ddp: from(port, ZIP_SOCKET, ddp.src, ddp.src_socket, DDP_ZIP, &body)?,
    })
}

/// GetZoneList, GetLocalZones and GetMyZone: one ATP response with as many
/// names as fit, and the last-packet flag when the list runs out (PDF 186).
fn zone_list(port: &Port, ddp: &Ddp, a: &Atp, tables: &Tables) -> Option<Emit> {
    if a.func != Func::Req || ddp.dst_socket != ZIP_SOCKET {
        return None;
    }
    let (all, start) = match ZipAtp::parse_request(&a.user_bytes, &a.data)? {
        ZipAtp::GetZoneList { start } => (tables.all_zones(), start),
        ZipAtp::GetLocalZones { start } => (port.zones.clone(), start),
        ZipAtp::GetMyZone => (vec![port.default_zone().to_string()], 1),
        ZipAtp::Reply { .. } => return None,
    };
    // The start index is 1-based; a start past the end is legal and answered
    // with an empty last page.
    let rest = all.get(start.saturating_sub(1) as usize..).unwrap_or(&[]);
    let mut names: Vec<String> = Vec::new();
    let mut size = 0;
    for n in rest {
        size += 1 + n.len().min(32);
        if size > ATP_MAX {
            break;
        }
        names.push(n.clone());
    }
    let (user, data) = ZipAtp::reply_parts(names.len() == rest.len(), &names);
    let body = Atp::response(a.tid, 0, true, false, user, data);
    Some(Emit::On {
        port: port.id,
        dest: Dest::Node(ddp.src.node),
        ddp: from(port, ZIP_SOCKET, ddp.src, ddp.src_socket, DDP_ATP, &body)?,
    })
}

/// A datagram from one of our sockets on `port`. `None` until the port holds
/// an address, because there is no legal source to send from before then.
fn from(
    port: &Port,
    src_socket: u8,
    dst: Addr,
    dst_socket: u8,
    typ: u8,
    body: &impl Encode,
) -> Option<Ddp> {
    Some(datagram(port.addr()?, src_socket, dst, dst_socket, typ, body.to_bytes()))
}

/// A port id no configured port holds. `tuples_for` drops the routes reached
/// through the port it is given, so naming a port that does not exist drops
/// nothing — which is exactly an RDR with function 3, the whole table.
fn no_port(ports: &[Port]) -> PortId {
    (0..=PortId::MAX)
        .find(|id| ports.iter().all(|p| p.id != *id))
        .unwrap_or(PortId::MAX)
}

/// A network with no zone list yet must not be advertised, or its neighbours
/// re-advertise it and the internet queries for zones that never arrive (the
/// spec's ZIP-storm rule). Our own ports are exempt: their zones come from
/// config, so they are complete by definition.
fn advertisable(tables: &Tables, ports: &[Port], tuples: Vec<NetworkTuple>) -> Vec<NetworkTuple> {
    tuples
        .into_iter()
        .filter(|t| {
            ports.iter().any(|p| p.range == t.range)
                || tables.zones(t.range.0).is_some_and(|z| z.complete())
        })
        .collect()
}

/// One or more RTMP Data packets carrying `tuples`, each inside DDP's payload
/// limit, sent from the RTMP socket to the RTMP socket.
fn rtmp_data(
    port: &Port,
    dest: Dest,
    dst: Addr,
    dst_socket: u8,
    tuples: &[NetworkTuple],
) -> Vec<Emit> {
    let Some(sender) = port.addr() else { return Vec::new() };
    // Only an extended network states a range; a nonextended one sends the
    // three-byte version marker in its place (PDF 139).
    let range = port.extended().then_some(port.range);
    chunk(sender, range, tuples)
        .into_iter()
        .map(|r| Emit::On {
            port: port.id,
            dest: dest.clone(),
            ddp: datagram(sender, RTMP_SOCKET, dst, dst_socket, r.ddp_type(), r.to_bytes()),
        })
        .collect()
}

/// Splits `tuples` across as many RTMP Data packets as it takes to keep each
/// encoded packet inside `DDP_MAX`. Always yields at least one packet, so a
/// Response with no tuples still goes out.
fn chunk(sender: Addr, range: Option<(u16, u16)>, tuples: &[NetworkTuple]) -> Vec<Rtmp> {
    // Four bytes of sender, then the first tuple: six for a range, three for
    // the version marker.
    let base = 4 + if range.is_some() { 6 } else { 3 };
    let mut out = Vec::new();
    let mut batch: Vec<NetworkTuple> = Vec::new();
    let mut size = base;
    for t in tuples {
        let n = if t.extended { 6 } else { 3 };
        if size + n > DDP_MAX && !batch.is_empty() {
            out.push(Rtmp::Data { sender, range, tuples: std::mem::take(&mut batch) });
            size = base;
        }
        batch.push(*t);
        size += n;
    }
    out.push(Rtmp::Data { sender, range, tuples: batch });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::ports::Kind;
    use crate::wire::{DDP_RTMP_DATA, DDP_RTMP_REQ};
    use pnet::util::MacAddr;

    const MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 1);
    const NET: u16 = 6800;
    const ZONE: &str = "68k Mac Club";
    const PEER: Addr = Addr { net: NET, node: 1 };

    fn ether(id: PortId, range: (u16, u16), zones: &[&str], node: u8, now: Instant) -> Port {
        let zones = zones.iter().map(|z| z.to_string()).collect();
        let mut p = Port::new(id, format!("eth{id}"), Kind::Ether { mac: MAC }, range, zones, now);
        p.node = Some(node);
        p
    }

    fn ltalk(id: PortId, net: u16, zones: &[&str], node: u8, now: Instant) -> Port {
        let zones = zones.iter().map(|z| z.to_string()).collect();
        let mut p = Port::new(id, "ltoudp".into(), Kind::Ltoudp, (net, net), zones, now);
        p.node = Some(node);
        p
    }

    /// A datagram addressed to us on `socket`, from `PEER`.
    fn to_us(port: &Port, socket: u8, typ: u8, body: &impl Encode) -> Ddp {
        datagram(PEER, 200, port.addr().unwrap(), socket, typ, body.to_bytes())
    }

    fn ext(start: u16, end: u16, distance: u8) -> NetworkTuple {
        NetworkTuple { range: (start, end), extended: true, distance }
    }

    /// The `Rtmp` inside an `Emit`, with the port and destination it went to.
    fn rtmp_of(e: &Emit) -> (PortId, &Dest, Rtmp) {
        match e {
            Emit::On { port, dest, ddp } => {
                (*port, dest, Rtmp::parse(ddp.typ, &ddp.data).expect("RTMP"))
            }
            other => panic!("expected a port-directed emit, got {other:?}"),
        }
    }

    #[test]
    fn rtmp_data_from_another_router_is_learned_and_our_own_is_ignored() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = Tables::new();
        tables.add_port(0, (NET, NET), true, vec![ZONE.into()], t);
        let mut l = Local::new("router".into());

        let data = Rtmp::Data {
            sender: PEER,
            range: Some((NET, NET)),
            tuples: vec![ext(2905, 2905, 1)],
        };
        let ddp = to_us(&p, RTMP_SOCKET, DDP_RTMP_DATA, &data);
        let (out, changes) =
            l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Rtmp(data), &mut tables, t);
        assert_eq!(out, Vec::new());
        assert_eq!(changes.len(), 1, "{changes:?}");
        let new = changes[0].new.as_ref().unwrap();
        assert_eq!((new.range, new.distance, new.next), ((2905, 2905), 2, PEER));
        assert_eq!(new.target, Target::Port(0));

        // Our own beacon, heard back: nothing learned, nothing changed.
        let mine = Rtmp::Data {
            sender: p.addr().unwrap(),
            range: Some((NET, NET)),
            tuples: vec![ext(4000, 4000, 1)],
        };
        let ddp = to_us(&p, RTMP_SOCKET, DDP_RTMP_DATA, &mine);
        let (out, changes) =
            l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Rtmp(mine), &mut tables, t);
        assert_eq!((out, changes), (Vec::new(), Vec::new()));
        assert!(tables.best(4000).is_none());
    }

    #[test]
    fn rtmp_request_gets_a_response_with_our_range_and_no_tuples() {
        let t = Instant::now();
        let p = ether(0, (NET, NET + 1), &[ZONE], 9, t);
        let mut tables = Tables::new();
        tables.add_port(0, (NET, NET + 1), true, vec![ZONE.into()], t);
        tables.learn(&ext(2905, 2905, 1), Target::Port(0), PEER, t);
        let mut l = Local::new("router".into());

        let ddp = to_us(&p, RTMP_SOCKET, DDP_RTMP_REQ, &Rtmp::Request);
        let (out, changes) =
            l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Rtmp(Rtmp::Request), &mut tables, t);
        assert_eq!(changes, Vec::new());
        assert_eq!(out.len(), 1);
        let (port, dest, r) = rtmp_of(&out[0]);
        assert_eq!((port, dest), (0, &Dest::Node(PEER.node)));
        assert_eq!(
            r,
            Rtmp::Data {
                sender: p.addr().unwrap(),
                range: Some((NET, NET + 1)),
                tuples: Vec::new(),
            }
        );
        let Emit::On { ddp, .. } = &out[0] else { panic!() };
        assert_eq!((ddp.src_socket, ddp.dst_socket, ddp.typ), (RTMP_SOCKET, 200, DDP_RTMP_DATA));
    }

    #[test]
    fn a_nonextended_port_answers_with_the_version_marker() {
        let t = Instant::now();
        let p = ltalk(1, 3, &[ZONE], 200, t);
        let mut tables = Tables::new();
        tables.add_port(1, (3, 3), false, vec![ZONE.into()], t);
        let mut l = Local::new("router".into());
        let ddp = to_us(&p, RTMP_SOCKET, DDP_RTMP_REQ, &Rtmp::Request);
        let (out, _) =
            l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Rtmp(Rtmp::Request), &mut tables, t);
        let (_, _, r) = rtmp_of(&out[0]);
        assert!(matches!(r, Rtmp::Data { range: None, .. }), "{r}");
    }

    #[test]
    fn rtmp_rdr_honours_split_horizon_or_returns_the_whole_table() {
        let t = Instant::now();
        let a = ether(0, (NET, NET), &[ZONE], 9, t);
        let b = ether(1, (100, 100), &["Other"], 9, t);
        let ports = vec![p_clone(&a), p_clone(&b)];
        let mut tables = Tables::new();
        tables.add_port(0, (NET, NET), true, vec![ZONE.into()], t);
        tables.add_port(1, (100, 100), true, vec!["Other".into()], t);
        // Learned over port 0, so split horizon must hide it from port 0.
        tables.learn(&ext(2905, 2905, 1), Target::Port(0), PEER, t);
        tables.add_zones(2905, &["BabCom".into()], None);
        let mut l = Local::new("router".into());

        let split = Rtmp::Rdr { split_horizon: true };
        let ddp = to_us(&a, RTMP_SOCKET, DDP_RTMP_REQ, &split);
        let (out, _) = l.handle(&a, &ports, &ddp, &DdpBody::Rtmp(split), &mut tables, t);
        let (_, _, r) = rtmp_of(&out[0]);
        let Rtmp::Data { tuples, .. } = &r else { panic!() };
        assert_eq!(tuples, &[ext(100, 100, 0)]);

        let full = Rtmp::Rdr { split_horizon: false };
        let ddp = to_us(&a, RTMP_SOCKET, DDP_RTMP_REQ, &full);
        let (out, _) = l.handle(&a, &ports, &ddp, &DdpBody::Rtmp(full), &mut tables, t);
        let (_, _, r) = rtmp_of(&out[0]);
        let Rtmp::Data { tuples, .. } = &r else { panic!() };
        assert_eq!(tuples, &[ext(NET, NET, 0), ext(100, 100, 0), ext(2905, 2905, 2)]);
    }

    #[test]
    fn two_hundred_tuples_need_three_packets() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let tuples: Vec<NetworkTuple> = (0..200).map(|i| ext(i + 1, i + 1, 1)).collect();
        let out = rtmp_data(&p, Dest::Broadcast, Addr { net: NET, node: 255 }, RTMP_SOCKET, &tuples);
        assert_eq!(out.len(), 3);
        let counts: Vec<usize> = out
            .iter()
            .map(|e| {
                let (_, _, r) = rtmp_of(e);
                let Rtmp::Data { tuples, .. } = r else { panic!() };
                tuples.len()
            })
            .collect();
        // 10 bytes of header and range, then 96 six-byte tuples: 586 exactly.
        assert_eq!(counts, vec![96, 96, 8]);
        for e in &out {
            let Emit::On { ddp, .. } = e else { panic!() };
            assert!(ddp.data.len() <= DDP_MAX, "{} bytes", ddp.data.len());
        }
    }

    /// The `Zip` inside an `Emit`, with the port and destination it went to.
    fn zip_of(e: &Emit) -> (PortId, &Dest, Zip) {
        match e {
            Emit::On { port, dest, ddp } => (*port, dest, Zip::parse(&ddp.data).expect("ZIP")),
            other => panic!("expected a port-directed emit, got {other:?}"),
        }
    }

    /// A table with our cable on port 0, a routed network 2905, and a routed
    /// network 100 nobody has told us the zones of yet.
    fn internet(t: Instant) -> Tables {
        let mut tables = Tables::new();
        tables.add_port(0, (NET, NET), true, vec![ZONE.into()], t);
        tables.learn(&ext(2905, 2905, 1), Target::Port(0), PEER, t);
        tables.add_zones(2905, &["BabCom".into()], None);
        tables.learn(&ext(100, 100, 1), Target::Port(0), PEER, t);
        tables
    }

    #[test]
    fn zip_query_answers_only_for_networks_with_a_complete_zone_list() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = internet(t);
        let mut l = Local::new("router".into());

        let q = Zip::Query { nets: vec![NET, 2905, 100, 999] };
        let ddp = to_us(&p, ZIP_SOCKET, DDP_ZIP, &q);
        let (out, changes) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Zip(q), &mut tables, t);
        assert_eq!(changes, Vec::new());
        assert_eq!(out.len(), 1);
        let (port, dest, z) = zip_of(&out[0]);
        assert_eq!((port, dest), (0, &Dest::Node(PEER.node)));
        // 100 has no zones and 999 no route at all, so neither appears.
        assert_eq!(
            z,
            Zip::Reply {
                zones: vec![(NET, ZONE.into()), (2905, "BabCom".into())],
                extended: false,
            }
        );
        assert_eq!(z.to_string(), "reply 6800=68k Mac Club, 2905=BabCom");
        let Emit::On { ddp, .. } = &out[0] else { panic!() };
        assert_eq!((ddp.src_socket, ddp.dst_socket, ddp.typ), (ZIP_SOCKET, 200, DDP_ZIP));

        // Nothing known about any network named: no reply at all.
        let q = Zip::Query { nets: vec![100, 999] };
        let ddp = to_us(&p, ZIP_SOCKET, DDP_ZIP, &q);
        let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Zip(q), &mut tables, t);
        assert_eq!(out, Vec::new());
    }

    #[test]
    fn a_zone_list_too_big_for_one_reply_goes_as_extended_replies() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = internet(t);
        // 33 bytes a pair, so 17 fit in a 586-byte Reply and 20 do not.
        let many: Vec<String> = (0..20).map(|i| format!("{i:0>30}")).collect();
        tables.add_zones(2905, &many, None);
        let mut l = Local::new("router".into());

        let q = Zip::Query { nets: vec![2905] };
        let ddp = to_us(&p, ZIP_SOCKET, DDP_ZIP, &q);
        let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Zip(q), &mut tables, t);
        assert_eq!(out.len(), 2);
        let mut seen = Vec::new();
        for (i, e) in out.iter().enumerate() {
            let (_, _, z) = zip_of(e);
            let Zip::Reply { zones, extended } = z else { panic!() };
            assert!(extended, "page {i} is not an Extended Reply");
            assert!(zones.iter().all(|(n, _)| *n == 2905), "one network per packet");
            let Emit::On { ddp, .. } = e else { panic!() };
            assert!(ddp.data.len() <= DDP_MAX, "page {i} is {} bytes", ddp.data.len());
            seen.extend(zones.into_iter().map(|(_, n)| n));
        }
        // "BabCom" was already there, then the twenty long ones.
        assert_eq!(seen.len(), 21);
        assert_eq!(&seen[1..], &many[..]);
    }

    #[test]
    fn a_zip_reply_fills_the_zone_table() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = internet(t);
        let mut l = Local::new("router".into());

        let r = Zip::Reply {
            zones: vec![(100, "Engineering".into()), (100, "Marketing".into())],
            extended: false,
        };
        let ddp = to_us(&p, ZIP_SOCKET, DDP_ZIP, &r);
        let (out, changes) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Zip(r), &mut tables, t);
        assert_eq!(out, Vec::new());
        // 100 had no zones, so it has just become advertisable.
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0].new.as_ref().unwrap().range, (100, 100));
        let list = tables.zones(100).unwrap();
        assert_eq!(list.names, vec!["Engineering".to_string(), "Marketing".into()]);
        assert_eq!(list.expected, None);

        // An Extended Reply announces the total, so the list is only complete
        // once that many names are in.
        let r = Zip::Reply { zones: vec![(100, "Sales".into())], extended: true };
        let ddp = to_us(&p, ZIP_SOCKET, DDP_ZIP, &r);
        l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Zip(r), &mut tables, t);
        assert_eq!(tables.zones(100).unwrap().expected, Some(1));
    }

    #[test]
    fn get_net_info_confirms_a_valid_zone() {
        let t = Instant::now();
        let p = ether(0, (NET, NET + 1), &[ZONE, "Other"], 9, t);
        let mut tables = internet(t);
        let mut l = Local::new("router".into());

        let g = Zip::GetNetInfo { zone: "68K MAC CLUB".into() };
        let ddp = to_us(&p, ZIP_SOCKET, DDP_ZIP, &g);
        let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Zip(g), &mut tables, t);
        let (port, dest, z) = zip_of(&out[0]);
        assert_eq!((port, dest), (0, &Dest::Node(PEER.node)));
        assert_eq!(
            z,
            Zip::NetInfoReply {
                // Two zones on this cable, and the name was valid: no flags.
                flags: 0,
                range: (NET, NET + 1),
                zone: "68K MAC CLUB".into(),
                multicast: Some(zone_multicast(ZONE)),
                default_zone: None,
            }
        );
    }

    #[test]
    fn get_net_info_rejects_an_unknown_or_empty_zone_and_names_the_default() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = internet(t);
        let mut l = Local::new("router".into());

        for asked in ["BabCom", ""] {
            let g = Zip::GetNetInfo { zone: asked.into() };
            let ddp = to_us(&p, ZIP_SOCKET, DDP_ZIP, &g);
            let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Zip(g), &mut tables, t);
            let (_, _, z) = zip_of(&out[0]);
            assert_eq!(
                z,
                Zip::NetInfoReply {
                    // 0x80 zone invalid, 0x20 only one zone on this cable.
                    flags: 0xa0,
                    range: (NET, NET),
                    zone: asked.into(),
                    // The default zone's address, not the one asked for.
                    multicast: Some(zone_multicast(ZONE)),
                    default_zone: Some(ZONE.into()),
                },
                "asked for {asked:?}"
            );
        }
    }

    #[test]
    fn get_net_info_on_localtalk_offers_no_multicast_address() {
        let t = Instant::now();
        let p = ltalk(1, 3, &[ZONE], 200, t);
        let mut tables = Tables::new();
        tables.add_port(1, (3, 3), false, vec![ZONE.into()], t);
        let mut l = Local::new("router".into());

        let g = Zip::GetNetInfo { zone: ZONE.into() };
        let ddp = datagram(Addr { net: 3, node: 1 }, 200, p.addr().unwrap(), ZIP_SOCKET, DDP_ZIP, g.to_bytes());
        let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Zip(g), &mut tables, t);
        let (_, dest, z) = zip_of(&out[0]);
        assert_eq!(dest, &Dest::Node(1));
        let Zip::NetInfoReply { flags, multicast, .. } = z else { panic!() };
        // 0x40 use-broadcast, 0x20 only one zone. The name was valid.
        assert_eq!((flags, multicast), (0x60, None));
    }

    #[test]
    fn get_net_info_is_broadcast_when_the_requester_is_not_on_this_cable() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = internet(t);
        let mut l = Local::new("router".into());

        // A node still on the startup range has no address we can send to.
        let g = Zip::GetNetInfo { zone: ZONE.into() };
        let ddp = datagram(
            Addr { net: 0xff10, node: 42 },
            200,
            Addr { net: NET, node: 255 },
            ZIP_SOCKET,
            DDP_ZIP,
            g.to_bytes(),
        );
        let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Zip(g), &mut tables, t);
        let (_, dest, _) = zip_of(&out[0]);
        assert_eq!(dest, &Dest::Broadcast);
    }

    #[test]
    fn atp_answers_get_zone_list_get_local_zones_and_get_my_zone() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE, "Other"], 9, t);
        let mut tables = internet(t);
        let mut l = Local::new("router".into());

        let cases: [(u8, u16, Vec<String>); 4] = [
            (8, 1, vec![ZONE.into(), "BabCom".into()]),
            (8, 2, vec!["BabCom".into()]),
            (9, 1, vec![ZONE.into(), "Other".into()]),
            (7, 0, vec![ZONE.into()]),
        ];
        for (func, start, want) in cases {
            let s = start.to_be_bytes();
            let a = Atp::request(0x1234, 1, None, [func, 0, s[0], s[1]], Vec::new());
            let ddp = to_us(&p, ZIP_SOCKET, DDP_ATP, &a);
            let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Atp(a), &mut tables, t);
            assert_eq!(out.len(), 1, "function {func}");
            let Emit::On { port, dest, ddp } = &out[0] else { panic!() };
            assert_eq!((*port, dest), (0, &Dest::Node(PEER.node)));
            assert_eq!((ddp.src_socket, ddp.dst_socket, ddp.typ), (ZIP_SOCKET, 200, DDP_ATP));
            let r = Atp::parse(&ddp.data).unwrap();
            assert_eq!((r.func, r.tid, r.bitmap, r.eom()), (Func::Resp, 0x1234, 0, true));
            assert_eq!(
                ZipAtp::parse_reply(&r.user_bytes, &r.data).unwrap(),
                ZipAtp::Reply { last: true, zones: want },
                "function {func} start {start}"
            );
        }

        // A start index past the end is legal: an empty last page.
        let a = Atp::request(1, 1, None, [8, 0, 0, 99], Vec::new());
        let ddp = to_us(&p, ZIP_SOCKET, DDP_ATP, &a);
        let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Atp(a), &mut tables, t);
        let Emit::On { ddp, .. } = &out[0] else { panic!() };
        let r = Atp::parse(&ddp.data).unwrap();
        assert_eq!(
            ZipAtp::parse_reply(&r.user_bytes, &r.data).unwrap(),
            ZipAtp::Reply { last: true, zones: Vec::new() }
        );

        // An ATP request to another socket is nobody's business here.
        let a = Atp::request(1, 1, None, [8, 0, 0, 1], Vec::new());
        let ddp = to_us(&p, 200, DDP_ATP, &a);
        let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Atp(a), &mut tables, t);
        assert_eq!(out, Vec::new());
    }

    #[test]
    fn get_zone_list_pages_a_list_that_does_not_fit_one_response() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = internet(t);
        // 40 names of 30 bytes, 31 bytes each on the wire, after our own two
        // shorter ones: 20 of them fill ATP's 578 bytes exactly.
        let many: Vec<String> = (0..40).map(|i| format!("{i:0>30}")).collect();
        tables.add_zones(100, &many, None);
        let mut l = Local::new("router".into());

        let page = |l: &mut Local, tables: &mut Tables, start: u16| {
            let s = start.to_be_bytes();
            let a = Atp::request(7, 1, None, [8, 0, s[0], s[1]], Vec::new());
            let ddp = to_us(&p, ZIP_SOCKET, DDP_ATP, &a);
            let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Atp(a), tables, t);
            let Emit::On { ddp, .. } = &out[0] else { panic!() };
            assert!(ddp.data.len() <= 8 + ATP_MAX, "{} bytes", ddp.data.len());
            let r = Atp::parse(&ddp.data).unwrap();
            let ZipAtp::Reply { last, zones } = ZipAtp::parse_reply(&r.user_bytes, &r.data).unwrap()
            else {
                panic!()
            };
            (last, zones)
        };

        // all_zones() is our own zone, then BabCom, then the forty.
        let (last, first) = page(&mut l, &mut tables, 1);
        assert_eq!((last, first.len()), (false, 20));
        assert_eq!(first[0], ZONE);

        // Walk the rest from the index the previous page ended at.
        let mut all = first;
        let mut start = 1 + all.len() as u16;
        loop {
            let (last, zones) = page(&mut l, &mut tables, start);
            assert!(!zones.is_empty());
            start += zones.len() as u16;
            all.extend(zones);
            if last {
                break;
            }
        }
        assert_eq!(all.len(), 42);
        assert_eq!(&all[2..], &many[..]);
    }

    /// The `Nbp` inside an `Emit::Route`, with the datagram that carried it.
    fn routed_nbp(e: &Emit) -> (&Ddp, Nbp) {
        match e {
            Emit::Route(ddp) => (ddp, Nbp::parse(&ddp.data).expect("NBP")),
            other => panic!("expected a routed emit, got {other:?}"),
        }
    }

    fn lookup(func: NbpFunc, id: u8, from: Addr, socket: u8, name: &str, typ: &str, zone: &str) -> Nbp {
        crate::node::lookup_request(func, id, from, socket, name, typ, zone)
    }

    /// Ports 0 (our cable) and 1 (net 100), plus a routed network 2905. Both
    /// port 1 and 2905 carry the zone "Shared".
    fn two_cables(t: Instant) -> (Port, Port, Tables) {
        let a = ether(0, (NET, NET), &[ZONE], 9, t);
        let b = ether(1, (100, 100), &["Shared"], 9, t);
        let mut tables = Tables::new();
        tables.add_port(0, (NET, NET), true, vec![ZONE.into()], t);
        tables.add_port(1, (100, 100), true, vec!["Shared".into()], t);
        tables.learn(&ext(2905, 2905, 1), Target::Port(0), PEER, t);
        tables.add_zones(2905, &["Shared".into()], None);
        (a, b, tables)
    }

    #[test]
    fn nbp_brrq_looks_up_directly_and_forwards_to_the_rest() {
        let t = Instant::now();
        let (a, b, mut tables) = two_cables(t);
        let ports = vec![p_clone(&a), p_clone(&b)];
        let mut l = Local::new("router".into());

        let n = lookup(NbpFunc::BrRq, 7, PEER, 250, "=", "AFPServer", "Shared");
        let ddp = to_us(&a, NBP_SOCKET, DDP_NBP, &n);
        let (out, changes) = l.handle(&a, &ports, &ddp, &DdpBody::Nbp(n), &mut tables, t);
        assert_eq!(changes, Vec::new());
        assert_eq!(out.len(), 2, "{out:?}");

        // Port 1 is directly on a network in that zone: a zone-multicast LkUp.
        let Emit::On { port, dest, ddp: sent } = &out[0] else { panic!("{:?}", out[0]) };
        assert_eq!((*port, dest), (1, &Dest::Zone("Shared".into())));
        assert_eq!(sent.dst, Addr { net: 0, node: 255 });
        assert_eq!((sent.src, sent.src_socket, sent.dst_socket), (b.addr().unwrap(), NBP_SOCKET, NBP_SOCKET));
        assert_eq!(
            Nbp::parse(&sent.data).unwrap(),
            lookup(NbpFunc::LkUp, 7, PEER, 250, "=", "AFPServer", "Shared")
        );

        // 2905 is somebody else's cable: a FwdReq to its first router, still
        // carrying the requester's own DDP source.
        let (sent, fwd) = routed_nbp(&out[1]);
        assert_eq!(sent.dst, Addr { net: 2905, node: 0 });
        assert_eq!((sent.src, sent.src_socket, sent.dst_socket), (PEER, 200, NBP_SOCKET));
        assert_eq!(fwd, lookup(NbpFunc::FwdReq, 7, PEER, 250, "=", "AFPServer", "Shared"));
    }

    #[test]
    fn nbp_brrq_replaces_a_wildcard_zone_with_the_ports_default() {
        let t = Instant::now();
        let (a, b, mut tables) = two_cables(t);
        let ports = vec![p_clone(&a), p_clone(&b)];
        let mut l = Local::new("router".into());

        for asked in ["*", ""] {
            let n = lookup(NbpFunc::BrRq, 3, PEER, 250, "Fred", "AFPServer", asked);
            let ddp = to_us(&a, NBP_SOCKET, DDP_NBP, &n);
            let (out, _) = l.handle(&a, &ports, &ddp, &DdpBody::Nbp(n), &mut tables, t);
            assert_eq!(out.len(), 1, "asked for {asked:?}: {out:?}");
            let Emit::On { port, dest, ddp: sent } = &out[0] else { panic!() };
            assert_eq!((*port, dest), (0, &Dest::Zone(ZONE.into())));
            // The far end cannot know what `*` meant here, so it is resolved.
            assert_eq!(
                Nbp::parse(&sent.data).unwrap(),
                lookup(NbpFunc::LkUp, 3, PEER, 250, "Fred", "AFPServer", ZONE)
            );
        }
    }

    #[test]
    fn nbp_fwdreq_becomes_a_lkup_on_every_port_holding_the_zone() {
        let t = Instant::now();
        let mut a = ether(0, (NET, NET), &[ZONE, "Shared"], 9, t);
        a.zones = vec![ZONE.into(), "Shared".into()];
        let (_, b, mut tables) = two_cables(t);
        let ports = vec![p_clone(&a), p_clone(&b)];
        let mut l = Local::new("router".into());

        let n = lookup(NbpFunc::FwdReq, 9, PEER, 250, "Fred", "AFPServer", "Shared");
        let ddp = datagram(PEER, 200, Addr { net: NET, node: 0 }, NBP_SOCKET, DDP_NBP, n.to_bytes());
        let (out, _) = l.handle(&a, &ports, &ddp, &DdpBody::Nbp(n), &mut tables, t);
        assert_eq!(out.len(), 2, "{out:?}");
        for (i, want) in [(0usize, 0u8), (1, 1)] {
            let Emit::On { port, dest, ddp: sent } = &out[i] else { panic!("{:?}", out[i]) };
            assert_eq!((*port, dest), (want, &Dest::Zone("Shared".into())));
            assert_eq!(sent.dst, Addr { net: 0, node: 255 });
            assert_eq!(
                Nbp::parse(&sent.data).unwrap(),
                lookup(NbpFunc::LkUp, 9, PEER, 250, "Fred", "AFPServer", "Shared")
            );
        }
    }

    #[test]
    fn nbp_lookups_naming_us_get_a_reply_to_the_tuples_own_address() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = internet(t);
        let mut l = Local::new("router".into());
        let asking = Addr { net: 2905, node: 7 };

        for (object, typ, zone) in [
            ("router", "AppleRouter", ZONE),
            ("ROUTER", "=", "*"),
            ("=", "=", ""),
        ] {
            let n = lookup(NbpFunc::LkUp, 21, asking, 250, object, typ, zone);
            let ddp = to_us(&p, NBP_SOCKET, DDP_NBP, &n);
            let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Nbp(n), &mut tables, t);
            assert_eq!(out.len(), 1, "{object}:{typ}@{zone}");
            // The requester's address comes from the tuple, not from DDP.
            let (sent, reply) = routed_nbp(&out[0]);
            assert_eq!((sent.dst, sent.dst_socket), (asking, 250));
            assert_eq!((sent.src, sent.src_socket, sent.typ), (p.addr().unwrap(), NBP_SOCKET, DDP_NBP));
            assert_eq!(
                reply,
                Nbp {
                    func: NbpFunc::LkUpReply,
                    id: 21,
                    tuples: vec![NbpTuple {
                        addr: p.addr().unwrap(),
                        socket: 253,
                        enumerator: 0,
                        object: "router".into(),
                        typ: "AppleRouter".into(),
                        zone: ZONE.into(),
                    }],
                }
            );
        }

        // Somebody else's name, type or zone is not ours to answer.
        for (object, typ, zone) in [
            ("Fred", "AppleRouter", ZONE),
            ("router", "AFPServer", ZONE),
            ("router", "AppleRouter", "BabCom"),
        ] {
            let n = lookup(NbpFunc::LkUp, 21, asking, 250, object, typ, zone);
            let ddp = to_us(&p, NBP_SOCKET, DDP_NBP, &n);
            let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Nbp(n), &mut tables, t);
            assert_eq!(out, Vec::new(), "{object}:{typ}@{zone}");
        }
    }

    #[test]
    fn aep_requests_are_echoed_and_replies_are_not() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = internet(t);
        let mut l = Local::new("router".into());

        let a = Aep { func: Echo::Request, data: vec![0xde, 0xad, 0xbe, 0xef] };
        let ddp = to_us(&p, AEP_SOCKET, DDP_AEP, &a);
        let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Aep(a), &mut tables, t);
        assert_eq!(out.len(), 1);
        let Emit::Route(sent) = &out[0] else { panic!("{:?}", out[0]) };
        assert_eq!((sent.dst, sent.dst_socket), (PEER, 200));
        assert_eq!((sent.src, sent.src_socket), (p.addr().unwrap(), AEP_SOCKET));
        assert_eq!(
            Aep::parse(&sent.data).unwrap(),
            Aep { func: Echo::Reply, data: vec![0xde, 0xad, 0xbe, 0xef] }
        );

        // A reply is somebody else's answer to somebody else's ping.
        let a = Aep { func: Echo::Reply, data: vec![1] };
        let ddp = to_us(&p, AEP_SOCKET, DDP_AEP, &a);
        let (out, _) = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Aep(a), &mut tables, t);
        assert_eq!(out, Vec::new());
    }

    #[test]
    fn anything_else_is_ignored() {
        let t = Instant::now();
        let p = ether(0, (NET, NET), &[ZONE], 9, t);
        let mut tables = internet(t);
        let mut l = Local::new("router".into());

        // A LkUp-Reply is forwarded like any datagram, not answered here.
        let n = Nbp { func: NbpFunc::LkUpReply, id: 1, tuples: Vec::new() };
        let ddp = to_us(&p, NBP_SOCKET, DDP_NBP, &n);
        let out = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Nbp(n), &mut tables, t);
        assert_eq!(out, (Vec::new(), Vec::new()));

        let ddp = datagram(PEER, 200, p.addr().unwrap(), 200, 7, vec![1, 2, 3]);
        let out = l.handle(&p, &[p_clone(&p)], &ddp, &DdpBody::Unknown, &mut tables, t);
        assert_eq!(out, (Vec::new(), Vec::new()));
    }

    /// `Port` is not `Clone`, and every test needs the port both as the one
    /// the datagram arrived on and as a member of `ports`.
    fn p_clone(p: &Port) -> Port {
        let now = Instant::now();
        let zones = p.zones.clone();
        let mut c = Port::new(p.id, p.name.clone(), p.kind, p.range, zones, now);
        c.node = p.node;
        c
    }
}
