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
use crate::wire::{Addr, Ddp, DdpBody, Encode, NetworkTuple, Rtmp};

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
            _ => (Vec::new(), Vec::new()),
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
