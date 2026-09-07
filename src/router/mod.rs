// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! The router: forwards DDP between ports and AURP peers, and runs the
//! routing, zone and name services a router owes its cables.
//!
//! `Router` is pure: every input is a decoded frame and a clock reading, and
//! every output is an `Action` for `run` to put on a wire. `run` is the only
//! part that opens anything.

pub mod aurp;
pub mod local;
pub mod ports;
pub mod table;

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use crate::capture::{self, Event, PortId, Tx};
use crate::config::Config;
use crate::ltoudp::Ltoudp;
use crate::router::aurp::{Peers, RECONNECT_SCAN};
use crate::router::local::Local;
use crate::router::ports::{Inbound, Kind, Port};
use crate::router::table::{RouteChange, Tables};
use crate::tashtalk::Tashtalk;
use crate::wire::{self, Body, Ddp, DdpBody, Di, Encode, Frame, Llap, Packet};

/// The port every AURP tunnel speaks over (`docs/AURP.md`).
const AURP_PORT: u16 = 387;
/// The longest a datagram may wait before the timers get a look in; the
/// bridge's loop uses the same one.
const TICK: Duration = Duration::from_millis(250);
/// How long shutdown waits for the peers to acknowledge our RDs.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
/// Events queued before a reader thread starts dropping.
const QUEUE: usize = 1024;

/// DDP's hop count is four bits, so a datagram that has already crossed this
/// many routers has nowhere left to go (PDF 147).
const MAX_HOPS: u8 = 15;

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

/// One thing that happened, as the run loop hands it to the router.
pub enum In<'a> {
    Ether { port: PortId, packet: &'a Packet },
    Llap { port: PortId, llap: &'a Llap },
    Aurp { from: Ipv4Addr, bytes: &'a [u8] },
    Tick,
    Dump,
}

pub struct Router {
    pub ports: Vec<Port>,
    pub tables: Tables,
    pub local: Local,
    pub peers: Peers,
}

impl Router {
    /// `cfg.public_ip` is read here as the AURP domain identifier, so `run`
    /// resolves it before calling this.
    ///
    /// `port_kinds` is one entry per configured port, in the config's own
    /// order — every EtherTalk port, then every LToUDP port, then every
    /// TashTalk one — carrying the name the link actually opened under and
    /// the framing it needs. The index is the `PortId`.
    pub fn new(cfg: &Config, port_kinds: Vec<(String, Kind)>, now: Instant) -> Router {
        let mut tables = Tables::new();
        let mut ports = Vec::new();
        for (id, ((name, kind), (range, zones))) in
            port_kinds.into_iter().zip(port_specs(cfg)).enumerate()
        {
            let p = Port::new(id as PortId, name, kind, range, zones.clone(), now);
            tables.add_port(p.id, range, p.extended(), zones, now);
            ports.push(p);
        }
        // ponytail: a peer created under open peering, or one whose configured
        // name later disappears, is never evicted — the peer table only grows.
        // Evict peers with both connections Unconnected if a public router
        // ever meets enough strangers for that to matter.
        let peers = Peers::new(
            cfg.public_ip.map_or(Di::Null, Di::Ip),
            cfg.open_peering,
            &cfg.peers,
            now,
        );
        Router { ports, tables, local: Local::new(cfg.name.clone()), peers }
    }

    pub fn step(&mut self, input: In, now: Instant) -> Vec<Action> {
        match input {
            In::Ether { port, packet } => {
                let Some(i) = self.index(port) else { return Vec::new() };
                let (inbound, mut out) = self.ports[i].inbound_ether(packet, now);
                // A port only lifts a datagram out of a frame it decoded, so
                // the body beside it is this datagram's own.
                if let (Inbound::Ddp(ddp), Body::Ddp(_, body)) = (inbound, &packet.body) {
                    out.extend(self.arrived(Some(port), ddp, body, now));
                }
                out
            }
            In::Llap { port, llap } => {
                let Some(i) = self.index(port) else { return Vec::new() };
                let (inbound, mut out) = self.ports[i].inbound_llap(llap, now);
                if let Inbound::Ddp(ddp) = inbound {
                    // LLAP carries no decode tree with it: the body has to be
                    // parsed here.
                    let body = wire::decode_ddp_body(&ddp);
                    out.extend(self.arrived(Some(port), ddp, &body, now));
                }
                out
            }
            In::Aurp { from, bytes } => {
                let (mut out, changes, ddp) =
                    self.peers.packet(from, bytes, &mut self.tables, now);
                out.extend(self.changed(changes));
                // A datagram off a tunnel enters the forwarding rules where a
                // local one does, minus the arriving port and the hop
                // increment (spec, "DDP forwarding").
                if let Some(d) = ddp.as_deref().and_then(Ddp::parse) {
                    let body = wire::decode_ddp_body(&d);
                    out.extend(self.arrived(None, d, &body, now));
                }
                out
            }
            In::Tick => {
                let mut out = Vec::new();
                for i in 0..self.ports.len() {
                    out.extend(self.ports[i].tick(now));
                }
                let changes = self.tables.age(now);
                out.extend(self.changed(changes));
                for e in self.local.tick(&self.ports, &self.tables, now) {
                    out.extend(self.emit(e, now));
                }
                let (acts, changes) = self.peers.tick(&mut self.tables, now);
                out.extend(acts);
                out.extend(self.changed(changes));
                out
            }
            In::Dump => {
                vec![Action::Log(format!(
                    "\n{}\n{}\n{}",
                    self.tables.dump().trim_end(),
                    self.peers.dump().trim_end(),
                    self.port_dump().trim_end()
                ))]
            }
        }
    }

    /// A datagram off a link (`from` a port) or off a tunnel (`from` None),
    /// run through the spec's forwarding order.
    fn arrived(
        &mut self,
        from: Option<PortId>,
        mut ddp: Ddp,
        body: &DdpBody,
        now: Instant,
    ) -> Vec<Action> {
        // A length field that disagrees with the bytes means a truncated or
        // padded datagram; fail closed rather than pass it on. (A Phase 1
        // frame carries its Ethernet padding into the payload, so a short one
        // lands here too — Phase 1 is not a link this router claims to
        // route.)
        if ddp.length as usize != 13 + ddp.data.len() {
            return Vec::new();
        }
        // Network 0 means "this cable" (PDF 118); everything downstream wants
        // a real network number.
        if let Some(i) = from.and_then(|id| self.index(id)) {
            let net = self.ports[i].range.0;
            if ddp.dst.net == 0 {
                ddp.dst.net = net;
            }
            if ddp.src.net == 0 {
                ddp.src.net = net;
            }
        }
        // The cable the destination network belongs to, if it is one of ours.
        let Some(q) = self.owner(ddp.dst.net) else { return self.forward(from, ddp, now) };
        let node = ddp.dst.node;
        // Node 0 means "any router on that network" and 255 means everybody,
        // and both include us.
        let for_us = node == 0 || node == 255 || Some(node) == self.ports[q].node;
        let mut out = Vec::new();
        if for_us {
            let (emits, changes) = self.local.handle(
                &self.ports[q],
                &self.ports,
                &ddp,
                body,
                &mut self.tables,
                now,
            );
            out.extend(self.changed(changes));
            for e in emits {
                out.extend(self.emit(e, now));
            }
        }
        // A broadcast still has to reach the cable it names, and a datagram
        // for somebody else's node on one of our other cables has to be put
        // on it. `forward` refuses to repeat it onto the port it came from,
        // which is what makes step 3's "already where it belongs" a drop.
        if node == 255 || !for_us {
            out.extend(self.forward(from, ddp, now));
        }
        out
    }

    /// The forwarding rules; `from` None means a datagram from a peer (no hop
    /// increment) or one we originated.
    pub fn forward(&mut self, from: Option<PortId>, mut ddp: Ddp, _now: Instant) -> Vec<Action> {
        if ddp.hops >= MAX_HOPS {
            return Vec::new();
        }
        let Some(route) = self.tables.best(ddp.dst.net) else { return Vec::new() };
        let (target, next, distance) = (route.target, route.next, route.distance);
        // Crossing this router costs a hop; originating a datagram here, or
        // relaying one off a tunnel, does not (`docs/AURP.md`, "Hop counts").
        if from.is_some() {
            ddp.hops += 1;
        }
        match target {
            Target::Peer(ip) => vec![self.peers.forward(ip, &ddp.to_bytes())],
            // Never repeat a datagram out the port it arrived on.
            Target::Port(id) if Some(id) != from => {
                let Some(i) = self.index(id) else { return Vec::new() };
                let dest = match (distance, ddp.dst.node) {
                    // Directly attached: the datagram is home.
                    (0, 255) => Dest::Broadcast,
                    (0, n) => Dest::Node(n),
                    // One more router to go, and it is on this cable.
                    _ => Dest::Node(next.node),
                };
                self.ports[i].emit(&dest, &ddp).into_iter().collect()
            }
            Target::Port(_) => Vec::new(),
        }
    }

    /// A service's datagram: pinned to a port, or handed back to the routing
    /// rules as if we had originated it.
    fn emit(&mut self, e: Emit, now: Instant) -> Vec<Action> {
        match e {
            Emit::On { port, dest, ddp } => match self.index(port) {
                Some(i) => self.ports[i].emit(&dest, &ddp).into_iter().collect(),
                None => Vec::new(),
            },
            Emit::Route(ddp) => self.forward(None, ddp, now),
        }
    }

    /// Route changes are what an AURP data sender reports to its peers, and
    /// the only place the routing and zone tables' movements are visible to
    /// anyone watching stderr (spec, "Observability").
    fn changed(&mut self, changes: Vec<RouteChange>) -> Vec<Action> {
        if changes.is_empty() {
            return Vec::new();
        }
        self.peers.route_changed(&changes, &self.tables);
        changes.iter().map(|c| Action::Log(self.describe(c))).collect()
    }

    /// One route change as a line. `Tables::add_zones` reports a network
    /// becoming exportable the same way it reports a new route, so the added
    /// line doubles as "zones learned for a network" — which is why it names
    /// the zones we now hold.
    fn describe(&self, c: &RouteChange) -> String {
        let range = format!("{}-{}", c.range.0, c.range.1);
        let zones = match self.tables.zones(c.range.0) {
            Some(z) if !z.names.is_empty() => format!(", zones {}", z.names.join(", ")),
            _ => String::new(),
        };
        match (&c.old, &c.new) {
            (None, Some(n)) => {
                format!("route {range} via {} distance {}{zones}", via(n.target), n.distance)
            }
            (Some(o), None) => {
                format!("route {range} deleted, was via {} distance {}", via(o.target), o.distance)
            }
            (Some(o), Some(n)) => format!(
                "route {range} now via {} distance {}, was via {} distance {}{zones}",
                via(n.target),
                n.distance,
                via(o.target),
                o.distance
            ),
            (None, None) => format!("route {range} unchanged"),
        }
    }

    fn index(&self, port: PortId) -> Option<usize> {
        self.ports.iter().position(|p| p.id == port)
    }

    /// The port a network of ours sits on.
    fn owner(&self, net: u16) -> Option<usize> {
        self.ports.iter().position(|p| p.range.0 <= net && net <= p.range.1)
    }

    fn port_dump(&self) -> String {
        let mut s = String::new();
        for p in &self.ports {
            let kind = match p.kind {
                Kind::Ether { .. } => "ethertalk",
                Kind::Ltoudp => "ltoudp",
                Kind::Tashtalk => "tashtalk",
            };
            let node = match p.node {
                Some(n) => n.to_string(),
                None => "claiming".to_string(),
            };
            s.push_str(&format!(
                "port {:<2} {:<9}  {:<20}  {}-{}  node {:<8}  {}\n",
                p.id,
                kind,
                p.name,
                p.range.0,
                p.range.1,
                node,
                p.zones.join(", ")
            ));
        }
        s
    }
}

/// How a route is reached, for a log line: `Tables::dump` says it the same way.
fn via(t: Target) -> String {
    match t {
        Target::Port(p) => format!("port {p}"),
        Target::Peer(ip) => ip.to_string(),
    }
}

/// Every configured port's range and zones, in the order `run` opens them, so
/// a port's index is its `PortId`.
fn port_specs(cfg: &Config) -> Vec<((u16, u16), Vec<String>)> {
    cfg.ethertalk
        .iter()
        .map(|p| (p.net, p.zones.clone()))
        .chain(cfg.ltoudp.iter().map(|p| ((p.net, p.net), p.zones.clone())))
        .chain(cfg.tashtalk.iter().map(|p| ((p.net, p.net), p.zones.clone())))
        .collect()
}

// ------------------------------------------------------------------ run loop

/// Set by the signal handlers, read on every pass of the loop. A handler must
/// do nothing but this: it runs between two arbitrary instructions.
static DUMP: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_dump(_: libc::c_int) {
    DUMP.store(true, Ordering::Relaxed);
}

extern "C" fn on_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// The links a port can be, once opened. EtherTalk transmits through the
/// capture handle; the two LocalTalk kinds own their own socket or UART.
enum Link {
    Ether(Tx),
    Ltoudp(Ltoudp),
    Tashtalk(Tashtalk),
}

pub fn run(mut cfg: Config) -> io::Result<()> {
    let (tx, events) = sync_channel(QUEUE);
    let (mut links, kinds, nic_ip) = open_ports(&cfg, &tx)?;

    let sock = UdpSocket::bind(cfg.listen)?;
    spawn_aurp(&sock, tx.clone())?;
    // Every reader thread holds its own clone; ours would keep the channel
    // alive for ever and hide the "all producers gone" case.
    drop(tx);

    cfg.public_ip = Some(domain_identifier(&cfg, &sock, nic_ip));

    let now = Instant::now();
    let mut r = Router::new(&cfg, kinds, now);
    eprintln!(
        "router: {} on {} port(s), AURP on {} as {}",
        cfg.name,
        r.ports.len(),
        cfg.listen,
        cfg.public_ip.expect("just set")
    );

    // SAFETY: both handlers only store to a `static AtomicBool`, which is all
    // a handler may portably do.
    unsafe {
        libc::signal(libc::SIGUSR1, on_dump as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_stop as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_stop as libc::sighandler_t);
    }

    let mut next_scan = now;
    let mut deadline: Option<Instant> = None;
    loop {
        // Sampled after the blocking receive, not before: taken any earlier,
        // `now` would be up to TICK stale by the time the event is handled.
        let event = events.recv_timeout(TICK);
        let now = Instant::now();
        let mut actions = match event {
            Ok(Event::Packet { port, packet, .. }) => {
                r.step(In::Ether { port, packet: &packet }, now)
            }
            Ok(Event::Llap { port, llap }) => r.step(In::Llap { port, llap: &llap }, now),
            Ok(Event::Aurp { from, bytes }) => {
                r.step(In::Aurp { from: *from.ip(), bytes: &bytes }, now)
            }
            Ok(Event::Dropped(n)) => {
                eprintln!("router: dropped {n} events (queue full)");
                r.step(In::Tick, now)
            }
            Ok(Event::Error(e)) => {
                eprintln!("router: rx: {e}");
                r.step(In::Tick, now)
            }
            Err(RecvTimeoutError::Timeout) => r.step(In::Tick, now),
            // Every link's reader thread has gone; there is nothing left to
            // route.
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        };
        if now >= next_scan {
            next_scan = now + RECONNECT_SCAN;
            resolve(&cfg.peers, &mut r.peers, now);
        }
        if DUMP.swap(false, Ordering::Relaxed) {
            actions.extend(r.step(In::Dump, now));
        }
        if deadline.is_none() && STOP.load(Ordering::Relaxed) {
            eprintln!("router: shutting down");
            actions.extend(r.peers.shutdown(now));
            deadline = Some(now + SHUTDOWN_GRACE);
        }
        for a in actions {
            execute(a, &mut links, &sock);
        }
        if deadline.is_some_and(|d| now >= d) {
            return Ok(());
        }
    }
}

/// Opens every configured link and starts its reader thread. Returns the
/// transmit halves by port, the `(name, kind)` pairs `Router::new` wants in
/// the same order, and the first IPv4 address any NIC offered.
#[allow(clippy::type_complexity)]
fn open_ports(
    cfg: &Config,
    tx: &SyncSender<Event>,
) -> io::Result<(HashMap<PortId, Link>, Vec<(String, Kind)>, Option<Ipv4Addr>)> {
    let mut links = HashMap::new();
    let mut kinds = Vec::new();
    let mut nic_ip = None;
    for p in &cfg.ethertalk {
        let id = kinds.len() as PortId;
        let nic = capture::spawn_into(Some(&p.interface), id, tx.clone())?;
        nic_ip = nic_ip.or(nic.ip);
        kinds.push((nic.iface, Kind::Ether { mac: nic.tx.mac }));
        links.insert(id, Link::Ether(nic.tx));
    }
    for p in &cfg.ltoudp {
        let id = kinds.len() as PortId;
        let lt = Ltoudp::open(p.interface)?;
        lt.spawn(id, tx.clone())?;
        let name = p.interface.map_or_else(|| "ltoudp".to_string(), |i| i.to_string());
        kinds.push((name, Kind::Ltoudp));
        links.insert(id, Link::Ltoudp(lt));
    }
    for p in &cfg.tashtalk {
        let id = kinds.len() as PortId;
        let tt = Tashtalk::open(&p.device)?;
        tt.spawn(id, tx.clone())?;
        kinds.push((p.device.clone(), Kind::Tashtalk));
        links.insert(id, Link::Tashtalk(tt));
    }
    Ok((links, kinds, nic_ip))
}

fn spawn_aurp(sock: &UdpSocket, tx: SyncSender<Event>) -> io::Result<()> {
    let sock = sock.try_clone()?;
    thread::spawn(move || {
        // One UDP datagram cannot exceed this, and an AURP one is far smaller.
        let mut buf = [0u8; 65535];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, std::net::SocketAddr::V4(from))) => {
                    // Blocks rather than dropping, unlike the link readers:
                    // the run loop is the only consumer and never sends into
                    // this channel, so it cannot deadlock, and a dropped
                    // routing packet costs a whole retransmit interval.
                    let event = Event::Aurp { from, bytes: buf[..n].to_vec() };
                    if tx.send(event).is_err() {
                        return;
                    }
                }
                // AURP is IPv4 only; anything else is not ours.
                Ok(_) => continue,
                // A recurring error would busy-spin this loop; back off first,
                // the same way every other reader thread does.
                Err(e) => {
                    thread::sleep(Duration::from_millis(100));
                    if tx.send(Event::Error(format!("aurp: {e}"))).is_err() {
                        return;
                    }
                }
            }
        }
    });
    Ok(())
}

/// Our AURP domain identifier: what we configured, else whatever address the
/// socket or a NIC gives us. A private or loopback address works between two
/// routers on one LAN and nowhere else, so say so rather than fail.
fn domain_identifier(cfg: &Config, sock: &UdpSocket, nic_ip: Option<Ipv4Addr>) -> Ipv4Addr {
    let bound = match sock.local_addr() {
        Ok(std::net::SocketAddr::V4(a)) if !a.ip().is_unspecified() => Some(*a.ip()),
        _ => None,
    };
    let ip = cfg.public_ip.or(bound).or(nic_ip).unwrap_or(Ipv4Addr::UNSPECIFIED);
    if ip.is_private() || ip.is_loopback() || ip.is_unspecified() {
        eprintln!("router: domain identifier {ip} is not a public address; set public_ip if peers are across the internet");
    }
    ip
}

/// Re-resolves every configured peer name.
///
/// ponytail: this blocks the run loop on DNS for as long as the resolver
/// takes, once every `RECONNECT_SCAN`. Move it to a thread that posts results
/// back if a slow resolver ever shows up as forwarding latency.
fn resolve(names: &[String], peers: &mut Peers, now: Instant) {
    for name in names {
        let addr = (name.as_str(), AURP_PORT)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.find_map(|a| match a {
                std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                _ => None,
            }));
        if let Some(a) = addr {
            peers.resolved(name, a, now);
        }
    }
}

/// One action on its wire. Every failure is reported and dropped: a router
/// that exits because one frame would not go out is worse than one that says
/// so and carries on.
fn wrong_link(port: PortId, what: &str) -> io::Result<()> {
    eprintln!("router: port {port} is not a link that carries {what}; dropped");
    Ok(())
}

fn execute(a: Action, links: &mut HashMap<PortId, Link>, sock: &UdpSocket) {
    let result = match a {
        Action::ToEther { port, ref frame } => match links.get_mut(&port) {
            Some(Link::Ether(tx)) => tx.send(frame),
            _ => wrong_link(port, "an Ethernet frame"),
        },
        Action::ToLlap { port, ref llap } => match links.get(&port) {
            Some(Link::Ltoudp(lt)) => lt.send(llap),
            Some(Link::Tashtalk(tt)) => tt.send(llap),
            _ => wrong_link(port, "an LLAP frame"),
        },
        Action::ToPeer { peer, ref bytes } => sock
            .send_to(bytes, SocketAddrV4::new(peer, AURP_PORT))
            .map(|_| ()),
        // Only a TashTalk port ever asks for this, and only with the node it
        // just claimed: `Port` picks LocalTalk candidates from 128..=254, so
        // the bitmap can never be set for the illegal 0 or 255.
        Action::SetNode { port, node } => match links.get(&port) {
            Some(Link::Tashtalk(tt)) => tt.set_node(node),
            _ => wrong_link(port, "a node-ID bitmap"),
        },
        Action::Log(m) => {
            eprintln!("router: {m}");
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("router: send failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{datagram, frame};
    use crate::router::local::AEP_SOCKET;
    use crate::router::local::RTMP_SOCKET;
    use crate::router::table::VALIDITY;
    use crate::wire::{
        Addr, Aep, Aurp, DomainHeader, Echo, NetworkTuple, Rtmp, DDP, DDP_AEP, DDP_RTMP_DATA,
        LLAP_LONG_DDP, LLAP_SHORT_DDP,
    };
    use pnet::util::MacAddr;

    const ETHER: u16 = 6800;
    const LOCAL: u16 = 6801;
    /// Our node on each of the two ports.
    const ETHER_NODE: u8 = 7;
    const LOCAL_NODE: u8 = 200;
    const OURS: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 1);
    const THEIRS: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 2);
    const PEER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);

    /// Two claimed ports and nothing else: an EtherTalk cable and an LToUDP
    /// one. No socket is opened anywhere.
    fn router(now: Instant) -> Router {
        let mut tables = Tables::new();
        let mut e = Port::new(
            0,
            "eth0".into(),
            Kind::Ether { mac: OURS },
            (ETHER, ETHER),
            vec!["Ether".into()],
            now,
        );
        e.node = Some(ETHER_NODE);
        let mut l =
            Port::new(1, "ltoudp".into(), Kind::Ltoudp, (LOCAL, LOCAL), vec!["Local".into()], now);
        l.node = Some(LOCAL_NODE);
        tables.add_port(0, (ETHER, ETHER), true, vec!["Ether".into()], now);
        tables.add_port(1, (LOCAL, LOCAL), false, vec!["Local".into()], now);
        Router {
            ports: vec![e, l],
            tables,
            local: Local::new("appletalk".into()),
            peers: Peers::new(Di::Ip(Ipv4Addr::new(203, 0, 113, 1)), true, &[], now),
        }
    }

    fn echo_request(src: Addr, dst: Addr) -> Ddp {
        let body = Aep { func: Echo::Request, data: vec![1, 2, 3] };
        datagram(src, 100, dst, AEP_SOCKET, DDP_AEP, body.to_bytes())
    }

    /// The datagram as it comes off a real Ethernet frame, so its length field
    /// and hop count are the ones the wire carried.
    fn on_ether(ddp: &Ddp) -> Packet {
        wire::decode(&frame(THEIRS, OURS, DDP, ddp.to_bytes()).to_bytes()).expect("our own frame")
    }

    fn on_llap(ddp: &Ddp, dst: u8, src: u8) -> Llap {
        Llap { dst, src, typ: LLAP_LONG_DDP, data: ddp.to_bytes() }
    }

    fn ether_out(a: &Action) -> Ddp {
        match a {
            Action::ToEther { frame, .. } => Ddp::parse(&frame.payload).expect("a datagram"),
            other => panic!("not an Ethernet frame: {other:?}"),
        }
    }

    fn llap_out(a: &Action) -> &Llap {
        match a {
            Action::ToLlap { llap, .. } => llap,
            other => panic!("not an LLAP frame: {other:?}"),
        }
    }

    fn aep_of(ddp: &Ddp) -> Aep {
        Aep::parse(&ddp.data).expect("an AEP body")
    }

    /// A route to a network that is not ours, reached the given way.
    fn route(r: &mut Router, net: u16, target: Target, next: Addr, now: Instant) {
        let t = NetworkTuple { range: (net, net), extended: true, distance: 0 };
        r.tables.learn(&t, target, next, now);
    }

    #[test]
    fn network_zero_is_filled_in_from_the_arriving_port() {
        let now = Instant::now();
        let mut r = router(now);
        // Both addresses say "this cable", which only the port knows.
        let req = echo_request(Addr { net: 0, node: 5 }, Addr { net: 0, node: ETHER_NODE });
        let out = r.step(In::Ether { port: 0, packet: &on_ether(&req) }, now);
        assert_eq!(out.len(), 1, "{out:?}");
        let reply = ether_out(&out[0]);
        assert_eq!(reply.dst, Addr { net: ETHER, node: 5 });
        assert_eq!(reply.src, Addr { net: ETHER, node: ETHER_NODE });
        assert_eq!(aep_of(&reply), Aep { func: Echo::Reply, data: vec![1, 2, 3] });
    }

    #[test]
    fn a_datagram_for_our_node_zero_or_the_broadcast_is_delivered_to_us() {
        let now = Instant::now();
        for node in [ETHER_NODE, 0, 255] {
            let mut r = router(now);
            let req =
                echo_request(Addr { net: ETHER, node: 5 }, Addr { net: ETHER, node });
            let out = r.step(In::Ether { port: 0, packet: &on_ether(&req) }, now);
            // Delivered, and never repeated onto the cable it came from.
            assert_eq!(out.len(), 1, "node {node}: {out:?}");
            assert_eq!(aep_of(&ether_out(&out[0])).func, Echo::Reply);
        }
    }

    #[test]
    fn a_broadcast_for_another_of_our_cables_is_delivered_and_repeated() {
        let now = Instant::now();
        let mut r = router(now);
        let req = echo_request(Addr { net: ETHER, node: 5 }, Addr { net: LOCAL, node: 255 });
        let out = r.step(In::Ether { port: 0, packet: &on_ether(&req) }, now);
        assert_eq!(out.len(), 2, "{out:?}");
        // Answered from our address on the cable the broadcast named.
        let reply = ether_out(&out[0]);
        assert_eq!(reply.src, Addr { net: LOCAL, node: LOCAL_NODE });
        assert_eq!(aep_of(&reply).func, Echo::Reply);
        // And put on that cable for everyone else on it.
        let llap = llap_out(&out[1]);
        assert_eq!(llap.dst, 255);
        let repeated = Ddp::parse(&llap.data).expect("a long header");
        assert_eq!(repeated.dst, Addr { net: LOCAL, node: 255 });
        assert_eq!(repeated.hops, 1);
    }

    #[test]
    fn a_datagram_that_has_already_crossed_fifteen_routers_is_dropped() {
        let now = Instant::now();
        let mut r = router(now);
        route(&mut r, 2905, Target::Peer(PEER), Addr { net: 0, node: 0 }, now);
        let mut req = echo_request(Addr { net: ETHER, node: 5 }, Addr { net: 2905, node: 10 });
        req.hops = 15;
        assert_eq!(r.step(In::Ether { port: 0, packet: &on_ether(&req) }, now), Vec::new());
    }

    #[test]
    fn hops_count_a_port_hop_and_not_a_tunnel_hop() {
        let now = Instant::now();
        let mut r = router(now);
        // One more router to go, and it is on the LToUDP cable.
        route(&mut r, 3000, Target::Port(1), Addr { net: LOCAL, node: 5 }, now);
        let mut req = echo_request(Addr { net: ETHER, node: 5 }, Addr { net: 3000, node: 9 });
        req.hops = 3;
        let out = r.step(In::Ether { port: 0, packet: &on_ether(&req) }, now);
        assert_eq!(out.len(), 1, "{out:?}");
        let llap = llap_out(&out[0]);
        // Handed to the next router, not to the far node.
        assert_eq!(llap.dst, 5);
        assert_eq!(Ddp::parse(&llap.data).expect("a long header").hops, 4);

        // The same datagram off a tunnel, bound for our Ethernet: the sending
        // side already paid the tunnel's one hop.
        let mut r = router(now);
        let mut over = echo_request(Addr { net: 2905, node: 5 }, Addr { net: ETHER, node: 42 });
        over.hops = 3;
        let wrapped = Aurp::Data {
            dh: DomainHeader { dst: Di::Ip(Ipv4Addr::new(203, 0, 113, 1)), src: Di::Ip(PEER) },
            ddp: over.to_bytes(),
        }
        .to_bytes();
        let out = r.step(In::Aurp { from: PEER, bytes: &wrapped }, now);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(ether_out(&out[0]).hops, 3);
    }

    #[test]
    fn localtalk_output_uses_the_short_header_when_both_nets_are_the_ports() {
        let now = Instant::now();
        let mut r = router(now);
        let req = echo_request(Addr { net: LOCAL, node: 5 }, Addr { net: LOCAL, node: LOCAL_NODE });
        let out = r.step(In::Llap { port: 1, llap: &on_llap(&req, LOCAL_NODE, 5) }, now);
        assert_eq!(out.len(), 1, "{out:?}");
        let llap = llap_out(&out[0]);
        assert_eq!(llap.typ, LLAP_SHORT_DDP);
        assert_eq!((llap.dst, llap.src), (5, LOCAL_NODE));
        let reply = Ddp::from_short(&llap.data, LOCAL, llap.dst, llap.src).expect("a short header");
        assert_eq!(aep_of(&reply), Aep { func: Echo::Reply, data: vec![1, 2, 3] });
    }

    #[test]
    fn a_datagram_is_never_repeated_out_the_port_it_arrived_on() {
        let now = Instant::now();
        let mut r = router(now);
        // The way to network 3000 is back down the cable this arrives on.
        route(&mut r, 3000, Target::Port(0), Addr { net: ETHER, node: 1 }, now);
        let req = echo_request(Addr { net: ETHER, node: 5 }, Addr { net: 3000, node: 9 });
        assert_eq!(r.step(In::Ether { port: 0, packet: &on_ether(&req) }, now), Vec::new());
    }

    #[test]
    fn a_peer_routed_network_leaves_as_a_tunnelled_datagram() {
        let now = Instant::now();
        let mut r = router(now);
        route(&mut r, 2905, Target::Peer(PEER), Addr { net: 0, node: 0 }, now);
        let req = echo_request(Addr { net: ETHER, node: 5 }, Addr { net: 2905, node: 10 });
        let out = r.step(In::Ether { port: 0, packet: &on_ether(&req) }, now);
        assert_eq!(out.len(), 1, "{out:?}");
        let Action::ToPeer { peer, bytes } = &out[0] else { panic!("not tunnelled: {out:?}") };
        assert_eq!(*peer, PEER);
        let mut expected = req.clone();
        expected.hops = 1;
        match Aurp::parse(bytes).expect("an AURP packet") {
            Aurp::Data { ddp, .. } => assert_eq!(ddp, expected.to_bytes()),
            other => panic!("not a Data packet: {other:?}"),
        }
    }

    /// The deviation that made the AURP arm call `arrived` rather than
    /// `forward`: node 0 means "any router on that network", and over a tunnel
    /// that is how an NBP FwdReq and everything like it reaches us. Forwarding
    /// it would have put it on our own cable addressed to the illegal node 0.
    #[test]
    fn a_tunnelled_datagram_for_node_zero_of_our_cable_is_delivered_here() {
        let now = Instant::now();
        let mut r = router(now);
        route(&mut r, 2905, Target::Peer(PEER), Addr { net: 0, node: 0 }, now);
        let req = echo_request(Addr { net: 2905, node: 5 }, Addr { net: ETHER, node: 0 });
        let wrapped = Aurp::Data {
            dh: DomainHeader { dst: Di::Ip(Ipv4Addr::new(203, 0, 113, 1)), src: Di::Ip(PEER) },
            ddp: req.to_bytes(),
        }
        .to_bytes();
        let out = r.step(In::Aurp { from: PEER, bytes: &wrapped }, now);
        // Answered by us, back down the tunnel — not repeated onto the cable.
        assert_eq!(out.len(), 1, "{out:?}");
        let Action::ToPeer { bytes, .. } = &out[0] else { panic!("not tunnelled: {out:?}") };
        let Aurp::Data { ddp, .. } = Aurp::parse(bytes).expect("an AURP packet") else {
            panic!("not a Data packet")
        };
        let reply = Ddp::parse(&ddp).expect("a datagram");
        assert_eq!(reply.src, Addr { net: ETHER, node: ETHER_NODE });
        assert_eq!(reply.dst, Addr { net: 2905, node: 5 });
        assert_eq!(aep_of(&reply).func, Echo::Reply);
    }

    #[test]
    fn a_route_learned_and_then_aged_out_is_reported_on_stderr() {
        let now = Instant::now();
        let mut r = router(now);
        // Another router on the LToUDP cable advertising network 3000.
        let beacon = Rtmp::Data {
            sender: Addr { net: LOCAL, node: 5 },
            range: None,
            tuples: vec![NetworkTuple { range: (3000, 3000), extended: true, distance: 0 }],
        };
        let ddp = datagram(
            Addr { net: LOCAL, node: 5 },
            RTMP_SOCKET,
            Addr { net: LOCAL, node: 255 },
            RTMP_SOCKET,
            DDP_RTMP_DATA,
            beacon.to_bytes(),
        );
        let out = r.step(In::Llap { port: 1, llap: &on_llap(&ddp, 255, 5) }, now);
        let logs: Vec<&String> = out
            .iter()
            .filter_map(|a| match a {
                Action::Log(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(logs.len(), 1, "{out:?}");
        assert!(logs[0].contains("3000-3000"), "{}", logs[0]);
        assert!(logs[0].contains("port 1"), "{}", logs[0]);
        // A tuple distance of 0 is one hop away through the router that sent it.
        assert!(logs[0].contains("distance 1"), "{}", logs[0]);

        // Good -> suspect -> bad -> worst -> gone, one step per validity period.
        let mut deleted = Vec::new();
        for step in 1..=4 {
            deleted.extend(r.step(In::Tick, now + VALIDITY * step).into_iter().filter_map(|a| {
                match a {
                    Action::Log(m) if m.contains("deleted") => Some(m),
                    _ => None,
                }
            }));
        }
        assert_eq!(deleted.len(), 1, "{deleted:?}");
        assert!(deleted[0].contains("3000-3000"), "{}", deleted[0]);
        assert!(deleted[0].contains("distance 1"), "{}", deleted[0]);
    }

    #[test]
    fn a_dump_is_one_log_line_naming_every_port() {
        let now = Instant::now();
        let mut r = router(now);
        let out = r.step(In::Dump, now);
        assert_eq!(out.len(), 1, "{out:?}");
        let Action::Log(text) = &out[0] else { panic!("not a log: {out:?}") };
        assert!(text.contains("eth0"), "{text}");
        assert!(text.contains("ltoudp"), "{text}");
        // The routing table's own header, so all three dumps are in there.
        assert!(text.contains("network"), "{text}");
    }
}
