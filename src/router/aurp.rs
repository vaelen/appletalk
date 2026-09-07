// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! The AURP peers: the tunnel connections, their state machines and timers.
//!
//! Every peer holds two independent one-way connections, one in each
//! direction: we are the **data receiver** on the one we opened, and the
//! **data sender** on the one the peer opened. `docs/AURP.md` has the wire
//! layouts, the dialog and the discard table; this module is the two state
//! machines and nothing else. It never touches a socket -- the run loop feeds
//! it datagrams and sends the `Action::ToPeer`s it hands back.


use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Write as _};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::table::{RouteChange, Tables};
use super::{Action, Target};
use crate::wire::{Addr, Aurp, Cmd, Di, DomainHeader, Encode, EventTuple, NetworkTuple};

/// Retransmit interval for everything that is retransmitted at all.
pub const RETRY: Duration = Duration::from_secs(10);
/// Tries for an Open-Req, an RI-Rsp, an RI-Upd or an RD before giving up.
pub const RETRIES: u32 = 5;
/// Quiet from the peer as data sender before we tickle it.
pub const LAST_HEARD: Duration = Duration::from_secs(90);
/// Tickles sent before the peer's routes are dropped.
pub const TICKLE_RETRIES: u32 = 10;
/// Minimum spacing between RI-Upds, so events batch.
pub const UPDATE_INTERVAL: Duration = Duration::from_secs(10);
/// How often the reconnect scan looks at unconnected configured peers.
pub const RECONNECT_SCAN: Duration = Duration::from_secs(10);
/// Minimum spacing between Open-Req bursts to one configured peer.
pub const RECONNECT_BACKOFF: Duration = Duration::from_secs(600);
/// How often zoneless tunnel networks get a fresh ZI-Req.
pub const ZI_REREQUEST: Duration = Duration::from_secs(30);
/// Body bytes an RI-Rsp, ZI-Rsp or ZI-Req is split at, so nothing fragments.
pub const MAX_BODY: usize = 1400;

/// Update event codes (`docs/AURP.md`, "RI-Upd"). 0 is the null event and 5 is
/// ZC, which the RFC reserves and every implementation ignores.
pub const NA: u8 = 1;
pub const ND: u8 = 2;
pub const NRC: u8 = 3;
pub const NDC: u8 = 4;

/// The placeholder a null event carries: one byte on the wire, no tuple.
const NO_EVENT_TUPLE: NetworkTuple = NetworkTuple { range: (0, 0), extended: false, distance: 0 };

/// Nothing learned over a tunnel has a next router on a cable.
const NO_NEXT: Addr = Addr { net: 0, node: 0 };

/// One log line per unknown address per this long.
const LOG_EVERY: Duration = Duration::from_secs(60);

/// Our side of the connection we opened: the peer is the data sender on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receiver {
    Unconnected,
    WaitOpenRsp,
    WaitRiRsp,
    Connected,
    WaitTickleAck,
}

/// Our side of the connection the peer opened: we are the data sender on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    Unconnected,
    Connected,
    WaitRiRspAck,
    WaitRiUpdAck,
    WaitRdAck,
}

/// The one sequenced packet a sender may have outstanding, kept verbatim:
/// retransmissions of RI-Rsp and RI-Upd are byte-identical repeats.
#[derive(Debug)]
struct Outstanding {
    seq: u16,
    bytes: Vec<u8>,
    /// The networks this packet named, for the ZI-Rsp an SZI ack asks for.
    nets: Vec<u16>,
    at: Instant,
    tries: u32,
}

/// Actions and route changes accumulated while handling one packet or tick.
#[derive(Default)]
struct Out {
    acts: Vec<Action>,
    chs: Vec<RouteChange>,
}

pub struct Peer {
    pub addr: Ipv4Addr,
    /// The configured name this address was resolved from, if any. Only
    /// configured peers are reconnected to.
    pub configured: Option<String>,
    /// What the peer calls itself: whatever source DI it last used.
    pub di: Di,
    pub receiver: Receiver,
    pub sender: Sender,

    /// Our own domain identifier, copied here so every send is one call.
    local: Di,

    // ---- as data receiver: the connection we opened ----
    /// The ID we chose. Differs from the last one used with this peer.
    conn_local: u16,
    /// The next sequence number we expect from the peer.
    seq_recv: u16,
    last_heard: Instant,
    /// When the outstanding Open-Req or Tickle went out, and how many have.
    recv_at: Instant,
    recv_tries: u32,
    last_reconnect: Option<Instant>,

    // ---- as data sender: the connection the peer opened ----
    /// The ID the peer chose.
    conn_remote: u16,
    /// The sequence number of our last sequenced packet.
    seq_send: u16,
    outstanding: Option<Outstanding>,
    /// RI-Rsp pages not yet sent; each waits for the previous one's ack.
    pages: Vec<Vec<NetworkTuple>>,
    /// Route changes not yet sent, one collapsed event per network.
    pending: Vec<EventTuple>,
    last_update: Instant,
    /// A null RI-Upd is out probing whether a conflicting Open-Req is genuine.
    probing: bool,
}

impl Peer {
    fn new(addr: Ipv4Addr, configured: Option<String>, conn_local: u16, local: Di, now: Instant) -> Self {
        Peer {
            addr,
            configured,
            di: Di::Ip(addr),
            receiver: Receiver::Unconnected,
            sender: Sender::Unconnected,
            local,
            conn_local,
            seq_recv: 1,
            last_heard: now,
            recv_at: now,
            recv_tries: 0,
            last_reconnect: None,
            conn_remote: 0,
            seq_send: 0,
            outstanding: None,
            pages: Vec::new(),
            pending: Vec::new(),
            last_update: now,
            probing: false,
        }
    }

    /// All our packets are addressed to what the peer calls itself and signed
    /// with our own identity (`docs/AURP.md`, "Domain identifiers").
    fn bytes(&self, conn: u16, seq: u16, cmd: Cmd) -> Vec<u8> {
        Aurp::Routing { dh: DomainHeader { dst: self.di, src: self.local }, conn, seq, cmd }
            .to_bytes()
    }

    fn send(&self, conn: u16, seq: u16, cmd: Cmd) -> Action {
        Action::ToPeer { peer: self.addr, bytes: self.bytes(conn, seq, cmd) }
    }

    /// Record a sequenced packet as the one outstanding and send it.
    fn send_sequenced(&mut self, cmd: Cmd, nets: Vec<u16>, now: Instant, out: &mut Out) {
        self.seq_send = succ(self.seq_send);
        let bytes = self.bytes(self.conn_remote, self.seq_send, cmd);
        out.acts.push(Action::ToPeer { peer: self.addr, bytes: bytes.clone() });
        self.outstanding =
            Some(Outstanding { seq: self.seq_send, bytes, nets, at: now, tries: 1 });
    }

    /// Open our own one-way connection: the receiver side's only fresh packet.
    fn open(&mut self, now: Instant, out: &mut Out) {
        self.seq_recv = 1;
        self.receiver = Receiver::WaitOpenRsp;
        self.recv_at = now;
        self.recv_tries = 1;
        self.last_reconnect = Some(now);
        out.acts.push(self.send(
            self.conn_local,
            0,
            Cmd::OpenReq { sui: Cmd::ALL_SUI, version: 1, options: Vec::new() },
        ));
    }

    /// Close as data receiver. The next Open-Req must carry a different
    /// connection ID or the peer takes it for a retransmission (RFC p. 43).
    fn close_receiver(&mut self) {
        self.receiver = Receiver::Unconnected;
        self.conn_local = succ(self.conn_local);
        self.seq_recv = 1;
        self.recv_tries = 0;
    }

    fn close_sender(&mut self) {
        self.sender = Sender::Unconnected;
        self.conn_remote = 0;
        self.seq_send = 0;
        self.outstanding = None;
        self.pages.clear();
        self.pending.clear();
        self.probing = false;
    }

    /// True once the connection we opened is far enough along to carry
    /// sequenced data or a ZI-Req.
    fn receiver_open(&self) -> bool {
        !matches!(self.receiver, Receiver::Unconnected | Receiver::WaitOpenRsp)
    }

    /// Queue one event, collapsing it with whatever is already pending for the
    /// same network (`docs/AURP.md`, "RI-Upd"; the spec's "Beyond jrouter").
    fn queue(&mut self, ev: EventTuple) {
        let start = ev.tuple.range.0;
        let Some(i) = self.pending.iter().position(|p| p.tuple.range.0 == start) else {
            self.pending.push(ev);
            return;
        };
        match (self.pending[i].code, ev.code) {
            // Added then deleted: the peer never heard of it, so say nothing.
            (NA, ND) | (NA, NRC) => {
                self.pending.remove(i);
            }
            // Still an addition, at the new distance.
            (NA, NDC) => self.pending[i].tuple = ev.tuple,
            // Deleted then added back: the peer still has it, so this is a
            // distance change.
            (ND, NA) | (NRC, NA) => self.pending[i] = EventTuple { code: NDC, tuple: ev.tuple },
            // Everything else, NDC after NDC included: the last one wins.
            _ => self.pending[i] = ev,
        }
    }

    /// Apply one update event to the tables (`docs/AURP.md`, "RI-Upd", and the
    /// inconsistent-event rules on RFC p. 34).
    fn apply(&self, e: &EventTuple, tables: &mut Tables, now: Instant) -> Vec<RouteChange> {
        let target = Target::Peer(self.addr);
        let start = e.tuple.range.0;
        let known = tables.routes().any(|r| r.target == target && r.range.0 == start);
        match e.code {
            // `learn` replaces an existing entry, so NA for a known network is
            // already treated as NDC.
            NA if e.tuple.distance < 15 => tables.learn(&e.tuple, target, NO_NEXT, now),
            // ND or NRC for an unknown network removes nothing, as the RFC asks.
            ND | NRC => tables.remove(target, start),
            NDC if e.tuple.distance >= 15 => tables.remove(target, start),
            // NDC for an unknown network is treated as NA.
            NDC if !known => tables.learn(&e.tuple, target, NO_NEXT, now),
            // The stored distance is the peer's plus the tunnel hop.
            NDC => tables.set_distance(target, start, e.tuple.distance + 1, now),
            // 0 null, 5 ZC and anything else: nothing to do beyond the ack.
            _ => Vec::new(),
        }
    }

    /// One routing packet, dispatched by command. Everything addressed to a
    /// connection ID that is not the one expected is discarded.
    fn routing(&mut self, conn: u16, seq: u16, cmd: Cmd, tables: &mut Tables, now: Instant, out: &mut Out) {
        match cmd {
            // ------------------------------------------- as the data sender
            Cmd::OpenReq { version, options, .. } => {
                self.open_req(conn, version, &options, now, out)
            }
            // Not during WaitRdAck: we are on the way down, and restarting
            // the export would abandon the RD.
            Cmd::RiReq { .. }
                if conn == self.conn_remote
                    && matches!(
                        self.sender,
                        Sender::Connected | Sender::WaitRiRspAck | Sender::WaitRiUpdAck
                    ) =>
            {
                // A refresh at any time: the sequence restarts at 1.
                self.seq_send = 0;
                self.outstanding = None;
                self.pages = split_tuples(tables.export());
                self.send_page(now, out);
            }
            Cmd::RiAck { szi } if conn == self.conn_remote => self.ri_ack(seq, szi, tables, now, out),
            Cmd::Tickle if conn == self.conn_remote && self.sender != Sender::Unconnected => {
                out.acts.push(self.send(conn, 0, Cmd::TickleAck))
            }
            // `conn_remote` is 0 until a peer opens its connection, so
            // without the state guard a stranger's ZI-Req carrying conn 0
            // would turn us into a reflector.
            Cmd::ZiReq { nets } if conn == self.conn_remote && self.sender != Sender::Unconnected => {
                for cmd in zi_pages(&nets, tables) {
                    out.acts.push(self.send(conn, 0, cmd));
                }
            }
            // Neither is supported, and neither costs any state to refuse --
            // but both still answer only on an open connection.
            Cmd::GznReq { zone } if conn == self.conn_remote && self.sender != Sender::Unconnected => {
                out.acts.push(self.send(conn, 0, Cmd::GznRsp { zone, tuples: None }))
            }
            Cmd::GdzlReq { .. } if conn == self.conn_remote && self.sender != Sender::Unconnected => {
                out.acts.push(self.send(
                    conn,
                    0,
                    Cmd::GdzlRsp { last: true, start: -1, zones: Vec::new() },
                ))
            }

            // ----------------------------------------- as the data receiver
            Cmd::OpenRsp { rate_or_err, .. }
                if conn == self.conn_local && self.receiver == Receiver::WaitOpenRsp =>
            {
                if rate_or_err < 0 {
                    self.close_receiver();
                    return;
                }
                // ponytail: the rate is ignored and UPDATE_INTERVAL used for
                // every peer. Honour it per peer if one ever asks for slower.
                self.receiver = Receiver::WaitRiRsp;
                self.seq_recv = 1;
                self.recv_tries = 1;
                self.recv_at = now;
                self.last_heard = now;
                out.acts.push(self.send(self.conn_local, 0, Cmd::RiReq { sui: Cmd::ALL_SUI }));
            }
            Cmd::RiRsp { last, tuples } if conn == self.conn_local && self.receiver_open() => {
                self.last_heard = now;
                match self.check_seq(seq) {
                    Seq::New => {
                        for t in &tuples {
                            if t.distance < 15 {
                                out.chs.extend(tables.learn(t, Target::Peer(self.addr), NO_NEXT, now));
                            }
                        }
                        self.seq_recv = succ(seq);
                        out.acts.push(self.send(conn, seq, Cmd::RiAck { szi: true }));
                        if last {
                            self.receiver = Receiver::Connected;
                        }
                    }
                    Seq::Dup => out.acts.push(self.send(conn, seq, Cmd::RiAck { szi: true })),
                    Seq::Ahead => self.close_receiver(),
                    Seq::Stale => {}
                }
            }
            Cmd::RiUpd { events } if conn == self.conn_local && self.receiver_open() => {
                self.last_heard = now;
                match self.check_seq(seq) {
                    Seq::New => {
                        let mut szi = false;
                        for e in &events {
                            out.chs.extend(self.apply(e, tables, now));
                            szi |= e.code == NA;
                        }
                        self.seq_recv = succ(seq);
                        out.acts.push(self.send(conn, seq, Cmd::RiAck { szi }));
                    }
                    // jrouter re-acks a duplicate with SZI, and a lost ZI-Rsp
                    // is the likelier reason to be here than a lost ack.
                    Seq::Dup => out.acts.push(self.send(conn, seq, Cmd::RiAck { szi: true })),
                    Seq::Ahead => self.close_receiver(),
                    Seq::Stale => {}
                }
            }
            Cmd::Rd { .. } if conn == self.conn_local && self.receiver_open() => {
                out.acts.push(self.send(conn, seq, Cmd::RiAck { szi: false }));
                out.chs.extend(tables.remove_target(Target::Peer(self.addr)));
                self.close_receiver();
                self.close_sender();
            }
            Cmd::ZiRsp { extended, zones } if conn == self.conn_local && self.receiver_open() => {
                self.last_heard = now;
                self.zi_rsp(extended, zones, tables, out);
            }
            Cmd::TickleAck if conn == self.conn_local && self.receiver == Receiver::WaitTickleAck => {
                self.receiver = Receiver::Connected;
                self.recv_tries = 0;
                self.last_heard = now;
            }
            _ => {}
        }
    }

    fn open_req(&mut self, conn: u16, version: u16, options: &[(u8, Vec<u8>)], now: Instant, out: &mut Out) {
        if version != 1 {
            out.acts.push(self.open_rsp(conn, -5));
            return;
        }
        if !options.is_empty() {
            out.acts.push(self.open_rsp(conn, -4));
            return;
        }
        // A different ID on an open connection probably means the peer
        // restarted -- but it may be a forgery, so probe the old connection
        // and answer only if the probe goes unanswered (RFC p. 42).
        if self.sender != Sender::Unconnected && conn != self.conn_remote {
            if !self.probing && self.outstanding.is_none() {
                self.probing = true;
                self.send_sequenced(null_upd(), Vec::new(), now, out);
                self.sender = Sender::WaitRiUpdAck;
            }
            return;
        }
        self.conn_remote = conn;
        self.seq_send = 0;
        self.outstanding = None;
        self.pages.clear();
        self.sender = Sender::Connected;
        out.acts.push(self.open_rsp(conn, 1));
        // A router that gets an Open-Req and has no connection of its own to
        // that peer opens one immediately (`docs/AURP.md`, "The dialog").
        if self.receiver == Receiver::Unconnected {
            self.open(now, out);
        }
    }

    /// Rate 1 and no environment flags: no remapping, no hop-count reduction.
    fn open_rsp(&self, conn: u16, rate_or_err: i16) -> Action {
        self.send(conn, 0, Cmd::OpenRsp { env: 0, rate_or_err, options: Vec::new() })
    }

    fn ri_ack(&mut self, seq: u16, szi: bool, tables: &Tables, now: Instant, out: &mut Out) {
        // An RI-Ack counts only against the packet actually outstanding.
        let Some(o) = &self.outstanding else { return };
        if o.seq != seq {
            return;
        }
        let nets = std::mem::take(&mut self.outstanding).map(|o| o.nets).unwrap_or_default();
        if szi {
            for cmd in zi_pages(&nets, tables) {
                out.acts.push(self.send(self.conn_remote, 0, cmd));
            }
        }
        match self.sender {
            Sender::WaitRiRspAck if !self.pages.is_empty() => self.send_page(now, out),
            Sender::WaitRiRspAck | Sender::WaitRiUpdAck => {
                self.sender = Sender::Connected;
                self.probing = false;
            }
            Sender::WaitRdAck => self.close_sender(),
            _ => {}
        }
    }

    /// Send the next RI-Rsp page, with Last set once it is the final one.
    fn send_page(&mut self, now: Instant, out: &mut Out) {
        if self.pages.is_empty() {
            return;
        }
        let tuples = self.pages.remove(0);
        let last = self.pages.is_empty();
        let nets = tuples.iter().map(|t| t.range.0).collect();
        self.send_sequenced(Cmd::RiRsp { last, tuples }, nets, now, out);
        self.sender = Sender::WaitRiRspAck;
    }

    fn zi_rsp(&self, extended: Option<u16>, zones: Vec<(u16, String)>, tables: &mut Tables, out: &mut Out) {
        // Tuples for one network are contiguous but a network may appear more
        // than once, so group before calling the table.
        let mut order: Vec<u16> = Vec::new();
        let mut by: HashMap<u16, Vec<String>> = HashMap::new();
        for (net, name) in zones {
            if !by.contains_key(&net) {
                order.push(net);
            }
            by.entry(net).or_default().push(name);
        }
        for net in order {
            // Split horizon in reverse: a peer has nothing to tell us about a
            // cable of our own.
            if matches!(tables.best(net).map(|r| r.target), Some(Target::Port(_))) {
                continue;
            }
            out.chs.extend(tables.add_zones(net, &by[&net], extended.map(usize::from)));
        }
    }

    /// Where a sequenced packet's number stands against the expected one
    /// (`docs/AURP.md`, "Sequence numbers").
    fn check_seq(&self, seq: u16) -> Seq {
        if seq == 0 {
            Seq::Stale // 0 is never a sequence number
        } else if seq == self.seq_recv {
            Seq::New
        } else if seq == pred(self.seq_recv) {
            Seq::Dup
        } else if seq == succ(self.seq_recv) {
            Seq::Ahead
        } else {
            Seq::Stale
        }
    }
}

enum Seq {
    New,
    Dup,
    Ahead,
    Stale,
}

pub struct Peers {
    local: Di,
    open_peering: bool,
    /// Ordered so every listing and every dump is deterministic.
    peers: BTreeMap<Ipv4Addr, Peer>,
    /// Configured names, whether or not they have resolved yet.
    configured: Vec<String>,
    /// The connection ID the next peer starts from.
    next_conn: u16,
    last_scan: Instant,
    last_zi: Instant,
    /// When the unknown-peer log last named each address.
    logged: HashMap<Ipv4Addr, Instant>,
}

impl Peers {
    pub fn new(local: Di, open_peering: bool, configured: &[String], now: Instant) -> Peers {
        Peers {
            local,
            open_peering,
            peers: BTreeMap::new(),
            configured: configured.to_vec(),
            next_conn: seed_conn(),
            last_scan: now,
            last_zi: now,
            logged: HashMap::new(),
        }
    }

    /// A configured name resolved (or re-resolved) by the run loop.
    pub fn resolved(&mut self, name: &str, addr: Ipv4Addr, now: Instant) {
        if let Some(p) = self.peers.get_mut(&addr) {
            p.configured = Some(name.to_string());
            return;
        }
        // The name moved: the old address cannot still be this peer.
        //
        // ponytail: routes learned from the old address stay until its tickles
        // run out. Have the run loop call `Tables::remove_target` here if a
        // peer ever moves often enough to matter.
        self.peers.retain(|_, p| p.configured.as_deref() != Some(name));
        let conn = self.take_conn();
        self.peers
            .insert(addr, Peer::new(addr, Some(name.to_string()), conn, self.local, now));
    }

    /// One datagram from the socket. Returns actions and route changes; a
    /// `Data` packet's DDP bytes come back for the router to forward.
    pub fn packet(
        &mut self,
        from: Ipv4Addr,
        bytes: &[u8],
        tables: &mut Tables,
        now: Instant,
    ) -> (Vec<Action>, Vec<RouteChange>, Option<Vec<u8>>) {
        let mut out = Out::default();
        let Some(pkt) = Aurp::parse(bytes) else {
            return (out.acts, out.chs, None);
        };
        if !self.peers.contains_key(&from) {
            if !self.open_peering {
                if self.log_unknown(from, now) {
                    out.acts.push(Action::Log(format!("aurp: packet from unknown peer {from}")));
                }
                return (out.acts, out.chs, None);
            }
            let conn = self.take_conn();
            self.peers.insert(from, Peer::new(from, None, conn, self.local, now));
        }
        let peer = self.peers.get_mut(&from).expect("just inserted");
        match pkt {
            Aurp::Data { dh, ddp } => {
                peer.di = named_by(dh.src, from);
                peer.last_heard = now;
                (out.acts, out.chs, Some(ddp))
            }
            Aurp::Routing { dh, conn, seq, cmd } => {
                peer.di = named_by(dh.src, from);
                peer.routing(conn, seq, cmd, tables, now, &mut out);
                (out.acts, out.chs, None)
            }
        }
    }

    /// Timers: retransmits, tickles, reconnects, pending RI-Upds, ZI
    /// re-requests.
    pub fn tick(&mut self, tables: &mut Tables, now: Instant) -> (Vec<Action>, Vec<RouteChange>) {
        let mut out = Out::default();
        let scan = now.saturating_duration_since(self.last_scan) >= RECONNECT_SCAN;
        if scan {
            self.last_scan = now;
        }
        let zi = now.saturating_duration_since(self.last_zi) >= ZI_REREQUEST;
        if zi {
            self.last_zi = now;
        }
        for peer in self.peers.values_mut() {
            if scan {
                reconnect(peer, now, &mut out);
            }
            receiver_timers(peer, tables, now, &mut out);
            sender_timers(peer, now, &mut out);
            if zi {
                zi_rerequest(peer, tables, &mut out);
            }
        }
        (out.acts, out.chs)
    }

    /// Queue events for every peer we are sender to.
    pub fn route_changed(&mut self, ch: &[RouteChange], tables: &Tables) {
        for c in ch {
            // A route via a peer is never re-exported: every other peer on the
            // tunnel already hears about it from the peer behind it.
            // Whether the old route's zones were complete at the time is gone
            // from the table, so `was` does not ask: a peer ignores ND or NRC
            // for a network it never heard of (RFC p. 34), and NDC is only
            // ever reached when `is` holds and the zones are complete.
            let was = c.old.as_ref().is_some_and(|r| matches!(r.target, Target::Port(_)) && r.distance < 15);
            let is = c.new.as_ref().is_some_and(|r| {
                matches!(r.target, Target::Port(_))
                    && r.distance < 15
                    && tables.zones(r.range.0).is_some_and(|z| z.complete())
            });
            let ev = match (was, is) {
                (false, false) => continue,
                (false, true) => EventTuple { code: NA, tuple: tuple_of(c.new.as_ref().unwrap()) },
                (true, false) => {
                    // Moved onto a tunnel: split horizon hides it, which is
                    // NRC rather than a plain deletion.
                    let code =
                        if matches!(c.new.as_ref().map(|r| r.target), Some(Target::Peer(_))) { NRC } else { ND };
                    let old = c.old.as_ref().unwrap();
                    let tuple =
                        NetworkTuple { range: old.range, extended: old.extended, distance: 0 };
                    EventTuple { code, tuple }
                }
                (true, true) => {
                    let (old, new) = (c.old.as_ref().unwrap(), c.new.as_ref().unwrap());
                    if old.distance == new.distance {
                        continue;
                    }
                    EventTuple { code: NDC, tuple: tuple_of(new) }
                }
            };
            // Changes that happen while we are not a data sender are dropped:
            // the peer will get everything in an RI-Rsp when it reconnects.
            for p in self.peers.values_mut().filter(|p| p.sender != Sender::Unconnected) {
                p.queue(ev.clone());
            }
        }
    }

    pub fn forward(&self, peer: Ipv4Addr, ddp: &[u8]) -> Action {
        let dst = self.peers.get(&peer).map_or(Di::Ip(peer), |p| p.di);
        let bytes = Aurp::Data { dh: DomainHeader { dst, src: self.local }, ddp: ddp.to_vec() }
            .to_bytes();
        Action::ToPeer { peer, bytes }
    }

    /// RD(-1) on every sender connection; the run loop waits up to 2 s for acks.
    pub fn shutdown(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Out::default();
        for p in self.peers.values_mut() {
            if p.sender == Sender::Unconnected || p.sender == Sender::WaitRdAck {
                continue;
            }
            p.outstanding = None;
            p.pages.clear();
            p.send_sequenced(Cmd::Rd { code: -1 }, Vec::new(), now, &mut out);
            p.sender = Sender::WaitRdAck;
        }
        out.acts
    }

    pub fn dump(&self) -> String {
        let mut s = String::new();
        for name in &self.configured {
            if !self.peers.values().any(|p| p.configured.as_deref() == Some(name.as_str())) {
                let _ = writeln!(s, "{name:<20}  unresolved");
            }
        }
        for p in self.peers.values() {
            let _ = writeln!(
                s,
                "{:<20}  {:<15}  recv {:<13} conn {:5} next seq {:5}  send {:<13} conn {:5} seq {:5}  {} pending  heard {}s ago",
                p.configured.as_deref().unwrap_or("-"),
                p.addr,
                p.receiver,
                p.conn_local,
                p.seq_recv,
                p.sender,
                p.conn_remote,
                p.seq_send,
                p.pending.len(),
                p.last_heard.elapsed().as_secs(),
            );
        }
        s
    }

    /// Whether we already hold a connection to this address. Nothing in the
    /// run loop asks: `packet` decides for itself what to do with a stranger,
    /// and `resolved` is idempotent. Kept because it is the only read-only
    /// window onto the peer set a caller has.
    #[allow(dead_code)]
    pub fn known(&self, addr: Ipv4Addr) -> bool {
        self.peers.contains_key(&addr)
    }

    fn take_conn(&mut self) -> u16 {
        let c = self.next_conn;
        self.next_conn = succ(self.next_conn);
        c
    }

    /// True if the unknown-peer log should name this address now.
    fn log_unknown(&mut self, from: Ipv4Addr, now: Instant) -> bool {
        match self.logged.get(&from) {
            Some(&t) if now.saturating_duration_since(t) < LOG_EVERY => false,
            _ => {
                self.logged.insert(from, now);
                true
            }
        }
    }
}

// ----------------------------------------------------------------- timers

fn reconnect(peer: &mut Peer, now: Instant, out: &mut Out) {
    if peer.configured.is_none() || peer.receiver != Receiver::Unconnected {
        return;
    }
    if peer.last_reconnect.is_some_and(|t| now.saturating_duration_since(t) <= RECONNECT_BACKOFF) {
        return;
    }
    peer.open(now, out);
}

fn receiver_timers(peer: &mut Peer, tables: &mut Tables, now: Instant, out: &mut Out) {
    match peer.receiver {
        Receiver::WaitOpenRsp | Receiver::WaitRiRsp
            if now.saturating_duration_since(peer.recv_at) >= RETRY =>
        {
            if peer.recv_tries >= RETRIES {
                peer.close_receiver();
                return;
            }
            peer.recv_tries += 1;
            peer.recv_at = now;
            // Retransmitted Open-Reqs and RI-Reqs are both fresh packets on
            // the same connection ID (`docs/AURP.md`, "Timers and limits").
            let cmd = if peer.receiver == Receiver::WaitOpenRsp {
                Cmd::OpenReq { sui: Cmd::ALL_SUI, version: 1, options: Vec::new() }
            } else {
                Cmd::RiReq { sui: Cmd::ALL_SUI }
            };
            out.acts.push(peer.send(peer.conn_local, 0, cmd));
        }
        Receiver::Connected if now.saturating_duration_since(peer.last_heard) > LAST_HEARD => {
            peer.receiver = Receiver::WaitTickleAck;
            peer.recv_tries = 1;
            peer.recv_at = now;
            out.acts.push(peer.send(peer.conn_local, 0, Cmd::Tickle));
        }
        Receiver::WaitTickleAck if now.saturating_duration_since(peer.recv_at) >= RETRY => {
            if peer.recv_tries >= TICKLE_RETRIES {
                out.chs.extend(tables.remove_target(Target::Peer(peer.addr)));
                peer.close_receiver();
                // One direction is dead; find out about the other (RFC p. 40).
                if peer.sender == Sender::Connected {
                    peer.send_sequenced(null_upd(), Vec::new(), now, out);
                    peer.sender = Sender::WaitRiUpdAck;
                }
                return;
            }
            peer.recv_tries += 1;
            peer.recv_at = now;
            out.acts.push(peer.send(peer.conn_local, 0, Cmd::Tickle));
        }
        _ => {}
    }
}

fn sender_timers(peer: &mut Peer, now: Instant, out: &mut Out) {
    if let Some(o) = &peer.outstanding {
        if now.saturating_duration_since(o.at) >= RETRY {
            if o.tries >= RETRIES {
                peer.close_sender();
                return;
            }
            // RI-Rsp and RI-Upd retransmissions are byte-identical repeats.
            let bytes = o.bytes.clone();
            out.acts.push(Action::ToPeer { peer: peer.addr, bytes });
            let o = peer.outstanding.as_mut().expect("still there");
            o.tries += 1;
            o.at = now;
        }
        return;
    }
    if peer.sender == Sender::Connected
        && !peer.pending.is_empty()
        && now.saturating_duration_since(peer.last_update) >= UPDATE_INTERVAL
    {
        let events = std::mem::take(&mut peer.pending);
        let nets = events.iter().filter(|e| e.code == NA).map(|e| e.tuple.range.0).collect();
        peer.last_update = now;
        peer.send_sequenced(Cmd::RiUpd { events }, nets, now, out);
        peer.sender = Sender::WaitRiUpdAck;
    }
}

/// A lost ZI-Rsp leaves a network with no zones forever unless somebody asks
/// again (RFC p. 25).
fn zi_rerequest(peer: &mut Peer, tables: &Tables, out: &mut Out) {
    if !peer.receiver_open() {
        return;
    }
    let target = Target::Peer(peer.addr);
    let nets: Vec<u16> =
        tables.zoneless().iter().filter(|r| r.target == target).map(|r| r.range.0).collect();
    // Two body bytes a network, behind the subcode.
    for chunk in nets.chunks((MAX_BODY - 2) / 2) {
        out.acts.push(peer.send(peer.conn_local, 0, Cmd::ZiReq { nets: chunk.to_vec() }));
    }
}

// ---------------------------------------------------------------- helpers

/// Sequence numbers and connection IDs both skip 0: 65535 is followed by 1.
fn succ(n: u16) -> u16 {
    match n.wrapping_add(1) {
        0 => 1,
        v => v,
    }
}

fn pred(n: u16) -> u16 {
    match n.wrapping_sub(1) {
        0 => u16::MAX,
        v => v,
    }
}

/// The connection ID the first peer starts from. It must differ from the last
/// one used with a sender, and a restart has no memory of that, so it is
/// random (RFC p. 43).
//
// ponytail: the wall clock stands in for a random number generator, which
// keeps this crate dependency-free. The tests read the ID out of the Open-Req
// we emit rather than pinning it, so they stay deterministic.
fn seed_conn() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(1, |d| d.subsec_nanos());
    succ(nanos as u16)
}

/// "Call you by what you call yourself": a peer's own source DI is how it is
/// addressed from then on. A null DI names nobody, so the IP header stands in.
fn named_by(src: Di, from: Ipv4Addr) -> Di {
    match src {
        Di::Null => Di::Ip(from),
        di => di,
    }
}

fn null_upd() -> Cmd {
    Cmd::RiUpd { events: vec![EventTuple { code: 0, tuple: NO_EVENT_TUPLE }] }
}

fn tuple_of(r: &super::table::Route) -> NetworkTuple {
    NetworkTuple { range: r.range, extended: r.extended, distance: r.distance }
}

/// Split an export into RI-Rsp pages of at most `MAX_BODY` body bytes. Always
/// at least one page, so a router with nothing to export still says so.
fn split_tuples(tuples: Vec<NetworkTuple>) -> Vec<Vec<NetworkTuple>> {
    let mut pages: Vec<Vec<NetworkTuple>> = vec![Vec::new()];
    let mut used = 0usize;
    for t in tuples {
        let n = if t.extended { 6 } else { 3 };
        if used + n > MAX_BODY {
            pages.push(Vec::new());
            used = 0;
        }
        used += n;
        pages.last_mut().expect("never empty").push(t);
    }
    pages
}

/// The ZI-Rsp(s) naming the zones of `nets`, split at `MAX_BODY`. A network
/// whose own list overflows a packet gets subcode 2, whose count is the whole
/// list's rather than the packet's.
//
// Sizes are the long tuple's, 2 + 1 + name; the optimized form only ever makes
// a packet smaller, so this never overshoots the limit.
fn zi_pages(nets: &[u16], tables: &Tables) -> Vec<Cmd> {
    let mut out = Vec::new();
    let mut page: Vec<(u16, String)> = Vec::new();
    let mut used = 0usize;
    for &net in nets {
        let Some(z) = tables.zones(net) else { continue };
        if z.names.is_empty() {
            continue;
        }
        let sizes: Vec<usize> = z.names.iter().map(|n| 3 + n.len()).collect();
        let total: usize = sizes.iter().sum();
        if total > MAX_BODY {
            if !page.is_empty() {
                out.push(Cmd::ZiRsp { extended: None, zones: std::mem::take(&mut page) });
                used = 0;
            }
            let count = z.names.len() as u16;
            let mut chunk: Vec<(u16, String)> = Vec::new();
            let mut chunked = 0usize;
            for (name, &s) in z.names.iter().zip(&sizes) {
                if chunked + s > MAX_BODY && !chunk.is_empty() {
                    out.push(Cmd::ZiRsp {
                        extended: Some(count),
                        zones: std::mem::take(&mut chunk),
                    });
                    chunked = 0;
                }
                chunked += s;
                chunk.push((net, name.clone()));
            }
            if !chunk.is_empty() {
                out.push(Cmd::ZiRsp { extended: Some(count), zones: chunk });
            }
            continue;
        }
        if used + total > MAX_BODY && !page.is_empty() {
            out.push(Cmd::ZiRsp { extended: None, zones: std::mem::take(&mut page) });
            used = 0;
        }
        used += total;
        page.extend(z.names.iter().map(|n| (net, n.clone())));
    }
    if !page.is_empty() {
        out.push(Cmd::ZiRsp { extended: None, zones: page });
    }
    out
}

impl fmt::Display for Receiver {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Receiver::Unconnected => "unconnected",
            Receiver::WaitOpenRsp => "wait open-rsp",
            Receiver::WaitRiRsp => "wait ri-rsp",
            Receiver::Connected => "connected",
            Receiver::WaitTickleAck => "wait tickle-ack",
        })
    }
}

impl fmt::Display for Sender {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Sender::Unconnected => "unconnected",
            Sender::Connected => "connected",
            Sender::WaitRiRspAck => "wait ri-rsp ack",
            Sender::WaitRiUpdAck => "wait ri-upd ack",
            Sender::WaitRdAck => "wait rd ack",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::table::Tables;
    use crate::wire::Ddp;

    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

    /// A packet as the peer would send it: our DI as destination, its own as source.
    fn routing(conn: u16, seq: u16, cmd: Cmd) -> Vec<u8> {
        Aurp::Routing {
            dh: DomainHeader { dst: Di::Ip(LOCAL), src: Di::Ip(REMOTE) },
            conn,
            seq,
            cmd,
        }
        .to_bytes()
    }

    /// Every `ToPeer` action, decoded.
    fn sent(acts: &[Action]) -> Vec<Aurp> {
        acts.iter()
            .filter_map(|a| match a {
                Action::ToPeer { bytes, .. } => Some(Aurp::parse(bytes).expect("we emit valid AURP")),
                _ => None,
            })
            .collect()
    }

    /// The `ToPeer` payloads as they go on the wire.
    fn raw(acts: &[Action]) -> Vec<Vec<u8>> {
        acts.iter()
            .filter_map(|a| match a {
                Action::ToPeer { bytes, .. } => Some(bytes.clone()),
                _ => None,
            })
            .collect()
    }

    fn cmds(acts: &[Action]) -> Vec<(u16, u16, Cmd)> {
        sent(acts)
            .into_iter()
            .map(|p| match p {
                Aurp::Routing { conn, seq, cmd, .. } => (conn, seq, cmd),
                Aurp::Data { .. } => panic!("expected a routing packet"),
            })
            .collect()
    }

    fn t(range: (u16, u16), d: u8) -> NetworkTuple {
        NetworkTuple { range, extended: true, distance: d }
    }

    fn open_rsp(rate: i16) -> Cmd {
        Cmd::OpenRsp { env: 0, rate_or_err: rate, options: Vec::new() }
    }

    fn open_req() -> Cmd {
        Cmd::OpenReq { sui: Cmd::ALL_SUI, version: 1, options: Vec::new() }
    }

    #[test]
    fn full_dialog() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["68k Mac Club".into()], t0);
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &["peer".to_string()], t0);
        ps.resolved("peer", REMOTE, t0);

        // The reconnect scan opens our receiver connection.
        let (a, _) = ps.tick(&mut tb, t0 + RECONNECT_SCAN);
        let a1 = match cmds(&a).as_slice() {
            [(c, 0, Cmd::OpenReq { sui, version, options })] => {
                assert_eq!((*sui, *version, options.len()), (Cmd::ALL_SUI, 1, 0));
                *c
            }
            other => panic!("expected one Open-Req, got {other:?}"),
        };

        // Open-Rsp accepted: we ask for their routes.
        let (a, ..) = ps.packet(REMOTE, &routing(a1, 0, open_rsp(1)), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(a1, 0, Cmd::RiReq { sui: Cmd::ALL_SUI })]);
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::WaitRiRsp);

        // Their Open-Req opens the other direction; we are their data sender.
        let b1 = 0xb001;
        let (a, ..) = ps.packet(REMOTE, &routing(b1, 0, open_req()), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(b1, 0, open_rsp(1))]);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::Connected);

        // Their routes arrive.
        let ri = Cmd::RiRsp { last: true, tuples: vec![t((2905, 2905), 0)] };
        let (a, ch, _) = ps.packet(REMOTE, &routing(a1, 1, ri), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(a1, 1, Cmd::RiAck { szi: true })]);
        assert_eq!(ch.len(), 1);
        assert_eq!(tb.best(2905).unwrap().distance, 1);
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Connected);

        // The zones for them, which nothing acknowledges.
        let zi = Cmd::ZiRsp { extended: None, zones: vec![(2905, "BabCom".into())] };
        let (a, ..) = ps.packet(REMOTE, &routing(a1, 0, zi), &mut tb, t0);
        assert!(a.is_empty());
        assert_eq!(tb.zones(2905).unwrap().names, vec!["BabCom".to_string()]);

        // They ask for ours.
        let (a, ..) = ps.packet(REMOTE, &routing(b1, 0, Cmd::RiReq { sui: Cmd::ALL_SUI }), &mut tb, t0);
        let ours = Cmd::RiRsp { last: true, tuples: vec![t((6800, 6800), 0)] };
        assert_eq!(cmds(&a), vec![(b1, 1, ours)]);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::WaitRiRspAck);

        // Their ack asks for the zones too.
        let (a, ..) = ps.packet(REMOTE, &routing(b1, 1, Cmd::RiAck { szi: true }), &mut tb, t0);
        let zones = Cmd::ZiRsp { extended: None, zones: vec![(6800, "68k Mac Club".into())] };
        assert_eq!(cmds(&a), vec![(b1, 0, zones)]);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::Connected);

        // An update: a network appeared behind them.
        let ev = EventTuple { code: NA, tuple: t((3000, 3000), 0) };
        let (a, ch, _) = ps.packet(REMOTE, &routing(a1, 2, Cmd::RiUpd { events: vec![ev] }), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(a1, 2, Cmd::RiAck { szi: true })]);
        assert_eq!(ch.len(), 1);
        assert_eq!(tb.best(3000).unwrap().distance, 1);
        let zi = Cmd::ZiRsp { extended: None, zones: vec![(3000, "BabCom".into())] };
        let (a, ..) = ps.packet(REMOTE, &routing(a1, 0, zi), &mut tb, t0);
        assert!(a.is_empty());

        // Ninety seconds of quiet and we tickle them.
        let quiet = t0 + LAST_HEARD + Duration::from_secs(1);
        let (a, _) = ps.tick(&mut tb, quiet);
        assert_eq!(cmds(&a), vec![(a1, 0, Cmd::Tickle)]);
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::WaitTickleAck);
        let (a, ..) = ps.packet(REMOTE, &routing(a1, 0, Cmd::TickleAck), &mut tb, quiet);
        assert!(a.is_empty());
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Connected);

        // They go down.
        let (a, ch, _) = ps.packet(REMOTE, &routing(a1, 3, Cmd::Rd { code: -1 }), &mut tb, quiet);
        assert_eq!(cmds(&a), vec![(a1, 3, Cmd::RiAck { szi: false })]);
        assert!(!ch.is_empty());
        assert!(tb.best(2905).is_none() && tb.best(3000).is_none());
        assert!(tb.best(6800).is_some()); // our own cable survives
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Unconnected);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::Unconnected);
    }

    /// Bring a peer up in both directions and hand back its two connection IDs.
    /// The peer's one network, 2905, is fully zoned, so nothing here is
    /// zoneless and the ZI re-request timer stays quiet.
    fn connected(tb: &mut Tables, now: Instant) -> (Peers, u16, u16) {
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &["peer".to_string()], now);
        ps.resolved("peer", REMOTE, now);
        let (a, _) = ps.tick(tb, now + RECONNECT_SCAN);
        let a1 = match cmds(&a).as_slice() {
            [(c, ..)] => *c,
            other => panic!("expected one Open-Req, got {other:?}"),
        };
        ps.packet(REMOTE, &routing(a1, 0, open_rsp(1)), tb, now);
        let ri = Cmd::RiRsp { last: true, tuples: vec![t((2905, 2905), 0)] };
        ps.packet(REMOTE, &routing(a1, 1, ri), tb, now);
        let zi = Cmd::ZiRsp { extended: None, zones: vec![(2905, "BabCom".into())] };
        ps.packet(REMOTE, &routing(a1, 0, zi), tb, now);
        let b1 = 0xb001;
        ps.packet(REMOTE, &routing(b1, 0, open_req()), tb, now);
        ps.packet(REMOTE, &routing(b1, 0, Cmd::RiReq { sui: Cmd::ALL_SUI }), tb, now);
        ps.packet(REMOTE, &routing(b1, 1, Cmd::RiAck { szi: false }), tb, now);
        (ps, a1, b1)
    }

    #[test]
    fn duplicate_sequence_re_acks_without_re_learning() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, a1, _) = connected(&mut tb, t0);
        let ev = EventTuple { code: NA, tuple: t((3000, 3000), 4) };
        ps.packet(REMOTE, &routing(a1, 2, Cmd::RiUpd { events: vec![ev] }), &mut tb, t0);
        assert_eq!(tb.best(3000).unwrap().distance, 5);
        // The same sequence number again, carrying a different distance: it is
        // re-acked and not re-applied.
        let stale = EventTuple { code: NA, tuple: t((3000, 3000), 9) };
        let upd = Cmd::RiUpd { events: vec![stale] };
        let (a, ch, _) = ps.packet(REMOTE, &routing(a1, 2, upd), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(a1, 2, Cmd::RiAck { szi: true })]);
        assert!(ch.is_empty());
        assert_eq!(tb.best(3000).unwrap().distance, 5);
        assert_eq!(ps.peers[&REMOTE].seq_recv, 3);
    }

    #[test]
    fn sequence_ahead_closes_the_receiver_and_increments_the_conn_id() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, a1, _) = connected(&mut tb, t0);
        // Expecting 2, receiving 3.
        let ev = EventTuple { code: NA, tuple: t((3000, 3000), 0) };
        let upd = Cmd::RiUpd { events: vec![ev] };
        let (a, ch, _) = ps.packet(REMOTE, &routing(a1, 3, upd), &mut tb, t0);
        assert!(a.is_empty() && ch.is_empty());
        assert!(tb.best(3000).is_none());
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Unconnected);
        assert_eq!(ps.peers[&REMOTE].conn_local, succ(a1));
    }

    #[test]
    fn open_rsp_error_leaves_the_receiver_unconnected() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &["peer".to_string()], t0);
        ps.resolved("peer", REMOTE, t0);
        let (a, _) = ps.tick(&mut tb, t0 + RECONNECT_SCAN);
        let a1 = match cmds(&a).as_slice() { [(c, ..)] => *c, o => panic!("{o:?}") };
        let (a, ..) = ps.packet(REMOTE, &routing(a1, 0, open_rsp(-5)), &mut tb, t0);
        assert!(a.is_empty());
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Unconnected);
        assert_eq!(ps.peers[&REMOTE].conn_local, succ(a1));
    }

    #[test]
    fn open_req_is_refused_on_version_and_on_options() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &[], t0);
        let bad = Cmd::OpenReq { sui: Cmd::ALL_SUI, version: 2, options: Vec::new() };
        let (a, ..) = ps.packet(REMOTE, &routing(7, 0, bad), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(7, 0, open_rsp(-5))]);
        let opts = Cmd::OpenReq { sui: Cmd::ALL_SUI, version: 1, options: vec![(1, vec![9])] };
        let (a, ..) = ps.packet(REMOTE, &routing(7, 0, opts), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(7, 0, open_rsp(-4))]);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::Unconnected);
    }

    #[test]
    fn tickle_after_ninety_seconds_quiet() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, a1, _) = connected(&mut tb, t0);
        // Ninety seconds exactly is not yet quiet enough.
        let (a, _) = ps.tick(&mut tb, t0 + LAST_HEARD);
        assert!(sent(&a).is_empty());
        let (a, _) = ps.tick(&mut tb, t0 + LAST_HEARD + Duration::from_secs(1));
        assert_eq!(cmds(&a), vec![(a1, 0, Cmd::Tickle)]);
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::WaitTickleAck);
    }

    #[test]
    fn ten_unanswered_tickles_drop_the_peers_routes() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, a1, b1) = connected(&mut tb, t0);
        let mut now = t0 + LAST_HEARD + Duration::from_secs(1);
        let (a, _) = ps.tick(&mut tb, now);
        assert_eq!(cmds(&a), vec![(a1, 0, Cmd::Tickle)]);
        // Nine more, ten tickles in all.
        for _ in 1..TICKLE_RETRIES {
            now += RETRY;
            let (a, ch) = ps.tick(&mut tb, now);
            assert_eq!(cmds(&a), vec![(a1, 0, Cmd::Tickle)]);
            assert!(ch.is_empty());
        }
        assert!(tb.best(2905).is_some());
        // The next timeout gives up: the routes go and the other direction is
        // probed with a null RI-Upd.
        now += RETRY;
        let (a, ch) = ps.tick(&mut tb, now);
        assert!(tb.best(2905).is_none());
        assert!(!ch.is_empty());
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Unconnected);
        assert_eq!(cmds(&a), vec![(b1, 2, null_upd())]);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::WaitRiUpdAck);
    }

    #[test]
    fn rd_is_acked_and_routes_dropped() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, a1, _) = connected(&mut tb, t0);
        let (a, ch, _) = ps.packet(REMOTE, &routing(a1, 2, Cmd::Rd { code: -1 }), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(a1, 2, Cmd::RiAck { szi: false })]);
        assert!(!ch.is_empty());
        assert!(tb.best(2905).is_none());
        assert!(tb.best(6800).is_some()); // our own cable survives
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Unconnected);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::Unconnected);
    }

    #[test]
    fn exported_tuples_split_into_three_ri_rsps_each_waiting_for_its_ack() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        // Six bytes an extended tuple: 500 of them need three packets.
        for i in 0..500u16 {
            tb.add_port(0, (1000 + i, 1000 + i), true, vec!["A".into()], t0);
        }
        let per = MAX_BODY / 6;
        let b1 = 0xb001;
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &[], t0);
        ps.packet(REMOTE, &routing(b1, 0, open_req()), &mut tb, t0);

        let (a, ..) = ps.packet(REMOTE, &routing(b1, 0, Cmd::RiReq { sui: Cmd::ALL_SUI }), &mut tb, t0);
        match cmds(&a).as_slice() {
            [(c, 1, Cmd::RiRsp { last: false, tuples })] => assert_eq!((*c, tuples.len()), (b1, per)),
            o => panic!("expected the first page, got {o:?}"),
        }
        // Nothing more goes out until that page is acked.
        let (a, _) = ps.tick(&mut tb, t0);
        assert!(sent(&a).is_empty());

        let (a, ..) = ps.packet(REMOTE, &routing(b1, 1, Cmd::RiAck { szi: false }), &mut tb, t0);
        match cmds(&a).as_slice() {
            [(_, 2, Cmd::RiRsp { last: false, tuples })] => assert_eq!(tuples.len(), per),
            o => panic!("expected the second page, got {o:?}"),
        }
        let (a, ..) = ps.packet(REMOTE, &routing(b1, 2, Cmd::RiAck { szi: false }), &mut tb, t0);
        match cmds(&a).as_slice() {
            [(_, 3, Cmd::RiRsp { last: true, tuples })] => assert_eq!(tuples.len(), 500 - 2 * per),
            o => panic!("expected the last page, got {o:?}"),
        }
        let (a, ..) = ps.packet(REMOTE, &routing(b1, 3, Cmd::RiAck { szi: false }), &mut tb, t0);
        assert!(sent(&a).is_empty());
        assert_eq!(ps.peers[&REMOTE].sender, Sender::Connected);
    }

    #[test]
    fn na_then_nd_collapse_to_nothing() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, _, _) = connected(&mut tb, t0);
        // A network behind a router on our cable: nothing to say until its
        // zones are known.
        let ch = tb.learn(&t((7100, 7100), 0), Target::Port(1), Addr { net: 6800, node: 9 }, t0);
        ps.route_changed(&ch, &tb);
        assert!(ps.peers[&REMOTE].pending.is_empty());
        // Zones complete: now it is exportable.
        let ch = tb.add_zones(7100, &["C".to_string()], None);
        ps.route_changed(&ch, &tb);
        assert_eq!(ps.peers[&REMOTE].pending, vec![EventTuple { code: NA, tuple: t((7100, 7100), 1) }]);
        // And it goes away again before the update interval elapses.
        let ch = tb.remove(Target::Port(1), 7100);
        ps.route_changed(&ch, &tb);
        assert!(ps.peers[&REMOTE].pending.is_empty());
        let (a, _) = ps.tick(&mut tb, t0 + UPDATE_INTERVAL);
        assert!(sent(&a).is_empty());
    }

    #[test]
    fn an_exported_network_that_moves_onto_a_tunnel_becomes_nrc() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, _, _) = connected(&mut tb, t0);
        tb.learn(&t((7100, 7100), 0), Target::Port(1), Addr { net: 6800, node: 9 }, t0);
        let ch = tb.add_zones(7100, &["C".to_string()], None);
        ps.route_changed(&ch, &tb);
        ps.peers.get_mut(&REMOTE).unwrap().pending.clear();
        // The port route goes and only the tunnel one is left.
        tb.learn(&t((7100, 7100), 0), Target::Peer(REMOTE), NO_NEXT, t0);
        let ch = tb.remove(Target::Port(1), 7100);
        ps.route_changed(&ch, &tb);
        assert_eq!(ps.peers[&REMOTE].pending[0].code, NRC);
    }

    #[test]
    fn conflicting_open_req_probes_the_old_connection() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, _, b1) = connected(&mut tb, t0);
        // A second Open-Req with a fresh ID: the old connection gets probed
        // and the Open-Req itself is dropped.
        let (a, ..) = ps.packet(REMOTE, &routing(0xb002, 0, open_req()), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(b1, 2, null_upd())]);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::WaitRiUpdAck);
        // Acked, so the old connection is alive and the Open-Req was bogus.
        let (a, ..) = ps.packet(REMOTE, &routing(b1, 2, Cmd::RiAck { szi: false }), &mut tb, t0);
        assert!(sent(&a).is_empty());
        assert_eq!(ps.peers[&REMOTE].sender, Sender::Connected);
        assert_eq!(ps.peers[&REMOTE].conn_remote, b1);
    }

    #[test]
    fn an_unanswered_probe_closes_the_sender_and_the_next_open_req_is_answered() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, _, _) = connected(&mut tb, t0);
        let (a, ..) = ps.packet(REMOTE, &routing(0xb002, 0, open_req()), &mut tb, t0);
        let probe = raw(&a);
        let mut now = t0;
        for _ in 1..RETRIES {
            now += RETRY;
            let (a, _) = ps.tick(&mut tb, now);
            // An RI-Upd retransmission is the same bytes, same sequence number.
            assert_eq!(raw(&a), probe);
        }
        now += RETRY;
        ps.tick(&mut tb, now);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::Unconnected);
        let (a, ..) = ps.packet(REMOTE, &routing(0xb002, 0, open_req()), &mut tb, now);
        assert_eq!(cmds(&a), vec![(0xb002, 0, open_rsp(1))]);
        assert_eq!(ps.peers[&REMOTE].conn_remote, 0xb002);
    }

    #[test]
    fn unknown_peer_dropped_with_open_peering_off() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        let mut ps = Peers::new(Di::Ip(LOCAL), false, &[], t0);
        let p = routing(1, 0, open_req());
        let (a, ..) = ps.packet(REMOTE, &p, &mut tb, t0);
        assert!(sent(&a).is_empty());
        assert!(matches!(a.as_slice(), [Action::Log(_)]));
        assert!(!ps.known(REMOTE));
        // One log per address per minute, no more.
        let (a, ..) = ps.packet(REMOTE, &p, &mut tb, t0 + Duration::from_secs(30));
        assert!(a.is_empty());
        let (a, ..) = ps.packet(REMOTE, &p, &mut tb, t0 + Duration::from_secs(61));
        assert!(matches!(a.as_slice(), [Action::Log(_)]));
    }

    #[test]
    fn shutdown_emits_rd_to_sender_connected_peers_only() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, _, b1) = connected(&mut tb, t0);
        // A second peer we never became data sender to.
        ps.resolved("other", Ipv4Addr::new(192, 0, 2, 3), t0);
        let a = ps.shutdown(t0);
        assert_eq!(cmds(&a), vec![(b1, 2, Cmd::Rd { code: -1 })]);
        assert_eq!(ps.peers[&REMOTE].sender, Sender::WaitRdAck);
        let d = ps.dump();
        assert!(d.contains("peer") && d.contains("192.0.2.2") && d.contains("wait rd ack"), "{d}");
        assert!(d.contains("other") && d.contains("192.0.2.3"), "{d}");
    }

    #[test]
    fn data_packets_come_back_for_forwarding_and_touch_no_state() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &[], t0);
        let ddp = Ddp {
            hops: 0,
            length: 0,
            checksum: 0,
            dst: Addr { net: 2905, node: 3 },
            dst_socket: 4,
            src: Addr { net: 6800, node: 1 },
            src_socket: 4,
            typ: 3,
            data: vec![1, 2, 3],
        }
        .to_bytes();
        let dh = DomainHeader { dst: Di::Ip(LOCAL), src: Di::Ip(REMOTE) };
        let bytes = Aurp::Data { dh, ddp: ddp.clone() }.to_bytes();
        let (a, ch, back) = ps.packet(REMOTE, &bytes, &mut tb, t0);
        assert!(a.is_empty() && ch.is_empty());
        assert_eq!(back, Some(ddp.clone()));
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Unconnected);
        // And the other way: a datagram wrapped for the peer.
        match ps.forward(REMOTE, &ddp) {
            Action::ToPeer { peer, bytes } => {
                assert_eq!(peer, REMOTE);
                let dh = DomainHeader { dst: Di::Ip(REMOTE), src: Di::Ip(LOCAL) };
                assert_eq!(Aurp::parse(&bytes), Some(Aurp::Data { dh, ddp }));
            }
            o => panic!("expected a ToPeer, got {o:?}"),
        }
    }

    #[test]
    fn zoneless_tunnel_networks_are_re_requested() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, a1, _) = connected(&mut tb, t0);
        // A second network from the peer, whose ZI-Rsp never arrives.
        let ev = EventTuple { code: NA, tuple: t((3000, 3000), 0) };
        ps.packet(REMOTE, &routing(a1, 2, Cmd::RiUpd { events: vec![ev] }), &mut tb, t0);
        let (a, _) = ps.tick(&mut tb, t0 + ZI_REREQUEST);
        assert_eq!(cmds(&a), vec![(a1, 0, Cmd::ZiReq { nets: vec![3000] })]);
    }

    #[test]
    fn gzn_and_gdzl_are_answered_not_supported() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, _, b1) = connected(&mut tb, t0);
        let req = Cmd::GznReq { zone: "A".into() };
        let (a, ..) = ps.packet(REMOTE, &routing(b1, 0, req), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(b1, 0, Cmd::GznRsp { zone: "A".into(), tuples: None })]);
        let (a, ..) = ps.packet(REMOTE, &routing(b1, 0, Cmd::GdzlReq { start: 0 }), &mut tb, t0);
        let rsp = Cmd::GdzlRsp { last: true, start: -1, zones: Vec::new() };
        assert_eq!(cmds(&a), vec![(b1, 0, rsp)]);
    }

    #[test]
    fn a_stranger_gets_nothing_back_before_we_are_its_data_sender() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["68k Mac Club".into()], t0);
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &[], t0);
        // Open peering makes a peer of whoever writes to us, and a fresh peer
        // has `conn_remote` 0 -- so conn 0 is exactly the forger's guess.
        for cmd in [
            Cmd::ZiReq { nets: vec![6800] },
            Cmd::GznReq { zone: "68k Mac Club".into() },
            Cmd::GdzlReq { start: 0 },
            Cmd::Tickle,
            Cmd::RiReq { sui: Cmd::ALL_SUI },
        ] {
            let (a, ..) = ps.packet(REMOTE, &routing(0, 0, cmd), &mut tb, t0);
            assert!(sent(&a).is_empty(), "answered a stranger: {a:?}");
        }
        assert_eq!(ps.peers[&REMOTE].sender, Sender::Unconnected);
    }

    #[test]
    fn an_ri_req_during_wait_rd_ack_does_not_abandon_the_rd() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, _, b1) = connected(&mut tb, t0);
        ps.shutdown(t0);
        let (a, ..) = ps.packet(REMOTE, &routing(b1, 0, Cmd::RiReq { sui: Cmd::ALL_SUI }), &mut tb, t0);
        assert!(sent(&a).is_empty());
        assert_eq!(ps.peers[&REMOTE].sender, Sender::WaitRdAck);
        // The RD is still the packet outstanding, so it is what retransmits.
        let (a, _) = ps.tick(&mut tb, t0 + RETRY);
        assert_eq!(cmds(&a), vec![(b1, 2, Cmd::Rd { code: -1 })]);
    }

    #[test]
    fn five_unanswered_ri_reqs_close_the_receiver() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &["peer".to_string()], t0);
        ps.resolved("peer", REMOTE, t0);
        let (a, _) = ps.tick(&mut tb, t0 + RECONNECT_SCAN);
        let a1 = match cmds(&a).as_slice() { [(c, ..)] => *c, o => panic!("{o:?}") };
        let (a, ..) = ps.packet(REMOTE, &routing(a1, 0, open_rsp(1)), &mut tb, t0);
        assert_eq!(cmds(&a), vec![(a1, 0, Cmd::RiReq { sui: Cmd::ALL_SUI })]);
        // Four retransmissions, five RI-Reqs in all, and the peer never answers.
        let mut now = t0;
        for _ in 1..RETRIES {
            now += RETRY;
            let (a, _) = ps.tick(&mut tb, now);
            assert_eq!(cmds(&a), vec![(a1, 0, Cmd::RiReq { sui: Cmd::ALL_SUI })]);
        }
        now += RETRY;
        let (a, _) = ps.tick(&mut tb, now);
        assert!(sent(&a).is_empty());
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Unconnected);
        assert_eq!(ps.peers[&REMOTE].conn_local, succ(a1));
        // Unconnected again, so the reconnect scan can have another go.
        now += RECONNECT_BACKOFF + RECONNECT_SCAN;
        let (a, _) = ps.tick(&mut tb, now);
        match cmds(&a).as_slice() {
            [(c, 0, Cmd::OpenReq { .. })] => assert_eq!(*c, succ(a1)),
            o => panic!("expected a fresh Open-Req, got {o:?}"),
        }
    }

    #[test]
    fn five_unanswered_open_reqs_close_the_receiver() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &["peer".to_string()], t0);
        ps.resolved("peer", REMOTE, t0);
        let (a, _) = ps.tick(&mut tb, t0 + RECONNECT_SCAN);
        let a1 = match cmds(&a).as_slice() { [(c, ..)] => *c, o => panic!("{o:?}") };
        let mut now = t0 + RECONNECT_SCAN;
        for _ in 1..RETRIES {
            now += RETRY;
            let (a, _) = ps.tick(&mut tb, now);
            assert_eq!(cmds(&a), vec![(a1, 0, open_req())]);
        }
        now += RETRY;
        let (a, _) = ps.tick(&mut tb, now);
        assert!(sent(&a).is_empty());
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::Unconnected);
    }

    #[test]
    fn an_inbound_open_req_opens_our_own_direction_at_once() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        let mut ps = Peers::new(Di::Ip(LOCAL), true, &[], t0);
        let (a, ..) = ps.packet(REMOTE, &routing(0xb001, 0, open_req()), &mut tb, t0);
        match cmds(&a).as_slice() {
            [(0xb001, 0, rsp), (c, 0, req @ Cmd::OpenReq { .. })] => {
                assert_eq!(*rsp, open_rsp(1));
                assert_eq!(*req, open_req());
                assert_ne!(*c, 0xb001); // our own ID, not theirs
            }
            o => panic!("expected an Open-Rsp then our own Open-Req, got {o:?}"),
        }
        assert_eq!(ps.peers[&REMOTE].receiver, Receiver::WaitOpenRsp);
    }

    #[test]
    fn pending_events_collapse_per_network() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], t0);
        let (mut ps, _, _) = connected(&mut tb, t0);
        let pending = |ps: &Peers| ps.peers[&REMOTE].pending.clone();
        let queue = |ps: &mut Peers, code: u8, d: u8| {
            ps.peers.get_mut(&REMOTE).unwrap().queue(EventTuple { code, tuple: t((7100, 7100), d) })
        };
        // NA then NDC stays an addition, at the new distance.
        queue(&mut ps, NA, 1);
        queue(&mut ps, NDC, 4);
        assert_eq!(pending(&ps), vec![EventTuple { code: NA, tuple: t((7100, 7100), 4) }]);
        // ND then NA is a distance change: the peer never lost the network.
        ps.peers.get_mut(&REMOTE).unwrap().pending.clear();
        queue(&mut ps, ND, 0);
        queue(&mut ps, NA, 2);
        assert_eq!(pending(&ps), vec![EventTuple { code: NDC, tuple: t((7100, 7100), 2) }]);
        // NDC after NDC: the last one wins.
        queue(&mut ps, NDC, 3);
        queue(&mut ps, NDC, 7);
        assert_eq!(pending(&ps), vec![EventTuple { code: NDC, tuple: t((7100, 7100), 7) }]);
        // One entry per network throughout, whatever else is queued.
        queue(&mut ps, NA, 1);
        ps.peers.get_mut(&REMOTE).unwrap().queue(EventTuple { code: NA, tuple: t((7200, 7200), 1) });
        assert_eq!(pending(&ps).len(), 2);
    }

    #[test]
    fn a_zone_list_too_long_for_one_packet_uses_subcode_two() {
        let t0 = Instant::now();
        let mut tb = Tables::new();
        // Thirty-two-character names, 35 body bytes each: 60 overflow MAX_BODY.
        let names: Vec<String> = (0..60).map(|i| format!("{i:032}")).collect();
        tb.add_port(0, (6800, 6800), true, names.clone(), t0);
        let pages = zi_pages(&[6800], &tb);
        assert!(pages.len() > 1);
        let mut seen = 0;
        for p in &pages {
            match p {
                Cmd::ZiRsp { extended: Some(total), zones } => {
                    assert_eq!(*total as usize, names.len());
                    assert!(zones.len() * 35 <= MAX_BODY);
                    seen += zones.len();
                }
                o => panic!("expected subcode 2, got {o:?}"),
            }
        }
        assert_eq!(seen, names.len());
    }
}
