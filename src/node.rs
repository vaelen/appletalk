// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! The node runtime: claim an AppleTalk address, defend it, ask questions.
//!
//! Everything that decides something is a free function over a `&Packet`, so
//! it can be tested without a NIC. The `Node` methods are the socket-and-timer
//! glue around them.

use std::collections::HashMap;
use std::io;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pnet::util::MacAddr;

use crate::capture::{Event, Tx};
use crate::session::{Message, Session};
use crate::wire::{
    Aarp, Addr, Aep, Atp, Body, Ddp, DdpBody, Echo, Encode, Frame, Func, Nbp, NbpFunc, NbpTuple,
    Packet, Zip, ZipAtp, AARP, DDP, DDP_AEP, DDP_ATP, DDP_NBP, DDP_ZIP,
};

/// Where ELAP sends AppleTalk broadcasts, and where AARP probes and requests
/// belong too (PDF 98). Non-AppleTalk nodes never register on it.
pub const BROADCAST_MAC: MacAddr = MacAddr(0x09, 0x00, 0x07, 0xff, 0xff, 0xff);

/// The bottom of the dynamic socket range. One conversation at a time means
/// one socket is enough.
pub const OUR_SOCKET: u8 = 128;

/// A datagram with its derived fields left for `encode`: the length is
/// recomputed there, and a zero checksum means "sender computed none", which
/// is legal and what we want.
pub fn datagram(
    src: Addr,
    src_socket: u8,
    dst: Addr,
    dst_socket: u8,
    typ: u8,
    data: Vec<u8>,
) -> Ddp {
    Ddp { hops: 0, length: 0, checksum: 0, dst, dst_socket, src, src_socket, typ, data }
}

/// Always Phase 2 — 802.3 + LLC + SNAP. Every network this is likely to meet
/// is Phase 2, and `Frame::encode` handles the framing when `snap` is set.
pub fn frame(src: MacAddr, dst: MacAddr, proto: u16, payload: Vec<u8>) -> Frame {
    Frame { dst, src, proto, snap: true, payload }
}

/// Picks a provisional address. The node ID is random and the network number
/// comes from the startup range $FF00–$FFFE (PDF 111). Node IDs 0, $FE and
/// $FF are reserved on Ethernet and token ring (PDF 98).
///
/// ponytail: the seed is the clock mixed with the NIC's MAC rather than a real
/// RNG. Collisions are what the probe is for, so a weak seed costs at most one
/// extra round of probing. Reach for a real RNG only if probing starts failing.
pub fn pick_address(seed: u64) -> Addr {
    Addr {
        net: 0xff00 + (seed % 0xff) as u16,
        node: 1 + ((seed >> 16) % 253) as u8,
    }
}

/// An AARP Probe: "is anyone using this address?". The target hardware
/// address is zero because that is exactly what we are asking for.
pub fn probe(addr: Addr, mac: MacAddr) -> Aarp {
    Aarp { op: 3, src_hw: mac, src: addr, dst_hw: MacAddr::zero(), dst: addr }
}

/// "Yes, that address is mine, at this MAC."
pub fn aarp_response(ours: Addr, our_mac: MacAddr, to: Addr, to_mac: MacAddr) -> Aarp {
    Aarp { op: 2, src_hw: our_mac, src: ours, dst_hw: to_mac, dst: to }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AarpAction {
    /// Someone else holds, or is also claiming, the address we want.
    Conflict,
    /// A request for our address, to be answered at this MAC.
    AnswerTo(MacAddr),
    Ignore,
}

/// What an incoming packet means for our address. `probing` is true until the
/// address is claimed — a probing node answers nothing (PDF 86).
pub fn aarp_action(p: &Packet, ours: Addr, our_mac: MacAddr, probing: bool) -> AarpAction {
    let Body::Aarp(a) = &p.body else { return AarpAction::Ignore };
    match a.op {
        // A response for the address means it is taken.
        2 if a.src == ours => AarpAction::Conflict,
        // Someone else probing for the same address. While we are probing too,
        // both sides give up (PDF 86). Once claimed, we defend it by answering
        // — that response is how the prober learns the address is taken (PDF 85).
        3 if a.src == ours && a.src_hw != our_mac => {
            if probing { AarpAction::Conflict } else { AarpAction::AnswerTo(a.src_hw) }
        }
        1 if a.dst == ours && !probing => AarpAction::AnswerTo(a.src_hw),
        _ => AarpAction::Ignore,
    }
}

/// Records the sender's address-to-MAC mapping, so a later directed frame has
/// somewhere to go. Gleaning is optional in the book and deliberately excludes
/// Probes, whose source address is only tentative (PDF 87).
pub fn glean(amt: &mut HashMap<Addr, MacAddr>, p: &Packet) {
    match &p.body {
        Body::Aarp(a) if a.op != 3 => {
            amt.insert(a.src, a.src_hw);
        }
        Body::Ddp(d, _) => {
            amt.insert(d.src, p.frame.src);
        }
        _ => {}
    }
}

/// How much of our address the user pinned down for us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// Nothing: pick a provisional address in the startup range and ask a
    /// router what this cable really is.
    Discover,
    /// This network, our choice of node — "I am on this net, give me a node".
    Net(u16),
    /// Exactly this address.
    Addr(Addr),
}

#[derive(Debug, PartialEq, Eq)]
pub enum NetInfo {
    /// Our provisional network number is valid on this cable.
    Keep,
    /// It is not; pick again inside this range.
    Repick { range: (u16, u16) },
}

/// Reads a ZIP GetNetInfo reply: whether our provisional address survives, the
/// zone name to adopt, and the address of the router that answered — which is
/// the only way we learn of a router (PDF 181).
pub fn netinfo_verdict(
    p: &Packet,
    provisional: Addr,
    requested_zone: &str,
) -> Option<(NetInfo, String, Addr)> {
    let Body::Ddp(d, DdpBody::Zip(Zip::NetInfoReply { range, zone, default_zone, .. })) = &p.body
    else {
        return None;
    };
    // Capture is promiscuous and another booting node's reply is on the wire
    // too, so a reply directed at someone else is not ours.
    if d.dst.node != 255 && d.dst != provisional {
        return None;
    }
    // Replies are often broadcast rather than directed — observed from a real
    // router, and PDF 190 provides for it — so the address alone cannot tell
    // ours apart. The book's own test is the echoed zone name: "nodes
    // receiving such replies should use this zone name to verify that the
    // response is for the zone name that they requested. If not, the reply
    // should be ignored."
    if zone != requested_zone {
        return None;
    }
    // A range whose end precedes its start is not something we recognise, and
    // the span arithmetic downstream would underflow on it. Fail closed: with
    // no verdict the caller falls through to the routerless path and keeps its
    // provisional address, exactly as if no router had answered.
    if range.1 < range.0 {
        return None;
    }
    // The reply echoes the zone we asked for; a default zone means that one
    // was not valid here and this is the name to use instead.
    let zone = default_zone.clone().unwrap_or_else(|| zone.clone());
    let verdict = if (range.0..=range.1).contains(&provisional.net) {
        NetInfo::Keep
    } else {
        NetInfo::Repick { range: *range }
    };
    Some((verdict, zone, d.src))
}

/// A lookup carries exactly one tuple: the name being asked about, with the
/// requester's own address in the address field so responders know where to
/// send the LkUp-Reply (PDF 169–172).
pub fn lookup_request(
    func: NbpFunc,
    id: u8,
    ours: Addr,
    socket: u8,
    object: &str,
    typ: &str,
    zone: &str,
) -> Nbp {
    Nbp {
        func,
        id,
        tuples: vec![NbpTuple {
            addr: ours,
            socket,
            // Ignored by the recipient of a lookup; only replies carry a
            // meaningful enumerator.
            enumerator: 0,
            object: object.to_string(),
            typ: typ.to_string(),
            zone: zone.to_string(),
        }],
    }
}

/// The tuples in a LkUp-Reply that answers lookup `id`, or nothing.
pub fn lookup_replies(p: &Packet, id: u8) -> &[NbpTuple] {
    match &p.body {
        Body::Ddp(_, DdpBody::Nbp(n)) if n.func == NbpFunc::LkUpReply && n.id == id => &n.tuples,
        _ => &[],
    }
}

/// Appends tuples we have not already seen. Requests are retransmitted, so the
/// same entity answers more than once. Dedupes on `(addr, socket, enumerator,
/// object, type)`, not the zone — a responder that spells its zone
/// differently across replies is still the same entity.
pub fn merge(into: &mut Vec<NbpTuple>, tuples: &[NbpTuple]) {
    let same = |a: &NbpTuple, b: &NbpTuple| {
        (a.addr, a.socket, a.enumerator, &a.object, &a.typ) == (b.addr, b.socket, b.enumerator, &b.object, &b.typ)
    };
    for t in tuples {
        if !into.iter().any(|e| same(e, t)) {
            into.push(t.clone());
        }
    }
}

/// `net.node`, both decimal. Node 0 is not a valid node ID, so it is rejected
/// here rather than producing a datagram nobody can answer.
pub fn parse_addr(s: &str) -> io::Result<Addr> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("bad address {s:?}"));
    let (net, node) = s.split_once('.').ok_or_else(bad)?;
    let net: u16 = net.parse().map_err(|_| bad())?;
    let node: u8 = node.parse().map_err(|_| bad())?;
    if node == 0 {
        return Err(bad());
    }
    Ok(Addr { net, node })
}

/// PDF 98: ten retransmissions, one fifth of a second apart.
const PROBE_TRIES: u32 = 10;
const PROBE_INTERVAL: Duration = Duration::from_millis(200);
/// How many different addresses to try before giving up entirely.
const ADDRESS_TRIES: u32 = 5;
/// We keep no saved zone across runs, so we request the empty zone name — the
/// "no saved zone" case (PDF 181) — and expect it echoed back in the reply.
const REQUESTED_ZONE: &str = "";
/// PDF 181: "retransmitted several times to insure that a response is received".
const NETINFO_TRIES: u32 = 3;
const NETINFO_INTERVAL: Duration = Duration::from_secs(1);
/// How many times to retransmit a lookup.
const LOOKUP_TRIES: u32 = 3;
const LOOKUP_INTERVAL: Duration = Duration::from_secs(1);
const PING_INTERVAL: Duration = Duration::from_secs(1);
const ZONE_TRIES: u32 = 3;
const ZONE_INTERVAL: Duration = Duration::from_secs(2);
/// ponytail: a page holds up to ~2300 names (PDF 187), so this covers any
/// plausible zone list with headroom to spare. Bumping it is the upgrade path
/// if a real network ever needs more; an unauthenticated "router" should
/// never be able to make us page forever.
const MAX_ZONE_PAGES: u32 = 1000;
/// ponytail: only `zone_list` drains this, so every other `wait` caller would
/// otherwise accumulate unrelated completed transactions for the life of the
/// node. Cap it well above the one-reply-per-request working set. Give each
/// caller its own drain if a future command needs more than the last reply.
const MAX_MESSAGES: usize = 64;

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

pub struct Node {
    tx: Tx,
    rx: Receiver<Event>,
    addr: Addr,
    /// None means no router answered: no zone, and `*` in every lookup.
    zone: Option<String>,
    router: Option<Addr>,
    /// Address-to-MAC mappings gleaned from traffic.
    amt: HashMap<Addr, MacAddr>,
    /// Reused wholesale for ATP reassembly.
    session: Session,
    /// True only while `claim_one` is sending Probes for an address;
    /// suppresses AARP answers for that interval (PDF 86).
    probing: bool,
    next_id: u16,
    /// Scratch for `wait` closures that accumulate across callbacks.
    pending: Vec<NbpTuple>,
    /// Messages `Session` completed since the last request looked.
    messages: Vec<Message>,
}

impl Node {
    /// Runs the book's two-step startup and returns a node ready to ask
    /// questions. Narrates to stderr, because stdout is for results.
    pub fn claim(tx: Tx, rx: Receiver<Event>, want: Want) -> io::Result<Node> {
        let mut n = Node {
            tx,
            rx,
            addr: Addr { net: 0, node: 0 },
            zone: None,
            router: None,
            amt: HashMap::new(),
            session: Session::new(),
            probing: false,
            next_id: 1,
            pending: Vec::new(),
            messages: Vec::new(),
        };

        n.addr = match want {
            Want::Addr(a) => {
                // 254 and 255 are reserved on Ethernet (PDF 98). Harmless as a
                // ping target, but not something to claim as our own address.
                if a.node == 254 || a.node == 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("node {} is reserved and cannot be claimed", a.node),
                    ));
                }
                n.claim_one(a)?;
                a
            }
            // A range of one network is the same problem as re-picking inside
            // a cable range: choose a node, probe it, try again if it is taken.
            Want::Net(net) => n.claim_in_range((net, net))?,
            Want::Discover => n.claim_any()?,
        };

        // Step two: ask a router what this cable actually is.
        if let Some((verdict, zone, router)) = n.get_net_info() {
            n.router = Some(router);
            n.zone = Some(zone);
            if let NetInfo::Repick { range } = verdict {
                if want != Want::Discover {
                    // The user asked for this address specifically; it is
                    // their business that it falls outside the cable range,
                    // and we say what we did rather than second-guessing it.
                    eprintln!(
                        "{} is outside this cable's range {}-{}; keeping it as requested",
                        n.addr, range.0, range.1
                    );
                } else {
                    let addr = n.claim_in_range(range)?;
                    n.addr = addr;
                }
            }
            eprintln!(
                "claimed {}, zone {:?}, router {}",
                n.addr,
                n.zone.as_deref().unwrap_or("*"),
                router
            );
        } else {
            // PDF 181: no reply means no router. The provisional address is
            // final and `*` is the only zone name valid in lookups.
            eprintln!("claimed {}, no router on this network", n.addr);
        }
        Ok(n)
    }

    fn claim_any(&mut self) -> io::Result<Addr> {
        for attempt in 0..ADDRESS_TRIES {
            let addr = pick_address(self.seed(attempt));
            if self.claim_one(addr).is_ok() {
                return Ok(addr);
            }
        }
        Err(io::Error::new(io::ErrorKind::AddrInUse, "could not claim an address"))
    }

    fn claim_in_range(&mut self, range: (u16, u16)) -> io::Result<Addr> {
        for attempt in 0..ADDRESS_TRIES {
            let seed = self.seed(attempt);
            let span = (range.1 - range.0) as u64 + 1;
            let addr = Addr {
                net: range.0 + (seed % span) as u16,
                node: pick_address(seed).node,
            };
            if self.claim_one(addr).is_ok() {
                return Ok(addr);
            }
        }
        Err(io::Error::new(io::ErrorKind::AddrInUse, "could not claim an address in range"))
    }

    /// Probes one address. Ok means nobody objected. `probing` is scoped to
    /// exactly this call — PDF 86 withholds AARP answers only "while sending
    /// Probe packets", not for the GetNetInfo round that follows.
    fn claim_one(&mut self, addr: Addr) -> io::Result<()> {
        self.probing = true;
        let our_mac = self.tx.mac;
        for _ in 0..PROBE_TRIES {
            let p = probe(addr, our_mac);
            let f = frame(our_mac, BROADCAST_MAC, AARP, p.to_bytes());
            if let Err(e) = self.tx.send(&f) {
                self.probing = false;
                return Err(e);
            }
            let taken = self.wait(Instant::now() + PROBE_INTERVAL, |_, pkt| {
                match aarp_action(pkt, addr, our_mac, true) {
                    AarpAction::Conflict => Some(()),
                    _ => None,
                }
            });
            if taken.is_some() {
                self.probing = false;
                return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("{addr} is taken")));
            }
        }
        self.probing = false;
        Ok(())
    }

    fn get_net_info(&mut self) -> Option<(NetInfo, String, Addr)> {
        let body = Zip::GetNetInfo { zone: REQUESTED_ZONE.to_string() }.to_bytes();
        let provisional = self.addr;
        for _ in 0..NETINFO_TRIES {
            // ZIP is a socket-6 protocol at both ends.
            self.send_from(6, Addr { net: 0, node: 255 }, 6, DDP_ZIP, body.clone()).ok()?;
            let got = self.wait(Instant::now() + NETINFO_INTERVAL, move |_, p| {
                netinfo_verdict(p, provisional, REQUESTED_ZONE)
            });
            if got.is_some() {
                return got;
            }
        }
        None
    }

    /// Sends a lookup and collects answers. With a router this is a BrRq to
    /// its NBP socket, which the router explodes into zone-wide LkUps for us;
    /// without one, a local broadcast reaches everybody who could answer.
    pub fn lookup(&mut self, object: &str, typ: &str, zone: &str) -> io::Result<Vec<NbpTuple>> {
        let id = self.next_id() as u8;
        let (func, dst) = match self.router() {
            Some(r) => (NbpFunc::BrRq, r),
            // Net 0 is the network-wide broadcast (PDF 110), same as
            // `get_net_info` uses. A network-specific broadcast to our own net
            // would only be accepted by nodes sharing it, and on a routerless
            // cable everyone picked their startup net independently, so
            // almost nobody would.
            None => (NbpFunc::LkUp, Addr { net: 0, node: 255 }),
        };
        let body = lookup_request(func, id, self.addr, OUR_SOCKET, object, typ, zone).to_bytes();

        let mut found = Vec::new();
        for _ in 0..LOOKUP_TRIES {
            self.send_ddp(dst, 2, DDP_NBP, body.clone())?;
            // Collect for the whole interval rather than stopping at the first
            // answer: a lookup has many responders, not one.
            let deadline = Instant::now() + LOOKUP_INTERVAL;
            while self
                .wait(deadline, |n, p| {
                    let tuples = lookup_replies(p, id);
                    (!tuples.is_empty()).then(|| merge(&mut n.pending, tuples))
                })
                .is_some()
            {}
            let batch = std::mem::take(&mut self.pending);
            merge(&mut found, &batch);
        }
        found.sort_by(|a, b| (&a.object, &a.typ).cmp(&(&b.object, &b.typ)));
        Ok(found)
    }

    /// One probe per second, each waiting up to a second. Returns whether
    /// anything answered.
    pub fn ping(&mut self, target: Addr, count: u16) -> io::Result<bool> {
        // Distinguishes our echoes from any other pinger's on the same cable.
        let magic = self.seed(0) as u32;
        let mut rtts: Vec<Duration> = Vec::new();

        for seq in 0..u32::from(count) {
            let data = echo_data(magic, seq);
            let body = Aep { func: Echo::Request, data }.to_bytes();
            let sent = Instant::now();
            self.send_ddp(target, 4, DDP_AEP, body)?;

            match self.wait(sent + PING_INTERVAL, |_, p| {
                echo_match(p, magic).filter(|(_, s)| *s == seq)
            }) {
                Some((from, _)) => {
                    let rtt = sent.elapsed();
                    println!("8 bytes from {from}: seq={seq} time={:.2} ms", ms(rtt));
                    rtts.push(rtt);
                }
                None => println!("timeout seq={seq}"),
            }
            // Pace the next probe even when this one answered early.
            if let Some(left) = (sent + PING_INTERVAL).checked_duration_since(Instant::now()) {
                let _ = self.wait(Instant::now() + left, |_, _| None::<()>);
            }
        }

        let lost = usize::from(count) - rtts.len();
        let loss = if count == 0 { 0.0 } else { lost as f64 * 100.0 / f64::from(count) };
        println!("\n--- {target} ping statistics ---");
        print!("{count} sent, {} received, {loss:.0}% loss", rtts.len());
        if let (Some(min), Some(max)) = (rtts.iter().min(), rtts.iter().max()) {
            let avg = rtts.iter().sum::<Duration>() / rtts.len() as u32;
            print!(", rtt min/avg/max {:.2}/{:.2}/{:.2} ms", ms(*min), ms(avg), ms(*max));
        }
        println!();
        Ok(!rtts.is_empty())
    }

    /// Walks the router's zone list, one ATP transaction per page.
    ///
    /// Every request in a series must go to the same router: routers order
    /// their lists differently, so mixing them would drop or repeat names.
    pub fn zone_list(&mut self) -> io::Result<Vec<String>> {
        let Some(router) = self.router() else { return Ok(Vec::new()) };
        let mut zones: Vec<String> = Vec::new();
        let mut start = 1u16;

        for _ in 0..MAX_ZONE_PAGES {
            let tid = self.next_id();
            let body = zone_list_request(tid, start).to_bytes();
            let mut reply = None;
            for _ in 0..ZONE_TRIES {
                // PDF 187's Figure 8-2 shows GetZoneList going out from socket
                // 6; we knowingly send from our dynamic socket (128) instead —
                // ATP replies go back to whatever socket asked, and `Session`
                // classifies on the responder's socket, so this works by
                // construction — and a jrouter seed router answered it happily
                // on 2026-08-16, so at least one real router does not care.
                self.send_ddp(router, 6, DDP_ATP, body.clone())?;
                reply = self.wait(Instant::now() + ZONE_INTERVAL, |n, p| {
                    if !zone_reply_matches(p, router, tid) {
                        return None;
                    }
                    n.messages.drain(..).find_map(|m| match m {
                        Message::Zip(z @ ZipAtp::Reply { .. }) => Some(z),
                        _ => None,
                    })
                });
                if reply.is_some() {
                    break;
                }
            }
            let Some(reply) = reply else {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "router stopped answering"));
            };
            if let ZipAtp::Reply { zones: names, .. } = &reply {
                // A router may repeat a name while zones are being renamed.
                for n in names {
                    if !zones.contains(n) {
                        zones.push(n.clone());
                    }
                }
            }
            match next_start(start, &reply) {
                Some(next) => start = next,
                None => break,
            }
        }
        Ok(zones)
    }

    /// The clock mixed with the NIC's MAC. See `pick_address` for why this is
    /// enough.
    fn seed(&self, attempt: u32) -> u64 {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        let m = self.tx.mac;
        let mac = u64::from(m.3) << 16 | u64::from(m.4) << 8 | u64::from(m.5);
        u64::from(nanos) ^ (mac << 8) ^ u64::from(attempt) << 32
    }

    pub fn zone(&self) -> &str {
        self.zone.as_deref().unwrap_or("*")
    }

    pub fn router(&self) -> Option<Addr> {
        self.router
    }

    /// Transaction and lookup identifiers, so a late reply to a previous
    /// request cannot be mistaken for an answer to this one.
    pub fn next_id(&mut self) -> u16 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    fn mac_for(&self, addr: Addr) -> MacAddr {
        // Unknown means broadcast: everyone on the cable hears it, and the one
        // it is for answers. Costs an interrupt on other AppleTalk nodes only.
        self.amt.get(&addr).copied().unwrap_or(BROADCAST_MAC)
    }

    fn send_ddp(&mut self, dst: Addr, dst_socket: u8, typ: u8, data: Vec<u8>) -> io::Result<()> {
        self.send_from(OUR_SOCKET, dst, dst_socket, typ, data)
    }

    fn send_from(
        &mut self,
        src_socket: u8,
        dst: Addr,
        dst_socket: u8,
        typ: u8,
        data: Vec<u8>,
    ) -> io::Result<()> {
        let d = datagram(self.addr, src_socket, dst, dst_socket, typ, data);
        // A broadcast node number always goes to the multicast address.
        let mac = if dst.node == 255 { BROADCAST_MAC } else { self.mac_for(dst) };
        let f = frame(self.tx.mac, mac, DDP, d.to_bytes());
        self.tx.send(&f)
    }

    /// Drains capture events until `f` yields a value or `deadline` passes.
    /// Answers AARP for our address, gleans mappings, and feeds `Session`
    /// along the way — this is the only loop in the program.
    fn wait<T>(
        &mut self,
        deadline: Instant,
        mut f: impl FnMut(&mut Node, &Packet) -> Option<T>,
    ) -> Option<T> {
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            match self.rx.recv_timeout(left) {
                Ok(Event::Packet { at, packet }) => {
                    glean(&mut self.amt, &packet);
                    self.messages.extend(self.session.push(at, &packet));
                    // Only `zone_list` drains this; every other caller must
                    // not let it grow unbounded on a busy wire.
                    if self.messages.len() > MAX_MESSAGES {
                        let drop = self.messages.len() - MAX_MESSAGES;
                        self.messages.drain(..drop);
                    }
                    if let AarpAction::AnswerTo(mac) =
                        aarp_action(&packet, self.addr, self.tx.mac, self.probing)
                        && let Body::Aarp(a) = &packet.body
                    {
                        let r = aarp_response(self.addr, self.tx.mac, a.src, mac);
                        let out = frame(self.tx.mac, mac, AARP, r.to_bytes());
                        let _ = self.tx.send(&out);
                    }
                    if let Some(v) = f(self, &packet) {
                        return Some(v);
                    }
                }
                Ok(Event::Dropped(_)) => self.session.flush(),
                Ok(Event::Error(e)) => eprintln!("rx: {e}"),
                Err(RecvTimeoutError::Timeout) => return None,
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }
}

/// What `ping` was aimed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Addr(Addr),
    /// Resolved through NBP before pinging. A missing zone means the local one.
    Name { object: String, typ: String, zone: Option<String> },
}

impl std::str::FromStr for Target {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // A name is anything wearing NBP punctuation; everything else must be
        // an address, and fails closed if it is not.
        if !s.contains(':') && !s.contains('@') {
            return parse_addr(s).map(Target::Addr);
        }
        let (name, zone) = match s.split_once('@') {
            Some((n, z)) => (n, Some(z.to_string())),
            None => (s, None),
        };
        let (object, typ) = name.split_once(':').unwrap_or((name, "="));
        Ok(Target::Name { object: object.to_string(), typ: typ.to_string(), zone })
    }
}

/// AEP carries no sequence number: the replier echoes the data back unchanged,
/// so the pinger plants its own marker and matches on that.
pub fn echo_data(magic: u32, seq: u32) -> Vec<u8> {
    let mut v = magic.to_be_bytes().to_vec();
    v.extend(seq.to_be_bytes());
    v
}

/// The responder's address and our sequence number, for a reply that is ours.
pub fn echo_match(p: &Packet, magic: u32) -> Option<(Addr, u32)> {
    let Body::Ddp(d, DdpBody::Aep(a)) = &p.body else { return None };
    if a.func != Echo::Reply {
        return None;
    }
    let m = u32::from_be_bytes(a.data.get(..4)?.try_into().ok()?);
    let seq = u32::from_be_bytes(a.data.get(4..8)?.try_into().ok()?);
    (m == magic).then_some((d.src, seq))
}

/// ZIP's GetZoneList rides ATP with the function in the user bytes: code 8,
/// then the 1-based index of the first zone name wanted (PDF 187). At-least-
/// once, and a bitmap of one because the reply is always a single packet.
pub fn zone_list_request(tid: u16, start: u16) -> Atp {
    let [hi, lo] = start.to_be_bytes();
    Atp::request(tid, 0x01, None, [8, 0, hi, lo], Vec::new())
}

/// Where the next request in the series starts, or None when the list is
/// complete. The next index is this one plus however many names came back.
pub fn next_start(start: u16, reply: &ZipAtp) -> Option<u16> {
    match reply {
        // An empty page that also claims more to come is malformed — a router
        // past the end of the list sets the flag (PDF 187). Stop rather than
        // re-requesting the same index forever.
        ZipAtp::Reply { last: false, zones } if !zones.is_empty() => {
            start.checked_add(zones.len() as u16)
        }
        _ => None,
    }
}

/// Whether this packet is the ATP response completing our zone-list request.
/// Capture is promiscuous and GetZoneList is at-least-once with no release, so
/// another node's reply — or a stale retransmission of our own previous page —
/// is on the wire too and must not be mistaken for this page's answer.
pub fn zone_reply_matches(p: &Packet, router: Addr, tid: u16) -> bool {
    matches!(&p.body, Body::Ddp(d, DdpBody::Atp(a))
        if d.src == router && a.func == Func::Resp && a.tid == tid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use pnet::util::MacAddr;

    use crate::wire::{
        Aarp, Aep, Body, DdpBody, Echo, Encode, Func, Nbp, NbpFunc, NbpTuple, Packet, Zip, ZipAtp,
        AARP, DDP, DDP_AEP, DDP_NBP, DDP_ZIP,
    };

    fn aarp_packet(op: u16, src: Addr, src_hw: MacAddr, dst: Addr) -> Packet {
        let body = Body::Aarp(Aarp {
            op,
            src_hw,
            src,
            // A request leaves the target hardware address unknown.
            dst_hw: MacAddr::zero(),
            dst,
        });
        Packet { frame: frame(src_hw, BROADCAST_MAC, AARP, Vec::new()), body }
    }

    const OURS: Addr = Addr { net: 0xff00, node: 137 };
    const OUR_MAC: MacAddr = MacAddr(0x00, 0x05, 0x02, 0xaa, 0xbb, 0xcc);
    const THEIR_MAC: MacAddr = MacAddr(0x08, 0x00, 0x07, 0x11, 0x22, 0x33);

    #[test]
    fn picked_addresses_stay_inside_the_startup_range() {
        // Node IDs 0, $FE and $FF are reserved on Ethernet; nets come from the
        // startup range. Sweep enough seeds to catch an off-by-one at either end.
        for seed in 0..2000u64 {
            let a = pick_address(seed.wrapping_mul(2_654_435_761));
            assert!((0xff00..=0xfffe).contains(&a.net), "net {:#06x}", a.net);
            assert!((1..=253).contains(&a.node), "node {}", a.node);
        }
    }

    #[test]
    fn a_probe_carries_a_zero_target_hardware_address() {
        let p = probe(OURS, OUR_MAC);
        assert_eq!(p.op, 3);
        assert_eq!(p.src, OURS);
        assert_eq!(p.dst, OURS);
        assert_eq!(p.dst_hw, MacAddr::zero());
        let b = p.to_bytes();
        assert_eq!(&b[..6], &[0x00, 0x01, 0x80, 0x9b, 6, 4]);
        assert_eq!(&b[6..8], &[0x00, 0x03]);
    }

    #[test]
    fn a_response_for_our_tentative_address_is_a_conflict() {
        let p = aarp_packet(2, OURS, THEIR_MAC, OURS);
        assert!(matches!(aarp_action(&p, OURS, OUR_MAC, true), AarpAction::Conflict));
    }

    #[test]
    fn another_nodes_probe_for_the_same_address_is_a_conflict() {
        // Two nodes probing at once: the book has the receiver give up too.
        let p = aarp_packet(3, OURS, THEIR_MAC, OURS);
        assert!(matches!(aarp_action(&p, OURS, OUR_MAC, true), AarpAction::Conflict));
    }

    #[test]
    fn a_probe_for_our_claimed_address_is_answered_not_conceded() {
        // Once claimed, a Probe for our address must be defended (PDF 85) —
        // conceding it here would let the newcomer take our address.
        let p = aarp_packet(3, OURS, THEIR_MAC, OURS);
        match aarp_action(&p, OURS, OUR_MAC, false) {
            AarpAction::AnswerTo(m) => assert_eq!(m, THEIR_MAC),
            other => panic!("expected AnswerTo, got {other:?}"),
        }
    }

    #[test]
    fn our_own_probe_coming_back_is_not_a_conflict() {
        let p = aarp_packet(3, OURS, OUR_MAC, OURS);
        assert!(matches!(aarp_action(&p, OURS, OUR_MAC, true), AarpAction::Ignore));
    }

    #[test]
    fn we_answer_requests_for_our_address_only_once_claimed() {
        let asking = aarp_packet(1, Addr { net: 3, node: 1 }, THEIR_MAC, OURS);
        // While probing, a node responds to nothing.
        assert!(matches!(aarp_action(&asking, OURS, OUR_MAC, true), AarpAction::Ignore));
        match aarp_action(&asking, OURS, OUR_MAC, false) {
            AarpAction::AnswerTo(m) => assert_eq!(m, THEIR_MAC),
            other => panic!("expected AnswerTo, got {other:?}"),
        }
        // Someone else's address is not our business.
        let other = aarp_packet(1, Addr { net: 3, node: 1 }, THEIR_MAC, Addr { net: 3, node: 9 });
        assert!(matches!(aarp_action(&other, OURS, OUR_MAC, false), AarpAction::Ignore));
    }

    #[test]
    fn a_response_names_us_as_the_source_and_the_asker_as_the_target() {
        let them = Addr { net: 3, node: 1 };
        let r = aarp_response(OURS, OUR_MAC, them, THEIR_MAC);
        assert_eq!((r.op, r.src, r.src_hw), (2, OURS, OUR_MAC));
        assert_eq!((r.dst, r.dst_hw), (them, THEIR_MAC));
    }

    #[test]
    fn gleaning_takes_mappings_from_data_and_responses_but_never_probes() {
        let mut amt = HashMap::new();
        let them = Addr { net: 3, node: 1 };

        // A probe's source address is tentative and must not be cached (PDF 98).
        glean(&mut amt, &aarp_packet(3, them, THEIR_MAC, them));
        assert!(amt.is_empty());

        glean(&mut amt, &aarp_packet(2, them, THEIR_MAC, OURS));
        assert_eq!(amt.get(&them), Some(&THEIR_MAC));

        // A DDP datagram carries both addresses too.
        let mut amt = HashMap::new();
        let d = datagram(them, 6, OURS, 128, DDP_ZIP, vec![1]);
        let p = Packet {
            frame: frame(THEIR_MAC, OUR_MAC, DDP, Vec::new()),
            body: Body::Ddp(d, DdpBody::Unknown),
        };
        glean(&mut amt, &p);
        assert_eq!(amt.get(&them), Some(&THEIR_MAC));
    }

    #[test]
    fn datagram_recomputes_its_length_and_orders_the_addresses() {
        // A ZIP GetNetInfo request: 7 bytes of data from 65280.128:6 to 0.255:6.
        let d = datagram(
            Addr { net: 0xff00, node: 128 },
            6,
            Addr { net: 0, node: 255 },
            6,
            DDP_ZIP,
            vec![5, 0, 0, 0, 0, 0, 0],
        );
        let b = d.to_bytes();
        assert_eq!(b[0], 0); // hops 0, and the top 2 bits of a length below 256
        assert_eq!(b[1], 20); // 13 header + 7 data, recomputed
        // Both network numbers come before either node number.
        assert_eq!(&b[4..8], &[0x00, 0x00, 0xff, 0x00]);
        assert_eq!((b[8], b[9]), (255, 128));
        assert_eq!((b[10], b[11], b[12]), (6, 6, DDP_ZIP));
    }

    /// A ZIP GetNetInfo reply from router 3.1, for cable range 3–5, zone
    /// "Engineering", optionally correcting an invalid requested zone.
    fn netinfo(range: (u16, u16), zone: &str, default_zone: Option<&str>) -> Packet {
        netinfo_to(OURS, range, zone, default_zone)
    }

    /// The same reply, addressed wherever the router chose to send it. Real
    /// routers broadcast it rather than directing it at the requester.
    fn netinfo_to(dst: Addr, range: (u16, u16), zone: &str, default_zone: Option<&str>) -> Packet {
        let z = Zip::NetInfoReply {
            flags: 0,
            range,
            zone: zone.to_string(),
            multicast: Some(MacAddr(0x09, 0x00, 0x07, 0x00, 0x00, 0x0f)),
            default_zone: default_zone.map(str::to_string),
        };
        let d = datagram(Addr { net: 3, node: 1 }, 6, dst, 6, DDP_ZIP, z.to_bytes());
        Packet {
            frame: frame(THEIR_MAC, OUR_MAC, DDP, Vec::new()),
            body: Body::Ddp(d, DdpBody::Zip(z)),
        }
    }

    #[test]
    fn a_provisional_net_inside_the_cable_range_is_kept() {
        let p = netinfo((0xff00, 0xff0a), "Engineering", None);
        let (verdict, zone, router) = netinfo_verdict(&p, OURS, "Engineering").unwrap();
        assert_eq!(verdict, NetInfo::Keep);
        assert_eq!(zone, "Engineering");
        assert_eq!(router, Addr { net: 3, node: 1 });
    }

    #[test]
    fn a_provisional_net_at_the_top_of_the_cable_range_is_kept() {
        // range.0..range.1 alone would exclude this end; pin it explicitly.
        // OURS.net is 0xff00, placed at range.1 here rather than range.0.
        let p = netinfo((0xfef0, 0xff00), "Engineering", None);
        let (verdict, _, _) = netinfo_verdict(&p, OURS, "Engineering").unwrap();
        assert_eq!(verdict, NetInfo::Keep);
    }

    #[test]
    fn a_provisional_net_outside_the_cable_range_forces_a_repick() {
        let p = netinfo((3, 5), "Engineering", None);
        let (verdict, _, _) = netinfo_verdict(&p, OURS, "Engineering").unwrap();
        assert_eq!(verdict, NetInfo::Repick { range: (3, 5) });
    }

    #[test]
    fn an_inverted_cable_range_is_rejected_rather_than_underflowing() {
        let p = netinfo((0xff0a, 0xff00), "Engineering", None);
        assert!(netinfo_verdict(&p, OURS, "Engineering").is_none());
    }

    #[test]
    fn a_reply_addressed_to_a_different_node_is_not_our_verdict() {
        // Capture is promiscuous and replies are sometimes broadcast; a reply
        // meant for another booting node must not be adopted as ours.
        let p = netinfo((0xff00, 0xff0a), "Engineering", None);
        let other = Addr { net: 3, node: 9 };
        assert!(netinfo_verdict(&p, other, "Engineering").is_none());
    }

    #[test]
    fn a_broadcast_reply_echoing_our_requested_zone_is_ours() {
        // What a real router actually sends: the reply goes to the broadcast
        // address, not to the requester, and echoes the empty zone name we
        // asked for while supplying the cable's default zone.
        let ours = Addr { net: 6800, node: 99 };
        let bcast = Addr { net: 0, node: 255 };
        let p = netinfo_to(bcast, (6800, 6800), REQUESTED_ZONE, Some("68k Mac Club"));
        let (verdict, zone, router) = netinfo_verdict(&p, ours, REQUESTED_ZONE).unwrap();
        assert_eq!(verdict, NetInfo::Keep);
        assert_eq!(zone, "68k Mac Club");
        assert_eq!(router, Addr { net: 3, node: 1 });
    }

    #[test]
    fn a_broadcast_reply_for_a_different_zone_is_not_ours() {
        // Broadcast means the address cannot tell replies apart, so the echoed
        // zone name is the only thing distinguishing another node's from ours.
        let bcast = Addr { net: 0, node: 255 };
        let p = netinfo_to(bcast, (0xff00, 0xff0a), "Accounts", None);
        assert!(netinfo_verdict(&p, OURS, "Engineering").is_none());
    }

    #[test]
    fn an_invalid_requested_zone_is_replaced_by_the_default_zone() {
        // The reply echoes back the zone we asked for — "Nonesuch" — and
        // appends the cable's real default, which is the one we adopt.
        let p = netinfo((3, 5), "Nonesuch", Some("Engineering"));
        let (_, zone, _) = netinfo_verdict(&p, OURS, "Nonesuch").unwrap();
        assert_eq!(zone, "Engineering");
    }

    #[test]
    fn other_zip_traffic_is_not_a_netinfo_verdict() {
        let z = Zip::Query { nets: vec![3] };
        let d = datagram(Addr { net: 3, node: 1 }, 6, OURS, 6, DDP_ZIP, z.to_bytes());
        let p = Packet {
            frame: frame(THEIR_MAC, OUR_MAC, DDP, Vec::new()),
            body: Body::Ddp(d, DdpBody::Zip(z)),
        };
        assert!(netinfo_verdict(&p, OURS, "Engineering").is_none());
    }

    fn lkup_reply(id: u8, tuples: Vec<NbpTuple>) -> Packet {
        let n = Nbp { func: NbpFunc::LkUpReply, id, tuples };
        let d = datagram(Addr { net: 3, node: 42 }, 2, OURS, OUR_SOCKET, DDP_NBP, n.to_bytes());
        Packet {
            frame: frame(THEIR_MAC, OUR_MAC, DDP, Vec::new()),
            body: Body::Ddp(d, DdpBody::Nbp(n)),
        }
    }

    fn tuple(object: &str, node: u8) -> NbpTuple {
        NbpTuple {
            addr: Addr { net: 3, node },
            socket: 253,
            enumerator: 0,
            object: object.to_string(),
            typ: "AFPServer".to_string(),
            zone: "Engineering".to_string(),
        }
    }

    #[test]
    fn a_broadcast_request_carries_the_wildcard_and_our_return_address() {
        let n = lookup_request(NbpFunc::BrRq, 7, OURS, OUR_SOCKET, "=", "=", "Engineering");
        assert_eq!(n.tuples.len(), 1);
        // The tuple's address field is where the responders send their answers.
        assert_eq!(n.tuples[0].addr, OURS);
        assert_eq!(n.tuples[0].socket, OUR_SOCKET);
        assert_eq!((&*n.tuples[0].object, &*n.tuples[0].typ), ("=", "="));

        let b = n.to_bytes();
        assert_eq!(b[0], 0x11); // function 1 (BrRq) in the high nibble, 1 tuple
        assert_eq!(b[1], 7); // the NBP id
    }

    #[test]
    fn replies_are_matched_by_nbp_id() {
        let p = lkup_reply(7, vec![tuple("Mac", 42)]);
        assert_eq!(lookup_replies(&p, 7).len(), 1);
        // A reply to somebody else's lookup, or to one we have moved past.
        assert!(lookup_replies(&p, 8).is_empty());
        // Not NBP at all.
        assert!(lookup_replies(&netinfo((3, 5), "Engineering", None), 7).is_empty());
    }

    #[test]
    fn merging_drops_tuples_we_already_have() {
        // Requests are retransmitted, so the same entity answers repeatedly.
        let mut all = Vec::new();
        merge(&mut all, &[tuple("Mac", 42), tuple("Printer", 43)]);
        merge(&mut all, &[tuple("Mac", 42)]);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn merging_ignores_zone_when_comparing_tuples() {
        // The spec's dedupe key is (addr, socket, enumerator, object, type) —
        // not zone. A responder spelling its zone differently across replies
        // is still the same entity.
        let mut a = tuple("Mac", 42);
        let mut b = tuple("Mac", 42);
        a.zone = "Engineering".to_string();
        b.zone = "engineering".to_string();
        let mut all = Vec::new();
        merge(&mut all, &[a]);
        merge(&mut all, &[b]);
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn addresses_parse_as_net_dot_node() {
        assert_eq!(parse_addr("65280.137").unwrap(), OURS);
        assert!(parse_addr("3.42").is_ok());
        // Fail closed on anything that is not exactly two numbers in range.
        for bad in ["", "3", "3.42.1", "3.", "eth0", "65536.1", "3.256", "3.0", "-1.2"] {
            assert!(parse_addr(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn targets_parse_as_an_address_or_a_name() {
        assert_eq!("65280.137".parse::<Target>().unwrap(), Target::Addr(OURS));
        assert_eq!(
            "Server:AFPServer@Engineering".parse::<Target>().unwrap(),
            Target::Name {
                object: "Server".to_string(),
                typ: "AFPServer".to_string(),
                zone: Some("Engineering".to_string()),
            }
        );
        // No zone means "wherever I am".
        assert_eq!(
            "Server:AFPServer".parse::<Target>().unwrap(),
            Target::Name {
                object: "Server".to_string(),
                typ: "AFPServer".to_string(),
                zone: None,
            }
        );
        // Anything with neither a colon nor an at-sign must be an address.
        assert!("eth0".parse::<Target>().is_err());
        assert!("".parse::<Target>().is_err());
    }

    #[test]
    fn echoes_are_matched_by_our_own_marker() {
        // AEP has no sequence number, so the pinger plants one in the data.
        let data = echo_data(0xdead_beef, 3);
        let a = Aep { func: Echo::Reply, data: data.clone() };
        let d = datagram(Addr { net: 3, node: 42 }, 4, OURS, OUR_SOCKET, DDP_AEP, a.to_bytes());
        let p = Packet {
            frame: frame(THEIR_MAC, OUR_MAC, DDP, Vec::new()),
            body: Body::Ddp(d, DdpBody::Aep(a)),
        };
        assert_eq!(echo_match(&p, 0xdead_beef), Some((Addr { net: 3, node: 42 }, 3)));
        // Someone else's ping.
        assert_eq!(echo_match(&p, 0x1234_5678), None);

        // Our own outgoing request, seen because the NIC is promiscuous.
        let req = Aep { func: Echo::Request, data };
        let d = datagram(OURS, OUR_SOCKET, Addr { net: 3, node: 42 }, 4, DDP_AEP, req.to_bytes());
        let p = Packet {
            frame: frame(OUR_MAC, THEIR_MAC, DDP, Vec::new()),
            body: Body::Ddp(d, DdpBody::Aep(req)),
        };
        assert_eq!(echo_match(&p, 0xdead_beef), None);
    }

    #[test]
    fn a_zone_list_request_asks_for_one_response_packet() {
        let a = zone_list_request(4660, 1);
        assert_eq!(a.func, Func::Req);
        // "These requests always ask for a single response packet" (PDF 187).
        assert_eq!(a.bitmap, 0x01);
        assert!(!a.xo()); // at-least-once
        assert_eq!(a.user_bytes, [8, 0, 0, 1]); // GetZoneList, start index 1
        assert!(a.data.is_empty());
        assert_eq!(a.tid, 4660);

        // The index is 1-based and carried big-endian.
        assert_eq!(zone_list_request(1, 300).user_bytes, [8, 0, 0x01, 0x2c]);
    }

    #[test]
    fn paging_continues_from_the_index_plus_the_names_returned() {
        let more = ZipAtp::Reply {
            last: false,
            zones: vec!["Engineering".into(), "Marketing".into(), "Sales".into()],
        };
        assert_eq!(next_start(1, &more), Some(4));

        let done = ZipAtp::Reply { last: true, zones: vec!["Accounts".into()] };
        assert_eq!(next_start(4, &done), None);

        // A router returns an empty, final response past the end of the list.
        let past_end = ZipAtp::Reply { last: true, zones: vec![] };
        assert_eq!(next_start(9, &past_end), None);

        // Anything that is not a reply ends the series rather than looping.
        assert_eq!(next_start(1, &ZipAtp::GetMyZone), None);
    }

    #[test]
    fn next_start_does_not_overflow_past_u16_max() {
        let reply = ZipAtp::Reply { last: false, zones: vec!["a".into()] };
        assert_eq!(next_start(u16::MAX, &reply), None);
    }

    #[test]
    fn an_empty_non_final_page_is_malformed_and_ends_the_series() {
        // A router past the end of the list sets `last` (PDF 187); `last:
        // false` with no zones is not a real page. Treating it as terminal,
        // not `Some(start)`, is what keeps this from looping forever.
        let malformed = ZipAtp::Reply { last: false, zones: vec![] };
        assert_eq!(next_start(9, &malformed), None);
    }

    #[test]
    fn zone_reply_matches_gates_on_router_func_and_tid() {
        let router = Addr { net: 3, node: 1 };
        let other = Addr { net: 3, node: 2 };

        let resp = |tid: u16| Packet {
            frame: frame(THEIR_MAC, OUR_MAC, DDP, Vec::new()),
            body: Body::Ddp(
                datagram(router, 6, OURS, OUR_SOCKET, DDP_ATP, Vec::new()),
                DdpBody::Atp(Atp::response(tid, 0, true, false, [8, 0, 0, 1], Vec::new())),
            ),
        };
        assert!(zone_reply_matches(&resp(4660), router, 4660));
        // A stale retransmission answering a different page.
        assert!(!zone_reply_matches(&resp(4660), router, 4661));

        // Someone else's reply, seen because capture is promiscuous.
        let mut wrong_source = resp(4660);
        if let Body::Ddp(d, _) = &mut wrong_source.body {
            d.src = other;
        }
        assert!(!zone_reply_matches(&wrong_source, router, 4660));

        // Not ATP at all.
        assert!(!zone_reply_matches(&netinfo((3, 5), "Engineering", None), router, 4660));
    }

    #[test]
    fn frames_go_out_as_phase_2_snap() {
        let f = frame(
            MacAddr::new(0x00, 0x05, 0x02, 0xaa, 0xbb, 0xcc),
            BROADCAST_MAC,
            DDP,
            vec![1, 2, 3],
        );
        assert!(f.snap);
        assert_eq!(f.dst, MacAddr::new(0x09, 0x00, 0x07, 0xff, 0xff, 0xff));
        let b = f.to_bytes();
        assert_eq!(&b[14..22], &[0xaa, 0xaa, 0x03, 0x08, 0x00, 0x07, 0x80, 0x9b]);
    }
}
