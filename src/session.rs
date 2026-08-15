// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Reassembly of messages that span several datagrams. The only stateful
//! module; it is driven by the frontend's loop rather than owning a thread,
//! so a frontend can render raw packets and reassembled messages side by side.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use crate::wire::{Addr, Body, DdpBody, Func, Packet, ZipAtp};

/// The Zone Information Socket. ZIP's ATP requests are always addressed here,
/// so a completed transaction from socket 6 is a ZIP reply.
const ZIS: u8 = 6;

/// Identifies one ATP transaction. The address pair plus sockets, because a
/// TID is only unique between a given pair of sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxnKey {
    pub src: Addr,
    pub src_socket: u8,
    pub dst: Addr,
    pub dst_socket: u8,
    pub tid: u16,
}

/// A completed ATP response message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub key: TxnKey,
    /// From response packet 0. ASP and PAP put their headers here.
    pub user_bytes: [u8; 4],
    /// Response payloads concatenated in sequence order.
    pub data: Vec<u8>,
    /// When the transaction completed.
    pub at: SystemTime,
}

/// Responses indexed by sequence number, so duplicates are idempotent and
/// out-of-order arrival needs no special case. Both are normal: a requester
/// that misses a response retransmits its TReq with a bitmap of only the
/// missing sequence numbers.
#[derive(Debug)]
struct Partial {
    segments: [Option<Vec<u8>>; 8],
    user_bytes: [u8; 4],
    /// Sequence number of the packet carrying EOM, once seen.
    last: Option<u8>,
    first_seen: SystemTime,
}

impl Partial {
    /// `SystemTime` has no `Default`, so this is a constructor rather than a
    /// derive.
    fn new(first_seen: SystemTime) -> Self {
        Partial {
            segments: Default::default(),
            user_bytes: [0; 4],
            last: None,
            first_seen,
        }
    }

    /// Complete once EOM has arrived and every sequence up to it is present.
    fn take_if_complete(&self) -> Option<Vec<u8>> {
        let last = self.last?;
        let mut out = Vec::new();
        for seq in 0..=last {
            out.extend(self.segments.get(seq as usize)?.as_ref()?);
        }
        Some(out)
    }
}

/// ATP's shortest release timer. A transaction quiet for longer than this is
/// never going to complete.
const TXN_TIMEOUT: Duration = Duration::from_secs(30);

/// ponytail: hard cap as a backstop for the timeout, in case a flood arrives
/// faster than the clock advances. Raise it if real captures overflow.
pub(crate) const MAX_OPEN: usize = 512;

#[derive(Debug, Default)]
pub struct Transactions {
    open: HashMap<TxnKey, Partial>,
}

impl Transactions {
    #[allow(dead_code)] // only tests construct Transactions directly; Session uses Default
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one packet in. Returns a Transaction on the packet that completes
    /// it. Non-ATP packets, requests, and releases are ignored.
    pub fn push(&mut self, at: SystemTime, p: &Packet) -> Option<Transaction> {
        self.expire(at);
        let Body::Ddp(ddp, DdpBody::Atp(atp)) = &p.body else { return None };
        if atp.func != Func::Resp {
            return None;
        }
        let seq = atp.bitmap;
        if seq > 7 {
            return None;
        }
        // A response travels from responder to requester, so the transaction's
        // source is this packet's source.
        let key = TxnKey {
            src: ddp.src,
            src_socket: ddp.src_socket,
            dst: ddp.dst,
            dst_socket: ddp.dst_socket,
            tid: atp.tid,
        };

        let partial = self.open.entry(key).or_insert_with(|| Partial::new(at));
        // Packet 0 is guaranteed present at completion (0..=eom), so anchoring
        // on it rather than "whichever fragment arrived first" is
        // deterministic under out-of-order delivery, which is normal traffic.
        if seq == 0 {
            partial.user_bytes = atp.user_bytes;
        }
        partial.segments[seq as usize] = Some(atp.data.clone());
        if atp.eom() {
            partial.last = Some(seq);
        }

        let data = partial.take_if_complete()?;
        let user_bytes = partial.user_bytes;
        self.open.remove(&key);
        Some(Transaction { key, user_bytes, data, at })
    }

    /// Number of transactions still awaiting completion. Used by `expire`'s
    /// cap check and by tests.
    fn open_count(&self) -> usize {
        self.open.len()
    }

    /// Discards everything in flight. Call on `Event::Dropped`: the capture
    /// thread reports how many frames were lost but not which, so any gap
    /// could have hit any transaction. Keeping them would silently produce a
    /// reassembled message with a hole in it.
    pub fn flush(&mut self) {
        self.open.clear();
    }

    /// Packet arrival is the clock, so this behaves identically when replaying
    /// a stored capture and needs no timer thread.
    ///
    /// Runs before `push`'s own insert, so the cap check trims to `MAX_OPEN -
    /// 1` rather than `MAX_OPEN`: it doesn't yet know whether this packet
    /// will add a new entry, and reserving that one slot is what keeps the
    /// post-insert count at exactly `MAX_OPEN` in steady state instead of
    /// settling one over it.
    fn expire(&mut self, now: SystemTime) {
        self.open.retain(|_, p| {
            now.duration_since(p.first_seen).unwrap_or_default() < TXN_TIMEOUT
        });
        if self.open_count() >= MAX_OPEN {
            let mut times: Vec<_> = self.open.iter().map(|(k, p)| (p.first_seen, *k)).collect();
            times.sort_by_key(|&(t, _)| t);
            for (_, key) in times.iter().take(self.open_count() - (MAX_OPEN - 1)) {
                self.open.remove(key);
            }
        }
    }
}

/// A message reassembled from several datagrams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A completed ATP transaction on a connection whose protocol we never saw
    /// negotiated. Classification into ASP and PAP arrives with those parsers.
    Unclassified(Transaction),
    /// A completed ZIP GetMyZone / GetZoneList / GetLocalZones reply.
    Zip(ZipAtp),
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Message::Unclassified(t) => write!(
                f,
                "transaction {} complete, {} bytes, user {}",
                t.key.tid,
                t.data.len(),
                t.user_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
            Message::Zip(z) => write!(f, "ZIP {z}"),
        }
    }
}

/// Owns every reassembler. The frontend drives it; it never spawns a thread.
#[derive(Debug, Default)]
pub struct Session {
    transactions: Transactions,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, at: SystemTime, p: &Packet) -> Vec<Message> {
        let Some(txn) = self.transactions.push(at, p) else { return Vec::new() };
        // A response travels responder -> requester, so the responder's socket
        // is the transaction's source socket.
        if txn.key.src_socket == ZIS
            && let Some(z) = ZipAtp::parse_reply(&txn.user_bytes, &txn.data)
        {
            return vec![Message::Zip(z)];
        }
        vec![Message::Unclassified(txn)]
    }

    /// Call on `Event::Dropped`.
    pub fn flush(&mut self) {
        self.transactions.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Addr, Atp, Ddp, DdpBody, Body, Packet, Frame, DDP, DDP_ATP};
    use pnet::util::MacAddr;
    use std::time::Duration;

    /// A DDP/ATP packet from 65280.128:6 to 3.42:253, wrapped as a Packet
    /// without going through the wire.
    fn packet(atp: Atp) -> Packet {
        let ddp = Ddp {
            hops: 0,
            length: 0,
            checksum: 0,
            dst: Addr { net: 3, node: 42 },
            dst_socket: 253,
            src: Addr { net: 65280, node: 128 },
            src_socket: 6,
            typ: DDP_ATP,
            data: Vec::new(),
        };
        Packet {
            frame: Frame {
                dst: MacAddr::new(0, 0, 0, 0, 0, 0),
                src: MacAddr::new(0, 0, 0, 0, 0, 0),
                proto: DDP,
                snap: true,
                payload: Vec::new(),
            },
            body: Body::Ddp(ddp, DdpBody::Atp(atp)),
        }
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn resp(seq: u8, eom: bool, data: &[u8]) -> Packet {
        packet(Atp::response(4660, seq, eom, false, [1, 2, 3, 4], data.to_vec()))
    }

    /// Like `resp`, but with caller-chosen user bytes, for tests that need to
    /// tell fragments apart by which one's user bytes won.
    fn resp_ub(seq: u8, eom: bool, user_bytes: [u8; 4], data: &[u8]) -> Packet {
        packet(Atp::response(4660, seq, eom, false, user_bytes, data.to_vec()))
    }

    #[test]
    fn completes_an_in_order_multi_packet_response() {
        let mut t = Transactions::new();
        assert!(t.push(at(0), &resp(0, false, b"aaa")).is_none());
        assert!(t.push(at(1), &resp(1, false, b"bbb")).is_none());
        let done = t.push(at(2), &resp(2, true, b"ccc")).unwrap();
        assert_eq!(done.data, b"aaabbbccc");
        assert_eq!(done.key.tid, 4660);
        assert_eq!(done.user_bytes, [1, 2, 3, 4]);
        assert_eq!(done.at, at(2));
    }

    #[test]
    fn completes_when_eom_arrives_before_an_earlier_packet() {
        let mut t = Transactions::new();
        assert!(t.push(at(0), &resp(2, true, b"ccc")).is_none());
        assert!(t.push(at(1), &resp(0, false, b"aaa")).is_none());
        let done = t.push(at(2), &resp(1, false, b"bbb")).unwrap();
        assert_eq!(done.data, b"aaabbbccc");
    }

    #[test]
    fn duplicate_responses_are_idempotent() {
        let mut t = Transactions::new();
        assert!(t.push(at(0), &resp(0, false, b"aaa")).is_none());
        assert!(t.push(at(1), &resp(0, false, b"aaa")).is_none());
        let done = t.push(at(2), &resp(1, true, b"bbb")).unwrap();
        assert_eq!(done.data, b"aaabbb");
    }

    #[test]
    fn a_single_packet_response_completes_immediately() {
        let mut t = Transactions::new();
        let done = t.push(at(0), &resp(0, true, b"only")).unwrap();
        assert_eq!(done.data, b"only");
    }

    #[test]
    fn requests_and_releases_do_not_complete_transactions() {
        let mut t = Transactions::new();
        let req = packet(Atp::request(4660, 0x07, None, [0; 4], Vec::new()));
        assert!(t.push(at(0), &req).is_none());
        assert!(t.push(at(1), &packet(Atp::release(4660))).is_none());
    }

    #[test]
    fn transactions_with_different_tids_do_not_mix() {
        let mut t = Transactions::new();
        let other = packet(Atp::response(9999, 0, true, false, [0; 4], b"x".to_vec()));
        assert!(t.push(at(0), &resp(0, false, b"aaa")).is_none());
        assert_eq!(t.push(at(1), &other).unwrap().data, b"x");
        assert_eq!(t.push(at(2), &resp(1, true, b"bbb")).unwrap().data, b"aaabbb");
    }

    #[test]
    fn user_bytes_come_from_packet_0_in_order() {
        let mut t = Transactions::new();
        assert!(t.push(at(0), &resp_ub(0, false, [0xaa, 0, 0, 0], b"aaa")).is_none());
        assert!(t.push(at(1), &resp_ub(1, false, [0xbb, 0, 0, 0], b"bbb")).is_none());
        let done = t.push(at(2), &resp_ub(2, true, [0xcc, 0, 0, 0], b"ccc")).unwrap();
        assert_eq!(done.user_bytes, [0xaa, 0, 0, 0]);
    }

    #[test]
    fn user_bytes_come_from_packet_0_out_of_order() {
        let mut t = Transactions::new();
        assert!(t.push(at(0), &resp_ub(2, true, [0xcc, 0, 0, 0], b"ccc")).is_none());
        assert!(t.push(at(1), &resp_ub(1, false, [0xbb, 0, 0, 0], b"bbb")).is_none());
        let done = t.push(at(2), &resp_ub(0, false, [0xaa, 0, 0, 0], b"aaa")).unwrap();
        assert_eq!(done.user_bytes, [0xaa, 0, 0, 0]);
    }

    #[test]
    fn sequence_numbers_past_7_are_rejected_without_opening_a_transaction() {
        let mut t = Transactions::new();
        assert!(t.push(at(0), &resp(8, true, b"x")).is_none());
        assert_eq!(t.open_count(), 0);
        assert!(t.push(at(1), &resp(255, true, b"x")).is_none());
        assert_eq!(t.open_count(), 0);
    }

    #[test]
    fn expires_transactions_that_never_complete() {
        let mut t = Transactions::new();
        assert!(t.push(at(0), &resp(0, false, b"aaa")).is_none());
        // 31s later a packet for an unrelated transaction drives the clock past
        // the 30s TRel timeout, evicting the stalled one.
        let other = packet(Atp::response(1, 0, true, false, [0; 4], b"x".to_vec()));
        assert_eq!(t.push(at(31), &other).unwrap().data, b"x");
        assert_eq!(t.open_count(), 0);

        // The stalled transaction is gone, so its EOM starts a fresh one that can
        // never complete rather than resurrecting the old data.
        assert!(t.push(at(32), &resp(1, true, b"bbb")).is_none());
    }

    #[test]
    fn flush_discards_everything_in_flight() {
        let mut t = Transactions::new();
        assert!(t.push(at(0), &resp(0, false, b"aaa")).is_none());
        assert_eq!(t.open_count(), 1);
        t.flush();
        assert_eq!(t.open_count(), 0);
        assert!(t.push(at(1), &resp(1, true, b"bbb")).is_none());
    }

    #[test]
    fn caps_the_number_of_open_transactions() {
        let mut t = Transactions::new();
        for tid in 0..(MAX_OPEN as u16 + 10) {
            let p = packet(Atp::response(tid, 0, false, false, [0; 4], b"x".to_vec()));
            t.push(at(0), &p);
        }
        assert!(t.open_count() <= MAX_OPEN);
    }

    #[test]
    fn session_emits_a_message_when_a_transaction_completes() {
        let mut s = Session::new();
        assert!(s.push(at(0), &resp(0, false, b"aaa")).is_empty());
        let msgs = s.push(at(1), &resp(1, true, b"bbb"));
        match msgs.as_slice() {
            [Message::Unclassified(t)] => assert_eq!(t.data, b"aaabbb"),
            other => panic!("expected one unclassified message, got {other:?}"),
        }
    }

    #[test]
    fn session_flush_clears_in_flight_state() {
        let mut s = Session::new();
        assert!(s.push(at(0), &resp(0, false, b"aaa")).is_empty());
        s.flush();
        assert!(s.push(at(1), &resp(1, true, b"bbb")).is_empty());
    }

    #[test]
    fn session_classifies_a_zip_reply_from_the_zone_information_socket() {
        use crate::wire::testkit::ps;
        let mut data = ps("Engineering");
        data.extend(ps("Marketing"));
        // resp() sends from 65280.128:6 — the ZIS.
        let p = packet(Atp::response(4660, 0, true, false, [1, 0, 0, 2], data));
        let mut s = Session::new();
        match s.push(at(0), &p).as_slice() {
            [Message::Zip(ZipAtp::Reply { last, zones })] => {
                assert!(last);
                assert_eq!(zones, &["Engineering".to_string(), "Marketing".to_string()]);
            }
            other => panic!("expected a ZIP reply, got {other:?}"),
        }
    }

    #[test]
    fn session_leaves_non_zip_sockets_unclassified() {
        let mut s = Session::new();
        // Same shape, but from a dynamically assigned socket rather than the ZIS.
        let mut p = packet(Atp::response(4660, 0, true, false, [1, 0, 0, 0], b"x".to_vec()));
        if let Body::Ddp(d, _) = &mut p.body {
            d.src_socket = 253;
        }
        match s.push(at(0), &p).as_slice() {
            [Message::Unclassified(_)] => {}
            other => panic!("expected unclassified, got {other:?}"),
        }
    }
}
