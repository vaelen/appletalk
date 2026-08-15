// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Reassembly of messages that span several datagrams. The only stateful
//! module; it is driven by the frontend's loop rather than owning a thread,
//! so a frontend can render raw packets and reassembled messages side by side.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::wire::{Addr, Body, DdpBody, Func, Packet};

/// Identifies one ATP transaction. The address pair plus sockets, because a
/// TID is only unique between a given pair of sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)] // Tasks 8-10 consume Transactions/TxnKey/Transaction
pub struct TxnKey {
    pub src: Addr,
    pub src_socket: u8,
    pub dst: Addr,
    pub dst_socket: u8,
    pub tid: u16,
}

/// A completed ATP response message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Tasks 8-10 consume Transactions/TxnKey/Transaction
pub struct Transaction {
    pub key: TxnKey,
    /// From the first response packet. ASP and PAP put their headers here.
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
#[allow(dead_code)] // Task 8's eviction reads first_seen; fields otherwise consumed via Transactions::push
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
    #[allow(dead_code)] // Tasks 8-10 exercise Transactions from outside this module
    fn new(first_seen: SystemTime) -> Self {
        Partial {
            segments: Default::default(),
            user_bytes: [0; 4],
            last: None,
            first_seen,
        }
    }

    /// Complete once EOM has arrived and every sequence up to it is present.
    #[allow(dead_code)] // Tasks 8-10 exercise Transactions from outside this module
    fn take_if_complete(&self) -> Option<Vec<u8>> {
        let last = self.last?;
        let mut out = Vec::new();
        for seq in 0..=last {
            out.extend(self.segments.get(seq as usize)?.as_ref()?);
        }
        Some(out)
    }
}

#[derive(Debug, Default)]
#[allow(dead_code)] // Tasks 8-10 consume Transactions/TxnKey/Transaction
pub struct Transactions {
    open: HashMap<TxnKey, Partial>,
}

impl Transactions {
    #[allow(dead_code)] // Tasks 8-10 construct Transactions from outside this module
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one packet in. Returns a Transaction on the packet that completes
    /// it. Non-ATP packets, requests, and releases are ignored.
    #[allow(dead_code)] // Tasks 8-10 call Transactions::push from the frontend loop
    pub fn push(&mut self, at: SystemTime, p: &Packet) -> Option<Transaction> {
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
        if partial.segments[seq as usize].is_none() {
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
}
