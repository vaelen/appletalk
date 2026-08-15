// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! The node runtime: claim an AppleTalk address, defend it, ask questions.
//!
//! Everything that decides something is a free function over a `&Packet`, so
//! it can be tested without a NIC. The `Node` methods are the socket-and-timer
//! glue around them.
//!
//! This task only adds the builders — only tests call them so far. Later
//! tasks wire them into `Node` methods that actually claim an address and
//! send. Drop the allow below once that happens.
#![allow(dead_code)]

use pnet::util::MacAddr;

use crate::wire::{Addr, Ddp, Frame};

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

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::util::MacAddr;

    use crate::wire::{Encode, DDP, DDP_ZIP};

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
