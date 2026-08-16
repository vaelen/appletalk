// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! LocalTalk over UDP multicast (LToUDP) — the transport Mini vMac, Snow,
//! jrouter and tashrouter use to carry LocalTalk between hosts.
//!
//! Each datagram is a 4-byte sender ID and then an LLAP frame with its FCS
//! already stripped. The sender ID exists only so a sender can discard its own
//! datagrams coming back off the group. `LToUDP.md` describes the protocol.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::thread;
use std::time::SystemTime;

use socket2::{Domain, Protocol, Socket, Type};

use crate::capture::Event;
use crate::wire::{Encode, Llap};

/// The group's last two octets spell "LT".
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 192, 76, 84);
pub const PORT: u16 = 1954;

/// The largest *legal* datagram: 4 bytes of sender ID, a 3-byte LLAP header,
/// and the 600-byte maximum data field. The read buffer is one byte larger
/// than this (see `read_loop`) so that filling it is an unambiguous
/// truncation signal rather than this size.
const MAX: usize = 4 + 3 + 600;

/// Prefixes a frame with the sender ID, which is the whole of the framing.
fn datagram(id: [u8; 4], f: &Llap) -> Vec<u8> {
    let mut out = id.to_vec();
    f.encode(&mut out);
    out
}

/// Decides what an arriving datagram means. Returns None for anything too
/// short to be a frame, anything larger than a legal frame could ever be
/// (`recv_from` truncates silently with no signal, so a datagram filling the
/// oversized read buffer means it did not fit — never trust length alone to
/// mean "genuine maximum-size frame"), anything we sent ourselves, and
/// anything that does not parse — the same "not ours, skip it" contract the
/// capture thread has.
fn inbound(buf: &[u8], id: [u8; 4]) -> Option<Llap> {
    if buf.len() < 7 || buf.len() > MAX || buf[..4] == id {
        return None;
    }
    Llap::parse(&buf[4..])
}

// ponytail: nothing constructs an Ltoudp until Task 8 wires the bridge in.
#[allow(dead_code)]
pub struct Ltoudp {
    sock: UdpSocket,
    /// Prefixed to everything we send, and the only way we recognise our own
    /// datagrams on the group. The process ID, as the reference
    /// implementations use.
    id: [u8; 4],
}

#[allow(dead_code)]
impl Ltoudp {
    /// Joins the group. `iface` is the local address to join on; None lets the
    /// kernel choose, which is only right on a single-homed host.
    pub fn open(iface: Option<Ipv4Addr>) -> io::Result<Ltoudp> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        // Both must be set before bind, which is why this is not a plain
        // UdpSocket: an emulator or another router on this host is normally
        // already on the group, and that is the case worth supporting.
        s.set_reuse_address(true)?;
        s.set_reuse_port(true)?;
        s.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT).into())?;
        s.join_multicast_v4(&GROUP, &iface.unwrap_or(Ipv4Addr::UNSPECIFIED))?;
        // One hop: this is a link, not an internet.
        s.set_multicast_ttl_v4(1)?;
        // Loopback is left at its default, which is on, so emulators sharing
        // this host hear us. Our own echo is filtered by sender ID instead.
        Ok(Ltoudp { sock: s.into(), id: std::process::id().to_be_bytes() })
    }

    pub fn send(&self, f: &Llap) -> io::Result<()> {
        self.sock.send_to(&datagram(self.id, f), SocketAddrV4::new(GROUP, PORT))?;
        Ok(())
    }

    /// Starts the reader thread. Same contract as the capture thread: it
    /// drops rather than blocking when the consumer falls behind, and reports
    /// the count so a gap is never silent.
    pub fn spawn(&self, tx: SyncSender<Event>) -> io::Result<()> {
        let sock = self.sock.try_clone()?;
        let id = self.id;
        thread::spawn(move || read_loop(sock, id, tx));
        Ok(())
    }
}

fn read_loop(sock: UdpSocket, id: [u8; 4], tx: SyncSender<Event>) {
    // One byte larger than the largest legal datagram (MAX), so that a
    // datagram filling the buffer to capacity is unambiguous truncation
    // rather than being confused with a coincidentally maximum-size frame.
    let mut buf = [0u8; MAX + 1];
    let mut dropped = 0u64;
    loop {
        let event = match sock.recv_from(&mut buf) {
            Ok((n, _)) => match inbound(&buf[..n], id) {
                Some(llap) => Event::Ltoudp { at: SystemTime::now(), llap },
                None => continue,
            },
            // ponytail: no backoff, so a recv_from error that keeps recurring
            // busy-spins this loop; same shape as capture_loop today, add a
            // shared backoff to both if a real error ever does this.
            Err(e) => Event::Error(e.to_string()),
        };

        // Report accumulated drops as soon as there is room to say so.
        if dropped > 0 && tx.try_send(Event::Dropped(dropped)).is_ok() {
            dropped = 0;
        }
        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => dropped += 1,
            Err(TrySendError::Disconnected(_)) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_group_is_the_one_everyone_else_uses() {
        // 76 and 84 are ASCII 'L' and 'T'.
        assert_eq!(GROUP.octets(), [239, 192, 76, 84]);
        assert_eq!(PORT, 1954);
    }

    #[test]
    fn a_datagram_is_the_sender_id_then_the_llap_frame() {
        let id = [0x00, 0x00, 0x30, 0x39];
        let f = Llap::control(42, 42, crate::wire::LLAP_ENQ);
        assert_eq!(datagram(id, &f), vec![0x00, 0x00, 0x30, 0x39, 42, 42, 0x81]);
    }

    #[test]
    fn our_own_datagrams_are_recognised_and_everything_short_is_dropped() {
        let id = [1, 2, 3, 4];
        // Four bytes of sender ID and a 3-byte LLAP header is the shortest
        // thing that can mean anything.
        assert_eq!(inbound(&[1, 2, 3, 4, 42, 42], id), None);
        assert_eq!(inbound(&[], id), None);
        // Ours, echoed back off the group.
        assert_eq!(inbound(&[1, 2, 3, 4, 42, 42, 0x81], id), None);
        // Someone else's.
        assert_eq!(
            inbound(&[9, 9, 9, 9, 42, 42, 0x81], id),
            Some(Llap::control(42, 42, 0x81))
        );
    }

    #[test]
    fn a_frame_that_does_not_parse_is_skipped() {
        // $83 is a reserved control type and must be discarded.
        assert_eq!(inbound(&[9, 9, 9, 9, 1, 2, 0x83], [1, 2, 3, 4]), None);
    }

    #[test]
    fn a_truncated_oversized_datagram_is_rejected() {
        // recv_from truncates silently at the buffer size with no signal;
        // MAX + 1 bytes is what a bigger-than-legal datagram looks like once
        // truncated to the read buffer, and must not be mistaken for a
        // genuine maximum-size frame.
        let buf = vec![9u8; MAX + 1];
        assert_eq!(inbound(&buf, [1, 2, 3, 4]), None);
    }
}
