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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    if buf.len() < 7 || buf.len() > MAX || buf.get(..4) == Some(id.as_slice()) {
        return None;
    }
    Llap::parse(&buf[4..])
}

/// Mixes the clock into the process ID, the same pattern `node::pick_address`
/// uses for its seed — clock mixed with something host-identifying, since
/// this crate carries no RNG dependency. The PID alone collides readily
/// across hosts (low PIDs repeat everywhere); XORing in the low bits of the
/// clock makes that far less likely without adding anything.
///
/// ponytail: not a real RNG, and does not need to be — the sender ID exists
/// only so a station can discard its own echo (LToUDP.md), no peer
/// interprets it, and a collision merely costs one round of silently dropped
/// traffic between the two colliding stations. Reach for a real RNG only if
/// that is ever observed in practice.
fn sender_id() -> [u8; 4] {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
    (std::process::id() ^ nanos).to_be_bytes()
}

pub struct Ltoudp {
    sock: UdpSocket,
    /// The local address to join and send on. None lets the kernel choose,
    /// which is only right on a single-homed host.
    iface: Option<Ipv4Addr>,
    /// Prefixed to everything we send, and the only way we recognise our own
    /// datagrams on the group. See `sender_id`.
    id: [u8; 4],
}

impl Ltoudp {
    /// Binds the port and nothing more. Deliberately does *not* join the
    /// group yet — `spawn` does that, immediately before the reader thread
    /// starts, so nothing sent to the group during the address claim (which
    /// can take tens of seconds) sits in the receive buffer waiting to be
    /// replayed onto Ethernet in one stale burst. Binding stays here: a port
    /// already held by an emulator on this host must fail fast, before we go
    /// claiming an AppleTalk address.
    pub fn open(iface: Option<Ipv4Addr>) -> io::Result<Ltoudp> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        // Both must be set before bind, which is why this is not a plain
        // UdpSocket: an emulator or another router on this host is normally
        // already on the group, and that is the case worth supporting.
        s.set_reuse_address(true)?;
        s.set_reuse_port(true)?;
        s.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT).into())?;
        // One hop: this is a link, not an internet.
        s.set_multicast_ttl_v4(1)?;
        // Loopback is left at its default, which is on, so emulators sharing
        // this host hear us. Our own echo is filtered by sender ID instead.
        Ok(Ltoudp { sock: s.into(), iface, id: sender_id() })
    }

    pub fn send(&self, f: &Llap) -> io::Result<()> {
        self.sock.send_to(&datagram(self.id, f), SocketAddrV4::new(GROUP, PORT))?;
        Ok(())
    }

    /// Joins the group and starts the reader thread. Same contract as the
    /// capture thread: it drops rather than blocking when the consumer falls
    /// behind, and reports the count so a gap is never silent.
    pub fn spawn(&self, tx: SyncSender<Event>) -> io::Result<()> {
        let iface = self.iface.unwrap_or(Ipv4Addr::UNSPECIFIED);
        self.sock.join_multicast_v4(&GROUP, &iface)?;
        // `set_multicast_if_v4` has no std API (LToUDP.md: "set the outgoing
        // multicast interface to match"), so borrow the fd through socket2
        // for this one call.
        Socket::from(self.sock.try_clone()?).set_multicast_if_v4(&iface)?;
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
                Some(llap) => Event::Ltoudp { llap },
                None => continue,
            },
            // A recv_from error that keeps recurring (the interface going
            // away, say) would otherwise busy-spin this loop at 100% CPU and
            // flood stderr; back off first. `capture_loop` does the same, so
            // the two stay consistent.
            Err(e) => {
                thread::sleep(Duration::from_millis(100));
                Event::Error(e.to_string())
            }
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

    #[test]
    fn the_legal_maximum_datagram_is_accepted() {
        // 4-byte sender ID, 3-byte LLAP header, 600-byte data field: exactly
        // MAX (607) bytes, the largest a real frame can ever be. A Critical
        // bug already lived at this exact boundary once.
        let mut data = vec![0u8; 600];
        // The data field's own low-10-bit length, itself included.
        data[..2].copy_from_slice(&600u16.to_be_bytes());
        let llap = crate::wire::Llap { dst: 42, src: 1, typ: crate::wire::LLAP_SHORT_DDP, data };
        let mut buf = [1, 2, 3, 4].to_vec();
        llap.encode(&mut buf);
        assert_eq!(buf.len(), MAX);
        assert_eq!(inbound(&buf, [9, 9, 9, 9]), Some(llap));
    }
}
