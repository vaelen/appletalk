// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Capture thread. Reads frames off a NIC, decodes them, and publishes the
//! results as events. Knows nothing about how they are displayed.

use std::io;
use std::net::Ipv4Addr;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::{Duration, SystemTime};

use pnet::datalink::{self, Channel::Ethernet, Config, DataLinkReceiver, DataLinkSender};
use pnet::util::MacAddr;

use crate::wire::{self, Encode};

/// Decoded packets that may queue before the capture thread starts dropping.
///
/// ponytail: fixed size. Make it a flag if a frontend proves slow enough to
/// matter.
const QUEUE: usize = 1024;

#[derive(Debug)]
pub enum Event {
    Packet {
        /// Stamped in userspace after the read, so it lags the wire by however
        /// long the frame sat in the kernel buffer.
        at: SystemTime,
        packet: wire::Packet,
    },
    /// An LLAP frame off a LocalTalk-shaped link. Posted by `ltoudp`, which
    /// holds a clone of the same sender the capture thread uses. No
    /// timestamp: nothing reads one — `text` never opens a LocalTalk link,
    /// and `bridge::run` works in `Instant`, not wall-clock time.
    Ltoudp { llap: wire::Llap },
    /// Frames discarded because the queue was full, counted since the last
    /// report. A frontend that ignores this shows a gap with no explanation.
    Dropped(u64),
    Error(String),
}

/// The transmit half of the NIC, wrapped so pnet stays inside this module.
/// Callers hand it a `wire::Frame`; it does the encoding. `node::Node` holds
/// one and uses `mac` to source every frame it builds.
pub struct Tx {
    inner: Box<dyn DataLinkSender>,
    /// The NIC's own MAC. Every frame we build is sourced from it.
    pub mac: MacAddr,
}

impl Tx {
    pub fn send(&mut self, f: &wire::Frame) -> io::Result<()> {
        let bytes = f.to_bytes();
        // pnet returns None when the frame does not fit its buffer.
        self.inner
            .send_to(&bytes, None)
            .unwrap_or_else(|| Err(io::Error::other("frame too large to send")))
    }
}

/// Everything opening a NIC yields. A struct rather than a tuple because a
/// bridge needs the interface's address to join a multicast group on the right
/// NIC, and a second producer for the queue.
pub struct Capture {
    /// The interface actually opened, which may not be the one asked for.
    pub iface: String,
    /// Its first IPv4 address, if it has one.
    pub ip: Option<Ipv4Addr>,
    pub tx: Tx,
    /// A second handle on the event queue, for another link's reader thread.
    pub sender: SyncSender<Event>,
    pub events: Receiver<Event>,
}

/// Opens `want` (or the first sensible interface) and starts capturing.
///
/// Returns the interface name and address, a transmit handle, a second
/// producer for the event queue, and the event stream itself. Opening
/// happens before the thread starts, so the common failure — no
/// CAP_NET_RAW — surfaces here rather than killing a thread nobody is
/// watching.
pub fn spawn(want: Option<&str>) -> io::Result<Capture> {
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| match want {
            Some(n) => i.name == n,
            None => i.is_up() && !i.is_loopback() && i.mac.is_some(),
        })
        .ok_or_else(|| {
            let which = want.unwrap_or("<any up, non-loopback interface>");
            io::Error::new(io::ErrorKind::NotFound, format!("no interface {which}"))
        })?;

    let cfg = Config { promiscuous: true, ..Default::default() };
    let (sender_half, rx) = match datalink::channel(&iface, cfg) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "not an Ethernet channel"));
        }
        Err(e) => {
            let msg = format!("{}: {e} (need CAP_NET_RAW or root)", iface.name);
            return Err(io::Error::new(e.kind(), msg));
        }
    };
    // A named interface is not guaranteed to have one; we cannot source frames
    // without it.
    let mac = iface.mac.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("{} has no MAC address", iface.name))
    })?;

    // A NIC may have no IPv4 address; a multicast join then falls back to
    // letting the kernel pick the interface.
    let ip = iface.ips.iter().find_map(|n| match n.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    });

    let (tx, events) = sync_channel(QUEUE);
    let sender = tx.clone();
    thread::spawn(move || capture_loop(rx, tx));
    Ok(Capture { iface: iface.name, ip, tx: Tx { inner: sender_half, mac }, sender, events })
}

fn capture_loop(mut rx: Box<dyn DataLinkReceiver>, tx: SyncSender<Event>) {
    let mut dropped = 0u64;
    loop {
        let event = match rx.next() {
            Ok(bytes) => match wire::decode(bytes) {
                Some(packet) => Event::Packet { at: SystemTime::now(), packet },
                None => continue, // not AppleTalk
            },
            // A read error that keeps recurring (the NIC going away, say)
            // would otherwise busy-spin this loop at 100% CPU and flood
            // stderr; back off first. `ltoudp::read_loop` does the same, so
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
            // The frontend hung up; nothing left to capture for.
            Err(TrySendError::Disconnected(_)) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Llap;

    /// The LToUDP reader posts into the same queue as the capture thread, so
    /// one loop can serve both links without a select.
    #[test]
    fn a_second_producer_shares_the_queue() {
        let (tx, rx) = sync_channel(QUEUE);
        let second = tx.clone();
        let llap = Llap::control(42, 42, 0x81);
        second.try_send(Event::Ltoudp { llap: llap.clone() }).unwrap();
        match rx.recv().unwrap() {
            Event::Ltoudp { llap: got } => assert_eq!(got, llap),
            other => panic!("wrong event: {other:?}"),
        }
    }
}
