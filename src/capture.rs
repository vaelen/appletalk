// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Capture thread. Reads frames off a NIC, decodes them, and publishes the
//! results as events. Knows nothing about how they are displayed.

use std::io;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::SystemTime;

use pnet::datalink::{self, Channel::Ethernet, Config, DataLinkReceiver};

use crate::wire;

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
    /// Frames discarded because the queue was full, counted since the last
    /// report. A frontend that ignores this shows a gap with no explanation.
    Dropped(u64),
    Error(String),
}

/// Opens `want` (or the first sensible interface) and starts capturing.
///
/// Returns the interface name and the event stream. Opening happens before the
/// thread starts, so the common failure — no CAP_NET_RAW — surfaces here
/// rather than killing a thread nobody is watching.
pub fn spawn(want: Option<&str>) -> io::Result<(String, Receiver<Event>)> {
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
    let rx = match datalink::channel(&iface, cfg) {
        Ok(Ethernet(_tx, rx)) => rx,
        Ok(_) => {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "not an Ethernet channel"));
        }
        Err(e) => {
            let msg = format!("{}: {e} (need CAP_NET_RAW or root)", iface.name);
            return Err(io::Error::new(e.kind(), msg));
        }
    };

    let (tx, events) = sync_channel(QUEUE);
    thread::spawn(move || capture_loop(rx, tx));
    Ok((iface.name, events))
}

fn capture_loop(mut rx: Box<dyn DataLinkReceiver>, tx: SyncSender<Event>) {
    let mut dropped = 0u64;
    loop {
        let event = match rx.next() {
            Ok(bytes) => match wire::decode(bytes) {
                Some(packet) => Event::Packet { at: SystemTime::now(), packet },
                None => continue, // not AppleTalk
            },
            Err(e) => Event::Error(e.to_string()),
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
