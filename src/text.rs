// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Plain-text frontend: one indented block per packet, on stdout.

use std::sync::mpsc::Receiver;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capture::Event;
use crate::cli::Output;
use crate::session::{Message, Session};
use crate::wire::{Body, DdpBody, Packet};

/// Wall clock, UTC, no date — a dumper's reader cares about the seconds
/// between packets, not the day.
fn timestamp(at: SystemTime) -> String {
    let d = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}.{:03}", s / 3600 % 24, s / 60 % 60, s % 60, d.subsec_millis())
}

fn hexdump(b: &[u8]) {
    for (i, chunk) in b.chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|x| format!("{x:02x} ")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&x| if (0x20..0x7f).contains(&x) { x as char } else { '.' })
            .collect();
        println!("  {:04x}  {hex:<48}|{ascii}|", i * 16);
    }
}

fn print_packet(at: SystemTime, p: &Packet, o: &Output) {
    if !o.no_link {
        println!("{} {}", timestamp(at), p.frame);
    }
    match &p.body {
        // Fully decoded: a hexdump would just repeat it.
        Body::Aarp(a) => println!("  {a}"),
        Body::Ddp(d, inner) => {
            if !o.no_net {
                println!("  {d}");
            }
            match inner {
                DdpBody::Atp(a) => {
                    println!("    {a}");
                    if o.hex {
                        hexdump(&a.data);
                    }
                }
                DdpBody::Aep(a) => {
                    println!("    {a}");
                    if o.hex {
                        hexdump(&a.data);
                    }
                }
                DdpBody::Nbp(n) => println!("    {n}"),
                DdpBody::Zip(z) => println!("    {z}"),
                // No protocol line to print: without --hex this packet shows
                // only its outer lines, and with those hidden too, nothing.
                DdpBody::Unknown => {
                    if o.hex {
                        hexdump(&d.data)
                    }
                }
            }
        }
        Body::Unknown => {
            if o.hex {
                hexdump(&p.frame.payload)
            }
        }
    }
}

/// Reassembled messages are indented under the packets that produced them.
pub fn print_message(m: &Message) {
    println!("  >> {m}");
}

/// Renders events until the capture thread goes away.
pub fn run(events: Receiver<Event>, output: &Output) {
    let mut session = Session::new();
    for event in events {
        match event {
            Event::Packet { at, packet } => {
                // Hidden packets still reassemble — only the printing stops —
                // so a filter can never break a transaction. Their completed
                // messages are suppressed with them.
                let show = output.shows(&packet);
                if show {
                    print_packet(at, &packet, output);
                }
                for msg in session.push(at, &packet) {
                    if show {
                        print_message(&msg);
                    }
                }
            }
            // The text frontend never opens a LocalTalk link, so it never
            // sees one of these.
            Event::Ltoudp { .. } => {}
            Event::Dropped(n) => {
                // Any gap could have hit any transaction in flight.
                session.flush();
                eprintln!("dropped {n} frames (queue full)");
            }
            Event::Error(e) => eprintln!("rx: {e}"),
        }
    }
}
