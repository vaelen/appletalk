// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! TashTalk: a LocalTalk link over a serial port, as the TashTalk firmware
//! frames it.
//!
//! The firmware is a PIC that does LocalTalk's bit-level work — flags, bit
//! stuffing, the CSMA/CA dialog — and speaks a byte protocol over a 1 Mbaud
//! UART with hardware flow control. Host to firmware it is command bytes:
//! `$01` a frame to transmit, `$02` the 32-byte bitmap of node IDs to answer
//! ENQ and RTS for, `$03` the feature bits. Firmware to host it is a raw byte
//! stream in which `$00` starts a two-byte escape: `$00 $FF` is a literal
//! zero, `$00 $FD` ends a good frame, and `$00 $FE`, `$00 $FA` and `$00 $FC`
//! each mean discard what came before.
//!
//! Unlike LToUDP, this link is real LocalTalk, so frames carry the 2-byte FCS
//! — CRC-CCITT, computed over the header and data field only (PDF 70), and
//! detailed in Appendix B (PDF 545). `wire::Llap` has no room for one, so it
//! is appended on the way out and verified and stripped on the way in.
//!
//! Reference: `repos/tashtalk/documentation/protocol.md`.

use std::io::{self, Read, Write};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serialport::{FlowControl, SerialPort};

use crate::capture::{Event, PortId};
use crate::wire::{Encode, Llap};

/// The firmware's only baud rate.
pub const BAUD: u32 = 1_000_000;

/// `maxFrameSize` from the book (PDF 526): a 3-byte header, a 600-byte data
/// field and the 2-byte FCS.
const MAX_FRAME: usize = 605;

/// CRC-CCITT with the polynomial reflected, which is how it is computed
/// byte-at-a-time: $8408 is $1021 bit-reversed.
fn crc_update(mut crc: u16, byte: u8) -> u16 {
    crc ^= byte as u16;
    for _ in 0..8 {
        crc = if crc & 1 != 0 { (crc >> 1) ^ 0x8408 } else { crc >> 1 };
    }
    crc
}

/// The frame check sequence over an LLAP header and data field: CRC-16/X-25
/// (CRC-CCITT, reflected, init $FFFF, final xor $FFFF). Low byte first, which
/// is the order LLAP puts it on the wire (PDF 545: the remainder is inverted
/// and its high-order bit sent first, which reflected arithmetic delivers low
/// byte first).
pub fn fcs(frame: &[u8]) -> [u8; 2] {
    let crc = frame.iter().fold(0xffff, |c, &b| crc_update(c, b));
    [(crc & 0xff) as u8 ^ 0xff, (crc >> 8) as u8 ^ 0xff]
}

/// Whether a frame *including* its trailing FCS checks out. Feeding both
/// leaves a fixed residue in the register — the book's 0001110100001111
/// (PDF 545), which is $F0B8 read back through the reflected algorithm.
/// Cheaper and less error-prone than recomputing and comparing.
pub(crate) fn fcs_residue_ok(frame_with_fcs: &[u8]) -> bool {
    frame_with_fcs.iter().fold(0xffff, |c, &b| crc_update(c, b)) == 0xf0b8
}

/// What to send the moment the port opens. 1024 `$00` no-ops return the
/// firmware's receiver to the state where it awaits a command byte no matter
/// what it was mid-way through, then an all-zero node bitmap (answer for
/// nobody until we have claimed an address) and `$03 $00` to clear every
/// optional feature — we compute and check our own CRCs, which the protocol
/// document recommends over letting the firmware do it.
pub fn init_sequence() -> Vec<u8> {
    let mut out = vec![0u8; 1024];
    out.extend(node_command(None));
    out.extend([0x03, 0x00]);
    out
}

/// A transmit command: `$01` and then the frame with its FCS appended. The
/// firmware infers the length from the frame itself and needs no terminator.
pub fn frame_command(l: &Llap) -> Vec<u8> {
    let frame = l.to_bytes();
    let mut out = vec![0x01];
    out.extend(&frame);
    out.extend(fcs(&frame));
    out
}

/// A set-node-IDs command: `$02` and a 256-bit little-endian-within-byte
/// bitmap. `None` clears it, so the firmware answers ENQ and RTS for nobody.
/// Node 0 and node 255 are not legal IDs and so can never be set here.
pub fn node_command(node: Option<u8>) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x02;
    if let Some(n) = node {
        // Bit n of the map: byte n/8, and within it the bit for n%8 counting
        // up from the least significant.
        out[1 + n as usize / 8] = 1 << (n % 8);
    }
    out
}

/// Reassembles the firmware's escaped byte stream into frames.
pub struct Decoder {
    buf: Vec<u8>,
    /// Set by a `$00`; the next byte is the second half of an escape.
    escaped: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Decoder { buf: Vec::with_capacity(MAX_FRAME), escaped: false }
    }

    /// Feeds one byte, returning a frame when one completes cleanly. Fails
    /// closed everywhere else: a framing error, an abort, a firmware-reported
    /// bad CRC, an FCS that does not check, a frame too short to hold a
    /// header and an FCS, or one that does not parse as LLAP all discard
    /// silently and leave the decoder ready for the next frame.
    pub fn feed(&mut self, byte: u8) -> Option<Llap> {
        if !self.escaped {
            if byte == 0x00 {
                self.escaped = true;
            } else if self.buf.len() < MAX_FRAME {
                self.buf.push(byte);
            }
            // Over-long frames drop the excess and then fail their FCS,
            // which is the same discard by another route.
            return None;
        }
        self.escaped = false;
        let frame = match byte {
            // A literal zero inside the frame.
            0xff => {
                if self.buf.len() < MAX_FRAME {
                    self.buf.push(0);
                }
                return None;
            }
            // End of a good frame: check the FCS and hand over what is left.
            0xfd => {
                let n = self.buf.len();
                if n >= 5 && fcs_residue_ok(&self.buf) {
                    Llap::parse(&self.buf[..n - 2])
                } else {
                    None
                }
            }
            // $FE framing error, $FA abort, $FC bad CRC — and anything else,
            // which means we lost sync and cannot trust the buffer either.
            _ => None,
        };
        self.buf.clear();
        frame
    }
}

/// An open TashTalk port.
pub struct Tashtalk {
    /// Writes serialise through this; the reader thread holds its own clone
    /// so a blocked write can never stall reception.
    port: Arc<Mutex<Box<dyn SerialPort>>>,
}

impl Tashtalk {
    /// Opens the device and puts the firmware into a known state.
    pub fn open(device: &str) -> io::Result<Tashtalk> {
        let mut port = serialport::new(device, BAUD)
            .flow_control(FlowControl::Hardware)
            // Reads are a poll loop; a timeout is normal, not an error.
            .timeout(Duration::from_millis(250))
            .open()
            .map_err(io::Error::other)?;
        port.write_all(&init_sequence())?;
        port.flush()?;
        Ok(Tashtalk { port: Arc::new(Mutex::new(port)) })
    }

    /// Starts the reader thread. Same contract as the capture thread and
    /// `ltoudp::spawn`: it drops rather than blocking when the consumer falls
    /// behind, and reports the count so a gap is never silent.
    pub fn spawn(&self, port: PortId, tx: SyncSender<Event>) -> io::Result<()> {
        let serial = self.port.lock().expect("tashtalk port lock").try_clone().map_err(io::Error::other)?;
        thread::spawn(move || read_loop(serial, port, tx));
        Ok(())
    }

    pub fn send(&self, l: &Llap) -> io::Result<()> {
        self.write(&frame_command(l))
    }

    /// Tells the firmware which node ID to answer ENQ and RTS for. Called
    /// once the address claim settles, and again if it ever moves.
    pub fn set_node(&self, node: Option<u8>) -> io::Result<()> {
        self.write(&node_command(node))
    }

    // ponytail: writes block the router thread for the frame's serial time
    // (~6 ms at 1 Mbaud for 600 bytes); queue them on a writer thread if it
    // ever shows in latency.
    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let mut port = self.port.lock().expect("tashtalk port lock");
        port.write_all(bytes)?;
        port.flush()
    }
}

fn read_loop(mut serial: Box<dyn SerialPort>, port: PortId, tx: SyncSender<Event>) {
    let mut buf = [0u8; 512];
    let mut decoder = Decoder::new();
    let mut dropped = 0u64;
    loop {
        let n = match serial.read(&mut buf) {
            Ok(n) => n,
            // The read timeout expiring just means the link was quiet.
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            // A recurring error (the adapter unplugged, say) would otherwise
            // busy-spin at 100% CPU and flood the queue; back off first, the
            // same way `capture_loop` and `ltoudp::read_loop` do.
            Err(e) => {
                thread::sleep(Duration::from_millis(100));
                if !post(&tx, Event::Error(e.to_string()), &mut dropped) {
                    return;
                }
                continue;
            }
        };
        for &b in &buf[..n] {
            if let Some(llap) = decoder.feed(b)
                && !post(&tx, Event::Llap { port, llap }, &mut dropped)
            {
                return;
            }
        }
    }
}

/// Queues one event, counting it instead of blocking when the consumer is
/// behind and reporting the accumulated count as soon as there is room.
/// Returns false once the receiver is gone.
fn post(tx: &SyncSender<Event>, event: Event, dropped: &mut u64) -> bool {
    if *dropped > 0 && tx.try_send(Event::Dropped(*dropped)).is_ok() {
        *dropped = 0;
    }
    match tx.try_send(event) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            *dropped += 1;
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Llap, LLAP_ENQ};

    #[test]
    fn fcs_matches_the_x25_check_value() {
        assert_eq!(fcs(b"123456789"), [0x6e, 0x90]);
    }

    #[test]
    fn fcs_residue_after_feeding_frame_and_fcs() {
        // Feeding a frame plus its own FCS leaves 0xF0B8 in the register — the check
        // tashrouter and the book (Appendix B) use. Exposed via `fcs_residue_ok`.
        let mut f = vec![42, 42, LLAP_ENQ];
        f.extend(fcs(&[42, 42, LLAP_ENQ]));
        assert!(fcs_residue_ok(&f));
        f[0] ^= 1;
        assert!(!fcs_residue_ok(&f));
    }

    #[test]
    fn frame_command_appends_the_fcs() {
        let l = Llap::control(42, 42, LLAP_ENQ);
        let mut want = vec![0x01, 42, 42, LLAP_ENQ];
        want.extend(fcs(&[42, 42, LLAP_ENQ]));
        assert_eq!(frame_command(&l), want);
    }

    #[test]
    fn node_command_sets_one_bit() {
        let c = node_command(Some(130));
        assert_eq!(c[0], 0x02);
        assert_eq!(c[1 + 130 / 8], 1 << (130 % 8));
        assert_eq!(c.iter().skip(1).filter(|&&b| b != 0).count(), 1);
        assert!(node_command(None)[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn init_sequence_layout() {
        let s = init_sequence();
        assert_eq!(s.len(), 1024 + 33 + 2);
        assert!(s[..1024].iter().all(|&b| b == 0));
        assert_eq!(s[1024], 0x02);
        assert_eq!(&s[1057..], &[0x03, 0x00]);
    }

    #[test]
    fn decoder_unescapes_and_verifies() {
        let frame = [42, 0, LLAP_ENQ]; // a literal zero in the source byte
        let mut wire = Vec::new();
        for &b in frame.iter().chain(fcs(&frame).iter()) {
            if b == 0 { wire.extend([0x00, 0xff]) } else { wire.push(b) }
        }
        wire.extend([0x00, 0xfd]);
        let mut d = Decoder::new();
        let mut got = None;
        for &b in &wire { if let Some(l) = d.feed(b) { got = Some(l) } }
        assert_eq!(got, Some(Llap { dst: 42, src: 0, typ: LLAP_ENQ, data: vec![] }));
    }

    #[test]
    fn decoder_discards_on_errors_and_bad_fcs() {
        let mut d = Decoder::new();
        for &b in &[42u8, 42, LLAP_ENQ, 1, 2, 0x00, 0xfd] { assert_eq!(d.feed(b), None); } // wrong FCS
        for &b in &[42u8, 42, LLAP_ENQ, 0x00, 0xfe] { assert_eq!(d.feed(b), None); }       // framing error
        for &b in &[42u8, 42, 0x00, 0xfa] { assert_eq!(d.feed(b), None); }                 // aborted
        for &b in &[42u8, 42, 0x00, 0xfc] { assert_eq!(d.feed(b), None); }                 // bad crc reported
        // And the decoder is clean afterwards: a good frame still decodes.
        let f = [1u8, 1, LLAP_ENQ];
        let mut wire = f.to_vec(); wire.extend(fcs(&f)); wire.extend([0x00, 0xfd]);
        let mut got = None;
        for &b in &wire { if let Some(l) = d.feed(b) { got = Some(l) } }
        assert!(got.is_some());
    }
}
