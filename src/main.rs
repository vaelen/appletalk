//! Dump EtherTalk (AppleTalk-over-Ethernet) frames off the wire.
//!
//! Usage: sudo ./appletalk [interface]

mod wire;

use pnet::datalink::{self, Channel::Ethernet, Config};

use wire::*;

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

fn main() {
    let want = std::env::args().nth(1);
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| match &want {
            Some(n) => &i.name == n,
            None => i.is_up() && !i.is_loopback() && i.mac.is_some(),
        })
        .expect("no such interface");

    let cfg = Config { promiscuous: true, ..Default::default() };
    let (_tx, mut rx) = match datalink::channel(&iface, cfg) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unsupported channel type"),
        Err(e) => panic!("open {}: {e} (need CAP_NET_RAW or root)", iface.name),
    };

    println!("listening on {}", iface.name);
    loop {
        let bytes = match rx.next() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("rx: {e}");
                continue;
            }
        };
        let Some(frame) = Frame::parse(bytes) else { continue };
        match frame.proto {
            DDP => {
                println!("{frame}");
                let Some(d) = Ddp::parse(frame.payload) else {
                    hexdump(frame.payload);
                    continue;
                };
                println!("  {d}");
                // One arm per DDP type we understand, each yielding a summary
                // and whatever bytes it did not consume. Anything else falls
                // through to a raw dump of the datagram.
                let inner = match d.typ {
                    DDP_NBP => Nbp::parse(d.data).map(|n| (n.to_string(), &[][..])),
                    DDP_ATP => Atp::parse(d.data).map(|a| (a.to_string(), a.data)),
                    DDP_AEP => Aep::parse(d.data).map(|a| (a.to_string(), a.data)),
                    DDP_ZIP => Zip::parse(d.data).map(|z| (z.to_string(), &[][..])),
                    _ => None,
                };
                match inner {
                    Some((summary, data)) => {
                        println!("    {summary}");
                        hexdump(data);
                    }
                    None => hexdump(d.data),
                }
            }
            AARP => {
                println!("{frame}");
                match Aarp::parse(frame.payload) {
                    // Fully decoded: a hexdump would just repeat it.
                    Some(a) => println!("  {a}"),
                    None => hexdump(frame.payload),
                }
            }
            _ => {}
        }
    }
}
