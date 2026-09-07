// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! Router configuration: the TOML file, the command line, and their merge.
//!
//! The file is read once at startup; nothing here is consulted again while the
//! router runs. `Config`'s fields are read by the router itself.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::cli::RouterArgs;

/// Highest legal AppleTalk network number; 0xff00 up is reserved.
const MAX_NET: u16 = 0xfefe;
const AURP_PORT: u16 = 387;
/// Searched in order when `--config` is absent.
const DEFAULTS: [&str; 2] = ["appletalk.toml", "/etc/appletalk/appletalk.toml"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtherPort {
    pub interface: String,
    pub net: (u16, u16),
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LtoudpPort {
    pub interface: Option<Ipv4Addr>,
    pub net: u16,
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TashtalkPort {
    pub device: String,
    pub net: u16,
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub name: String,
    pub public_ip: Option<Ipv4Addr>,
    pub listen: SocketAddrV4,
    pub open_peering: bool,
    pub peers: Vec<String>,
    pub ethertalk: Vec<EtherPort>,
    pub ltoudp: Vec<LtoudpPort>,
    pub tashtalk: Vec<TashtalkPort>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            name: "appletalk".into(),
            public_ip: None,
            listen: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, AURP_PORT),
            open_peering: true,
            peers: Vec::new(),
            ethertalk: Vec::new(),
            ltoudp: Vec::new(),
            tashtalk: Vec::new(),
        }
    }
}

// ---- the file -------------------------------------------------------------

/// The TOML as written. Separate from `Config` so unknown keys are rejected and
/// absent ones can take their defaults; `parse_file` converts.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    router: FileRouter,
    #[serde(default)]
    ethertalk: Vec<FileEther>,
    #[serde(default)]
    ltoudp: Vec<FileLocal>,
    #[serde(default)]
    tashtalk: Vec<FileTash>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileRouter {
    name: Option<String>,
    public_ip: Option<Ipv4Addr>,
    listen: Option<SocketAddrV4>,
    open_peering: Option<bool>,
    #[serde(default)]
    peers: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEther {
    interface: String,
    net: FileNet,
    zones: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileLocal {
    interface: Option<Ipv4Addr>,
    net: FileNet,
    zones: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTash {
    device: String,
    net: FileNet,
    zones: Vec<String>,
}

/// `net = 6801` and `net = "6800-6805"` are both accepted.
#[derive(Deserialize)]
#[serde(untagged)]
enum FileNet {
    Num(u16),
    Text(String),
}

impl FileNet {
    fn range(&self) -> Result<(u16, u16), String> {
        match self {
            FileNet::Num(n) => parse_net(&n.to_string()),
            FileNet::Text(s) => parse_net(s),
        }
    }

    fn one(&self) -> Result<u16, String> {
        one_net(&match self {
            FileNet::Num(n) => n.to_string(),
            FileNet::Text(s) => s.clone(),
        })
    }
}

/// TOML text to a `Config` with the defaults filled in. Unknown keys are an
/// error, so a typo does not silently disable something.
pub fn parse_file(text: &str) -> Result<Config, String> {
    let f: FileConfig = toml_edit::de::from_str(text).map_err(|e| e.to_string())?;
    let r = f.router;
    let d = Config::default();
    Ok(Config {
        name: r.name.unwrap_or(d.name),
        public_ip: r.public_ip,
        listen: r.listen.unwrap_or(d.listen),
        open_peering: r.open_peering.unwrap_or(d.open_peering),
        peers: r.peers,
        ethertalk: f
            .ethertalk
            .into_iter()
            .map(|p| {
                Ok(EtherPort { interface: p.interface, net: p.net.range()?, zones: p.zones })
            })
            .collect::<Result<_, String>>()?,
        ltoudp: f
            .ltoudp
            .into_iter()
            .map(|p| Ok(LtoudpPort { interface: p.interface, net: p.net.one()?, zones: p.zones }))
            .collect::<Result<_, String>>()?,
        tashtalk: f
            .tashtalk
            .into_iter()
            .map(|p| Ok(TashtalkPort { device: p.device, net: p.net.one()?, zones: p.zones }))
            .collect::<Result<_, String>>()?,
    })
}

// ---- port specs -----------------------------------------------------------

/// `6800` or `6800-6805`, as a closed range.
pub fn parse_net(s: &str) -> Result<(u16, u16), String> {
    let (a, b) = s.split_once('-').unwrap_or((s, s));
    let num = |t: &str| t.trim().parse::<u16>().map_err(|_| format!("{t:?} is not a network number"));
    let (start, end) = (num(a)?, num(b)?);
    if start == 0 || end > MAX_NET {
        return Err(format!("network {s:?} is outside 1-{MAX_NET}"));
    }
    if start > end {
        return Err(format!("network range {s:?} starts above where it ends"));
    }
    Ok((start, end))
}

/// A LocalTalk link is one network, never a range.
fn one_net(s: &str) -> Result<u16, String> {
    let (start, end) = parse_net(s)?;
    if start != end {
        return Err(format!("a LocalTalk port is one network, not the range {s:?}"));
    }
    Ok(start)
}

/// The last field of a spec: a comma-separated zone list. The first is the
/// port's default zone.
fn zone_list(s: &str) -> Vec<String> {
    s.split(',').map(|z| z.trim().to_string()).collect()
}

/// `eth0:6800-6805:Zone A,Zone B`
pub fn parse_ether_spec(s: &str) -> Result<EtherPort, String> {
    // A colon in a zone name would be indistinguishable from a field
    // separator, so the spec cannot carry one; the config file can.
    let [interface, net, zones] = s.split(':').collect::<Vec<_>>()[..] else {
        return Err(format!(
            "ethertalk port {s:?}: expected INTERFACE:NET[-NET]:ZONE[,ZONE...] (a zone name containing a colon has to go in the config file)"
        ));
    };
    Ok(EtherPort {
        interface: interface.to_string(),
        net: parse_net(net)?,
        zones: zone_list(zones),
    })
}

/// `6801:Zone` or `192.168.1.5:6801:Zone`
pub fn parse_ltoudp_spec(s: &str) -> Result<LtoudpPort, String> {
    let (interface, net, zones) = match s.split(':').collect::<Vec<_>>()[..] {
        [net, zones] => (None, net, zones),
        [ip, net, zones] => (
            Some(ip.parse::<Ipv4Addr>().map_err(|_| {
                format!("ltoudp port {s:?}: {ip:?} is not an IPv4 address")
            })?),
            net,
            zones,
        ),
        _ => {
            return Err(format!(
                "ltoudp port {s:?}: expected [IP:]NET:ZONE[,ZONE...] (a zone name containing a colon has to go in the config file)"
            ));
        }
    };
    Ok(LtoudpPort { interface, net: one_net(net)?, zones: zone_list(zones) })
}

/// `/dev/ttyAMA0:6802:Zone`
pub fn parse_tashtalk_spec(s: &str) -> Result<TashtalkPort, String> {
    let [device, net, zones] = s.split(':').collect::<Vec<_>>()[..] else {
        return Err(format!(
            "tashtalk port {s:?}: expected DEVICE:NET:ZONE[,ZONE...] (a zone name containing a colon has to go in the config file)"
        ));
    };
    Ok(TashtalkPort { device: device.to_string(), net: one_net(net)?, zones: zone_list(zones) })
}

// ---- merge and validate ---------------------------------------------------

/// The file's config (or the defaults) overlaid with the command line.
pub fn merge(file: Option<Config>, args: &RouterArgs) -> Result<Config, String> {
    let mut c = file.unwrap_or_default();
    if let Some(n) = &args.name {
        c.name = n.clone();
    }
    if let Some(ip) = args.public_ip {
        c.public_ip = Some(ip);
    }
    if let Some(l) = args.listen {
        c.listen = l;
    }
    if args.no_open_peering {
        c.open_peering = false;
    }
    c.peers = merge_list(c.peers, &args.peer, &args.add_peer, args.no_peers, |s| Ok(s.to_string()))?;
    c.ethertalk = merge_list(
        c.ethertalk,
        &args.ethertalk,
        &args.add_ethertalk,
        args.no_ethertalk,
        parse_ether_spec,
    )?;
    c.ltoudp =
        merge_list(c.ltoudp, &args.ltoudp, &args.add_ltoudp, args.no_ltoudp, parse_ltoudp_spec)?;
    c.tashtalk = merge_list(
        c.tashtalk,
        &args.tashtalk,
        &args.add_tashtalk,
        args.no_tashtalk,
        parse_tashtalk_spec,
    )?;
    Ok(c)
}

/// One list's three flags. Clap already refuses more than one of them, so the
/// order here only decides what a hand-built `RouterArgs` means.
fn merge_list<T>(
    file: Vec<T>,
    replace: &[String],
    add: &[String],
    none: bool,
    parse: fn(&str) -> Result<T, String>,
) -> Result<Vec<T>, String> {
    if !replace.is_empty() {
        return replace.iter().map(|s| parse(s)).collect();
    }
    if none {
        return Ok(Vec::new());
    }
    let mut v = file;
    for s in add {
        v.push(parse(s)?);
    }
    Ok(v)
}

/// Everything that only makes sense once the file and the command line have
/// been combined. One message per problem: the first one found.
pub fn validate(cfg: &Config) -> Result<(), String> {
    // (what to call the port, its network range, its zones). LToUDP has one
    // socket per interface, so two ports without an explicit one collide too.
    let mut ports: Vec<(String, (u16, u16), &[String])> = Vec::new();
    for p in &cfg.ethertalk {
        ports.push((p.interface.clone(), p.net, &p.zones));
    }
    for p in &cfg.ltoudp {
        let iface = p.interface.map_or_else(|| "the default interface".to_string(), |i| i.to_string());
        ports.push((iface, (p.net, p.net), &p.zones));
    }
    for p in &cfg.tashtalk {
        ports.push((p.device.clone(), (p.net, p.net), &p.zones));
    }
    if ports.is_empty() {
        return Err("no ports configured: name at least one ethertalk, ltoudp or tashtalk port".into());
    }
    for (i, (name, net, zones)) in ports.iter().enumerate() {
        let earlier = &ports[..i];
        if earlier.iter().any(|(n, _, _)| n == name) {
            return Err(format!("two ports use {name}"));
        }
        if net.0 == 0 || net.1 > MAX_NET || net.0 > net.1 {
            return Err(format!("port {name}: network {}-{} is outside 1-{MAX_NET}", net.0, net.1));
        }
        if let Some((other, r, _)) = earlier.iter().find(|(_, r, _)| r.0 <= net.1 && net.0 <= r.1) {
            return Err(format!(
                "networks overlap: {}-{} on {other} and {}-{} on {name}",
                r.0, r.1, net.0, net.1
            ));
        }
        if zones.is_empty() {
            return Err(format!("port {name} has no zones"));
        }
        if let Some(z) = zones.iter().find(|z| z.is_empty() || z.len() > 32) {
            return Err(format!("port {name}: zone name {z:?} must be 1 to 32 bytes"));
        }
    }
    Ok(())
}

/// Find the config file, read it, merge the command line over it, check it.
pub fn load(args: &RouterArgs) -> io::Result<Config> {
    let file = match find_config(args.config.as_deref())? {
        Some(p) => {
            let text = fs::read_to_string(&p)?;
            Some(parse_file(&text).map_err(|e| bad(format!("{}: {e}", p.display())))?)
        }
        None => None,
    };
    let cfg = merge(file, args).map_err(bad)?;
    validate(&cfg).map_err(bad)?;
    Ok(cfg)
}

fn bad(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// An explicit `--config` must exist; a missing default is just "no file".
fn find_config(explicit: Option<&Path>) -> io::Result<Option<PathBuf>> {
    let Some(p) = explicit else {
        return Ok(default_config());
    };
    if !p.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: no such config file", p.display()),
        ));
    }
    Ok(Some(p.to_path_buf()))
}

fn default_config() -> Option<PathBuf> {
    DEFAULTS.iter().map(PathBuf::from).find(|p| p.exists())
}

// ---- peers import ---------------------------------------------------------

/// One IPv4 literal or hostname per line; blank lines and `#` comments are
/// skipped. Every bad line is reported at once, so a long list is fixed in one
/// pass. No DNS: syntax only.
pub fn parse_peer_list(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut bad = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if is_host(l) {
            out.push(l.to_string());
        } else {
            bad.push(format!("line {}", i + 1));
        }
    }
    if !bad.is_empty() {
        return Err(format!("not an IP address or hostname: {}", bad.join(", ")));
    }
    Ok(out)
}

/// An IPv4 literal, or labels of 1-63 `[A-Za-z0-9-]` joined by dots, 253 bytes
/// at most, no label starting or ending with a hyphen.
fn is_host(s: &str) -> bool {
    if s.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    s.len() <= 253
        && s.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Append the peers that are not already there to `router.peers`, creating the
/// table and the array if need be. Returns (added, already present); the
/// comparison is case-insensitive, as hostnames are.
pub fn merge_peers(doc: &mut toml_edit::DocumentMut, new: &[String]) -> (usize, usize) {
    let router = doc.entry("router").or_insert_with(toml_edit::table);
    // ponytail: a `router` or `peers` of the wrong shape is left alone rather
    // than reported; `import_peers` parses the file first, so it never gets
    // here. Give this a Result if another caller appears.
    let Some(router) = router.as_table_like_mut() else { return (0, 0) };
    let peers = router.entry("peers").or_insert_with(|| toml_edit::value(toml_edit::Array::new()));
    let Some(arr) = peers.as_array_mut() else { return (0, 0) };

    let mut seen: HashSet<String> =
        arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_ascii_lowercase()).collect();
    let (mut added, mut present) = (0, 0);
    for host in new {
        if !seen.insert(host.to_ascii_lowercase()) {
            present += 1;
            continue;
        }
        // Match the spacing of a hand-written array rather than jamming the
        // new entry against the last comma.
        let space = if arr.is_empty() { "" } else { " " };
        arr.push_formatted(toml_edit::Value::from(host.as_str()).decorated(space, ""));
        added += 1;
    }
    (added, present)
}

/// Merge a peer list file into the config file, keeping its comments and
/// formatting. Returns (added, already present).
pub fn import_peers(config: Option<&Path>, list: &Path) -> io::Result<(usize, usize)> {
    // Unlike `router`, the named file need not exist yet: we create it.
    let path = config
        .map(Path::to_path_buf)
        .or_else(default_config)
        .unwrap_or_else(|| PathBuf::from(DEFAULTS[0]));
    let hosts = parse_peer_list(&fs::read_to_string(list)?)
        .map_err(|e| bad(format!("{}: {e}", list.display())))?;
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    // Refuse to rewrite a config the router itself would reject.
    parse_file(&text).map_err(|e| bad(format!("{}: {e}", path.display())))?;
    let mut doc: toml_edit::DocumentMut =
        text.parse().map_err(|e| bad(format!("{}: {e}", path.display())))?;
    let counts = merge_peers(&mut doc, &hosts);

    // Written beside the config and renamed over it, so an interrupted write
    // cannot leave a half-config behind.
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, doc.to_string())?;
    fs::rename(&tmp, &path)?;
    Ok(counts)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::RouterArgs;

    const FILE: &str = r#"
[router]
name = "r1"
public_ip = "203.0.113.5"
peers = ["a.example.net", "192.0.2.7"]   # keep me

[[ethertalk]]
interface = "eth0"
net = "6800-6800"
zones = ["68k Mac Club"]

[[ltoudp]]
net = 6801
zones = ["Emulators"]
"#;

    #[test]
    fn file_parses_with_defaults() {
        let c = parse_file(FILE).unwrap();
        assert_eq!(c.name, "r1");
        assert_eq!(c.listen.port(), 387);
        assert!(c.open_peering);
        assert_eq!(c.peers, ["a.example.net", "192.0.2.7"]);
        assert_eq!(c.ethertalk[0].net, (6800, 6800));
        assert_eq!(c.ltoudp[0].net, 6801);
        assert!(parse_file("[router]\nbogus = 1\n").unwrap_err().contains("bogus"));
        assert!(parse_file("[[ltoudp]]\nnet = \"1-2\"\nzones=[\"z\"]\n").is_err()); // LocalTalk range
    }

    #[test]
    fn specs() {
        assert_eq!(parse_ether_spec("eth0:6800-6805:A,B").unwrap(), EtherPort { interface: "eth0".into(), net: (6800, 6805), zones: vec!["A".into(), "B".into()] });
        assert_eq!(parse_ltoudp_spec("6801:Z").unwrap().interface, None);
        assert_eq!(parse_ltoudp_spec("192.168.1.5:6801:Z").unwrap().interface, Some("192.168.1.5".parse().unwrap()));
        assert_eq!(parse_tashtalk_spec("/dev/ttyAMA0:6802:Z").unwrap().device, "/dev/ttyAMA0");
        assert!(parse_ether_spec("eth0:6800").is_err());
        assert!(parse_net("0").is_err());
        assert!(parse_net("5-3").is_err());
        assert!(parse_net("65280").is_err());
    }

    #[test]
    fn cli_replaces_adds_or_empties_each_list() {
        let file = parse_file(FILE).unwrap();
        let a = RouterArgs { peer: vec!["x".into()], ..Default::default() };
        assert_eq!(merge(Some(file.clone()), &a).unwrap().peers, ["x"]);
        let a = RouterArgs { add_peer: vec!["x".into()], ..Default::default() };
        assert_eq!(merge(Some(file.clone()), &a).unwrap().peers, ["a.example.net", "192.0.2.7", "x"]);
        let a = RouterArgs { no_peers: true, ..Default::default() };
        assert!(merge(Some(file.clone()), &a).unwrap().peers.is_empty());
        let a = RouterArgs { no_ethertalk: true, add_ltoudp: vec!["6803:Q".into()], ..Default::default() };
        let m = merge(Some(file.clone()), &a).unwrap();
        assert!(m.ethertalk.is_empty());
        assert_eq!(m.ltoudp.len(), 2);
        let a = RouterArgs { name: Some("n".into()), no_open_peering: true, ..Default::default() };
        let m = merge(Some(file), &a).unwrap();
        assert_eq!((m.name.as_str(), m.open_peering), ("n", false));
        // No file at all: the CLI alone is enough.
        let a = RouterArgs { ethertalk: vec!["eth0:1:Z".into()], ..Default::default() };
        assert_eq!(merge(None, &a).unwrap().ethertalk[0].interface, "eth0");
    }

    #[test]
    fn validation() {
        let mut c = parse_file(FILE).unwrap();
        assert!(validate(&c).is_ok());
        c.ltoudp[0].net = 6800;                       // overlaps the EtherTalk range
        assert!(validate(&c).unwrap_err().contains("overlap"));
        let mut c = parse_file(FILE).unwrap();
        c.ethertalk.push(c.ethertalk[0].clone());
        assert!(validate(&c).unwrap_err().contains("eth0"));
        let mut c = parse_file(FILE).unwrap();
        c.ethertalk.clear(); c.ltoudp.clear();
        assert!(validate(&c).unwrap_err().contains("no ports"));
        let mut c = parse_file(FILE).unwrap();
        c.ltoudp[0].zones = vec!["x".repeat(33)];
        assert!(validate(&c).is_err());
    }

    #[test]
    fn peer_list_and_merge_keep_comments() {
        let list = "# GlobalTalk\n a.example.net \n\n192.0.2.7\nNEW.example.org\n";
        assert_eq!(parse_peer_list(list).unwrap(), ["a.example.net", "192.0.2.7", "NEW.example.org"]);
        let err = parse_peer_list("ok.example\nbad host\n-x.y\n").unwrap_err();
        assert!(err.contains("line 2") && err.contains("line 3"));
        let mut doc: toml_edit::DocumentMut = FILE.parse().unwrap();
        let (added, present) = merge_peers(&mut doc, &["A.EXAMPLE.NET".into(), "new.example.org".into()]);
        assert_eq!((added, present), (1, 1));
        let out = doc.to_string();
        assert!(out.contains("# keep me"));
        assert!(out.contains("new.example.org"));
        assert_eq!(parse_file(&out).unwrap().peers.len(), 3);
        // An empty document grows a [router] table with just peers.
        let mut doc = toml_edit::DocumentMut::new();
        assert_eq!(merge_peers(&mut doc, &["p".into()]), (1, 0));
        assert_eq!(parse_file(&doc.to_string()).unwrap().peers, ["p"]);
    }

    /// The only test that touches the disk: the file lookup, the atomic
    /// rewrite and creating a config that was not there.
    #[test]
    fn import_writes_a_config_that_load_reads_back() {
        let dir = std::env::temp_dir().join(format!("appletalk-config-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("appletalk.toml");
        let list = dir.join("peers.txt");
        fs::remove_file(&cfg).ok();
        fs::write(&list, "# GlobalTalk\n192.0.2.7\n").unwrap();

        assert_eq!(import_peers(Some(&cfg), &list).unwrap(), (1, 0));
        assert_eq!(import_peers(Some(&cfg), &list).unwrap(), (0, 1));
        assert!(!cfg.with_extension("toml.tmp").exists(), "temporary file left behind");

        let args = RouterArgs {
            config: Some(cfg.clone()),
            ethertalk: vec!["eth0:6800:Z".into()],
            ..Default::default()
        };
        let c = load(&args).unwrap();
        assert_eq!(c.peers, ["192.0.2.7"]);
        assert_eq!(c.ethertalk[0].net, (6800, 6800));
        assert_eq!(c.name, "appletalk");

        // That config alone has no ports, and a named file must exist.
        assert!(load(&RouterArgs { config: Some(cfg), ..Default::default() }).is_err());
        let gone = RouterArgs { config: Some(dir.join("nope.toml")), ..Default::default() };
        assert!(load(&gone).is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
