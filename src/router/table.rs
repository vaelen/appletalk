// Copyright 2026 Andrew C. Young <andrew@vaelen.org>
// SPDX-License-Identifier: MIT

//! The routing and zone tables: what the router knows about every network on
//! the internet, and which zones sit on each.
//!
//! Nothing drives these yet -- the router runtime that will is stub: Task 11.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::{self, Write};
use std::time::{Duration, Instant};

use super::Target;
use crate::capture::PortId;
use crate::wire::{Addr, NetworkTuple};

/// The book's validity timer: an entry unconfirmed for this long ages a step
/// (PDF 137).
pub const VALIDITY: Duration = Duration::from_secs(20);

/// How stale an entry is. The validity timer walks it one step at a time and
/// deletes it after `Worst` (PDF 136-137, 147).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Good,
    Suspect,
    Bad,
    Worst,
}

impl State {
    /// Good and suspect entries still carry traffic; bad ones only get
    /// announced at distance 31 until they are deleted.
    fn usable(self) -> bool {
        matches!(self, State::Good | State::Suspect)
    }

    /// One tick of the validity timer. `None` means delete the entry.
    fn aged(self) -> Option<State> {
        match self {
            State::Good => Some(State::Suspect),
            State::Suspect => Some(State::Bad),
            State::Bad => Some(State::Worst),
            State::Worst => None,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            State::Good => "good",
            State::Suspect => "suspect",
            State::Bad => "bad",
            State::Worst => "worst",
        })
    }
}

/// One way to reach one network range. There is one per (target, next router)
/// pair, so an alternative path through a second router on the same cable is a
/// separate entry and does not displace the incumbent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub range: (u16, u16),
    pub extended: bool,
    pub distance: u8,
    pub target: Target,
    /// The next internet router. Zero for a directly attached network and for
    /// anything learned over a tunnel.
    pub next: Addr,
    pub state: State,
    pub seen: Instant,
}

impl Route {
    fn contains(&self, net: u16) -> bool {
        self.range.0 <= net && net <= self.range.1
    }

    /// Identity within a range start: what `Tables::best` remembers so a tie
    /// keeps the incumbent.
    fn key(&self) -> (Target, Addr) {
        (self.target, self.next)
    }

    fn tuple(&self) -> NetworkTuple {
        NetworkTuple { range: self.range, extended: self.extended, distance: self.distance }
    }

    /// True for a network of our own: never replaced, never aged (PDF 145).
    fn direct(&self) -> bool {
        self.distance == 0 && matches!(self.target, Target::Port(_))
    }
}

/// A change to the *best* route for a range. `old`/`new` both set is a move or
/// a distance change; `old` alone is a deletion, `new` alone an addition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteChange {
    pub range: (u16, u16),
    pub old: Option<Route>,
    pub new: Option<Route>,
}

/// The zones on one network range.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneList {
    pub names: Vec<String>,
    /// Total announced by an extended reply, when known.
    pub expected: Option<usize>,
}

impl ZoneList {
    /// A list nobody has filled in yet is never complete; an extended reply
    /// that named a total is complete once we hold that many.
    pub fn complete(&self) -> bool {
        !self.names.is_empty() && self.expected.is_none_or(|e| self.names.len() >= e)
    }
}

fn overlaps(a: (u16, u16), b: (u16, u16)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

/// The routing and zone tables.
//
// ponytail: O(n) linear scans over a Vec. Index by network number if the table
// ever passes a few thousand entries; GlobalTalk is two orders off that.
pub struct Tables {
    routes: Vec<Route>,
    /// Range start -> (range end, zones).
    zones: HashMap<u16, (u16, ZoneList)>,
    /// Range start -> the route that is currently best, so a tie keeps it.
    best: HashMap<u16, (Target, Addr)>,
}

impl Default for Tables {
    fn default() -> Self {
        Self::new()
    }
}

impl Tables {
    pub fn new() -> Self {
        Tables { routes: Vec::new(), zones: HashMap::new(), best: HashMap::new() }
    }

    /// A directly attached network: distance 0, always good, zones complete
    /// from config (PDF 145, "Initialization").
    pub fn add_port(
        &mut self,
        port: PortId,
        range: (u16, u16),
        extended: bool,
        zones: Vec<String>,
        now: Instant,
    ) {
        self.routes.push(Route {
            range,
            extended,
            distance: 0,
            target: Target::Port(port),
            next: Addr { net: 0, node: 0 },
            state: State::Good,
            seen: now,
        });
        self.zones.insert(range.0, (range.1, ZoneList { names: zones, expected: None }));
        self.best.insert(range.0, (Target::Port(port), Addr { net: 0, node: 0 }));
    }

    /// The book's "RTMP Data packet received" algorithm for one tuple, reached
    /// via `target` with next router `next` (PDF 146). Distance stored is
    /// `tuple.distance + 1`; a tuple distance of 31 marks the entry bad.
    pub fn learn(
        &mut self,
        t: &NetworkTuple,
        target: Target,
        next: Addr,
        now: Instant,
    ) -> Vec<RouteChange> {
        // A correctly maintained table holds no overlapping ranges, so a tuple
        // that overlaps an entry without matching it is dropped (PDF 149).
        if self.routes.iter().any(|r| r.range != t.range && overlaps(r.range, t.range)) {
            return Vec::new();
        }
        let start = t.range.0;
        let old = self.snapshot(&[start]);
        let distance = t.distance.saturating_add(1);
        let state = if t.distance == 31 { State::Bad } else { State::Good };
        match self
            .routes
            .iter_mut()
            .find(|r| r.range == t.range && r.target == target && r.next == next)
        {
            Some(r) if r.direct() => {}
            // Replace-Entry.
            Some(r) => {
                r.extended = t.extended;
                r.distance = distance;
                r.state = state;
                r.seen = now;
            }
            // Create-New-Entry: an alternative path, which may not be the best.
            None => self.routes.push(Route {
                range: t.range,
                extended: t.extended,
                distance,
                target,
                next,
                state,
                seen: now,
            }),
        }
        self.settle(&[start], old)
    }

    pub fn best(&self, net: u16) -> Option<&Route> {
        self.pick(|r| r.contains(net))
    }

    /// Validity timer: good -> suspect -> bad -> worst -> deleted, one step per
    /// expiry (PDF 147). Directly attached networks and routes learned from an
    /// AURP peer never age; a peer's networks leave when the peer says so.
    pub fn age(&mut self, now: Instant) -> Vec<RouteChange> {
        let starts = self.starts();
        let old = self.snapshot(&starts);
        self.routes.retain_mut(|r| {
            if r.direct() || matches!(r.target, Target::Peer(_)) {
                return true;
            }
            if now.saturating_duration_since(r.seen) < VALIDITY {
                return true;
            }
            r.seen = now;
            match r.state.aged() {
                Some(s) => {
                    r.state = s;
                    true
                }
                None => false,
            }
        });
        self.settle(&starts, old)
    }

    pub fn remove_target(&mut self, t: Target) -> Vec<RouteChange> {
        let starts = self.starts_where(|r| r.target == t);
        let old = self.snapshot(&starts);
        self.routes.retain(|r| r.target != t);
        self.settle(&starts, old)
    }

    pub fn remove(&mut self, t: Target, start: u16) -> Vec<RouteChange> {
        let old = self.snapshot(&[start]);
        self.routes.retain(|r| !(r.target == t && r.range.0 == start));
        self.settle(&[start], old)
    }

    pub fn set_distance(
        &mut self,
        t: Target,
        start: u16,
        distance: u8,
        now: Instant,
    ) -> Vec<RouteChange> {
        let old = self.snapshot(&[start]);
        for r in self.routes.iter_mut().filter(|r| r.target == t && r.range.0 == start) {
            r.distance = distance;
            r.seen = now;
        }
        self.settle(&[start], old)
    }

    /// Tuples to beacon on `port`: every best route not reached through `port`
    /// (split horizon). A range whose entries have all gone bad is still
    /// announced at distance 31 -- notify neighbour (PDF 136).
    pub fn tuples_for(&self, port: PortId) -> Vec<NetworkTuple> {
        let mut out = Vec::new();
        for start in self.starts() {
            let r = match self.best_for_start(start) {
                Some(r) => r,
                None => match self.routes.iter().find(|r| r.range.0 == start) {
                    Some(r) => r,
                    None => continue,
                },
            };
            if r.target == Target::Port(port) {
                continue;
            }
            let mut tuple = r.tuple();
            if !r.state.usable() {
                tuple.distance = 31;
            }
            out.push(tuple);
        }
        out
    }

    /// What an AURP peer may learn: our local internet only, so every best
    /// route via one of our ports, with complete zones and distance below 15
    /// (`docs/AURP.md`, "What to export").
    pub fn export(&self) -> Vec<NetworkTuple> {
        self.starts()
            .into_iter()
            .filter(|&s| self.exportable(s))
            .filter_map(|s| self.best_for_start(s).map(Route::tuple))
            .collect()
    }

    pub fn routes(&self) -> impl Iterator<Item = &Route> {
        self.routes.iter()
    }

    pub fn zones(&self, start: u16) -> Option<&ZoneList> {
        self.zones.get(&start).map(|(_, z)| z)
    }

    /// Extends the list for a range, dropping names it already holds;
    /// `expected` comes from an extended reply. Returns an addition when the
    /// network has just become exportable.
    pub fn add_zones(
        &mut self,
        start: u16,
        names: &[String],
        expected: Option<usize>,
    ) -> Vec<RouteChange> {
        let Some(range) = self.routes.iter().find(|r| r.range.0 == start).map(|r| r.range) else {
            return Vec::new();
        };
        let was = self.exportable(start);
        let entry = self.zones.entry(start).or_insert((range.1, ZoneList::default()));
        entry.0 = range.1;
        if expected.is_some() {
            entry.1.expected = expected;
        }
        for n in names {
            if !entry.1.names.iter().any(|h| h.eq_ignore_ascii_case(n)) {
                entry.1.names.push(n.clone());
            }
        }
        match self.best_for_start(start) {
            Some(r) if !was && self.exportable(start) => {
                vec![RouteChange { range: r.range, old: None, new: Some(r.clone()) }]
            }
            _ => Vec::new(),
        }
    }

    /// Range starts, with the target to reach each, whose complete zone list
    /// names `zone`.
    pub fn nets_in_zone(&self, zone: &str) -> Vec<(u16, Target)> {
        self.starts()
            .into_iter()
            .filter(|s| {
                self.zones.get(s).is_some_and(|(_, z)| {
                    z.complete() && z.names.iter().any(|n| n.eq_ignore_ascii_case(zone))
                })
            })
            .filter_map(|s| self.best_for_start(s).map(|r| (s, r.target)))
            .collect()
    }

    /// Networks still missing zones, with the best route to ask. Our own
    /// networks are skipped: their zones come from config, and there is nobody
    /// to query.
    pub fn zoneless(&self) -> Vec<Route> {
        self.starts()
            .into_iter()
            .filter(|s| !self.zones.get(s).is_some_and(|(_, z)| z.complete()))
            .filter_map(|s| self.best_for_start(s))
            .filter(|r| !r.direct())
            .cloned()
            .collect()
    }

    /// Every zone name across complete lists, deduplicated case-insensitively,
    /// in first-seen order.
    pub fn all_zones(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for start in self.starts() {
            let Some((_, z)) = self.zones.get(&start) else { continue };
            if !z.complete() {
                continue;
            }
            for n in &z.names {
                if !out.iter().any(|h| h.eq_ignore_ascii_case(n)) {
                    out.push(n.clone());
                }
            }
        }
        out
    }

    /// An aligned dump of both tables, for SIGUSR1.
    pub fn dump(&self) -> String {
        let mut rows = vec![[
            "network".to_string(),
            "dist".to_string(),
            "via".to_string(),
            "next".to_string(),
            "state".to_string(),
            "zones".to_string(),
        ]];
        for r in &self.routes {
            let best = self.best.get(&r.range.0) == Some(&r.key()) && r.state.usable();
            let zones = match self.zones.get(&r.range.0) {
                Some((_, z)) if !z.names.is_empty() => z.names.join(", "),
                Some((_, z)) if z.expected.is_some() => format!("? of {}", z.expected.unwrap()),
                _ => "?".to_string(),
            };
            rows.push([
                format!(
                    "{}{}-{}{}",
                    if best { "*" } else { " " },
                    r.range.0,
                    r.range.1,
                    if r.extended { "" } else { " (n)" }
                ),
                r.distance.to_string(),
                match r.target {
                    Target::Port(p) => format!("port {p}"),
                    Target::Peer(ip) => ip.to_string(),
                },
                if r.next.net == 0 && r.next.node == 0 { "-".to_string() } else { r.next.to_string() },
                r.state.to_string(),
                zones,
            ]);
        }
        let mut width = [0usize; 6];
        for row in &rows {
            for (w, cell) in width.iter_mut().zip(row) {
                *w = (*w).max(cell.chars().count());
            }
        }
        let mut out = String::new();
        for row in &rows {
            for (i, cell) in row.iter().enumerate() {
                if i + 1 == row.len() {
                    let _ = write!(out, "{cell}");
                } else {
                    let _ = write!(out, "{cell:<w$}  ", w = width[i]);
                }
            }
            out.push('\n');
        }
        out
    }

    // ------------------------------------------------------------- internals

    /// Distinct range starts, in the order the routes were learned, so every
    /// listing this module returns is deterministic.
    fn starts(&self) -> Vec<u16> {
        self.starts_where(|_| true)
    }

    fn starts_where(&self, f: impl Fn(&Route) -> bool) -> Vec<u16> {
        let mut out: Vec<u16> = Vec::new();
        for r in self.routes.iter().filter(|r| f(r)) {
            if !out.contains(&r.range.0) {
                out.push(r.range.0);
            }
        }
        out
    }

    /// The shortest usable route matching `f`; on a tie the incumbent, else the
    /// first one found.
    fn pick(&self, f: impl Fn(&Route) -> bool) -> Option<&Route> {
        let mut best: Option<&Route> = None;
        for r in self.routes.iter().filter(|r| r.state.usable() && f(r)) {
            let take = match best {
                None => true,
                Some(b) => {
                    r.distance < b.distance
                        || (r.distance == b.distance && self.incumbent(r) && !self.incumbent(b))
                }
            };
            if take {
                best = Some(r);
            }
        }
        best
    }

    fn best_for_start(&self, start: u16) -> Option<&Route> {
        self.pick(|r| r.range.0 == start)
    }

    fn incumbent(&self, r: &Route) -> bool {
        self.best.get(&r.range.0) == Some(&r.key())
    }

    fn exportable(&self, start: u16) -> bool {
        self.best_for_start(start)
            .is_some_and(|r| matches!(r.target, Target::Port(_)) && r.distance < 15)
            && self.zones.get(&start).is_some_and(|(_, z)| z.complete())
    }

    fn snapshot(&self, starts: &[u16]) -> Vec<Option<Route>> {
        starts.iter().map(|&s| self.best_for_start(s).cloned()).collect()
    }

    /// Recompute the best route for each touched range start, record the new
    /// incumbent, drop a zone list whose last route has gone, and report the
    /// ranges whose best route changed target, distance or existence.
    fn settle(&mut self, starts: &[u16], old: Vec<Option<Route>>) -> Vec<RouteChange> {
        let mut out = Vec::new();
        for (&start, old) in starts.iter().zip(old) {
            let new = self.best_for_start(start).cloned();
            match &new {
                Some(r) => self.best.insert(start, r.key()),
                None => self.best.remove(&start),
            };
            if !self.routes.iter().any(|r| r.range.0 == start) {
                self.zones.remove(&start);
                self.best.remove(&start);
            }
            let changed = match (&old, &new) {
                (None, None) => false,
                (Some(a), Some(b)) => a.target != b.target || a.distance != b.distance,
                _ => true,
            };
            if changed {
                let range = new.as_ref().or(old.as_ref()).map_or((start, start), |r| r.range);
                out.push(RouteChange { range, old, new });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(range: (u16,u16), ext: bool, d: u8) -> NetworkTuple { NetworkTuple { range, extended: ext, distance: d } }
    fn r1() -> Addr { Addr { net: 6800, node: 1 } }
    fn peer() -> Target { Target::Peer("192.0.2.7".parse().unwrap()) }

    #[test]
    fn ports_are_direct_and_exportable_once_zoned() {
        let now = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (6800, 6800), true, vec!["A".into()], now);
        let b = tb.best(6800).unwrap();
        assert_eq!((b.distance, b.target), (0, Target::Port(0)));
        assert_eq!(tb.export(), vec![t((6800, 6800), true, 0)]);
        assert!(tb.tuples_for(0).is_empty());          // split horizon: not beaconed back onto itself
        assert_eq!(tb.tuples_for(1), vec![t((6800, 6800), true, 0)]);
    }

    #[test]
    fn learns_prefers_shorter_and_keeps_incumbent_on_tie() {
        let now = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (1, 1), false, vec!["A".into()], now);
        let ch = tb.learn(&t((5, 5), false, 2), Target::Port(0), Addr { net: 1, node: 9 }, now);
        assert_eq!(ch.len(), 1);
        assert!(ch[0].old.is_none());
        assert_eq!(tb.best(5).unwrap().distance, 3);
        // Same distance from another router: incumbent stays.
        let ch = tb.learn(&t((5, 5), false, 2), Target::Port(0), Addr { net: 1, node: 10 }, now);
        assert!(ch.is_empty());
        assert_eq!(tb.best(5).unwrap().next.node, 9);
        // Shorter from the other: it wins.
        let ch = tb.learn(&t((5, 5), false, 1), Target::Port(0), Addr { net: 1, node: 10 }, now);
        assert_eq!(ch[0].new.as_ref().unwrap().next.node, 10);
        assert_eq!(tb.best(5).unwrap().distance, 2);
    }

    #[test]
    fn overlapping_ranges_are_ignored_and_31_marks_bad() {
        let now = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (1, 1), false, vec![], now);
        tb.learn(&t((10, 12), true, 1), Target::Port(0), r1(), now);
        assert!(tb.learn(&t((11, 11), false, 0), Target::Port(0), r1(), now).is_empty());
        assert_eq!(tb.best(11).unwrap().range, (10, 12));
        let ch = tb.learn(&t((10, 12), true, 31), Target::Port(0), r1(), now);
        assert_eq!(ch.len(), 1);
        assert!(ch[0].new.is_none());
        assert!(tb.best(10).is_none());
        assert_eq!(tb.tuples_for(1), vec![t((1, 1), false, 0), t((10, 12), true, 31)]); // notify neighbour
    }

    #[test]
    fn aging_walks_the_states_and_peer_routes_do_not_age() {
        let now = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (1, 1), false, vec![], now);
        tb.learn(&t((5, 5), false, 0), Target::Port(0), r1(), now);
        tb.learn(&t((7, 7), false, 0), peer(), Addr { net: 0, node: 0 }, now);
        assert!(tb.age(now + VALIDITY).is_empty());                  // suspect, still best
        assert_eq!(tb.best(5).unwrap().state, State::Suspect);
        let ch = tb.age(now + VALIDITY * 2);                          // bad: no longer best
        assert_eq!(ch.len(), 1);
        assert!(tb.best(5).is_none());
        tb.age(now + VALIDITY * 3);
        assert!(tb.age(now + VALIDITY * 4).is_empty());               // deleted quietly (already not best)
        assert!(tb.routes().all(|r| r.range != (5, 5)));
        assert_eq!(tb.best(7).unwrap().state, State::Good);
        // A refresh brings a suspect entry back to good.
        tb.learn(&t((9, 9), false, 0), Target::Port(0), r1(), now);
        tb.age(now + VALIDITY);
        tb.learn(&t((9, 9), false, 0), Target::Port(0), r1(), now + VALIDITY);
        assert_eq!(tb.best(9).unwrap().state, State::Good);
    }

    #[test]
    fn remove_target_and_set_distance_report_best_changes() {
        let now = Instant::now();
        let mut tb = Tables::new();
        tb.learn(&t((5, 5), false, 0), peer(), Addr { net: 0, node: 0 }, now);
        let ch = tb.set_distance(peer(), 5, 4, now);
        assert_eq!((ch[0].old.as_ref().unwrap().distance, ch[0].new.as_ref().unwrap().distance), (1, 4));
        let ch = tb.remove_target(peer());
        assert!(ch[0].new.is_none());
        assert!(tb.zones(5).is_none());
    }

    #[test]
    fn zone_lists_gate_export_and_answer_lookups() {
        let now = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (1, 1), false, vec!["Local".into()], now);
        tb.learn(&t((5, 6), true, 0), Target::Port(0), r1(), now);
        assert_eq!(tb.export().len(), 1);                          // 5-6 has no zones yet
        assert_eq!(tb.zoneless().len(), 1);
        let ch = tb.add_zones(5, &["Eng".into()], Some(2));
        assert!(ch.is_empty());                                    // incomplete: 1 of 2
        let ch = tb.add_zones(5, &["Sales".into(), "Eng".into()], Some(2));
        assert_eq!(ch.len(), 1);                                   // duplicates filtered, now complete
        assert_eq!(tb.zones(5).unwrap().names, ["Eng", "Sales"]);
        assert_eq!(tb.export().len(), 2);
        assert_eq!(tb.nets_in_zone("eng"), vec![(5, Target::Port(0))]);
        assert_eq!(tb.all_zones(), ["Local", "Eng", "Sales"]);
        assert!(tb.zoneless().is_empty());
    }

    #[test]
    fn dump_aligns_its_columns() {
        let now = Instant::now();
        let mut tb = Tables::new();
        tb.add_port(0, (1, 1), false, vec!["Local".into()], now);
        tb.learn(&t((5, 6), true, 0), Target::Port(0), r1(), now);
        tb.add_zones(5, &["Eng".into()], None);
        let d = tb.dump();
        let lines: Vec<&str> = d.lines().collect();
        assert_eq!(lines[0], "network   dist  via     next    state  zones");
        assert_eq!(lines[1], "*1-1 (n)  0     port 0  -       good   Local");
        assert_eq!(lines[2], "*5-6      1     port 0  6800.1  good   Eng");
    }
}
