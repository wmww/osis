//! The sims' one reachability model (`World`, `NetSim`): who can reach whom through a `peer://`
//! address. Not a packet machine (that is osis-transport's `nat`, whose `punch_opens` rule this
//! applies): each node sits on LAN segments and has a public address, a NAT, or no uplink, and
//! `route` answers from that alone, with the caller's partitions, whether some item of a dialed
//! URL connects, and how: an address on a shared segment, a public address, a punch the NAT pair
//! allows, or a relay both ends reach (the punch and the relay need a relay both reach; a punched
//! connection outlives it, a relayed one does not).

use osis_transport::nat::{Nat, punch_opens};
use osis_transport::p2p::{self, Relay};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// A LAN segment.
pub type Seg = u32;
/// A relay of the model, by the order of `add_relay`.
pub type RelayId = usize;

/// The port every model address uses. Minor: addresses are compared by IP, a port is only what
/// the URL and an announcement need; any value does.
pub const PORT: u16 = 47_380;

/// A node's way to the internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uplink {
    /// Its LANs only.
    None,
    /// A public address of its own.
    Public,
    /// Behind this NAT (`add_nat`).
    Nat(usize),
}

/// Who a partition can separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Who {
    Node(usize),
    Relay(RelayId),
}

/// How a dial connects, best first: a dial takes the best route its items give.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Route {
    Lan(Seg),
    Public,
    /// Direct, through a punch arranged over this relay.
    Punch(RelayId),
    /// Through this relay for as long as it runs.
    Relay(RelayId),
}

impl Route {
    /// The relay this route's connection goes through.
    pub fn relayed_by(self) -> Option<RelayId> {
        if let Route::Relay(r) = self { Some(r) } else { None }
    }
}

#[derive(Clone, Debug)]
struct Place {
    lan: Vec<(Seg, IpAddr)>,
    uplink: Uplink,
    public: Option<IpAddr>,
    /// Relays it registered with: what its items list and what can reach it through them.
    relays: BTreeSet<RelayId>,
}

#[derive(Clone, Debug)]
struct RelayPlace {
    relay: Relay,
    /// On this segment only; else on a public address.
    seg: Option<Seg>,
    up: bool,
}

/// Positions of nodes and relays, and the keys nodes listen with.
#[derive(Clone, Debug, Default)]
pub struct Reach {
    places: BTreeMap<usize, Place>,
    relays: Vec<RelayPlace>,
    nats: Vec<Nat>,
    /// Listening key -> node: the dialable key and LAN transport keys.
    keys: BTreeMap<[u8; 32], usize>,
    /// Node and segment -> its LAN listener's key (`lan_key`).
    lan_keys: BTreeMap<(usize, Seg), [u8; 32]>,
    /// Addresses handed out so far (each address unique).
    next_ip: u32,
}

impl Reach {
    /// Any node placed: the scenario has peer links.
    pub fn is_used(&self) -> bool {
        !self.places.is_empty()
    }

    /// A NAT behaving as `nat`.
    pub fn add_nat(&mut self, nat: Nat) -> usize {
        self.nats.push(nat);
        self.nats.len() - 1
    }

    /// A relay on segment `seg`, or on a public address. Listens from the start.
    pub fn add_relay(&mut self, seg: Option<Seg>) -> RelayId {
        let r = self.relays.len();
        self.next_ip += 1;
        let ip = match seg {
            Some(s) => lan_ip(s, self.next_ip),
            None => public_ip(self.next_ip),
        };
        let mut key = [0x70u8; 32];
        key[..8].copy_from_slice(&(r as u64).to_le_bytes());
        self.relays.push(RelayPlace { relay: Relay { key, addr: SocketAddr::new(ip, PORT) }, seg, up: true });
        r
    }

    /// Node `n` sits on `lans` with `uplink`, registered with `relays`.
    pub fn place(&mut self, n: usize, lans: &[Seg], uplink: Uplink, relays: &[RelayId]) {
        let mut lan = Vec::new();
        for s in lans {
            self.next_ip += 1;
            lan.push((*s, lan_ip(*s, self.next_ip)));
        }
        let public = (uplink == Uplink::Public).then(|| {
            self.next_ip += 1;
            public_ip(self.next_ip)
        });
        self.places.insert(n, Place { lan, uplink, public, relays: relays.iter().copied().collect() });
    }

    /// Node `old`'s place, keys and all, now belong to `new` (it restarted under another index).
    pub fn renumber(&mut self, old: usize, new: usize) {
        if let Some(p) = self.places.remove(&old) {
            self.places.insert(new, p);
        }
        for v in self.keys.values_mut() {
            if *v == old {
                *v = new;
            }
        }
        self.lan_keys = std::mem::take(&mut self.lan_keys).into_iter().map(|((n, s), k)| ((if n == old { new } else { n }, s), k)).collect();
    }

    /// Node `n` listens with `key` as its dialable key: an earlier dialable key stops.
    pub fn listen(&mut self, n: usize, key: [u8; 32]) {
        let lan: BTreeSet<[u8; 32]> = self.lan_keys.iter().filter(|((m, _), _)| *m == n).map(|(_, k)| *k).collect();
        self.keys.retain(|k, m| *m != n || lan.contains(k));
        self.keys.insert(key, n);
    }

    /// Node `n`'s LAN listener on segment `s`, made with `make` at its first join.
    pub fn lan_key(&mut self, n: usize, s: Seg, make: impl FnOnce() -> [u8; 32]) -> [u8; 32] {
        let k = *self.lan_keys.entry((n, s)).or_insert_with(make);
        self.keys.insert(k, n);
        k
    }

    /// The node listening with `key`.
    pub fn node_of(&self, key: &[u8; 32]) -> Option<usize> {
        self.keys.get(key).copied()
    }

    /// What node `n` lists in `reach.0`, as `p2p::reach_items` does: its public address, then its
    /// relays. A LAN address is announced, never listed.
    pub fn items(&self, n: usize) -> Vec<String> {
        let Some(p) = self.places.get(&n) else { return Vec::new() };
        let mut out: Vec<String> = p.public.iter().map(|ip| SocketAddr::new(*ip, PORT).to_string()).collect();
        out.extend(p.relays.iter().filter_map(|r| self.relays.get(*r)).map(|r| r.relay.item()));
        out
    }

    /// Node `n`'s address on segment `s`.
    pub fn lan_addr(&self, n: usize, s: Seg) -> Option<SocketAddr> {
        self.places.get(&n)?.lan.iter().find(|(x, _)| *x == s).map(|(_, ip)| SocketAddr::new(*ip, PORT))
    }

    /// The segments node `n` sits on.
    pub fn segments(&self, n: usize) -> Vec<Seg> {
        self.places.get(&n).map(|p| p.lan.iter().map(|x| x.0).collect()).unwrap_or_default()
    }

    /// The other placed nodes on segment `s`.
    pub fn on_segment(&self, s: Seg, except: usize) -> Vec<usize> {
        self.places.iter().filter(|(m, p)| **m != except && p.lan.iter().any(|x| x.0 == s)).map(|(m, _)| *m).collect()
    }

    /// A relay's own item, for a URL by hand.
    pub fn relay_item(&self, r: RelayId) -> Option<String> {
        self.relays.get(r).map(|x| x.relay.item())
    }

    /// A relay starts or stops. What it carried is the caller's to cut (`Route::relayed_by`).
    pub fn set_relay_up(&mut self, r: RelayId, up: bool) {
        if let Some(x) = self.relays.get_mut(r) {
            x.up = up;
        }
    }

    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }

    fn reaches_relay(&self, p: &Place, r: &RelayPlace) -> bool {
        match r.seg {
            Some(s) => p.lan.iter().any(|x| x.0 == s),
            None => p.uplink != Uplink::None,
        }
    }

    fn nat_of(&self, p: &Place) -> Result<Option<Nat>, ()> {
        match p.uplink {
            Uplink::None => Err(()),
            Uplink::Public => Ok(None),
            Uplink::Nat(i) => self.nats.get(i).copied().map(Some).ok_or(()),
        }
    }

    /// Whether a punch can connect `from` to `to` (both need an address outside, and two
    /// nodes behind one NAT reach each other on their LAN only: no hairpinning).
    fn punches(&self, from: &Place, to: &Place) -> bool {
        if let (Uplink::Nat(a), Uplink::Nat(b)) = (from.uplink, to.uplink)
            && a == b
        {
            return false;
        }
        matches!((self.nat_of(from), self.nat_of(to)), (Ok(a), Ok(b)) if punch_opens(a, b))
    }

    /// How `from` connects to `to` dialing `url`, or none. `blocked` says which pairs a partition
    /// separates at this moment (asked of the two nodes and of each with a relay).
    pub fn route(&self, from: usize, to: usize, url: &str, blocked: impl Fn(Who, Who) -> bool) -> Option<Route> {
        let (a, b) = (self.places.get(&from)?, self.places.get(&to)?);
        if blocked(Who::Node(from), Who::Node(to)) {
            return None;
        }
        let items = p2p::items(url).ok()?;
        let mut best: Option<Route> = None;
        let mut offer = |r: Route| {
            if best.is_none_or(|b| r < b) {
                best = Some(r);
            }
        };
        for addr in &items.direct {
            if let Some((seg, _)) = b.lan.iter().find(|(s, ip)| *ip == addr.ip() && a.lan.iter().any(|x| x.0 == *s)) {
                offer(Route::Lan(*seg));
            } else if b.uplink == Uplink::Public && b.public == Some(addr.ip()) && a.uplink != Uplink::None {
                offer(Route::Public);
            }
        }
        for item in &items.relays {
            let Some(r) = self.relays.iter().position(|x| x.relay == *item) else { continue };
            let Some(place) = self.relays.get(r) else { continue };
            let open = |n, p: &Place| self.reaches_relay(p, place) && !blocked(Who::Node(n), Who::Relay(r));
            if place.up && b.relays.contains(&r) && open(from, a) && open(to, b) {
                // a relay on their own segment sees each one's LAN address: nothing filters the punch
                offer(if place.seg.is_some() || self.punches(a, b) { Route::Punch(r) } else { Route::Relay(r) });
            }
        }
        best
    }

    /// Whether nodes `a` and `b` can connect either way: each dialing what the other lists in
    /// `reach.0`, or a LAN address it would hear announced, both listening.
    pub fn linked(&self, a: usize, b: usize, blocked: impl Fn(Who, Who) -> bool) -> bool {
        let listens = |n| self.keys.values().any(|m| *m == n);
        if !listens(a) || !listens(b) {
            return false;
        }
        let url = |to: usize, from: usize| {
            let mut items = self.items(to);
            for s in self.segments(to).into_iter().filter(|s| self.segments(from).contains(s)) {
                items.extend(self.lan_addr(to, s).map(|x| x.to_string()));
            }
            osis_transport::peer_url(&items)
        };
        self.route(a, b, &url(b, a), &blocked).is_some() || self.route(b, a, &url(a, b), &blocked).is_some()
    }
}

fn lan_ip(s: Seg, i: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + ((s & 0xff) << 16) + (i & 0xffff)))
}

fn public_ip(i: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x0800_0000 + i))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn url(items: &[String]) -> String {
        osis_transport::peer_url(items)
    }

    fn one(item: &str) -> String {
        osis_transport::peer_url(&[item.to_string()])
    }

    // spec: none (test harness, spec/sync.md §10): one route per item kind, the best one taken; no
    // route where no item reaches. Each `assert` a case of the model's rule.
    #[test]
    fn routes_by_item_kind() {
        let open = |_: Who, _: Who| false;
        let mut m = Reach::default();
        let lanes = [1];
        m.place(0, &lanes, Uplink::Public, &[]);
        m.place(1, &lanes, Uplink::None, &[]);
        m.place(2, &[2], Uplink::Public, &[]);
        let lan0 = m.lan_addr(0, 1).unwrap().to_string();
        assert_eq!(m.route(1, 0, &one(&lan0), open), Some(Route::Lan(1)), "a shared segment");
        assert_eq!(m.route(2, 0, &url(&[lan0]), open), None, "no shared segment");
        let public = m.items(0);
        assert_eq!(m.route(2, 0, &url(&public), open), Some(Route::Public));
        assert_eq!(m.route(1, 0, &url(&public), open), None, "no uplink");
        assert_eq!(m.route(0, 2, &url(&m.items(1)), open), None, "not its address");
        // relay and punch
        let (cone, sym) = (m.add_nat(Nat::CONE), m.add_nat(Nat::SYMMETRIC));
        let r = m.add_relay(None);
        m.place(3, &[], Uplink::Nat(cone), &[r]);
        m.place(4, &[], Uplink::Nat(sym), &[r]);
        let cone2 = m.add_nat(Nat::CONE);
        m.place(5, &[], Uplink::Nat(cone2), &[r]);
        let item = m.relay_item(r).unwrap();
        assert_eq!(m.route(5, 3, &one(&item), open), Some(Route::Punch(r)));
        assert_eq!(m.route(3, 4, &one(&item), open), Some(Route::Relay(r)), "a symmetric target: relayed");
        assert_eq!(m.route(5, 3, &url(&[]), open), None, "no item");
        // both on the same NAT: no punch (their LAN is their way)
        m.place(6, &[], Uplink::Nat(cone), &[r]);
        assert_eq!(m.route(3, 6, &one(&item), open), Some(Route::Relay(r)));
        // a target registered elsewhere is not reached through a relay it never registered with
        m.place(7, &[], Uplink::Nat(cone), &[]);
        assert_eq!(m.route(3, 7, &one(&item), open), None);
        // a relay on their shared segment: the punch stays on the LAN, whatever their uplinks
        let lr = m.add_relay(Some(3));
        m.place(10, &[3], Uplink::Nat(cone), &[lr]);
        m.place(11, &[3], Uplink::None, &[lr]);
        assert_eq!(m.route(10, 11, &one(&m.relay_item(lr).unwrap()), open), Some(Route::Punch(lr)));
        // a relay gone or cut off from one side
        m.set_relay_up(r, false);
        assert_eq!(m.route(5, 3, &one(&item), open), None, "relay down");
        m.set_relay_up(r, true);
        assert_eq!(m.route(5, 3, &one(&item), |a, b| a == Who::Node(5) && b == Who::Relay(r)), None, "cut from the relay");
        // best of several, partitions first
        m.place(8, &lanes, Uplink::Public, &[r]);
        m.place(9, &lanes, Uplink::Nat(cone), &[r]);
        let lan8 = m.lan_addr(8, 1).unwrap().to_string();
        let mut both = m.items(8);
        both.insert(0, lan8);
        assert_eq!(m.route(9, 8, &url(&both), open), Some(Route::Lan(1)));
        assert_eq!(m.route(9, 8, &url(&both), |a, b| (a, b) == (Who::Node(9), Who::Node(8))), None);
    }

    // spec: none (test harness): a restart moves a node's place and keys with it.
    #[test]
    fn renumbering_moves_the_place() {
        let mut m = Reach::default();
        m.place(1, &[1], Uplink::Public, &[]);
        m.listen(1, [7; 32]);
        m.renumber(1, 5);
        assert_eq!(m.node_of(&[7; 32]), Some(5));
        assert!(m.lan_addr(5, 1).is_some() && m.lan_addr(1, 1).is_none());
    }
}
