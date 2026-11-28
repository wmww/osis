//! Links (spec/wire.md §10, spec/permissions.md §7): the canonical layout, caps and the text
//! form `osis://link/` + unpadded base64url. A link's peers are dial hints (`DialHint`).

use osis_base::base64url;
use crate::cbor::{get_bytes, get_tid, get_uint, tid};
use crate::Error;
use osis_base::cbor::{Limits, decode, encode};
use osis_base::format::MAX_URL_BYTES;
use osis_base::{SyncId, Tid, Value};
use osis_crypto::Secret32;

/// A node's dialable key and URLs: a dial hint (spec/wire.md §10 `peer`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DialHint {
    pub dialable: [u8; 32],
    pub urls: Vec<String>,
}

impl DialHint {
    /// `[dialable, [url*]]` (spec/wire.md §10 `peer`).
    pub fn to_value(&self) -> Value {
        Value::List(vec![Value::bytes(&self.dialable), Value::List(self.urls.iter().map(|u| Value::Str(u.clone())).collect())])
    }

    /// From `[dialable, [url*]]`: at most `max_urls` URLs, each at most `MAX_URL_BYTES`.
    pub fn from_value(v: &Value, max_urls: usize, what: &'static str) -> Result<DialHint, Error> {
        let Value::List(d) = v else { return Err(Error::Malformed(what)) };
        let [k, Value::List(urls)] = d.as_slice() else { return Err(Error::Malformed(what)) };
        if urls.len() > max_urls {
            return Err(Error::Malformed(what));
        }
        let urls = urls
            .iter()
            .map(|u| match u {
                Value::Str(u) if u.len() <= MAX_URL_BYTES => Ok(u.clone()),
                _ => Err(Error::Malformed(what)),
            })
            .collect::<Result<_, _>>()?;
        Ok(DialHint { dialable: get_bytes(k, "dialable key")?, urls })
    }
}

const MAX_PEERS: usize = 4;
const MAX_URLS: usize = 4;
const FORMAT: i64 = 1;
/// A locator's format (spec/wire.md §10).
const PUBLIC_FORMAT: i64 = 2;
const LINK_PREFIX: &str = "osis://link/";
/// Far above the largest layout the caps allow.
const LIMITS: Limits = Limits::new(8, 16 * 1024);

/// `Link := [1, seed, target, k, k_sync_id, [peer*], ? flags]` (spec/wire.md §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareLink {
    /// L's seed.
    pub seed: Secret32,
    pub target: Tid,
    pub k: Tid,
    pub k_sync_id: SyncId,
    /// The nodes to dial for first contact (spec/wire.md §10 `peer`).
    pub peers: Vec<DialHint>,
    /// `flags` bit 0: the redemption removes L's own grant (spec/permissions.md §7).
    pub single_use: bool,
}

/// A link's peers as a sharer node makes them (spec/wire.md §10): itself, `own` with one
/// `peer://` URL of its `relays` (relay items, in order, those that would take the URL past
/// 256 bytes left out), then each of its configured addresses `dial` of another key, in order,
/// while there is room.
pub fn link_peers(own: [u8; 32], relays: &[String], dial: &[crate::Address]) -> Vec<DialHint> {
    let mut items: Vec<String> = Vec::new();
    for r in relays {
        items.push(r.clone());
        if osis_base::peer_url(&items).len() > MAX_URL_BYTES {
            items.pop();
        }
    }
    let mut out = vec![DialHint { dialable: own, urls: vec![osis_base::peer_url(&items)] }];
    for a in dial {
        if out.len() == MAX_PEERS {
            break;
        }
        if a.url.len() <= MAX_URL_BYTES && !out.iter().any(|p| p.dialable == a.key) {
            out.push(DialHint { dialable: a.key, urls: vec![a.url.clone()] });
        }
    }
    out
}

/// `flags` bit 0 of a link.
const FLAG_SINGLE_USE: i64 = 1;

fn check_url(u: &str) -> Result<(), Error> {
    if u.len() > MAX_URL_BYTES {
        return Err(Error::Malformed("url longer than 256 bytes"));
    }
    Ok(())
}

/// A link's format: 1 a share link, 2 a locator (spec/wire.md §10).
fn format_of(v: &Value) -> Result<u64, Error> {
    match get_uint(v, "format")? {
        n @ (1 | 2) => Ok(n),
        n => Err(Error::UnknownVersion(n)),
    }
}

/// `[peer*]`, checked against the caps (spec/wire.md §10).
pub fn peers_value(peers: &[DialHint]) -> Result<Value, Error> {
    if peers.len() > MAX_PEERS {
        return Err(Error::Malformed("more than 4 peers"));
    }
    let mut out = Vec::with_capacity(peers.len());
    for p in peers {
        if p.urls.len() > MAX_URLS {
            return Err(Error::Malformed("more than 4 URLs"));
        }
        p.urls.iter().try_for_each(|r| check_url(r))?;
        out.push(p.to_value());
    }
    Ok(Value::List(out))
}

/// Peers from `[peer*]`, checked against the caps (spec/wire.md §10).
pub fn peers_from(peers: &[Value]) -> Result<Vec<DialHint>, Error> {
    if peers.len() > MAX_PEERS {
        return Err(Error::Malformed("more than 4 peers"));
    }
    peers.iter().map(|p| DialHint::from_value(p, MAX_URLS, "link peer")).collect()
}

fn text_of(v: &Value) -> String {
    format!("{LINK_PREFIX}{}", base64url::encode(&encode(v)))
}

fn value_of_text(s: &str) -> Result<Value, Error> {
    let rest = s.strip_prefix(LINK_PREFIX).ok_or(Error::Malformed("text form prefix"))?;
    if rest.len() > LIMITS.max_bytes * 2 {
        return Err(Error::Malformed("text form too long"));
    }
    Ok(decode(&base64url::decode(rest).ok_or(Error::Malformed("base64url"))?, &LIMITS)?)
}

/// A link of either format (spec/wire.md §10), as a redeemer reads its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    Share(ShareLink),
    Locator(Locator),
}

impl Link {
    /// The thing it names.
    pub fn target(&self) -> Tid {
        match self {
            Link::Share(l) => l.target,
            Link::Locator(l) => l.target,
        }
    }

    pub fn to_text(&self) -> Result<String, Error> {
        match self {
            Link::Share(l) => l.to_text(),
            Link::Locator(l) => l.to_text(),
        }
    }

    pub fn from_value(v: &Value) -> Result<Link, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("link")) };
        match format_of(items.first().ok_or(Error::Malformed("link"))?)? {
            1 => Ok(Link::Share(ShareLink::from_value(v)?)),
            _ => Ok(Link::Locator(Locator::from_value(v)?)),
        }
    }

    pub fn from_text(s: &str) -> Result<Link, Error> {
        Link::from_value(&value_of_text(s)?)
    }
}

/// `Link := [2, target, target_sync_id, [peer*], ? independent]` (spec/wire.md §10): a thing the
/// public reads, its independent's sync ID and the nodes to dial; no secret; `independent` the
/// thing the sync ID is of where the target is a dependent of it (spec/sync-set.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locator {
    pub target: Tid,
    pub sync_id: SyncId,
    pub peers: Vec<DialHint>,
    /// The thing the sync ID is of, where it is not the target (a dependent target's independent).
    pub independent: Option<Tid>,
}

impl Locator {
    /// The thing whose sync ID the redeemer follows: the target's independent.
    pub fn followed(&self) -> Tid {
        self.independent.unwrap_or(self.target)
    }

    pub fn to_value(&self) -> Result<Value, Error> {
        let mut v = vec![Value::Int(PUBLIC_FORMAT), tid(&self.target), Value::bytes(&self.sync_id.0), peers_value(&self.peers)?];
        v.extend(self.independent.as_ref().map(tid));
        Ok(Value::List(v))
    }

    pub fn from_value(v: &Value) -> Result<Locator, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("link")) };
        let (f, target, sync_id, peers, independent) = match items.as_slice() {
            [f, t, s, Value::List(p)] => (f, t, s, p, None),
            [f, t, s, Value::List(p), i] => (f, t, s, p, Some(i)),
            _ => return Err(Error::Malformed("link")),
        };
        if format_of(f)? != 2 {
            return Err(Error::Malformed("not a locator"));
        }
        let target = get_tid(target, "link target")?;
        let independent = independent.map(|i| get_tid(i, "link independent")).transpose()?;
        if independent == Some(target) {
            return Err(Error::Malformed("link independent is its target"));
        }
        Ok(Locator { target, sync_id: SyncId(get_bytes(sync_id, "link sync ID")?), peers: peers_from(peers)?, independent })
    }

    pub fn to_text(&self) -> Result<String, Error> {
        Ok(text_of(&self.to_value()?))
    }
}

impl ShareLink {
    /// The value the text form encodes (spec/wire.md §10); the conformance vectors and the link
    /// fuzz target build and judge it directly.
    pub fn to_value(&self) -> Result<Value, Error> {
        let mut v = vec![
            Value::Int(FORMAT),
            Value::bytes(self.seed.expose()),
            tid(&self.target),
            tid(&self.k),
            Value::bytes(&self.k_sync_id.0),
            peers_value(&self.peers)?,
        ];
        // `flags` only when a bit is set: one encoding per link
        if self.single_use {
            v.push(Value::Int(FLAG_SINGLE_USE));
        }
        Ok(Value::List(v))
    }

    pub fn from_value(v: &Value) -> Result<ShareLink, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("link")) };
        let (f, rest) = items.split_first().ok_or(Error::Malformed("link"))?;
        if format_of(f)? != 1 {
            return Err(Error::Malformed("not a share link"));
        }
        let (rest, single_use) = match rest {
            [head @ .., flags] if rest.len() == 6 => {
                let f = get_uint(flags, "link flags")?;
                if f == 0 || f & !(FLAG_SINGLE_USE as u64) != 0 {
                    return Err(Error::Malformed("link flags"));
                }
                (head, true)
            }
            _ => (rest, false),
        };
        let [seed, target, k, k_sync_id, Value::List(peers)] = rest else { return Err(Error::Malformed("link")) };
        if peers.len() > MAX_PEERS {
            return Err(Error::Malformed("more than 4 peers"));
        }
        let peers = peers.iter().map(|p| DialHint::from_value(p, MAX_URLS, "link peer")).collect::<Result<_, _>>()?;
        Ok(ShareLink {
            seed: Secret32::from_bytes(get_bytes(seed, "link seed")?),
            target: get_tid(target, "link target")?,
            k: get_tid(k, "link k")?,
            k_sync_id: SyncId(get_bytes(k_sync_id, "link sync ID")?),
            peers,
            single_use,
        })
    }

    pub fn to_text(&self) -> Result<String, Error> {
        Ok(text_of(&self.to_value()?))
    }

    /// A share link's text (a locator's is no share link: `Link::from_text` reads either).
    pub fn from_text(s: &str) -> Result<ShareLink, Error> {
        ShareLink::from_value(&value_of_text(s)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn link() -> ShareLink {
        ShareLink {
            seed: Secret32::from_bytes([1; 32]),
            target: Tid::from_bytes([2; 15]),
            k: Tid::from_bytes([3; 15]),
            k_sync_id: SyncId([4; 16]),
            peers: vec![DialHint { dialable: [6; 32], urls: vec!["quic://example.org:4040".into()] }],
            single_use: false,
        }
    }

    // spec/wire.md §10 (reserved flags): `flags` is present only with a bit set; a zero or
    // unknown flag is refused.
    #[test]
    fn flags() {
        let mut l = link();
        assert!(matches!(l.to_value().unwrap(), Value::List(v) if v.len() == 6));
        l.single_use = true;
        let v = l.to_value().unwrap();
        assert!(matches!(&v, Value::List(x) if x.len() == 7 && x[6] == Value::Int(1)));
        assert_eq!(ShareLink::from_value(&v).unwrap(), l);
        for bad in [0, 2, 3] {
            let mut v = v.clone();
            if let Value::List(x) = &mut v {
                x[6] = Value::Int(bad);
            }
            assert!(ShareLink::from_value(&v).is_err(), "flags {bad}");
        }
    }

    // spec/wire.md §10: the link layout and text form round trip, with and without peers;
    // the seed is not printed by Debug.
    #[test]
    fn round_trips() {
        let l = link();
        let t = l.to_text().unwrap();
        assert!(t.starts_with("osis://link/"));
        assert_eq!(ShareLink::from_text(&t).unwrap(), l);
        let mut bare = link();
        bare.peers.clear();
        assert_eq!(ShareLink::from_text(&bare.to_text().unwrap()).unwrap(), bare);
        assert!(!format!("{l:?}").contains("[1, 1"));
    }

    // spec/wire.md §10 (the nodes to dial for first contact): the sharer first, its relays as one `peer://` URL, those
    // that would take it past 256 bytes left out; then its configured addresses of other keys, in
    // order, up to 4 peers.
    #[test]
    fn peers_are_the_sharer_then_its_configured_addresses() {
        let relay = |b: u8| format!("{}@[2001:db8::{b}]:4040", "ab".repeat(32));
        let at = |k: u8| crate::Address { url: format!("quic://n{k}.example:4040"), key: [k; 32] };
        let p = link_peers([1; 32], &[relay(1), relay(2), relay(3)], &[at(1), at(2), at(2), at(3), at(4), at(5)]);
        assert_eq!(p[0].urls, vec![format!("peer://{} {}", relay(1), relay(2))], "a third relay would pass 256 bytes");
        assert_eq!(p.iter().map(|x| x.dialable[0]).collect::<Vec<_>>(), [1, 2, 3, 4], "own key once, then in order, distinct");
        assert_eq!(p[1].urls, vec![at(2).url]);
        assert_eq!(link_peers([1; 32], &[], &[])[0].urls, vec!["peer://".to_string()], "no relay: LAN only");
    }

    // spec/wire.md §10: caps (4 peers, 4 URLs per peer, 256-byte URLs); an unknown format
    // parks.
    #[test]
    fn caps() {
        let mut l = link();
        l.peers = vec![l.peers[0].clone(); 5];
        assert!(l.to_value().is_err());
        let mut l = link();
        l.peers[0].urls = vec!["r".into(); 5];
        assert!(l.to_value().is_err());
        let mut l = link();
        l.peers[0].urls = vec!["r".repeat(257)];
        assert!(l.to_value().is_err());
        let mut v = link().to_value().unwrap();
        if let Value::List(items) = &mut v {
            items[0] = Value::Int(3);
        }
        assert_eq!(Link::from_value(&v), Err(Error::UnknownVersion(3)));
        assert!(ShareLink::from_text("osis://link/!!").is_err());
    }

    // spec/wire.md §10 (locator): format 2, target, its sync ID and peers, no seed, and a
    // dependent target's independent; read as a locator only, its text round trips.
    #[test]
    fn locators() {
        let l = link();
        let k = l.k;
        let p = Locator { target: l.target, sync_id: l.k_sync_id, peers: l.peers.clone(), independent: None };
        let t = p.to_text().unwrap();
        assert_eq!(Link::from_text(&t).unwrap(), Link::Locator(p.clone()));
        assert_eq!(Link::from_text(&l.to_text().unwrap()).unwrap(), Link::Share(l));
        assert!(ShareLink::from_text(&t).is_err(), "a locator is no share link");
        let Value::List(mut items) = p.to_value().unwrap() else { panic!() };
        items.push(Value::Int(1));
        assert!(Link::from_value(&Value::List(items.clone())).is_err(), "no flags");
        let d = Locator { independent: Some(k), ..p.clone() };
        assert_eq!(Link::from_text(&d.to_text().unwrap()).unwrap(), Link::Locator(d.clone()), "a dependent target names its independent");
        let same = Locator { independent: Some(p.target), ..p };
        assert!(Link::from_text(&same.to_text().unwrap()).is_err(), "an independent target names none");
        let Value::List(mut items) = d.to_value().unwrap() else { panic!() };
        items.push(Value::Int(1));
        assert!(Link::from_value(&Value::List(items)).is_err(), "nothing past the independent");
    }
}
