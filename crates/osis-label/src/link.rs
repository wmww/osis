//! Links and recovery cards (spec/wire.md §10, spec/permissions.md §9): canonical layouts, caps
//! and text forms `osis://link/` / `osis://card/` + unpadded base64url.

use crate::addr::{Address, address_from_value, b64_decode, b64_encode};
use crate::auth::{get_bytes, get_uint};
use crate::Error;
use osis_core::cbor::{Limits, decode, encode};
use osis_core::format::MAX_URL_BYTES;
use osis_core::{LabelId, Tid, Value};
use osis_crypto::Secret32;
use osis_schema::Codec;

pub const MAX_ADDRESSES: usize = 8;
pub const MAX_PEERS: usize = 4;
pub const MAX_RELAYS: usize = 4;
const FORMAT: i64 = 1;
const LINK_PREFIX: &str = "osis://link/";
const CARD_PREFIX: &str = "osis://card/";
/// Far above the largest layout the caps allow.
const LIMITS: Limits = Limits { max_depth: 8, max_bytes: 16 * 1024 };

/// A sharer node's P2P reach for first contact: dialable key and relay URLs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub dialable: [u8; 32],
    pub relays: Vec<String>,
}

/// `Link := [1, seed, target, k, k_label, [address*], [peer*]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareLink {
    /// L's seed.
    pub seed: Secret32,
    pub target: Tid,
    pub k: Tid,
    pub k_label: LabelId,
    pub servers: Vec<Address>,
    pub peers: Vec<Peer>,
}

/// `Card := [1, seed, person, home_label, [address+]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryCard {
    /// The recovery key's seed.
    pub seed: Secret32,
    pub person: Tid,
    pub home_label: LabelId,
    pub servers: Vec<Address>,
}

fn tid(t: &Tid) -> Value {
    Value::Bytes(t.as_bytes().to_vec())
}

fn check_url(u: &str) -> Result<(), Error> {
    if u.len() > MAX_URL_BYTES {
        return Err(Error::Malformed("url longer than 256 bytes"));
    }
    Ok(())
}

fn servers_value(s: &[Address]) -> Result<Value, Error> {
    if s.len() > MAX_ADDRESSES {
        return Err(Error::Malformed("more than 8 addresses"));
    }
    s.iter().try_for_each(|a| check_url(&a.url))?;
    Ok(Value::List(s.iter().map(Codec::to_value).collect()))
}

fn get_servers(v: &Value) -> Result<Vec<Address>, Error> {
    let Value::List(l) = v else { return Err(Error::Malformed("addresses")) };
    if l.len() > MAX_ADDRESSES {
        return Err(Error::Malformed("more than 8 addresses"));
    }
    l.iter().map(address_from_value).collect()
}

fn format_of(v: &Value) -> Result<(), Error> {
    match get_uint(v, "format")? {
        1 => Ok(()),
        n => Err(Error::UnknownFormat(n)),
    }
}

fn from_text(s: &str, prefix: &str) -> Result<Value, Error> {
    let rest = s.strip_prefix(prefix).ok_or(Error::Malformed("text form prefix"))?;
    if rest.len() > LIMITS.max_bytes * 2 {
        return Err(Error::Malformed("text form too long"));
    }
    Ok(decode(&b64_decode(rest)?, &LIMITS)?)
}

impl ShareLink {
    pub fn to_value(&self) -> Result<Value, Error> {
        if self.peers.len() > MAX_PEERS {
            return Err(Error::Malformed("more than 4 peers"));
        }
        let mut peers = Vec::with_capacity(self.peers.len());
        for p in &self.peers {
            if p.relays.len() > MAX_RELAYS {
                return Err(Error::Malformed("more than 4 relays"));
            }
            p.relays.iter().try_for_each(|r| check_url(r))?;
            peers.push(Value::List(vec![Value::Bytes(p.dialable.to_vec()), Value::List(p.relays.iter().map(|r| Value::Str(r.clone())).collect())]));
        }
        Ok(Value::List(vec![
            Value::Int(FORMAT),
            Value::Bytes(self.seed.expose().to_vec()),
            tid(&self.target),
            tid(&self.k),
            Value::Bytes(self.k_label.0.to_vec()),
            servers_value(&self.servers)?,
            Value::List(peers),
        ]))
    }

    pub fn from_value(v: &Value) -> Result<ShareLink, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("link")) };
        let (f, rest) = items.split_first().ok_or(Error::Malformed("link"))?;
        format_of(f)?;
        let [seed, target, k, k_label, servers, Value::List(peers)] = rest else { return Err(Error::Malformed("link")) };
        if peers.len() > MAX_PEERS {
            return Err(Error::Malformed("more than 4 peers"));
        }
        let peers = peers
            .iter()
            .map(|p| {
                let Value::List(f) = p else { return Err(Error::Malformed("peer")) };
                let [dialable, Value::List(relays)] = f.as_slice() else { return Err(Error::Malformed("peer")) };
                if relays.len() > MAX_RELAYS {
                    return Err(Error::Malformed("more than 4 relays"));
                }
                let relays = relays
                    .iter()
                    .map(|r| match r {
                        Value::Str(s) => check_url(s).map(|()| s.clone()),
                        _ => Err(Error::Malformed("relay")),
                    })
                    .collect::<Result<_, _>>()?;
                Ok(Peer { dialable: get_bytes(dialable, "dialable key")?, relays })
            })
            .collect::<Result<_, _>>()?;
        Ok(ShareLink {
            seed: Secret32::from_bytes(get_bytes(seed, "link seed")?),
            target: Tid::from_bytes(get_bytes(target, "link target")?),
            k: Tid::from_bytes(get_bytes(k, "link k")?),
            k_label: LabelId(get_bytes(k_label, "link label")?),
            servers: get_servers(servers)?,
            peers,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(encode(&self.to_value()?))
    }

    pub fn to_text(&self) -> Result<String, Error> {
        Ok(format!("{LINK_PREFIX}{}", b64_encode(&self.to_bytes()?)))
    }

    pub fn from_text(s: &str) -> Result<ShareLink, Error> {
        ShareLink::from_value(&from_text(s, LINK_PREFIX)?)
    }
}

impl RecoveryCard {
    pub fn to_value(&self) -> Result<Value, Error> {
        if self.servers.is_empty() {
            return Err(Error::Malformed("card without addresses"));
        }
        Ok(Value::List(vec![
            Value::Int(FORMAT),
            Value::Bytes(self.seed.expose().to_vec()),
            tid(&self.person),
            Value::Bytes(self.home_label.0.to_vec()),
            servers_value(&self.servers)?,
        ]))
    }

    pub fn from_value(v: &Value) -> Result<RecoveryCard, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("card")) };
        let (f, rest) = items.split_first().ok_or(Error::Malformed("card"))?;
        format_of(f)?;
        let [seed, person, home, servers] = rest else { return Err(Error::Malformed("card")) };
        let servers = get_servers(servers)?;
        if servers.is_empty() {
            return Err(Error::Malformed("card without addresses"));
        }
        Ok(RecoveryCard {
            seed: Secret32::from_bytes(get_bytes(seed, "card seed")?),
            person: Tid::from_bytes(get_bytes(person, "card person")?),
            home_label: LabelId(get_bytes(home, "card label")?),
            servers,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(encode(&self.to_value()?))
    }

    pub fn to_text(&self) -> Result<String, Error> {
        Ok(format!("{CARD_PREFIX}{}", b64_encode(&self.to_bytes()?)))
    }

    pub fn from_text(s: &str) -> Result<RecoveryCard, Error> {
        RecoveryCard::from_value(&from_text(s, CARD_PREFIX)?)
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
            k_label: LabelId([4; 16]),
            servers: vec![Address { url: "quic://a".into(), key: [5; 32] }],
            peers: vec![Peer { dialable: [6; 32], relays: vec!["https://relay".into()] }],
        }
    }

    // spec/wire.md §10: link and card layouts and text forms round trip, with and without peers;
    // the seed is not printed by Debug.
    #[test]
    fn round_trips() {
        let l = link();
        let t = l.to_text().unwrap();
        assert!(t.starts_with("osis://link/"));
        assert_eq!(ShareLink::from_text(&t).unwrap(), l);
        let mut bare = link();
        bare.peers.clear();
        bare.servers.clear();
        assert_eq!(ShareLink::from_text(&bare.to_text().unwrap()).unwrap(), bare);
        let c = RecoveryCard { seed: Secret32::from_bytes([7; 32]), person: Tid::from_bytes([8; 15]), home_label: LabelId([9; 16]), servers: l.servers.clone() };
        assert_eq!(RecoveryCard::from_text(&c.to_text().unwrap()).unwrap(), c);
        assert!(ShareLink::from_text(&c.to_text().unwrap()).is_err());
        assert!(!format!("{l:?}").contains("[1, 1"));
    }

    // spec/wire.md §10: caps (8 addresses, 4 peers, 4 relays, 256-byte URLs), a card needs an
    // address, an unknown format parks.
    #[test]
    fn caps() {
        let a = Address { url: "quic://a".into(), key: [5; 32] };
        let mut l = link();
        l.servers = vec![a.clone(); 9];
        assert!(l.to_value().is_err());
        let mut v = link().to_value().unwrap();
        if let Value::List(items) = &mut v {
            items[5] = Value::List(vec![a.to_value(); 9]);
        }
        assert!(ShareLink::from_value(&v).is_err());
        let mut l = link();
        l.peers = vec![l.peers[0].clone(); 5];
        assert!(l.to_value().is_err());
        let mut l = link();
        l.peers[0].relays = vec!["r".into(); 5];
        assert!(l.to_value().is_err());
        let mut l = link();
        l.peers[0].relays = vec!["r".repeat(257)];
        assert!(l.to_value().is_err());
        let mut v = link().to_value().unwrap();
        if let Value::List(items) = &mut v {
            items[0] = Value::Int(2);
        }
        assert_eq!(ShareLink::from_value(&v), Err(Error::UnknownFormat(2)));
        let c = RecoveryCard { seed: Secret32::from_bytes([7; 32]), person: Tid::from_bytes([8; 15]), home_label: LabelId([9; 16]), servers: vec![] };
        assert!(c.to_value().is_err());
        assert!(ShareLink::from_text("osis://link/!!").is_err());
    }
}
