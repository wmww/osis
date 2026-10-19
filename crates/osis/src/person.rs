//! The person across devices (spec/permissions.md §1, §9; notes/api.md Handle and lifecycle):
//! restoring from a recovery card on a fresh device, and pairing a new device. Pairing is
//! transport-agnostic: the app carries two messages between the devices (QR, clipboard, a local
//! socket): the new device's request (its node card) and the existing device's reply (the grant
//! and the commits it needs), both authenticated by the offer's one-time secret.

use crate::error::{Error, Result};
use crate::handle::{Fresh, Osis, PERSON, fresh_engine, save_servers};
use crate::share::{RecoveryCard, ServerAddr, SyncState};
use crate::Config;
use osis_core::cbor::{Limits, decode, encode};
use osis_core::{BlobId, CommitId, Tid, Value, base64url};
use osis_node::flows::PreSync;
use osis_node::local_peer::Package;

/// How long a pairing offer can be accepted.
pub const OFFER_LIFETIME_MS: u64 = 10 * 60_000;

const OFFER: &str = "osis://pair/";
const REQUEST: &str = "osis://pair-request/";
const REPLY: &str = "osis://pair-reply/";

macro_rules! pair_text {
    ($(#[$m:meta])* $n:ident, $prefix:expr) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $n(String);
        impl std::str::FromStr for $n {
            type Err = Error;
            fn from_str(s: &str) -> Result<$n> {
                let s = s.trim();
                unpack(s, $prefix)?;
                Ok($n(s.to_string()))
            }
        }
        impl std::fmt::Display for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl std::fmt::Debug for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($n), "(..)"))
            }
        }
    };
}

pair_text!(
    /// A short-lived offer to pair a new device, made on an existing one (holds a one-time
    /// secret: show it only to the new device).
    PairOffer,
    OFFER
);
pair_text!(
    /// The new device's answer to an offer, for `Osis::pair_accept` on the offering device.
    PairRequest,
    REQUEST
);
pair_text!(
    /// The offering device's answer to a request, for `Joining::finish` on the new device.
    PairReply,
    REPLY
);

fn pack(prefix: &str, v: &Value) -> String {
    format!("{prefix}{}", base64url::encode(&encode(v)))
}

fn unpack(s: &str, prefix: &str) -> Result<Vec<Value>> {
    let bad = || Error::Invalid("malformed pairing message".into());
    let b = s.strip_prefix(prefix).and_then(base64url::decode).ok_or_else(bad)?;
    match decode(&b, &Limits { max_depth: 8, max_bytes: b.len() }).map_err(|_| bad())? {
        Value::List(items) if items.first() == Some(&Value::Int(1)) => Ok(items),
        _ => Err(bad()),
    }
}

fn mac(secret: &[u8; 32], purpose: &str, body: &Value) -> Vec<u8> {
    osis_crypto::kdf::kdf(purpose, secret, &encode(body)).expose().to_vec()
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn packages_value(pks: &[Package]) -> Value {
    Value::List(pks.iter().map(|p| Value::List(vec![Value::Bytes(p.bytes.clone()), Value::List(p.blobs.iter().map(|(id, b)| Value::List(vec![Value::Bytes(id.0.to_vec()), Value::Bytes(b.clone())])).collect())])).collect())
}

/// Commit bytes with their blobs.
type Packages = Vec<(Vec<u8>, Vec<(BlobId, Vec<u8>)>)>;

fn packages_of(v: &Value) -> Result<Packages> {
    let bad = || Error::Invalid("malformed pairing packages".into());
    let Value::List(items) = v else { return Err(bad()) };
    let mut out = Vec::new();
    for i in items {
        let Value::List(f) = i else { return Err(bad()) };
        let [Value::Bytes(bytes), Value::List(blobs)] = f.as_slice() else { return Err(bad()) };
        let mut bs = Vec::new();
        for b in blobs {
            let Value::List(x) = b else { return Err(bad()) };
            let [Value::Bytes(id), Value::Bytes(data)] = x.as_slice() else { return Err(bad()) };
            bs.push((BlobId(id.as_slice().try_into().map_err(|_| bad())?), data.clone()));
        }
        out.push((bytes.clone(), bs));
    }
    Ok(out)
}

/// A new device waiting for the offering device's reply.
pub struct Joining {
    db: Osis,
    secret: [u8; 32],
    person: Tid,
    request: PairRequest,
}

impl std::fmt::Debug for Joining {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Joining({})", self.db.node())
    }
}

impl Joining {
    /// The request to carry to the offering device.
    pub fn request(&self) -> &PairRequest {
        &self.request
    }

    /// This new device's node tid.
    pub fn node(&self) -> Tid {
        self.db.node()
    }

    /// Takes the offering device's reply: applies the grant and what came with it, places the
    /// grant's certificate copy under the home label (spec/sync.md §3) and returns the
    /// database, now a device of the person.
    pub fn finish(self, reply: &PairReply) -> Result<Osis> {
        let items = unpack(&reply.0, REPLY)?;
        let [_, Value::Bytes(grant), pks, Value::Bytes(tag)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing reply".into())) };
        let body = Value::List(vec![Value::Int(1), Value::Bytes(grant.clone()), pks.clone()]);
        if !same(&mac(&self.secret, "osis pair reply", &body), tag) {
            return Err(Error::Invalid("pairing reply does not match the offer".into()));
        }
        let grant = CommitId(grant.as_slice().try_into().map_err(|_| Error::Invalid("malformed pairing reply".into()))?);
        let pks = packages_of(pks)?;
        let person = self.person;
        let done = self.db.engine(|e| -> Result<_> {
            for (bytes, blobs) in pks {
                e.ingest(&bytes, blobs)?;
            }
            let done = e.paired(&person, &grant).map_err(|_| Error::Invalid("pairing reply: this device was not made an admin of the person".into()))?;
            e.set_app_record(PERSON, person.as_bytes())?;
            Ok(done)
        })?;
        let servers = self.db.servers()?;
        self.db.engine(|e| save_servers(e, &servers))?;
        self.db.carry(done)?;
        Ok(self.db)
    }
}

impl Osis {
    /// Restores the person of a recovery card on this fresh device (spec/permissions.md §9):
    /// claims the home label by the card's key, downloads it, then (signing as the recovery key)
    /// makes this node an admin of the person. Needs a runtime; the card's servers are added
    /// to `Config.servers`. Fails `Network` after `Config::wait_timeout`; on any failure (or a
    /// dropped future) the recovery key is forgotten and the store gets no person record (it
    /// does not open as a database; use a fresh store for the next attempt).
    pub async fn restore(cfg: Config, card: &RecoveryCard) -> Result<Osis> {
        let c = card.parse()?;
        let mut servers = cfg.servers.clone();
        for a in &c.servers {
            let a = ServerAddr(a.clone());
            if !servers.contains(&a) {
                servers.push(a);
            }
        }
        let Fresh { mut sync, clock } = fresh_engine(&cfg, &servers)?;
        let engine = sync.engine_mut();
        let r = engine.hold_key_actor(c.seed.clone())?;
        save_servers(engine, &servers)?;
        let db = Osis::start(sync, clock, &cfg, c.person)?;
        let key = crate::share::KeyGuard { db: db.downgrade(), l: r };
        db.locked(|x| {
            let acts = x.sync.follow(c.person, c.home_label, c.servers.clone());
            db.inner.net.apply(acts);
        });
        let p = c.person;
        db.wait_until(Some(db.inner.wait_timeout), Box::new(move |s, st| (s.engine().knows(&p) && st.groups.get(&p).is_some_and(|g| g.state == SyncState::Synced)).then_some(Ok(())))).await?;
        let done = db.engine(|e| e.recover(&c, &[], PreSync::Synced))?;
        drop(key);
        db.carry(done)?;
        // the person record last: a store without it is no osis database yet
        db.engine(|e| e.set_app_record(PERSON, c.person.as_bytes()))?;
        Ok(db)
    }

    /// An offer to pair a new device (valid `OFFER_LIFETIME_MS`, once): the new device runs
    /// `Osis::pair` with it and the app carries the request back to `pair_accept`. Whoever holds
    /// the offer can make their device a full admin device of this person until it is used or
    /// expires (10 minutes): show it only to the new device.
    pub fn pair_offer(&self) -> Result<PairOffer> {
        let (me, node) = (self.me(), self.node());
        let servers: Vec<Value> = self.servers()?.iter().map(|s| Value::Str(s.to_string())).collect();
        let now = self.inner.clock.now_wall_ms().0;
        let secret = self.locked(|x| {
            let mut s = [0u8; 32];
            osis_crypto::RngCore::fill_bytes(&mut osis_crypto::OsRng, &mut s);
            x.offers.retain(|(_, until)| *until > now);
            x.offers.push((s, now.saturating_add(OFFER_LIFETIME_MS)));
            s
        });
        Ok(PairOffer(pack(OFFER, &Value::List(vec![Value::Int(1), Value::Tid(me), Value::Tid(node), Value::Bytes(secret.to_vec()), Value::List(servers)]))))
    }

    /// Accepts a new device's request to an offer of this device: makes it an admin of the
    /// person (or re-seals a device already one, notes/sync.md Limits) and returns its node tid
    /// with the reply to carry back.
    pub fn pair_accept(&self, req: &PairRequest) -> Result<(Tid, PairReply)> {
        let items = unpack(&req.0, REQUEST)?;
        let [_, Value::Tid(node), pks, Value::Bytes(tag)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing request".into())) };
        let body = Value::List(vec![Value::Int(1), Value::Tid(*node), pks.clone()]);
        let now = self.inner.clock.now_wall_ms().0;
        let secret = self
            .locked(|x| {
                x.offers.retain(|(_, until)| *until > now);
                let i = x.offers.iter().position(|(s, _)| same(&mac(s, "osis pair request", &body), tag))?;
                Some(x.offers.remove(i).0)
            })
            .ok_or(Error::Invalid("pairing request matches no open offer".into()))?;
        let node = *node;
        let pks = packages_of(pks)?;
        let me = self.me();
        let (grant, mine) = self.locked(|x| -> Result<(CommitId, Vec<Package>)> {
            for (bytes, blobs) in pks {
                x.engine().ingest(&bytes, blobs)?;
            }
            let done = x.engine().pair(&me, &node)?;
            let grant = *done.commits.last().ok_or(Error::Invalid("pairing made no commit".into()))?;
            let acts = x.sync.carry_out(done)?;
            self.inner.net.apply(acts);
            let mine = x.sync.take_direct_for(&node);
            Ok((grant, mine))
        })?;
        let body = Value::List(vec![Value::Int(1), Value::Bytes(grant.0.to_vec()), packages_value(&mine)]);
        let tag = mac(&secret, "osis pair reply", &body);
        let Value::List(mut v) = body else { return Err(Error::Invalid("pairing reply".into())) };
        v.push(Value::Bytes(tag));
        Ok((node, PairReply(pack(REPLY, &Value::List(v)))))
    }

    /// Starts pairing this fresh store as a new device of the person that made `offer`: returns
    /// the request to carry to the offering device and, with its reply, `Joining::finish`.
    pub fn pair(cfg: Config, offer: &PairOffer) -> Result<Joining> {
        let items = unpack(&offer.0, OFFER)?;
        let [_, Value::Tid(person), Value::Tid(_), Value::Bytes(secret), Value::List(addrs)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing offer".into())) };
        let secret: [u8; 32] = secret.as_slice().try_into().map_err(|_| Error::Invalid("malformed pairing offer".into()))?;
        let mut servers = cfg.servers.clone();
        for a in addrs {
            let Value::Str(s) = a else { return Err(Error::Invalid("malformed pairing offer".into())) };
            let a: ServerAddr = s.parse()?;
            if !servers.contains(&a) {
                servers.push(a);
            }
        }
        let Fresh { sync, clock } = fresh_engine(&cfg, &servers)?;
        let db = Osis::start(sync, clock, &cfg, *person)?;
        let node = db.node();
        let pks = db.engine(|e| -> Result<Vec<Package>> {
            let ids = e.commit_ids();
            let mut v = Vec::new();
            for id in ids {
                v.extend(e.package(&id)?);
            }
            Ok(v)
        })?;
        let body = Value::List(vec![Value::Int(1), Value::Tid(node), packages_value(&pks)]);
        let tag = mac(&secret, "osis pair request", &body);
        let Value::List(mut v) = body else { return Err(Error::Invalid("pairing request".into())) };
        v.push(Value::Bytes(tag));
        Ok(Joining { db, secret, person: *person, request: PairRequest(pack(REQUEST, &Value::List(v))) })
    }
}
