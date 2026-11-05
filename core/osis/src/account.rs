//! The account across nodes (spec/permissions.md §1, §8; notes/api.md Handle and lifecycle):
//! restoring from a recovery card on a fresh node, and pairing a new node. Pairing is
//! transport-agnostic: the app carries two messages between the nodes (QR, clipboard, a local
//! socket): the new node's request (its node card) and the existing node's reply (the grant
//! and the commits it needs), both authenticated by the offer's one-time secret.

use crate::error::{Error, Result};
use crate::handle::{Fresh, Osis, PERSON, fresh_engine, save_hosts};
use crate::share::{RecoveryCard, Address, SyncState};
use crate::{Config, Store};
use osis_base::cbor::{Limits, decode, encode};
use osis_base::{BlobId, CommitId as RawCommitId, Tid, Value, base64url};
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
    /// A short-lived offer to pair a new node, made on an existing one (holds a one-time
    /// secret: show it only to the new node).
    PairOffer,
    OFFER
);
pair_text!(
    /// The new node's answer to an offer, for `Osis::pair_accept` on the offering node.
    PairRequest,
    REQUEST
);
pair_text!(
    /// The offering node's answer to a request, for `Joining::finish` on the new node.
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

/// The message `[1, items.., tag]` with `prefix`; the tag MACs `[1, items..]`.
fn seal(prefix: &str, secret: &[u8; 32], purpose: &str, items: Vec<Value>) -> String {
    let mut v = vec![Value::Int(1)];
    v.extend(items);
    let tag = mac(secret, purpose, &Value::List(v.clone()));
    v.push(Value::Bytes(tag));
    pack(prefix, &Value::List(v))
}

/// Whether an unpacked message's last item is its tag under `secret`.
fn tag_ok(secret: &[u8; 32], purpose: &str, items: &[Value]) -> bool {
    let Some((Value::Bytes(tag), body)) = items.split_last() else { return false };
    same(&mac(secret, purpose, &Value::List(body.to_vec())), tag)
}

/// `hosts` plus those of `more` it lacks.
fn with_hosts(hosts: &[Address], more: Vec<Address>) -> Vec<Address> {
    let mut hosts = hosts.to_vec();
    for a in more {
        if !hosts.contains(&a) {
            hosts.push(a);
        }
    }
    hosts
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

/// A new node waiting for the offering node's reply.
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
    /// The request to carry to the offering node.
    pub fn request(&self) -> &PairRequest {
        &self.request
    }

    /// This new node's node tid (`internals::joining_node`).
    pub(crate) fn node(&self) -> Tid {
        self.db.node()
    }

    /// Takes the offering node's reply and returns the node, now a node of the account.
    pub fn finish(self, reply: &PairReply) -> Result<Osis> {
        let items = unpack(&reply.0, REPLY)?;
        let [_, Value::Bytes(grant), pks, Value::Bytes(_)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing reply".into())) };
        if !tag_ok(&self.secret, "osis pair reply", &items) {
            return Err(Error::Invalid("pairing reply does not match the offer".into()));
        }
        let grant = RawCommitId(grant.as_slice().try_into().map_err(|_| Error::Invalid("malformed pairing reply".into()))?);
        let pks = packages_of(pks)?;
        let person = self.person;
        let done = self.db.engine(|e| -> Result<_> {
            for (bytes, blobs) in pks {
                e.ingest(&bytes, blobs)?;
            }
            let done = e.paired(&person, &grant).map_err(|_| Error::Invalid("pairing reply: this node was not made an admin of the account".into()))?;
            e.set_app_record(PERSON, person.as_bytes())?;
            Ok(done)
        })?;
        let hosts = self.db.saved_peers()?;
        self.db.engine(|e| save_hosts(e, &hosts))?;
        self.db.carry(done)?;
        Ok(self.db)
    }
}

impl Osis {
    /// Restores the account of a recovery card on this fresh node: downloads its home group by the
    /// card's key, then makes this node an admin of the account. Needs a runtime; the card's peers
    /// join `peers`. `Invalid` when they refuse the card's key; `Unsynced` when the home group stops
    /// opening under this attempt's keys (it changed meanwhile: try again); with nobody answering
    /// it waits. On any failure, or a dropped future, the recovery key is forgotten and the store
    /// does not open: use a fresh store for the next attempt.
    pub async fn restore(store: Store, peers: &[Address], card: &RecoveryCard, cfg: Config) -> Result<Osis> {
        cfg.check(peers)?;
        let c = card.parse()?;
        let peers = with_hosts(peers, c.hosts.iter().cloned().map(Address).collect());
        let Fresh { mut sync, clock } = fresh_engine(&store, &cfg, &peers)?;
        let engine = sync.engine_mut();
        let r = engine.hold_key_actor(c.seed.clone())?;
        save_hosts(engine, &peers)?;
        let db = Osis::start(sync, clock, store, &cfg, c.person)?;
        let key = crate::share::KeyGuard { db: db.downgrade(), l: r, link: None };
        db.act(|x| x.sync.follow(r, c.person, c.home_label, c.hosts.clone()));
        let (p, home) = (c.person, c.home_label);
        db.wait_until(None, Box::new(move |s, st, _| {
            if s.static_entry_refused(&home) {
                return Some(Err(Error::Invalid("this recovery card no longer works".into())));
            }
            // `Stranded`: the head moved while this read the roster that lists the card's key, and
            // nothing here opens it now. A fresh attempt opens the new head.
            match st.groups.get(&p).map(|g| g.state) {
                Some(SyncState::Stranded) => Some(Err(Error::Unsynced { groups: vec![p] })),
                Some(SyncState::Synced) if s.engine().knows(&p) => Some(Ok(())),
                _ => None,
            }
        }))
        .await?;
        let done = db.engine(|e| e.recover(&c, &[], PreSync::Synced))?;
        drop(key);
        db.carry(done)?;
        // the account record last: a store without it is no osis node yet
        db.engine(|e| e.set_app_record(PERSON, c.person.as_bytes()))?;
        Ok(db)
    }

    /// An offer to pair a new node, good once: the new node runs
    /// `Osis::pair` with it and the app carries the request back to `pair_accept`. Whoever holds
    /// the offer can make their node a full admin node of this account until it is used or
    /// expires (10 minutes): show it only to the new node.
    /// `Unsupported` on a client with its own actor.
    pub fn pair_offer(&self) -> Result<PairOffer> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::PAIR_OFFER, vec![])?;
            return crate::port::codec::Args::of(vec![v]).text()?.parse();
        }
        let (me, node) = (self.me(), self.node());
        let hosts: Vec<Value> = self.saved_peers()?.iter().map(|s| Value::Str(s.to_string())).collect();
        let now = self.inner.clock.now_wall_ms().0;
        let secret = self.locked(|x| {
            let mut s = [0u8; 32];
            osis_crypto::RngCore::fill_bytes(&mut osis_crypto::OsRng, &mut s);
            x.offers.retain(|(_, until)| *until > now);
            x.offers.push((s, now.saturating_add(OFFER_LIFETIME_MS)));
            s
        });
        Ok(PairOffer(pack(OFFER, &Value::List(vec![Value::Int(1), Value::Tid(me), Value::Tid(node), Value::Bytes(secret.to_vec()), Value::List(hosts)]))))
    }

    /// Accepts a new node's request to an offer of this node: makes it an admin of the
    /// account (or lets back in a node already one) and returns its node tid
    /// with the reply to carry back.
    /// `Unsupported` on a client with its own actor.
    pub fn pair_accept(&self, req: &PairRequest) -> Result<(Tid, PairReply)> {
        if !self.has_store() {
            // once: a `TooLarge` retry would find the offer used
            let v = self.primary_call_big(crate::port::method::PAIR_ACCEPT, vec![Value::Str(req.to_string())], osis_proto::serving::REPLY_BUDGET)?;
            let mut a = crate::port::codec::Args::new(v)?;
            return Ok((a.tid()?, a.text()?.parse()?));
        }
        let items = unpack(&req.0, REQUEST)?;
        let [_, Value::Tid(node), pks, Value::Bytes(_)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing request".into())) };
        let now = self.inner.clock.now_wall_ms().0;
        let secret = self
            .locked(|x| {
                x.offers.retain(|(_, until)| *until > now);
                let i = x.offers.iter().position(|(s, _)| tag_ok(s, "osis pair request", &items))?;
                Some(x.offers.remove(i).0)
            })
            .ok_or(Error::Invalid("pairing request matches no open offer".into()))?;
        let node = *node;
        let pks = packages_of(pks)?;
        let me = self.me();
        let (grant, mine) = self.locked(|x| -> Result<(RawCommitId, Vec<Package>)> {
            for (bytes, blobs) in pks {
                x.engine().ingest(&bytes, blobs)?;
            }
            let done = x.engine().pair(&me, &node)?;
            let grant = *done.commits.last().ok_or(Error::Invalid("pairing made no commit".into()))?;
            let acts = x.sync.carry_out(done)?;
            self.inner.apply(acts);
            let mine = x.sync.take_direct_for(&node);
            Ok((grant, mine))
        })?;
        Ok((node, PairReply(seal(REPLY, &secret, "osis pair reply", vec![Value::Bytes(grant.0.to_vec()), packages_value(&mine)]))))
    }

    /// Starts pairing this fresh store as a new node of the account that made `offer`: returns
    /// the request to carry to the offering node and, with its reply, `Joining::finish`. The
    /// offer's peers join `peers`.
    pub fn pair(store: Store, peers: &[Address], offer: &PairOffer, cfg: Config) -> Result<Joining> {
        cfg.check(peers)?;
        let items = unpack(&offer.0, OFFER)?;
        let [_, Value::Tid(person), Value::Tid(_), Value::Bytes(secret), Value::List(addrs)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing offer".into())) };
        let secret: [u8; 32] = secret.as_slice().try_into().map_err(|_| Error::Invalid("malformed pairing offer".into()))?;
        let addrs = addrs.iter().map(|a| if let Value::Str(s) = a { s.parse() } else { Err(Error::Invalid("malformed pairing offer".into())) }).collect::<Result<_>>()?;
        let peers = with_hosts(peers, addrs);
        let Fresh { sync, clock } = fresh_engine(&store, &cfg, &peers)?;
        let db = Osis::start(sync, clock, store, &cfg, *person)?;
        let node = db.node();
        let pks = db.engine(|e| -> Result<Vec<Package>> {
            let ids = e.commit_ids();
            let mut v = Vec::new();
            for id in ids {
                v.extend(e.package(&id)?);
            }
            Ok(v)
        })?;
        let request = PairRequest(seal(REQUEST, &secret, "osis pair request", vec![Value::Tid(node), packages_value(&pks)]));
        Ok(Joining { db, secret, person: *person, request })
    }
}
