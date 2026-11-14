//! The account across nodes (spec/permissions.md §1, §7; notes/api.md Handle and lifecycle):
//! pairing a new node. Pairing is
//! transport-agnostic: the app carries two messages between the nodes (QR, clipboard, a local
//! socket): the new node's request (its node card) and the existing node's reply (the grant
//! and the commits it needs), both authenticated by the offer's one-time secret.

use crate::error::{Error, Result};
use crate::handle::{Fresh, Osis, fresh_engine};
use crate::{Config, Store};
use osis_base::cbor::{Limits, decode, encode};
use osis_base::{BlobId, CommitId as RawCommitId, Tid, Value, base64url};
use osis_engine::local_peer::Package;

/// How long a pairing offer can be accepted.
pub const OFFER_LIFETIME_MS: u64 = 10 * 60_000;

const OFFER: &str = "osis://pair/";
const REQUEST: &str = "osis://pair-request/";
const REPLY: &str = "osis://pair-reply/";

crate::share::secret_text!(
    /// A short-lived offer to pair a new node, made on an existing one (holds a one-time
    /// secret: show it only to the new node).
    PairOffer, Vec<Value>, |s| unpack(s, OFFER)
);
crate::share::secret_text!(
    /// The new node's answer to an offer, for `Osis::pair_accept` on the offering node.
    PairRequest, Vec<Value>, |s| unpack(s, REQUEST)
);
crate::share::secret_text!(
    /// The offering node's answer to a request, for `Joining::finish` on the new node.
    PairReply, Vec<Value>, |s| unpack(s, REPLY)
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

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn packages_value(pks: &[Package]) -> Value {
    Value::List(pks.iter().map(|p| Value::List(vec![Value::Bytes(p.bytes.clone()), Value::List(p.blobs.iter().map(|(id, b)| Value::List(vec![Value::Bytes(id.0.to_vec()), Value::Bytes(b.clone())])).collect()), Value::List(p.lists.iter().map(|l| Value::Bytes(l.clone())).collect())])).collect())
}

/// Commit bytes with their blobs and (a rotation's) list blobs.
type Packages = Vec<(Vec<u8>, Vec<(BlobId, Vec<u8>)>, Vec<Vec<u8>>)>;

fn packages_of(v: &Value) -> Result<Packages> {
    let bad = || Error::Invalid("malformed pairing packages".into());
    let Value::List(items) = v else { return Err(bad()) };
    let mut out = Vec::new();
    for i in items {
        let Value::List(f) = i else { return Err(bad()) };
        let [Value::Bytes(bytes), Value::List(blobs), Value::List(lists)] = f.as_slice() else { return Err(bad()) };
        let lists = lists.iter().map(|l| match l {
            Value::Bytes(b) => Ok(b.clone()),
            _ => Err(bad()),
        }).collect::<Result<Vec<_>>>()?;
        let mut bs = Vec::new();
        for b in blobs {
            let Value::List(x) = b else { return Err(bad()) };
            let [Value::Bytes(id), Value::Bytes(data)] = x.as_slice() else { return Err(bad()) };
            bs.push((BlobId(id.as_slice().try_into().map_err(|_| bad())?), data.clone()));
        }
        out.push((bytes.clone(), bs, lists));
    }
    Ok(out)
}

/// A new node waiting for the offering node's reply.
pub struct Joining {
    db: Osis,
    secret: [u8; 32],
    account: Tid,
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

    /// Takes the offering node's reply and returns the node, now a node of the account.
    pub fn finish(self, reply: &PairReply) -> Result<Osis> {
        let items = reply.parse()?;
        let [_, Value::Bytes(grant), pks, Value::Bytes(_)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing reply".into())) };
        if !tag_ok(&self.secret, "osis pair reply", &items) {
            return Err(Error::Invalid("pairing reply does not match the offer".into()));
        }
        let grant = RawCommitId(grant.as_slice().try_into().map_err(|_| Error::Invalid("malformed pairing reply".into()))?);
        let pks = packages_of(pks)?;
        let account = self.account;
        self.db.engine(|e| -> Result<_> {
            for (bytes, blobs, lists) in pks {
                e.ingest_with_lists(&bytes, blobs, None, &lists)?;
            }
            let _ = grant;
            e.paired(&account).map_err(|_| Error::Invalid("pairing reply: this node was not made a node of the account".into()))
        })?;
        Ok(self.db)
    }
}

impl Osis {
    /// An offer to pair a new node, good once: the new node runs
    /// `Osis::pair` with it and the app carries the request back to `pair_accept`. Whoever holds
    /// the offer can make their node a full admin node of this account until it is used or
    /// expires (10 minutes): show it only to the new node.
    /// `Unsupported` on a client with its own actor.
    pub fn pair_offer(&self) -> Result<PairOffer> {
        let (me, home, node) = (self.me(), self.home(), self.node());
        // every node of the account learns the profile from the offer it paired by
        let profile = self.profile()?;
        let now = self.inner.clock.now_wall_ms().0;
        let secret = self.locked(|x| {
            let mut s = [0u8; 32];
            osis_crypto::RngCore::fill_bytes(&mut osis_crypto::OsRng, &mut s);
            x.offers.retain(|(_, until)| *until > now);
            x.offers.push((s, now.saturating_add(OFFER_LIFETIME_MS)));
            s
        });
        Ok(PairOffer(pack(OFFER, &Value::List(vec![Value::Int(1), Value::Tid(me), Value::Tid(home), Value::Tid(node), Value::Tid(profile), Value::Bytes(secret.to_vec())]))))
    }

    /// Accepts a new node's request to an offer of this node: makes it an admin of the
    /// account (or lets back in a node already one) and returns its node tid
    /// with the reply to carry back.
    /// `Unsupported` on a client with its own actor.
    pub fn pair_accept(&self, req: &PairRequest) -> Result<(Tid, PairReply)> {
        let items = req.parse()?;
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
        let (grant, mine) = self.locked(|x| -> Result<(RawCommitId, Vec<Package>)> {
            for (bytes, blobs, lists) in pks {
                x.engine().ingest_with_lists(&bytes, blobs, None, &lists)?;
            }
            let (done, send) = x.engine().pair(&node)?;
            let grant = *done.commits.last().ok_or(Error::Invalid("pairing made no commit".into()))?;
            // what the new node needs of it goes in the reply
            let mut mine = Vec::new();
            for c in &send {
                mine.extend(x.engine().package(c)?);
            }
            Ok((grant, mine))
        })?;
        Ok((node, PairReply(seal(REPLY, &secret, "osis pair reply", vec![Value::Bytes(grant.0.to_vec()), packages_value(&mine)]))))
    }

    /// Starts pairing this fresh store as a new node of the account that made `offer`: returns
    /// the request to carry to the offering node and, with its reply, `Joining::finish`.
    pub fn pair(store: Store, offer: &PairOffer, cfg: Config) -> Result<Joining> {
        cfg.check()?;
        let items = offer.parse()?;
        let [_, Value::Tid(account), Value::Tid(home), Value::Tid(_), Value::Tid(profile), Value::Bytes(secret)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing offer".into())) };
        let secret: [u8; 32] = secret.as_slice().try_into().map_err(|_| Error::Invalid("malformed pairing offer".into()))?;
        let Fresh { mut engine, clock, sync } = fresh_engine(&store, &cfg)?;
        engine.set_app_record(crate::handle::PROFILE, profile.as_bytes())?;
        let db = Osis::start(engine, sync, clock, store, &cfg, *account, *home, 0)?;
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
        Ok(Joining { db, secret, account: *account, request })
    }
}
