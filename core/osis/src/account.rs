//! The account across nodes (spec/permissions.md §8; notes/api.md Handle and lifecycle): pairing
//! a new node. Pairing is transport-agnostic: the app carries three messages between the nodes
//! (QR, clipboard, a local socket), each the pairing channel of spec/permissions.md §8: the
//! offer (the account, its profile and a one-time secret), the new node's request (its node
//! thing's public key record) and the existing node's reply (the engine's offer of the account
//! and its trust records), the last two authenticated by the offer's secret.

use crate::error::{Error, Result};
use crate::handle::{Fresh, Osis, fresh_engine};
use crate::{Config, Store};
use osis_base::cbor::{Limits, decode, encode};
use osis_base::{Role, Tid, Value, base64url};

/// How long a pairing offer can be accepted: the time for a user to carry it to the new node and
/// back. At 0 no offer is ever accepted; at infinity an offer shown once pairs any node for good.
const OFFER_LIFETIME_MS: u64 = 10 * 60_000;

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
    match decode(&b, &Limits::new(osis_base::format::MAX_OBJECT_DEPTH, b.len())).map_err(|_| bad())? {
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

/// Whether `a` equals `b`, compared in constant time.
pub(crate) fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A new node waiting for the offering node's reply.
pub struct Joining {
    db: Osis,
    secret: [u8; 32],
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
        let [_, offer, Value::Bytes(_)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing reply".into())) };
        if !tag_ok(&self.secret, "osis pair reply", &items) {
            return Err(Error::Invalid("pairing reply does not match the offer".into()));
        }
        let offer = osis_engine::flows::pairing::Offer::from_value(offer).ok_or_else(|| Error::Invalid("malformed pairing reply".into()))?;
        if offer.account != self.db.account_root() {
            return Err(Error::Invalid("pairing reply: an offer of another account".into()));
        }
        self.db.locked(|l| {
            l.engine().take_offer(&offer).map_err(|e| Error::Invalid(format!("pairing reply: {e}")))?;
            l.handle(osis_sync::Input::Wrote);
            Ok::<_, Error>(())
        })?;
        Ok(self.db)
    }
}

impl Osis {
    /// An offer to pair a new node, good once: the new node runs `Osis::pair` with it and the
    /// app carries the request back to `pair_accept`. Whoever holds the offer can make their node
    /// a full admin node of this account until it is used or expires (10 minutes): show it only
    /// to the new node. `Unsupported` on a client with its own actor.
    pub fn pair_offer(&self) -> Result<PairOffer> {
        self.local("pair_offer")?;
        let (account, profile) = (self.account_root(), self.profile()?);
        let now = self.inner.clock.now_wall_ms().0;
        let secret = self.locked(|x| {
            let mut s = [0u8; 32];
            osis_crypto::RngCore::fill_bytes(&mut osis_crypto::OsRng, &mut s);
            x.offers.retain(|(_, until)| *until > now);
            x.offers.push((s, now.saturating_add(OFFER_LIFETIME_MS)));
            s
        });
        Ok(PairOffer(pack(OFFER, &Value::List(vec![Value::Int(1), Value::bytes(account.as_bytes()), Value::bytes(profile.as_bytes()), Value::Bytes(secret.to_vec())]))))
    }

    /// Accepts a new node's request to an offer of this node: makes it an admin node of the
    /// account and returns its node thing with the reply to carry back. `Unsupported` on a
    /// client with its own actor.
    pub fn pair_accept(&self, req: &PairRequest) -> Result<(Tid, PairReply)> {
        self.local("pair_accept")?;
        let items = req.parse()?;
        let malformed = || Error::Invalid("malformed pairing request".into());
        let [_, node, commits, records, Value::Bytes(_)] = items.as_slice() else { return Err(malformed()) };
        let node = node.as_array().map(Tid::from_bytes).ok_or_else(malformed)?;
        let keys = osis_blob::Certificates::from_values(commits, records, usize::MAX).map_err(|_| malformed())?;
        let now = self.inner.clock.now_wall_ms().0;
        let secret = self
            .locked(|x| {
                x.offers.retain(|(_, until)| *until > now);
                let i = x.offers.iter().position(|(s, _)| tag_ok(s, "osis pair request", &items))?;
                Some(x.offers.remove(i).0)
            })
            .ok_or(Error::Invalid("pairing request matches no open offer".into()))?;
        let a = self.account_root();
        let offer = self.locked(|x| {
            let r = x.engine().pair(&a, &node, &keys, Role::Admin).map(|o| o.0);
            x.handle(osis_sync::Input::Wrote);
            r
        })?;
        Ok((node, PairReply(seal(REPLY, &secret, "osis pair reply", vec![offer.to_value()]))))
    }

    /// Starts pairing this fresh store as a new node of the account that made `offer`: returns
    /// the request to carry to the offering node and, with its reply, `Joining::finish`.
    pub fn pair(store: Store, offer: &PairOffer, cfg: Config) -> Result<Joining> {
        cfg.check()?;
        let items = offer.parse()?;
        let malformed = || Error::Invalid("malformed pairing offer".into());
        let [_, account, profile, Value::Bytes(secret)] = items.as_slice() else { return Err(malformed()) };
        let tid = |v: &Value| v.as_array().map(Tid::from_bytes).ok_or_else(malformed);
        let (account, profile) = (tid(account)?, tid(profile)?);
        let secret: [u8; 32] = secret.as_slice().try_into().map_err(|_| malformed())?;
        let Fresh { mut engine, clock, sync } = fresh_engine(&store, &cfg)?;
        crate::handle::record_account(&mut engine, account, profile)?;
        let me = engine.me();
        let keys = engine.node_keys()?;
        let db = Osis::start(engine, sync, clock, store, &cfg, me, account, 0)?;
        let [commits, records] = keys.to_values();
        let request = PairRequest(seal(REQUEST, &secret, "osis pair request", vec![Value::bytes(me.as_bytes()), commits, records]));
        Ok(Joining { db, secret, request })
    }
}
