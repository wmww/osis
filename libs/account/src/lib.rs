//! A person's account over osis (spec/permissions.md §8): an arrangement of ordinary things, read
//! by no rule of core. The account is a thing its nodes hold admin (pair, remove) or write on, each
//! writing as its own node thing through it; it holds its profile (what others read about the
//! person, the target of its contact card) and its inbox (where grants and requests from others
//! arrive). Things made for the person are minted with the account as admin and held from its
//! `holds.0`, so every node of the account holds them. "Me", for a person, is the account
//! (`Account::thing`); a node itself is its node thing (`Osis::node`).
//!
//! Pairing a new node is transport-agnostic: the app carries three texts between the nodes (a QR
//! code, the clipboard, a local socket), the pairing channel of spec/permissions.md §8: the offer
//! (the account, its profile and a one-time secret), the new node's request (its node thing's
//! public key record) and the existing node's reply (the account's offer and its trust records),
//! the last two authenticated by the offer's secret.

#![forbid(unsafe_code)]

// Interim (notes/public-and-cards-brief.md, piece 7): making, pairing and removing a node go
// through the engine (`osis::internals`) until the `osis` API has the calls they need (minting a
// thing with keys of its own in a transaction, the offer of a grant handed over by hand).
use osis::internals::Internals as _;
use osis::internals::engine as eng;
use osis::internals::{base, core_types as ct, crypto};
use osis::{Error, LinkInfo, LinkOpts, Osis, ReadOnly, Result, Role, SetRoleOpts, ShareLink, Store, Tid, Time, Value, Weak};

/// Typed keys of schema/account.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::generated as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/account.rs"));
}

use schema::{CARD, CONTACTS, OF, PROFILE};

/// A person's account (spec/permissions.md §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    thing: Tid,
}

/// A node of an account and its role on the account (`Account::nodes`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountNode {
    /// Its node thing.
    pub node: Tid,
    /// Admin: it pairs and removes nodes; write: it writes as the account, no more.
    pub role: Role,
}

impl Account {
    /// Makes an account on `db`, a node acting for none yet, with its inbox and profile: the
    /// node becomes its first admin node. `Invalid` on a node that acts for an account already;
    /// `Unsupported` through a connection.
    pub fn make(db: &Osis) -> Result<Account> {
        if !db.has_store() {
            return Err(Error::Unsupported("making an account: not through a connection to a node".into()));
        }
        if let Some(a) = db.settings_thing()? {
            return Err(Error::Invalid(format!("this node acts for {a} already")));
        }
        let (a, profile) = db.engine(make)?;
        db.publish_dial_on(&[a, profile])?;
        Ok(Account { thing: a })
    }

    /// The account `db`'s node acts for, if any: the thing it keeps its settings on.
    pub fn of(db: &ReadOnly) -> Result<Option<Account>> {
        Ok(db.settings_thing()?.map(|thing| Account { thing }))
    }

    /// The account itself: what a person is, as holder of roles ("me" for a person). Grant it
    /// what the person may reach from every node; mint what the person makes with it as admin and
    /// hold it from its `holds.0`.
    pub fn thing(&self) -> Tid {
        self.thing
    }

    /// The account's profile: everyone holding its contact card reads it, so the person writes
    /// what others may know of them there (`name.0`, `contact:*`). `None` on a node paired a moment
    /// ago that holds none of the account yet.
    pub fn profile(&self, db: &ReadOnly) -> Result<Option<Tid>> {
        Ok(db.at(self.thing, PROFILE).get()?.map(|w| w.0))
    }

    /// The account's nodes: its holders of write or admin.
    pub fn nodes(&self, db: &ReadOnly) -> Result<Vec<AccountNode>> {
        Ok(db.grants(self.thing)?.into_iter().filter(|(_, g)| g.role >= Role::Write).map(|(node, g)| AccountNode { node, role: g.role }).collect())
    }

    /// Removes a node from the account (spec/permissions.md §8 Removing): its role removed with
    /// the account's rotation, erasing unless `o.retain_copy` says retain, and its dial and settings
    /// entries on the account and its profile dropped. It returns what is easy to forget: this
    /// node's links still working. The removed node keeps their keys, so whoever holds it can read
    /// and join through each until `revoke_link`, and ending them is the caller's choice. None when
    /// `node` was not one of the account's. `Unsupported` through a connection.
    pub fn remove_node(&self, db: &Osis, node: Tid, o: SetRoleOpts) -> Result<Vec<LinkInfo>> {
        if !db.has_store() {
            return Err(Error::Unsupported("remove_node: not through a connection to a node".into()));
        }
        if !db.grants(self.thing)?.contains_key(&node) {
            return Ok(Vec::new());
        }
        let also: Vec<Tid> = self.profile(db)?.into_iter().collect();
        let (a, retain) = (self.thing, o.retain_copy.unwrap_or(false));
        db.engine(|e| match o.leave_adminless {
            true => e.leaving_adminless(|e| e.remove_node(&a, &node, retain, &also)),
            false => e.remove_node(&a, &node, retain, &also),
        })?;
        db.links()
    }

    /// The account's contact card: a read link to its profile, made once for the account (every
    /// node of it hands out the same card once it has synced).
    pub fn contact_card(&self, db: &Osis) -> Result<ContactCard> {
        if let Some(c) = db.at(self.thing, CARD).get()? {
            return c.parse();
        }
        let p = self.profile(db)?.ok_or_else(|| Error::Invalid("the account's profile is not here yet".into()))?;
        let card = ContactCard(db.make_link(p, Role::Read, LinkOpts::default())?);
        let mut w = db.write();
        w.at(self.thing, CARD).set(&card.to_string())?;
        w.commit()?;
        Ok(card)
    }

    /// Imports a contact card into the account: joins the profile it names, records it, and
    /// returns the card's account once its keys are here, usable in `grant`. Waits for the card's
    /// node meanwhile (wrap it in a timeout).
    pub async fn import_contact(&self, db: &Osis, card: &ContactCard) -> Result<Tid> {
        let p = db.redeem(&card.0, self.thing).await?;
        // the profile's content comes with its sync, once joined
        if db.at(p, OF).get()?.is_none() {
            db.wait_synced(osis::SyncScope::Thing(p)).await?;
        }
        let who = db.at(p, OF).get()?.ok_or_else(|| Error::Invalid("contact card: its profile names no account".into()))?.0;
        let mut w = db.write();
        w.at(self.thing, CONTACTS).path(osis::p![Weak(who)]).set(&Weak(p))?;
        w.commit()?;
        Ok(who)
    }

    /// The profile of an account whose contact card this account imported, if any.
    pub fn profile_of(&self, db: &ReadOnly, account: Tid) -> Result<Option<Tid>> {
        Ok(db.at(self.thing, CONTACTS).get()?.and_then(|m| m.get(&Weak(account)).map(|w| w.0)))
    }

    /// An offer to pair a new node, good once and for 10 minutes: the new node runs `pair` with
    /// it and the app carries its request back to `Offering::accept`. Whoever holds the offer can
    /// make their node a full admin node of the account until then: show it only to the new node.
    pub fn offer_pairing(&self, db: &Osis) -> Result<Offering> {
        let profile = self.profile(db)?.ok_or_else(|| Error::Invalid("the account's profile is not here yet".into()))?;
        let mut secret = [0u8; 32];
        crypto::RngCore::fill_bytes(&mut crypto::OsRng, &mut secret);
        let until = Time(db.now()?.0.saturating_add(OFFER_LIFETIME_MS));
        let offer = PairOffer(pack(OFFER, &Value::List(vec![Value::Int(1), Value::bytes(self.thing.as_bytes()), Value::bytes(profile.as_bytes()), Value::Bytes(secret.to_vec())])));
        Ok(Offering { account: *self, offer, secret, until })
    }
}

/// Makes the account on `e` (spec/permissions.md §8 Making), in one transaction: A minted with the
/// node thing as mint admin, its inbox and profile minted with admin A, each independent, held by
/// strongs from A's `holds.0`; the inbox's setting enabling both inbox signals; A's card on the
/// profile naming the inbox; the node root's strong to A, its settings on A and its dial entry on A and the
/// profile. A and the profile.
fn make(e: &mut eng::Engine) -> Result<(Tid, Tid)> {
    let root = e.node_root().ok_or_else(|| Error::Storage("no node root".into()))?;
    let admins = [eng::MintAdmin::Thing(e.me()), eng::MintAdmin::Minted(0), eng::MintAdmin::Minted(0)];
    let now = e.now();
    let (ts, _) = e.mint_independent(&admins, |ts| {
        let [a, inbox, profile] = *ts else { return Err(eng::Error::Misuse("three minted")) };
        let add = |v| osis::internals::crdt::PathOp { path: Vec::new(), op: osis::internals::crdt::Op::Add(v) };
        let mut held = eng::Mutation::new();
        held.op(a, &ct::HOLDS, add(Value::Strong(inbox)))?.op(a, &ct::HOLDS, add(Value::Strong(profile)))?;
        held.set(a, &PROFILE, &Weak(profile))?.set(profile, &OF, &Weak(a))?;
        let mut signals = eng::Mutation::new();
        let mut setting = ct::RetentionSetting::default();
        setting.take_inbox_signals();
        signals.set(inbox, &ct::RETENTION, &setting)?;
        // A's card on the profile naming the inbox, acting as A (spec/sync-inbox.md §1 Card): its
        // keys are filled in as A's `keys.0` is written (`Engine::take_cards`)
        let card = eng::flows::cards::put(profile, a, &eng::flows::cards::naming(Some(inbox), now))?;
        // the node root's in commits of their own: it is local, under no sync ID
        let mut hold = eng::Mutation::new();
        hold.op(root, &ct::HOLDS, add(Value::Strong(a)))?;
        let mut settings = eng::Mutation::new();
        settings.set(root, &ct::SETTINGS, &Weak(a))?.set(root, &ct::DIAL_ON, &[Weak(a), Weak(profile)].into_iter().collect())?;
        Ok(vec![held, signals, card, hold, settings])
    })?;
    // the card carries A's keys and the inbox's
    e.refresh_cards()?;
    match ts.as_slice() {
        [a, _, profile] => Ok((*a, *profile)),
        _ => Err(Error::Storage("account making minted otherwise".into())),
    }
}

/// How long a pairing offer can be accepted: the time for a user to carry it to the new node and
/// back. At 0 no offer is ever accepted; at infinity an offer shown once pairs any node for good.
const OFFER_LIFETIME_MS: u64 = 10 * 60_000;

const OFFER: &str = "osis://pair/";
const REQUEST: &str = "osis://pair-request/";
const REPLY: &str = "osis://pair-reply/";

/// A secret-bearing text form: checked by `$parse` when parsed (`parse` reads it), redacted in `Debug`.
macro_rules! secret_text {
    ($(#[$m:meta])* $n:ident, $inner:ty, $parse:expr) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $n($inner);
        impl std::str::FromStr for $n {
            type Err = Error;
            fn from_str(s: &str) -> Result<$n> {
                ($parse)(s.trim()).map($n)
            }
        }
        impl std::fmt::Display for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        impl std::fmt::Debug for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($n), "(..)"))
            }
        }
    };
}

secret_text!(
    /// A contact card: a read link to an account's profile. Whoever holds it reads the profile.
    ContactCard, ShareLink, |s: &str| s.parse::<ShareLink>().map_err(|e| Error::Invalid(format!("contact card: {e}")))
);
secret_text!(
    /// A short-lived offer to pair a new node, made on an existing one (holds a one-time
    /// secret: show it only to the new node).
    PairOffer, String, |s: &str| unpack(s, OFFER).map(|_| s.to_string())
);
secret_text!(
    /// The new node's answer to an offer, for `Offering::accept` on the offering node.
    PairRequest, String, |s: &str| unpack(s, REQUEST).map(|_| s.to_string())
);
secret_text!(
    /// The offering node's answer to a request, for `Joining::finish` on the new node.
    PairReply, String, |s: &str| unpack(s, REPLY).map(|_| s.to_string())
);

fn pack(prefix: &str, v: &Value) -> String {
    format!("{prefix}{}", base::base64url::encode(&base::cbor::encode(v)))
}

fn unpack(s: &str, prefix: &str) -> Result<Vec<Value>> {
    let bad = || Error::Invalid("malformed pairing message".into());
    let b = s.strip_prefix(prefix).and_then(base::base64url::decode).ok_or_else(bad)?;
    match base::cbor::decode(&b, &base::cbor::Limits::new(base::format::MAX_OBJECT_DEPTH, b.len())).map_err(|_| bad())? {
        Value::List(items) if items.first() == Some(&Value::Int(1)) => Ok(items),
        _ => Err(bad()),
    }
}

fn mac(secret: &[u8; 32], purpose: &str, body: &Value) -> Vec<u8> {
    crypto::kdf::kdf(purpose, secret, &base::cbor::encode(body)).expose().to_vec()
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
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn tid(v: &Value) -> Option<Tid> {
    v.as_array().map(Tid::from_bytes)
}

/// An open offer to pair a new node (`Account::offer_pairing`).
pub struct Offering {
    account: Account,
    offer: PairOffer,
    secret: [u8; 32],
    until: Time,
}

impl std::fmt::Debug for Offering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Offering({})", self.account.thing)
    }
}

impl Offering {
    /// The offer to carry to the new node.
    pub fn offer(&self) -> &PairOffer {
        &self.offer
    }

    /// Accepts the new node's request to this offer: makes it an admin node of the account and
    /// returns its node thing with the reply to carry back. The offer is used up. `Invalid` past
    /// its 10 minutes or for a request to another offer; `Unsupported` through a connection.
    pub fn accept(self, db: &Osis, req: &PairRequest) -> Result<(Tid, PairReply)> {
        if !db.has_store() {
            return Err(Error::Unsupported("pairing: not through a connection to a node".into()));
        }
        let items = unpack(&req.0, REQUEST)?;
        let malformed = || Error::Invalid("malformed pairing request".into());
        let [_, node, commits, records, Value::Bytes(_)] = items.as_slice() else { return Err(malformed()) };
        if db.now()? >= self.until || !tag_ok(&self.secret, "osis pair request", &items) {
            return Err(Error::Invalid("pairing request matches no open offer".into()));
        }
        let node = tid(node).ok_or_else(malformed)?;
        let keys = osis::internals::blob::Certificates::from_values(commits, records, usize::MAX).map_err(|_| malformed())?;
        let a = self.account.thing;
        let (offer, _) = db.engine(|e| e.pair(&a, &node, &keys, Role::Admin))?;
        Ok((node, PairReply(seal(REPLY, &self.secret, "osis pair reply", vec![offer.to_value()]))))
    }
}

/// A new node waiting for the offering node's reply (`pair`).
pub struct Joining {
    db: Osis,
    account: Tid,
    profile: Tid,
    secret: [u8; 32],
    request: PairRequest,
}

impl std::fmt::Debug for Joining {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Joining({})", self.db.node())
    }
}

/// Starts pairing a fresh store as a new node of the account that made `offer`: returns the
/// request to carry to the offering node and, with its reply, `Joining::finish`.
pub fn pair(store: Store, offer: &PairOffer, cfg: osis::Config) -> Result<Joining> {
    let items = unpack(&offer.0, OFFER)?;
    let malformed = || Error::Invalid("malformed pairing offer".into());
    let [_, account, profile, Value::Bytes(secret)] = items.as_slice() else { return Err(malformed()) };
    let (account, profile) = (tid(account).ok_or_else(malformed)?, tid(profile).ok_or_else(malformed)?);
    let secret: [u8; 32] = secret.as_slice().try_into().map_err(|_| malformed())?;
    let db = Osis::create(store, cfg)?;
    let keys = db.engine(|e| e.node_keys())?;
    let [commits, records] = keys.to_values();
    let request = PairRequest(seal(REQUEST, &secret, "osis pair request", vec![Value::bytes(db.node().as_bytes()), commits, records]));
    Ok(Joining { db, account, profile, secret, request })
}

impl Joining {
    /// The request to carry to the offering node.
    pub fn request(&self) -> &PairRequest {
        &self.request
    }

    /// Takes the offering node's reply and returns the node, now a node of the account, with
    /// the account.
    pub fn finish(self, reply: &PairReply) -> Result<(Osis, Account)> {
        let items = unpack(&reply.0, REPLY)?;
        let [_, offer, Value::Bytes(_)] = items.as_slice() else { return Err(Error::Invalid("malformed pairing reply".into())) };
        if !tag_ok(&self.secret, "osis pair reply", &items) {
            return Err(Error::Invalid("pairing reply does not match the offer".into()));
        }
        let offer = eng::flows::pairing::Offer::from_value(offer).ok_or_else(|| Error::Invalid("malformed pairing reply".into()))?;
        if offer.account != self.account {
            return Err(Error::Invalid("pairing reply: an offer of another account".into()));
        }
        self.db.engine(|e| e.take_offer(&offer)).map_err(|e| Error::Invalid(format!("pairing reply: {e}")))?;
        self.db.publish_dial_on(&[self.account, self.profile])?;
        Ok((self.db, Account { thing: self.account }))
    }
}
