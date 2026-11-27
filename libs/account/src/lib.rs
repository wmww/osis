//! Realms and accounts over osis (schema/realm.osis): arrangements of ordinary things, read by no
//! rule of core. A realm is a thing whose holders are its members (`Realm`); what is made in it is
//! minted with it as admin and held from its `holds.0`. A person's account (spec/permissions.md §8)
//! is a realm its nodes hold admin (pair, remove) or write on, each writing as its own node thing
//! through it: the person's home. It holds its profile (what everyone may read about the person,
//! the target of its contact card, carrying the account's card) and its inbox (where grants and
//! requests from others arrive). "Me", for a person, is the account (`Account::thing`); a node
//! itself is its node thing (`Osis::node`).
//!
//! Pairing a new node is transport-agnostic: the app carries three texts between the nodes (a QR
//! code, the clipboard, a local socket), the pairing channel of spec/permissions.md §8: the offer
//! (the account, its profile and a one-time secret), the new node's request (its node thing's
//! public key record) and the existing node's reply (the account's offer, with its trust records
//! and where to reach the offering node), the last two authenticated by the offer's secret.

#![forbid(unsafe_code)]

use osis_base as base;
use osis_crypto as crypto;
use osis::core::{CAPS, DIAL, NAME, RETENTION, RetentionSetting, SETTINGS};
use osis::{Error, GrantOpts, HolderKind, Keys, Link, LinkInfo, Osis, ReadOnly, Result, Role, SetRoleOpts, Store, Tid, Value, Weak};

/// Typed keys of schema/realm.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::generated as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/realm.rs"));
}

use schema::{CONTACTS, OF, PROFILE, REALM};

/// A realm (schema/realm.osis): a thing whose holders are its members, at their roles. Members
/// are added by `Osis::grant` or a link, changed and removed by `Osis::set_role`; a thing is
/// shared into it by a grant to it. Its admins are equals: its mint admin's edge is removed like
/// any. An account is one (`Account::realm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Realm {
    thing: Tid,
}

impl Realm {
    /// The realm `thing` is (marked `realm:realm^.0`, or an account).
    pub fn at(thing: Tid) -> Realm {
        Realm { thing }
    }

    /// Makes a realm named `name` in `within` (a realm or the person's account): minted with
    /// `within` as admin, so `within`'s members are its first, and held from its `holds.0`. A
    /// member removed keeps a read-only copy of what they could read unless their remover says
    /// otherwise.
    pub fn make(db: &Osis, within: Realm, name: &str) -> Result<Realm> {
        let mut w = db.write();
        // with its keys: it holds roles on what is shared into it from the start
        let r = w.create_with_keys(within.thing)?;
        w.hold(within.thing, r)?;
        w.at(r, REALM).set(&schema::Realm { color: None })?;
        w.at(r, NAME).set(&name.to_string())?;
        w.at(r, RETENTION).set(&RetentionSetting { retain_copies: true, ..RetentionSetting::default() })?;
        w.commit()?;
        Ok(Realm { thing: r })
    }

    /// The realm itself, as holder of roles: grant it a role on a thing to share the thing into
    /// it; mint with it as admin to make a thing in it.
    pub fn thing(&self) -> Tid {
        self.thing
    }

    /// The realm's profile: everyone may read it, so its admins write what others may know of
    /// the realm there (`name.0`, `contact:*`). `None` where it has none, or on a node paired a
    /// moment ago that holds none of the account yet.
    pub fn profile(&self, db: &ReadOnly) -> Result<Option<Tid>> {
        Ok(db.at(self.thing, PROFILE).get()?.map(|w| w.0))
    }

    /// The realm's contact card: a locator of its profile, naming this node to reach it
    /// (`Osis::locator`). Whoever imports it can grant the realm roles.
    pub fn contact_card(&self, db: &Osis) -> Result<Link> {
        let p = self.profile(db)?.ok_or_else(|| Error::Invalid("the realm's profile is not here yet".into()))?;
        publish_profile(db, p)?;
        db.locator(p)
    }

    /// Imports a contact card into the realm: holds the profile it names, records it, and returns
    /// the card's realm (an account, for a person's card) once its keys are here, usable in
    /// `grant`. Waits for the card's node meanwhile (wrap it in a timeout).
    pub async fn import_contact(&self, db: &Osis, card: &Link) -> Result<Tid> {
        let p = db.redeem(card, self.thing).await?;
        // the profile's content comes with its sync, once joined
        if db.at(p, OF).get()?.is_none() {
            db.wait_synced(osis::SyncScope::Thing(p)).await?;
        }
        let who = db.at(p, OF).get()?.ok_or_else(|| Error::Invalid("contact card: its profile names no realm".into()))?.0;
        let mut w = db.write();
        w.at(self.thing, CONTACTS).path(osis::p![Weak(who)]).set(&Weak(p))?;
        w.commit()?;
        Ok(who)
    }

    /// The profile of a realm whose contact card this realm imported, if any.
    pub fn profile_of(&self, db: &ReadOnly, realm: Tid) -> Result<Option<Tid>> {
        Ok(db.at(self.thing, CONTACTS).get()?.and_then(|m| m.get(&Weak(realm)).map(|w| w.0)))
    }
}

/// Makes profile `p` public, unless it is (`Account::make` does; a node stopped between its two
/// transactions left it to the first contact card).
fn publish_profile(db: &Osis, p: Tid) -> Result<()> {
    if !db.grants(p)?.contains_key(&Tid::PUBLIC) {
        db.grant(p, Tid::PUBLIC, Role::Read, GrantOpts::default())?;
    }
    Ok(())
}

/// A person's account (spec/permissions.md §8): a realm, the person's home.
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
    /// Makes an account on `db`, a node acting for none yet, with its inbox and its profile,
    /// which everyone may read: the node becomes its first admin node. `Invalid` on a node that
    /// acts for an account already; `Unsupported` through a connection.
    pub fn make(db: &Osis) -> Result<Account> {
        if let Some(a) = Account::of(db)? {
            // one made by a node stopped before its last step is finished; one made, refused
            return match a.realm().profile(db)? {
                Some(p) if !db.grants(p)?.contains_key(&Tid::PUBLIC) => a.finish(db, p).map(|()| a),
                _ => Err(Error::Invalid(format!("this node acts for {} already", a.thing))),
            };
        }
        let root = db.node_root()?;
        // A, its inbox and profile, held: A by the node root, naming A its settings thing, the
        // others by A, in one transaction (spec/permissions.md §8 Making)
        let mut w = db.write();
        // with their keys: a node paired in or a contact learns of each with its role entries
        let a = w.create_with_keys(db.node())?;
        let (inbox, profile) = (w.create_with_keys(a)?, w.create_with_keys(a)?);
        w.hold(root, a)?;
        w.at(root, SETTINGS).set(&Weak(a))?;
        w.at(a, REALM).set(&schema::Realm { color: None })?;
        w.hold(a, inbox)?;
        w.hold(a, profile)?;
        w.at(a, PROFILE).set(&Weak(profile))?;
        w.at(profile, OF).set(&Weak(a))?;
        let mut setting = RetentionSetting::default();
        setting.enable_inbox_signals();
        w.at(inbox, RETENTION).set(&setting)?;
        // grants to A from outside go to the inbox: named in A's minting
        w.set_inbox(a, inbox)?;
        w.commit()?;
        let a = Account { thing: a };
        a.finish(db, profile)?;
        Ok(a)
    }

    /// `make`'s steps after its first transaction, each kept where it is done, so `make` on a
    /// node stopped between them finishes them: A's card on the profile, the dial
    /// entries on A and the profile, then the profile made public (what tells `make` it is done).
    fn finish(&self, db: &Osis, profile: Tid) -> Result<()> {
        db.put_card(profile, self.thing)?;
        db.publish_dial_on(&[self.thing, profile])?;
        publish_profile(db, profile)
    }

    /// The account `db`'s node acts for, if any: the thing it keeps its settings on, which its
    /// node thing holds write or admin on (as `nodes` counts it). None once it learns its
    /// removal (`remove_node`) or a lowering below write; `make` then makes it another.
    pub fn of(db: &ReadOnly) -> Result<Option<Account>> {
        Ok(db.settings_thing()?.map(|thing| Account { thing }))
    }

    /// The account itself: what a person is, as holder of roles ("me" for a person), and their
    /// home. Grant it what the person may reach from every node; mint what the person makes with
    /// it as admin and hold it from its `holds.0`.
    pub fn thing(&self) -> Tid {
        self.thing
    }

    /// The account as a realm: its profile, contact card and contacts.
    pub fn realm(&self) -> Realm {
        Realm { thing: self.thing }
    }

    /// The account's nodes: the node things granted write or admin on it. Its other holders (a
    /// realm, a client's thing) are none.
    pub fn nodes(&self, db: &ReadOnly) -> Result<Vec<AccountNode>> {
        let direct = db.holders(self.thing)?.into_iter().filter(|h| h.through.is_empty() && h.kind == HolderKind::Key && h.role >= Role::Write);
        Ok(direct.map(|h| AccountNode { node: h.thing, role: h.role }).collect())
    }

    /// Removes a node from the account (spec/permissions.md §8 Removing): its role removed with
    /// the account's rotation, erasing unless `o.retain_copy` says retain, and its dial and settings
    /// entries on the account and its profile dropped. It returns what is easy to forget: the
    /// account's links still working. The removed node keeps their keys, so whoever holds it can
    /// read and join through each until `revoke_link`, and ending them is the caller's choice.
    /// None when `node` was not one of the account's (its entries dropped where they stand). `Permission` unless this node is an admin
    /// node of the account; `Unsupported` through a connection.
    pub fn remove_node(&self, db: &Osis, node: Tid, o: SetRoleOpts) -> Result<Vec<LinkInfo>> {
        let a = self.thing;
        // its entries go whenever they stand, so a removal stopped halfway ends by calling again
        let entries = || -> Result<()> {
            let mut w = db.write();
            for t in std::iter::once(a).chain(self.realm().profile(db)?) {
                if db.at(t, DIAL).get()?.is_some_and(|d| d.contains_key(&Weak(node))) {
                    w.at(t, DIAL).path(osis::p![Weak(node)]).remove()?;
                }
            }
            if db.at(a, CAPS).get()?.is_some_and(|c| c.contains_key(&Weak(node))) {
                w.at(a, CAPS).path(osis::p![Weak(node)]).remove()?;
            }
            w.commit()?;
            Ok(())
        };
        if !db.grants(a)?.contains_key(&node) {
            entries()?;
            return Ok(Vec::new());
        }
        let role = || db.set_role(a, node, None, SetRoleOpts { retain_copy: Some(o.retain_copy.unwrap_or(false)), ..o });
        // a node removing itself drops its entries first, while it may still write A
        if node == db.node() {
            entries()?;
            role()?;
        } else {
            role()?;
            entries()?;
        }
        db.links()
    }

    /// An offer to pair a new node, good once while the `Offering` is kept: the new node runs
    /// `pair` with it and the app carries its request back to `Offering::accept`. Whoever holds
    /// the offer can make their node a full admin node of the account until then: show it only to
    /// the new node, and drop the `Offering` once the pairing is given up.
    pub fn offer_pairing(&self, db: &Osis) -> Result<Offering> {
        let profile = self.realm().profile(db)?.ok_or_else(|| Error::Invalid("the account's profile is not here yet".into()))?;
        let mut secret = [0u8; 32];
        crypto::RngCore::fill_bytes(&mut crypto::OsRng, &mut secret);
        let offer = PairOffer(pack(OFFER, &Value::List(vec![Value::Int(1), Value::bytes(self.thing.as_bytes()), Value::bytes(profile.as_bytes()), Value::Bytes(secret.to_vec())])));
        Ok(Offering { account: *self, offer, secret })
    }
}

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

fn mac(secret: &[u8; 32], purpose: &str, body: &Value) -> crypto::Secret32 {
    crypto::kdf::kdf(purpose, secret, &base::cbor::encode(body))
}

/// The message `[1, items.., tag]` with `prefix`; the tag MACs `[1, items..]`.
fn seal(prefix: &str, secret: &[u8; 32], purpose: &str, items: Vec<Value>) -> String {
    let mut v = vec![Value::Int(1)];
    v.extend(items);
    let tag = mac(secret, purpose, &Value::List(v.clone()));
    v.push(Value::bytes(tag.expose()));
    pack(prefix, &Value::List(v))
}

/// Whether an unpacked message's last item is its tag under `secret`.
fn tag_ok(secret: &[u8; 32], purpose: &str, items: &[Value]) -> bool {
    let Some((Value::Bytes(tag), body)) = items.split_last() else { return false };
    // Secret32's comparison takes constant time
    <[u8; 32]>::try_from(tag.as_slice()).is_ok_and(|t| mac(secret, purpose, &Value::List(body.to_vec())) == crypto::Secret32::from_bytes(t))
}

fn tid(v: &Value) -> Option<Tid> {
    v.as_array().map(Tid::from_bytes)
}

/// An open offer to pair a new node (`Account::offer_pairing`).
pub struct Offering {
    account: Account,
    offer: PairOffer,
    secret: [u8; 32],
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
    /// returns its node thing with the reply to carry back. The offer is used up. `Invalid` for a
    /// request to another offer; `Unsupported` through a connection.
    pub fn accept(self, db: &Osis, req: &PairRequest) -> Result<(Tid, PairReply)> {
        let items = unpack(&req.0, REQUEST)?;
        let malformed = || Error::Invalid("malformed pairing request".into());
        let [_, Value::Str(keys), Value::Bytes(_)] = items.as_slice() else { return Err(malformed()) };
        if !tag_ok(&self.secret, "osis pair request", &items) {
            return Err(Error::Invalid("pairing request matches no open offer".into()));
        }
        let keys: Keys = keys.parse()?;
        let a = self.account.thing;
        // only an admin node pairs: a grant by any other is invalid wherever it lands, and would
        // hand the new node an offer of nothing
        if db.role_on(a)? != Some(Role::Admin) {
            return Err(Error::Permission { tid: a, needs: Role::Admin });
        }
        let node = db.take_keys(&keys)?;
        db.grant(a, node, Role::Admin, GrantOpts::default())?;
        // the account's locator: the new node reaches the account by it, as its holder
        let link = db.locator(a)?;
        Ok((node, PairReply(seal(REPLY, &self.secret, "osis pair reply", vec![Value::Str(link.to_string())]))))
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
    let keys = db.keys(db.node())?;
    let request = PairRequest(seal(REQUEST, &secret, "osis pair request", vec![Value::Str(keys.to_string())]));
    Ok(Joining { db, account, profile, secret, request })
}

impl Joining {
    /// The request to carry to the offering node.
    pub fn request(&self) -> &PairRequest {
        &self.request
    }

    /// Takes the offering node's reply and returns the node, now a node of the account, with
    /// the account: once it reaches the account by the reply's link (`Osis::redeem`, which holds
    /// it from the node root), at the offering node or any other of the account's.
    pub async fn finish(self, reply: &PairReply) -> Result<(Osis, Account)> {
        let items = unpack(&reply.0, REPLY)?;
        let malformed = || Error::Invalid("malformed pairing reply".into());
        let [_, Value::Str(link), Value::Bytes(_)] = items.as_slice() else { return Err(malformed()) };
        if !tag_ok(&self.secret, "osis pair reply", &items) {
            return Err(Error::Invalid("pairing reply does not match the offer".into()));
        }
        let link: osis::Link = link.parse()?;
        if link.target()? != self.account {
            return Err(malformed());
        }
        let root = self.db.node_root()?;
        let mut w = self.db.write();
        w.hold(root, self.account)?;
        w.at(root, SETTINGS).set(&Weak(self.account))?;
        w.commit()?;
        self.db.redeem(&link, root).await?;
        self.db.publish_dial_on(&[self.account, self.profile])?;
        Ok((self.db, Account { thing: self.account }))
    }
}
