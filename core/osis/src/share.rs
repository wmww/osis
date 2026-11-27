//! Sharing, links, cards, nodes, peers and sync (notes/api.md Sharing and roles, Sync
//! configuration and status) over role flows: each sharing call is one role commit made locally
//! (spec/permissions.md §2); calls that wait for another node are `async` (runtime-agnostic
//! futures).

use crate::error::{Error, Result};
use crate::handle::{Osis, ReadOnly};
use osis_base::{Role, Tid, Time, Value};
use osis_engine::flows;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// When a grant ends, what its holder may grant others, and what it reads of what was written
/// before it (`Osis::grant`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrantOpts {
    /// The grant ends at this time.
    pub until: Option<Time>,
    /// When `until` passes: whether the holder's nodes retain a read-only copy of what it could
    /// read (`true`) or erase it (`false`). `None`: the thing's default as it is now
    /// (`core::RetentionSetting::retain_copies`); a later change of the default leaves the grant
    /// as written. `Invalid` without `until`.
    pub retain_copy: Option<bool>,
    /// The holder may add new holders, up to its own role.
    pub may_grant: bool,
    /// What the holder reads of what was written before its first grant.
    pub reads: Reads,
    /// The grant may leave `target` with no admin: an `until` on its last admin whose grant has
    /// none (`Error::LeavesNoAdmin` without it).
    pub leave_adminless: bool,
    /// The holder is not told: its nodes reach `target` only by a reference they already sync.
    pub quiet: bool,
}

/// What a grant's holder reads of what was written on the thing before its first grant
/// (`GrantOpts::reads`). Showing it is never undone: a holder that has read it keeps it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Reads {
    /// As the holder reads now; a new holder reads everything.
    #[default]
    Kept,
    /// From the holder's first grant on: it reads the thing's current values as they stand at the
    /// grant, then every write after it, but no commit from before: no earlier version, no past
    /// fire of a signal (a chat's past messages), no listed history, on any of its nodes nor
    /// through anyone it grants. A shared document shows its text, not the edits that made it.
    /// A value with an expiry written before reads absent to it. A new holder's, or one already
    /// granted so (`Grant::from_now`); `Invalid` on a holder that reads what came before. Needs
    /// admin.
    FromNow,
    /// Everything, also for a holder granted `FromNow`, which it shows what came before.
    All,
}

/// What a holder is, as its creator declared: a thing's creation fixes this, so it reads alike on
/// every node and never changes, and nothing checks it. A holder whose creation has not reached
/// this node reads as `Thing`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HolderKind {
    /// Any other thing: an account, an organization, a realm.
    Thing,
    /// A share link's thing: those who joined by the link hold through it.
    Link,
    /// A thing minted with a key: a node thing, or a share link's key, which holds that link's
    /// thing until the link ends.
    Key,
    /// The public (`Tid::PUBLIC`): everyone, a node or not, holding nothing; read at most.
    Public,
}

/// `f` on the engine, its edge writes allowed to leave a thing with no admin when `adminless`.
fn marked<R>(e: &mut osis_engine::Engine, adminless: bool, f: impl FnOnce(&mut osis_engine::Engine) -> R) -> R {
    match adminless {
        true => e.leaving_adminless(f),
        false => f(e),
    }
}

/// Whether this node may end `holder`'s grant on `t` for `Osis::leave`.
fn leave_allowed(e: &mut osis_engine::Engine, holder: Tid, t: Tid, own: bool) -> Result<()> {
    match e.may_remove(&t, &holder)? {
        Some(flows::Removal::Explicit) if !own => Err(Error::Invalid(format!("this node is an admin of {t}: use set_role"))),
        None if !own => Err(Error::Permission { tid: holder, needs: Role::Admin }),
        _ => Ok(()),
    }
}

/// One way a thing holds a role on another (`Osis::holders`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    /// The thing holding the role.
    pub thing: Tid,
    /// What that thing is.
    pub kind: HolderKind,
    /// The role this way gives: the least along it.
    pub role: Role,
    /// When this way ends: the earliest end along it. One that has ended is not listed.
    pub until: Option<Time>,
    /// The things between the thing held and this holder, nearest the thing held first: empty for
    /// a grant on it itself, the link's thing for someone who joined by a link, an organization for its
    /// members.
    pub through: Vec<Tid>,
}

/// How `Osis::set_role` takes a role away.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetRoleOpts {
    /// On removal: whether the holder's nodes retain a read-only copy of what it could read (`true`)
    /// or erase it (`false`). `None`: the thing's default (`core::RetentionSetting::retain_copies`). `Invalid` when a role remains.
    pub retain_copy: Option<bool>,
    /// The change may leave the thing with no admin, for good: nobody can then change its
    /// grants (`Error::LeavesNoAdmin` without it).
    pub leave_adminless: bool,
}

/// How a link made by `Osis::make_link` ends. The link names the node that made it (by its key),
/// and the nodes it dials by `Config::dial`, so a redeemer reaches the thing at any of them that
/// holds the link's thing: anyone holding the link can dial them, also after the link ends (this
/// node until `Osis::rotate_peer_address`); dialing opens nothing the link no longer grants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkOpts {
    /// The link expires. It closes when one of your nodes next syncs after `until`: until then
    /// anyone holding the link can still join.
    pub until: Option<Time>,
    /// The first redemption ends the link.
    pub single_use: bool,
}

/// Names a link (`LinkInfo::id`, `Osis::revoke_link`). Its text form is what `FromStr` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub(crate) Tid);

impl LinkId {
    /// The thing those who joined by this link hold through: `Holder::through` names it, and
    /// `Osis::holders` of it lists them.
    pub fn thing(&self) -> Tid {
        self.0
    }
}

impl std::fmt::Display for LinkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.to_uri())
    }
}

impl std::str::FromStr for LinkId {
    type Err = Error;
    fn from_str(s: &str) -> Result<LinkId> {
        s.trim().parse().map(LinkId).map_err(|_| Error::Invalid(format!("no link id: {s}")))
    }
}

/// A link this node made (`links`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    /// What `revoke_link` takes.
    pub id: LinkId,
    /// The thing it shares.
    pub target: Tid,
    /// The role it gives.
    pub role: Role,
    /// When it expires.
    pub until: Option<Time>,
    /// The first redemption ends it.
    pub single_use: bool,
}

fn bad(what: &str) -> impl Fn(osis_blob::Error) -> Error + '_ {
    move |e| Error::Invalid(format!("{what}: {e}"))
}

/// A secret-bearing text form: checked by `$parse` when parsed (`parse` reads it), redacted in `Debug`.
macro_rules! secret_text {
    ($(#[$m:meta])* $n:ident, $inner:ty, $parse:expr) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $n(pub(crate) String);
        impl $n {
            // not every form is parsed back here (a contact card only by contact import)
            #[allow(dead_code)]
            pub(crate) fn parse(&self) -> Result<$inner> {
                ($parse)(self.0.as_str())
            }
        }
        impl std::str::FromStr for $n {
            type Err = Error;
            fn from_str(s: &str) -> Result<$n> {
                let s = s.trim();
                ($parse)(s)?;
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


secret_text!(
    /// A link (`osis://link/...`) that `Osis::redeem` takes: a share link (`Osis::make_link`),
    /// which whoever holds this text can redeem, so hand it over as a secret; or a locator
    /// (`Osis::locator`), which names a thing and where to find it and grants nothing.
    Link, osis_blob::Link, |s| osis_blob::Link::from_text(s).map_err(bad("link"))
);
impl Link {
    /// The thing the link leads to.
    pub fn target(&self) -> Result<Tid> {
        Ok(self.parse()?.target())
    }
}

/// A text form `prefix` + base64url(CBOR of `v`).
fn packed(prefix: &str, v: &Value) -> String {
    format!("{prefix}{}", osis_base::base64url::encode(&osis_base::cbor::encode(v)))
}

/// What `packed` packed, or `Invalid` naming `what`.
fn unpacked(s: &str, prefix: &str, what: &str) -> Result<Value> {
    let bad = || Error::Invalid(format!("malformed {what}"));
    let b = s.trim().strip_prefix(prefix).and_then(osis_base::base64url::decode).ok_or_else(bad)?;
    osis_base::cbor::decode(&b, &osis_base::cbor::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, b.len())).map_err(|_| bad())
}

/// A thing's public keys (`Osis::keys`), shown by hand to a node that has no card of it to read:
/// once it takes them (`Osis::take_keys`) it can grant the thing roles. No secret. Text form
/// `osis://keys/...`.
#[derive(Clone, Debug, PartialEq)]
pub struct Keys {
    thing: Tid,
    certs: osis_blob::Certificates,
}

const KEYS: &str = "osis://keys/";

impl Keys {
    /// The thing they are of.
    pub fn thing(&self) -> Tid {
        self.thing
    }
}

impl std::fmt::Display for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [commits, records] = self.certs.to_values();
        f.write_str(&packed(KEYS, &Value::List(vec![Value::bytes(self.thing.as_bytes()), commits, records])))
    }
}

impl std::str::FromStr for Keys {
    type Err = Error;
    fn from_str(s: &str) -> Result<Keys> {
        let bad = || Error::Invalid("malformed keys".into());
        let Value::List(v) = unpacked(s, KEYS, "keys")? else { return Err(bad()) };
        let [thing, commits, records] = v.as_slice() else { return Err(bad()) };
        let thing = thing.as_array().map(Tid::from_bytes).ok_or_else(bad)?;
        let certs = osis_blob::Certificates::from_values(commits, records, usize::MAX).map_err(|_| bad())?;
        Ok(Keys { thing, certs })
    }
}

/// A transport URL, such as `quic://example.org:4040`: where something listens or is dialed.
/// `FromStr` checks it; a `quic://` URL without a port gets `:4040` spelled out.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Url(String);

impl std::str::FromStr for Url {
    type Err = Error;
    fn from_str(s: &str) -> Result<Url> {
        let s = s.trim();
        let bad = |why: &str| Err(Error::Invalid(format!("URL {s:?}: {why}")));
        if s.split_once("://").is_none_or(|(scheme, rest)| scheme.is_empty() || rest.is_empty()) {
            return bad("needs scheme://");
        }
        // `#` starts an address's key
        if s.contains('#') || s.contains(char::is_whitespace) {
            return bad("no `#` or spaces");
        }
        let url = osis_transport::quic::explicit_port(s);
        if url.len() > osis_base::format::MAX_URL_BYTES {
            return bad("too long");
        }
        Ok(Url(url))
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How to reach a node: a transport URL and the node's key (`<url>#<base64url key>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub(crate) osis_blob::Address);

impl std::str::FromStr for Address {
    type Err = Error;
    /// A `quic://` URL without a port gets `:4040` spelled out, so one node has one address.
    fn from_str(s: &str) -> Result<Address> {
        let mut a = osis_blob::address_from_text(s.trim()).map_err(bad("address"))?;
        a.url = osis_transport::quic::explicit_port(&a.url);
        if a.url.len() > osis_base::format::MAX_URL_BYTES {
            return Err(Error::Invalid(format!("address: URL over {} bytes", osis_base::format::MAX_URL_BYTES)));
        }
        Ok(Address(a))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&osis_blob::address_to_text(&self.0))
    }
}

impl Address {
    /// From a transport URL and the node's 32-byte key.
    pub fn new(url: &Url, key: [u8; 32]) -> Address {
        Address(osis_blob::Address { url: url.0.clone(), key })
    }

    /// Where to dial.
    pub fn url(&self) -> Url {
        Url(self.0.url.clone())
    }

    /// The node's key, which it proves when dialed.
    pub fn key(&self) -> [u8; 32] {
        self.0.key
    }
}

/// The edge `o` grants `role` with on `t`: a timed one retains as `o` says, else as `t`'s default
/// now (spec/permissions.md §3, Retain).
fn edge(e: &osis_engine::Engine, t: &Tid, role: Role, o: GrantOpts) -> Result<ct::Edge> {
    if o.until.is_none() && o.retain_copy.is_some() {
        return Err(Error::Invalid("retain_copy is for a grant with an until".into()));
    }
    let retain = o.until.is_some() && o.retain_copy.unwrap_or_else(|| e.retains_by_default(t));
    Ok(ct::Edge { role, until: o.until, may_grant: o.may_grant, retain, floor: None })
}

/// Whether an admin's grant of `role` to `h` on `t` would lower `h`'s grant still in the state (a
/// present one, or one past its `until` not yet removed): `h`'s departure, whose rotation only a
/// demotion carries (spec/permissions.md §3), so it takes `set_role`.
fn below_held(e: &osis_engine::Engine, t: &Tid, h: &Tid, role: Role) -> bool {
    e.role_on(t) == Some(Role::Admin) && e.key_role(t, h).is_some_and(|r| role < r)
}

/// `UnknownKeys` unless `h` is the public or known here as a thing a grant can box: one with a
/// mint admin, or one minted with a key (a node thing or a link key) whose `keys.0` is held.
fn known_holder(e: &mut osis_engine::Engine, h: Tid) -> Result<()> {
    if h.is_public() {
        return Ok(());
    }
    if !e.knows(&h) || (e.mint_admin(&h).is_none() && e.get_typed(&h, &ct::KEYS)?.is_none()) {
        return Err(Error::UnknownKeys { tid: h });
    }
    Ok(())
}

/// `ReadOnly::holders`, read by `r` (as the thing it acts as: nothing behind a thing it may not read).
pub(crate) fn holders_in(r: &crate::read::Reader<'_>, target: Tid) -> Vec<Holder> {
    let mut out: Vec<Holder> = Vec::new();
    // the ways looked behind so far, per holder: a way none of them beats goes behind it too,
    // else a member's role through a nested holder is that of the holder's first way in
    let mut seen: BTreeMap<Tid, Vec<(Role, Option<Time>)>> = BTreeMap::new();
    let mut queue = std::collections::VecDeque::<(Tid, Option<Role>, Option<Time>, Vec<Tid>)>::from([(target, None, None, Vec::new())]);
    while let Some((at, role, until, through)) = queue.pop_front() {
        for (thing, g) in r.grants(at) {
            if thing == target || through.contains(&thing) {
                continue;
            }
            let way = Holder {
                thing,
                kind: r.holder_kind(thing),
                role: role.map_or(g.role, |x| x.min(g.role)),
                until: [until, g.until].into_iter().flatten().min(),
                through: through.clone(),
            };
            let ways = seen.entry(thing).or_default();
            let beaten = ways.iter().any(|(r, u)| *r >= way.role && (u.is_none() || way.until.is_some_and(|w| Some(w) <= *u)));
            if !beaten {
                ways.push((way.role, way.until));
                let mut on = way.through.clone();
                on.push(thing);
                queue.push_back((thing, Some(way.role), way.until, on));
            }
            out.push(way);
        }
    }
    out
}

impl ReadOnly {
    /// Everyone who holds a role on `target`, directly or through a thing that holds one (an account
    /// through an organization, a joiner through a link), nearest first. A holder with several ways in is
    /// listed once per way: the shortest to each grant it holds them by, and a longer one when it
    /// gives more, so its best role and latest end are among its entries. Who holds through a thing:
    /// `holders` of that thing, or those here with it in `through`. Grants one level down, with
    /// `may_grant` and whether a grant goes with a membership: `grants`. Nothing behind a thing
    /// this node (on a client with a thing of its own, that thing) does not read: its roster is not
    /// shown here (`grants`).
    pub fn holders(&self, target: Tid) -> Result<Vec<Holder>> {
        self.thing_read(target, "holders", crate::port::method::HOLDERS, crate::watch::Filter::Due(crate::watch::Watch::RoleGraph), move |r| Ok(holders_in(r, target)))
    }

    /// This node's root: the thing holding what this node keeps (`Write::hold(root, t)`: this
    /// node alone syncs and keeps `t` so) and naming the thing it keeps its settings on
    /// (`core::SETTINGS`, read by `settings_thing`). Its own: nothing references it, no other
    /// node reads it, and its writes beside others in a `Write` are a commit of their own in the
    /// same transaction, so a thing it holds can be made in one write with its strong.
    /// `Unsupported` through a connection.
    pub fn node_root(&self) -> Result<Tid> {
        self.local("node_root")?;
        Ok(self.inner.node_root)
    }
}

impl Osis {
    /// Grants `holder` `role` on `target`: adds a holder, raises a role, or changes `until` and
    /// `may_grant` (what `opts` leaves out goes). It never waits and never lowers a role: a role below
    /// the holder's present one, or below one whose grant ended and is still on record, is `Invalid`
    /// and takes `set_role`.
    ///
    /// `set_role` also adds and raises, and this overlap is on purpose: `grant` is the call that
    /// does not block and takes no role away, for sync code and for callers that mean only that, and
    /// the only one that sets `until` and `may_grant`. What it does take away, it takes as `set_role`
    /// does: taking `may_grant` away undoes the grants the
    /// holder made by it that this node had not received, and a role below one the holder had before
    /// (it left, or its grant ended and was removed) undoes what it wrote with that role that this
    /// node had not received.
    ///
    /// A thing's first grant to anyone but its mint admin also gives it its keys, so every
    /// holder of a role on it can read it.
    ///
    /// The grant is `target`'s: the holder's nodes learn of it only by being told or by a
    /// reference to `target` they already sync. Unless `GrantOpts::quiet`, the holder is told:
    /// a signal to its inbox (`Write::set_inbox`, else the holder itself) names `target` and this
    /// node, and its nodes reach `target` while their inbox keeps it (its setting enabling inbox
    /// signals, `core::RetentionSetting::enable_inbox_signals`); a holder telling nothing reaches
    /// nothing, and the grant stands all the same.
    ///
    /// `Tid::PUBLIC` as holder makes `target` public: everyone may read it, from any node holding
    /// it (`locator`); a thing it holds by a strong is read with it. Read at most, no
    /// `may_grant` (`Invalid`); `set_role(target, Tid::PUBLIC, None, ..)` makes it private again,
    /// for what is written from then on.
    ///
    /// Needs admin on the target (or `may_grant` with a role of at least `role`, for someone with no grant yet;
    /// a grant that ended above `role` counts as one until an admin takes it away), else `Permission`,
    /// and the holder's keys here (a card of it, a shared thing, pairing), else `UnknownKeys`.
    /// Each grant costs about 2.6 KB of keys: to share with many, grant one thing they all hold a role on. `Unsupported` on
    /// a client with a thing of its own. An `until` on the last admin whose grant has none is
    /// `LeavesNoAdmin` unless `GrantOpts::leave_adminless` says it is meant (`set_role`).
    pub fn grant(&self, target: Tid, holder: Tid, role: Role, opts: GrantOpts) -> Result<()> {
        self.local_at(target, "grant")?;
        if !self.has_record(target) {
            return Err(Error::UnknownThing { tid: target });
        }
        self.locked(|l| {
            let e = l.engine();
            known_holder(e, holder)?;
            let cur = e.roster(&target).get(&holder).copied();
            if cur.is_some_and(|x| role < x.role) || below_held(e, &target, &holder, role) {
                return Err(Error::Invalid("a lower role takes set_role".into()));
            }
            let new = edge(e, &target, role, opts)?;
            marked(e, opts.leave_adminless, |e| match (opts.reads, cur.map(|x| x.floor)) {
                (Reads::FromNow, None) => e.grant_with(&target, &holder, &new, flows::edges::History::None).map_err(Error::from),
                (Reads::FromNow, Some(None)) => Err(Error::Invalid(format!("{holder} already reads what was written on {target} before"))),
                // a change keeps the floor: still from its first grant on
                (Reads::FromNow | Reads::Kept, Some(floor)) => e.grant(&target, &holder, &ct::Edge { floor, ..new }).map_err(Error::from),
                (Reads::Kept | Reads::All, _) => e.grant(&target, &holder, &new).map_err(Error::from),
            })
        })?;
        if !opts.quiet {
            let peers = self.link_peers();
            self.engine(|e| e.signal_grant(&target, &holder, &peers))?;
        }
        Ok(())
    }

    /// Makes `holder`'s role on `target` this one: raises, lowers, or with `None` removes. The usual
    /// way to change a role (`grant` says why both exist). A role that does not change writes
    /// nothing. Someone with no role gets a `grant` with default options, or with `None` nothing is
    /// written. `until` and `may_grant` stay as they are: `grant`
    /// sets those.
    ///
    /// Lowering or removing a role writes at once, keeping what this node has received of the
    /// holder's work and what any other writer had received before the removal (each vouches for
    /// it in an addendum, spec/permissions.md §5.2). What reached no writer in time (an offline
    /// node, a reader or a node keeping it unread alone) is undone until the holder is granted the role again. To
    /// keep more, sync first: `wait_synced(SyncScope::Thing(target))` under your runtime's timeout,
    /// removing anyway when it times out or fails (crate docs, Sharing). A raise waits
    /// for nothing.
    ///
    /// A role below one whose grant ended and is still on record ends the old grant in a commit of
    /// its own (a failure between the two leaves the holder with no role, as it had: call again).
    /// `SetRoleOpts::retain_copy` with a role is `Invalid`.
    ///
    /// A removal follows every way the holder has in (`holders`) until none is left: dropped or
    /// failed midway, the ways already removed stay so (call again). A holder who
    /// joined by a link whose K this node administers is removed together with the link's key, in one commit:
    /// it may have kept the link's text. The link then stops working for anyone who has not used
    /// it yet (make a new one), and its other joiners stay. A joiner's role cannot be changed, only
    /// removed (`Invalid`; `grant` gives it a role of its own). Nor can this call reach through
    /// another holder (a realm, a link this node does not administer): `Invalid`, naming the holder to set
    /// the role on.
    ///
    /// A writer that changed the keys so only it can read locks the others out; removing it (or
    /// lowering it below write) here recovers: the new keys replace the ones it made. Lacking keys
    /// made by a writer it keeps, the lowering applies without changing the keys, and nothing is
    /// written under the thing here until that writer changes them (or is removed too).
    ///
    /// A change that would leave `target` with no admin (its last admin removed, lowered or
    /// leaving) is `LeavesNoAdmin` unless `SetRoleOpts::leave_adminless` says it is meant: nobody
    /// can change the grants of such a thing again, nor delete it; its holders keep their roles.
    ///
    /// `Unsupported` on a client with a thing of its own, and on a thing this node reads at another node: move its sync unit
    /// back here first. A removal written to the copy here would never leave it.
    pub fn set_role(&self, target: Tid, holder: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        self.local_at(target, "set_role")?;
        retain_only_on_removal(role, o)?;
        self.change_role(target, holder, role, o)
    }

    /// `set_role`'s writes.
    fn change_role(&self, target: Tid, holder: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        // each round removes one way in; the bound only guards against grants that never settle
        for _ in 0..16 {
            let Some(way) = self.holders(target)?.into_iter().find(|h| h.thing == holder) else {
                let Some(r) = role else { return Ok(()) };
                // a grant ended above `r`, still on record: its removal first
                if self.engine(|e| below_held(e, &target, &holder, r)) {
                    self.lower(target, holder, None, o)?;
                }
                return self.grant(target, holder, r, GrantOpts::default());
            };
            match way.through.as_slice() {
                [] => {
                    let cur = self.grants(target)?.get(&holder).copied().ok_or(Error::Invalid(format!("{holder} is no holder of {target}")))?;
                    match role {
                        Some(r) if r == cur.role => return Ok(()),
                        Some(r) if r > cur.role => return self.grant(target, holder, r, GrantOpts { until: cur.until, retain_copy: cur.until.map(|_| cur.retain_copy), may_grant: cur.may_grant, reads: Reads::Kept, leave_adminless: false, quiet: true }),
                        _ => self.lower(target, holder, role, o)?,
                    }
                }
                [k] if self.own_link(*k, target) => {
                    if role.is_some() {
                        return Err(Error::Invalid(format!("{holder} joined {target} by a link: it can only be removed")));
                    }
                    self.remove_joiner(*k, holder, o)?;
                }
                [k, ..] => return Err(Error::Invalid(format!("{holder} reaches {target} through {k}: set its role there"))),
            }
            if role.is_some() {
                return Ok(());
            }
        }
        Err(Error::Invalid(format!("{holder} still reaches {target}")))
    }

    /// The edge `m` holds on `t` after lowering it to `role` (`None`: removed): `until` and what
    /// its passing says kept, `may_grant` as it is.
    fn lowered_edge(&self, t: Tid, m: Tid, role: Option<Role>) -> Result<Option<ct::Edge>> {
        let Some(role) = role else { return Ok(None) };
        let cur = self.grants(t)?.get(&m).copied().ok_or(Error::Invalid(format!("{m} is no holder of {t}")))?;
        let held = self.engine(|e| e.roster(&t).get(&m).copied());
        Ok(Some(ct::Edge { role, until: cur.until, may_grant: cur.may_grant, retain: cur.until.is_some() && cur.retain_copy, floor: held.and_then(|x| x.floor) }))
    }

    /// Lowers or removes the grant of `m` on `t`: the demotion with this node's frontier and the
    /// target's rotation, in one commit (spec/permissions.md §2, §3, §5).
    fn lower(&self, t: Tid, m: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        let new = self.lowered_edge(t, m, role)?;
        let fd = flows::Demotion { holder: m, new, retain: o.retain_copy };
        self.engine(|e| marked(e, o.leave_adminless, |e| e.demote(&t, &fd)))?;
        Ok(())
    }

    /// Ends `holder`'s ways in that exist for `target`: its own grant on it, and its join of any link
    /// to it. `holder` is `author()`, or an organization or other thing this node is an admin of (as when an organization's
    /// admin drops a thing that was shared with it). The keys change when the target's next writer or
    /// admin writes, or at once when this node is an admin of `target` by another way. No way in at all
    /// writes nothing.
    ///
    /// An organization or other thing the holder reaches `target` through stays: `Invalid` when that is all it
    /// has, naming that thing, as leaving it is what ends the role. `Invalid` for another
    /// holder when this node is an admin of `target`: taking that role away is `set_role`'s.
    /// `Permission` when this node is no admin of `holder`; on a client with a thing of its
    /// own, for any `holder` but that thing. `LeavesNoAdmin` when `holder` is the last admin
    /// of `target` (`SetRoleOpts::leave_adminless` means it).
    pub fn leave(&self, holder: Tid, target: Tid, o: SetRoleOpts) -> Result<()> {
        self.local_at(target, "leave")?;
        let own = holder == self.author();
        // the flow below runs with the node's authority: a client ends only its own thing's role
        if self.acting.is_some() && !own {
            return Err(Error::Permission { tid: holder, needs: Role::Admin });
        }
        let holders = self.holders(target)?;
        let links: BTreeSet<Tid> = holders.iter().filter(|h| h.kind == HolderKind::Link && h.through.is_empty()).map(|h| h.thing).collect();
        let ways: Vec<&Holder> = holders.iter().filter(|h| h.thing == holder).collect();
        let mut on: BTreeSet<Tid> = ways.iter().filter_map(|h| match h.through.as_slice() {
            [k] if links.contains(k) => Some(*k),
            _ => None,
        }).collect();
        if self.grants(target)?.contains_key(&holder) {
            on.insert(target);
        }
        if on.is_empty() {
            return match ways.first() {
                Some(h) => Err(Error::Invalid(format!("{holder} holds {target} through {}: leave that", h.through.last().copied().unwrap_or(target)))),
                None => Ok(()),
            };
        }
        // every refusal before anything is written
        for t in &on {
            self.engine(|e| leave_allowed(e, holder, *t, own))?;
            if !o.leave_adminless && self.engine(|e| e.leaves_no_admin(t, &holder, None)) {
                return Err(Error::LeavesNoAdmin { tid: *t });
            }
        }
        // the target's own grant first: its next rotation still seals a link's K at the keyset
        // it holds, which the leave of K then leaves uncovered (until a joiner rotates K)
        let order: Vec<Tid> = on.iter().copied().filter(|t| *t == target).chain(on.iter().copied().filter(|t| *t != target)).collect();
        for t in order {
            self.leave_grant(holder, t, own, o)?;
        }
        Ok(())
    }

    /// `leave`'s removal of `holder`'s grant on `t`.
    fn leave_grant(&self, holder: Tid, t: Tid, own: bool, o: SetRoleOpts) -> Result<()> {
        self.engine(|e| {
            leave_allowed(e, holder, t, own)?;
            // this account's own grant, whichever way this node also holds the target
            marked(e, o.leave_adminless, |e| e.demote(&t, &flows::Demotion { holder, new: None, retain: o.retain_copy })).map_err(Error::from)
        })?;
        Ok(())
    }

    /// The things this node retains a read-only copy of after being removed from them (for a client
    /// with a thing of its own, those it reads). A copy reads as before, and nothing syncs or writes it.
    /// `drop_retained_copy` erases one.
    pub fn retained_copies(&self) -> Result<Vec<Tid>> {
        self.local("retained_copies")?;
        Ok(self.engine(|e| {
            let mut v = e.kept_copies();
            // acting as a thing: the copies it reads
            if let Some(a) = self.acting {
                v.retain(|x| e.copy_readable_by(&a, x));
            }
            v
        }))
    }

    /// Erases the retained copy of `thing`, and what only it retained: its disk space is this user's.
    pub fn drop_retained_copy(&self, thing: Tid) -> Result<()> {
        self.local("drop_retained_copy")?;
        self.engine(|e| e.forget_lost(osis_engine::rotation::LostScope::Kept(&[thing])))?;
        Ok(())
    }

    /// Makes a share link to `target` with `role` (read or above: `Invalid` below). Anyone
    /// holding the link can redeem it until `until` or `revoke_link`. The link's thing is minted
    /// with admin `admin` (as `Write::create`'s), a thing this node is an admin of (`Permission`
    /// otherwise): every node holding `admin` holds the link, and any of its admins lists and
    /// ends it (`links`, `revoke_link`). A person's links take their account, so each of its
    /// nodes sees and ends them.
    pub fn make_link(&self, target: Tid, role: Role, admin: Tid, opts: LinkOpts) -> Result<Link> {
        if let Some(at) = self.process_at("make_link")? {
            return self.forward(&at, crate::port::method::MAKE_LINK, (target, role, admin, opts.until, opts.single_use));
        }
        self.local_at(target, "make_link")?;
        let peers = self.link_peers();
        let spec = flows::LinkSpec { target, role, until: opts.until.map(|t| osis_base::WallMs(t.0)), peers, single_use: opts.single_use };
        let (link, _, _) = self.engine(|e| e.create_link(&admin, &spec))?;
        Ok(Link(link.to_text().map_err(bad("link"))?))
    }

    /// A locator of `target`: a link that holds no secret and grants nothing, naming `target` and
    /// the nodes `make_link`'s would. Whoever holds it can `redeem` it and reach `target` there if it may: everyone while
    /// the public reads it (`grant` to `Tid::PUBLIC`), and a holder of a role on it (an account's
    /// new node, a grantee told of its grant) at any node reading it. `Invalid` while `target` has
    /// no keys of its own here yet.
    pub fn locator(&self, target: Tid) -> Result<Link> {
        if let Some(at) = self.process_at("locator")? {
            return self.forward(&at, crate::port::method::LOCATOR, (target,));
        }
        self.local_at(target, "locator")?;
        let peers = self.link_peers();
        let link = self.engine(|e| e.locator(&target, peers))?;
        let link = link.ok_or_else(|| Error::Invalid(format!("{target} has no keys of its own yet")))?;
        Ok(Link(link.to_text().map_err(bad("link"))?))
    }

    /// A link's first-contact peers (spec/wire.md §10): this node by its dialable key,
    /// then the nodes it dials by configured address (`Config::dial`).
    fn link_peers(&self) -> Vec<osis_blob::DialHint> {
        self.locked(|l| osis_blob::link_peers(l.secret.public_key(), &[], &l.node.config().dial))
    }

    /// `t`'s public keys as held here, to show by hand (`Keys`). `UnknownKeys` when none are
    /// held: `t` has no keys yet (`Write::create_with_keys` makes it with them; a `grant` to it or `put_card` of it gives it some).
    /// `Unsupported` through a connection.
    pub fn keys(&self, t: Tid) -> Result<Keys> {
        self.local("keys")?;
        let certs = self.engine(|e| e.holder_keys(&t))?;
        if certs.commits.is_empty() {
            return Err(Error::UnknownKeys { tid: t });
        }
        Ok(Keys { thing: t, certs })
    }

    /// Takes keys shown by hand (`keys`): their thing can then be granted roles here. `Invalid`
    /// when they hold no keys of it that this node judges valid. `Unsupported` through a
    /// connection.
    pub fn take_keys(&self, k: &Keys) -> Result<Tid> {
        self.local("take_keys")?;
        let t = k.thing;
        let taken = self.engine(|e| e.take_holder_keys(&t, &k.certs, None).and_then(|_| e.current_keys(&t)).map(|k| !k.is_empty()))?;
        if !taken {
            return Err(Error::Invalid(format!("the keys shown are no keys of {t}")));
        }
        Ok(t)
    }

    /// Puts `of`'s card on `on`: whoever reads `on` may then grant `of` roles and reach its inbox
    /// (`grant`, `Write::set_inbox`). `of`'s keys and its inbox's go with it, and this node keeps them
    /// current. Needs write on `on` through `of` (`Write::act_as`) and `of`'s keys here, else
    /// `Permission` or `UnknownKeys`. `Unsupported` on a client with a thing of its own.
    pub fn put_card(&self, on: Tid, of: Tid) -> Result<()> {
        self.local_at(on, "put_card")?;
        if !self.has_record(on) {
            return Err(Error::UnknownThing { tid: on });
        }
        if !self.engine(|e| e.write_card(on, of))? {
            return Err(Error::UnknownKeys { tid: of });
        }
        Ok(())
    }

    /// Removes `of`'s card from `on` (`put_card`). Needs write on `on`, else `Permission`.
    /// `Unsupported` on a client with a thing of its own.
    pub fn remove_card(&self, on: Tid, of: Tid) -> Result<()> {
        self.local_at(on, "remove_card")?;
        Ok(self.engine(|e| e.remove_card(on, of))?)
    }

    /// Redeems a link for `joiner`: reaches what it names and joins it, returning the thing.
    /// `joiner` is the thing given the role and holding the thing by a strong from its `holds.0`
    /// (`node()`, or a thing this node writes). Returns once this node holds a role on the thing
    /// here; it waits for the link's node meanwhile, for about an hour from the first call (this
    /// node's policy), then fails with `Network` and keeps nothing: redeem it again to try again. A
    /// link to a thing this node already reaches joins nothing. What a share link holds is kept
    /// until the join is held elsewhere or the node gives up, a dropped call included. A public
    /// link joins nothing: `joiner` holds the thing by its strong, written once the thing is
    /// found public or this node is found to hold a role on it.
    pub async fn redeem(&self, link: &Link, joiner: Tid) -> Result<Tid> {
        if let Some(at) = self.process_at("redeem")? {
            return self.remote_wait(&at, crate::port::method::REDEEM, (link.clone(), joiner))?.await;
        }
        self.redeeming(link, joiner)?.await
    }

    /// `redeem` here, as a future holding nothing of the node (the port runs it for a main
    /// session).
    pub(crate) fn redeeming(&self, link: &Link, joiner: Tid) -> Result<impl std::future::Future<Output = Result<Tid>> + Send + 'static> {
        let link = link.parse()?;
        let target = link.target();
        let mut started = false;
        Ok(self.waiting(move |db| {
            if db.engine(|e| e.role_on(&target).is_some()) {
                return Some(Ok(target));
            }
            redeem_started(db, &link, joiner, &mut started, "link").or_else(|| redeem_over(db, &link, "link"))
        }))
    }

    /// The links that still work made with an `admin` (`make_link`) this node holds, whichever
    /// node made them: an admin of that `admin` ends them (`revoke_link`). Filter by
    /// `LinkInfo::target`. `Unsupported` on a client with a thing of its own, which is also why a node
    /// connected with a client secret adds none.
    pub fn links(&self) -> Result<Vec<LinkInfo>> {
        self.local("links")?;
        self.live_links()
    }

    fn live_links(&self) -> Result<Vec<LinkInfo>> {
        Ok(self
            .held_links()?
            .into_iter()
            .filter_map(|h| {
                let e = self.engine(|e| e.roster(&h.k).get(&h.l).copied())?;
                Some(LinkInfo { id: LinkId(h.k), target: h.target, role: e.role, until: e.until, single_use: h.single_use })
            })
            .collect())
    }

    /// The links whose seed this node holds: on a thing minted with K's mint admin S as admin,
    /// so held by S's readers alone (spec/permissions.md §7).
    fn held_links(&self) -> Result<Vec<flows::HeldLink>> {
        Ok(self.engine(|e| e.held_links())?.to_vec())
    }

    /// The key L of link's thing `k` while its link works (`held_links`: its seed goes with its end).
    fn link_key(&self, k: Tid) -> Result<Option<Tid>> {
        Ok(self.held_links()?.iter().find(|h| h.k == k).map(|h| h.l))
    }

    /// Whether `k` is the thing of a link to `target` this node may end, working or ended: its record
    /// names the target, and this node is an admin of it (by its mint admin, spec/permissions.md
    /// §7). Invariant (security): only an admin of K removes L or a joiner from it
    /// (`finalize_link`, `revoke_joiner`; any other node's removal is judged invalid wherever it
    /// lands): a reader of K's mint admin lists the link (`links`) and ends nothing.
    fn own_link(&self, k: Tid, target: Tid) -> bool {
        self.engine(|e| e.core.created(&k).and_then(|r| r.link_target()) == Some(target) && e.role_on(&k) == Some(Role::Admin))
    }

    /// Ends a link: nobody can use it from now on. Those who joined by it keep their role; to remove
    /// one, `set_role`. Writes at once: a join this node has not received yet is undone (one another
    /// writer received stands, as `set_role` says). `Permission` unless this node is an admin of
    /// the link's `admin` (`make_link`); `Unsupported` on a client with a thing of its own.
    pub fn revoke_link(&self, id: LinkId) -> Result<()> {
        self.local("revoke_link")?;
        match self.link_key(id.0)? {
            Some(l) => {
                self.engine(|e| e.finalize_link(&id.0, &l))?;
                Ok(())
            }
            // ended already: its seed went with its end
            None if self.engine(|e| e.core.created(&id.0).and_then(|r| r.link_target())).is_some_and(|t| self.own_link(id.0, t)) => Ok(()),
            None => Err(Error::Invalid(format!("no link {} here", id.0))),
        }
    }

    /// Removes `joiner` from the link's thing `k` and ends the link in the same commit, under one rotation
    /// (spec/permissions.md §7: a joiner may keep the seed); the other joiners stay holders of K and
    /// need a new link to add anyone.
    fn remove_joiner(&self, k: Tid, joiner: Tid, o: SetRoleOpts) -> Result<()> {
        let l = self.link_key(k)?;
        self.engine(|e| marked(e, o.leave_adminless, |e| e.revoke_joiner(&k, l.as_ref(), &joiner, o.retain_copy)))?;
        Ok(())
    }
}

/// `SetRoleOpts::retain_copy` is a removal's word.
fn retain_only_on_removal(role: Option<Role>, o: SetRoleOpts) -> Result<()> {
    if role.is_some() && o.retain_copy.is_some() {
        return Err(Error::Invalid("retain_copy is for removing a role: there is no copy to retain while a role remains".into()));
    }
    Ok(())
}


/// Starts redeeming `link` for `joiner` on a redeem's first check: an error when the node can never
/// redeem it.
fn redeem_started<R>(db: &Osis, link: &osis_blob::Link, joiner: Tid, started: &mut bool, what: &str) -> Option<Result<R>> {
    if std::mem::replace(started, true) {
        return None;
    }
    let w = db.locked(|l| {
        let w = l.node.redeem(link, joiner);
        l.handle(osis_sync::Input::Wrote);
        w
    });
    match w {
        osis_sync::types::Waiting::Never(why) => Some(Err(Error::Invalid(format!("{what}: {why}")))),
        _ => None,
    }
}

/// A redeem with no role on its target yet whose node stopped
/// redeeming the link: it ended (`Invalid`), or the sharer never answered within the node's
/// follow time (`Network`, `osis_sync::Policy::follow_link_ms`). `None` while it is redeemed.
fn redeem_over<R>(db: &Osis, link: &osis_blob::Link, what: &str) -> Option<Result<R>> {
    let k = match link {
        osis_blob::Link::Share(l) => l.k,
        osis_blob::Link::Locator(l) => l.target,
    };
    if db.locked(|l| l.node.redeeming(&k)) {
        return None;
    }
    let ended = match link {
        osis_blob::Link::Share(l) => db.engine(|e| e.link_ended(l)),
        osis_blob::Link::Locator(_) => false,
    };
    Some(Err(if ended {
        Error::Invalid(format!("{what}: the link has ended"))
    } else {
        Error::Network(format!("{what}: no holder answered"))
    }))
}
