//! Sharing, links, cards, devices, hosts and sync (notes/api.md Sharing and roles, Sync
//! configuration and status) over role flows and the sync engine: each sharing call is
//! one role commit made locally (spec/permissions.md §2), whose deliveries the sync engine
//! carries out; calls that wait for another node are `async` (runtime-agnostic futures).

use crate::error::{Error, Result};
use crate::handle::{LINKS, Locked, MadeLink, Osis, save_hosts};
use crate::watch::{Delivery, Filter, Subscription};
use osis_base::{Ak, LabelId, Role, Tid, Value, WallMs};
use osis_node::flows::{self, PreSync};
use osis_node::sync::SyncEngine;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// When a grant ends and what its holder may grant others (`Osis::grant`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrantOpts {
    /// The grant ends at this time.
    pub until: Option<WallMs>,
    /// The highest role the holder may grant others, at most its own.
    pub invite: Option<Role>,
}

/// What a group contains. Being a member grants nothing: who may read a thing is who holds a role
/// on it (`Osis::grants`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Member {
    /// A thing in the group.
    Item(Tid),
    /// A group whose own members count as members of this one.
    Subgroup(Tid),
}

impl Member {
    /// The member's tid, whichever way it is in the group.
    pub fn tid(self) -> Tid {
        self.parts().0
    }

    /// The thing, and whether it is a subgroup.
    pub(crate) fn parts(self) -> (Tid, bool) {
        match self {
            Member::Item(t) => (t, false),
            Member::Subgroup(t) => (t, true),
        }
    }
}

/// One way an actor holds a role on a thing (`Osis::holders`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    pub actor: Tid,
    /// The role this way gives: the least along it.
    pub role: Role,
    /// When this way ends: the earliest end along it. One that has ended is not listed.
    pub until: Option<WallMs>,
    /// The actors between the thing and this holder, nearest the thing first: empty for a grant
    /// on the thing itself, the link's actor for someone who joined by a link, a team for its
    /// members.
    pub through: Vec<Tid>,
}

/// What to do about work a holder may have done that this device has not seen, before lowering
/// or removing its role. Work not seen by then is undone everywhere.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SyncFirst {
    /// Catch up first, for as long as it takes; fail `Unsynced` when it is known it cannot be done
    /// (a group stranded or without hosts, or no runtime).
    #[default]
    Required,
    /// Try to catch up for this long, then go ahead with a diagnostic. At 0 only what is already
    /// synced counts.
    Try(Duration),
    /// Go ahead now, keeping what this device has seen: for a stolen device or a hostile holder.
    Skip,
    /// Go ahead now, keeping only what this device had seen by this time.
    Backdate(WallMs),
}

/// How `Osis::set_role` takes a role away.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetRoleOpts {
    pub sync: SyncFirst,
    /// On removal: whether the holder's devices keep a read-only copy (`true`) or erase it
    /// (`false`). `None`: the thing's default (`core::RequiredRules::keep`), and erase for a device
    /// leaving its account. `Invalid` when a role remains.
    pub keep: Option<bool>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkOpts {
    /// The link expires: a device of this person removes the link key once it passed and K's
    /// label synced (spec/permissions.md §8). An expiring link closes when one of your devices
    /// next syncs after `until`: until then anyone holding the link can still join.
    pub until: Option<WallMs>,
    /// The first redemption ends the link: the link says so (`flags`, spec/wire.md §10), the
    /// redeemer removes the link key in its redemption, and a device of this person finalizes
    /// the link when it sees that (spec/permissions.md §8).
    pub single_use: bool,
    /// Opt-in: the link text carries this device's dialable key and relays (never its lan
    /// secret; spec/permissions.md §8), so a redeemer that shares no host with it reaches it
    /// directly while it is online. Anyone holding the link can dial this device until the link
    /// ends by revocation or expiry, when the key rotates (a single-use link's redemption keeps
    /// it: the redeemer keeps the direct path). Needs this device reachable (a runtime, `Config.peers`); a
    /// database without hosts can only make direct links.
    pub direct: bool,
}

/// Names a link (`LinkInfo::id`, `Osis::revoke_link`). Its text form is what `FromStr` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub(crate) Tid);

impl LinkId {
    /// The actor those who joined by this link hold through: `Holder::through` names it, and
    /// `Osis::holders` of it lists them.
    pub fn actor(&self) -> Tid {
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

/// A link of this person (`links`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    /// What `revoke_link` takes.
    pub id: LinkId,
    pub target: Tid,
    pub role: Role,
    pub until: Option<WallMs>,
    pub single_use: bool,
}

/// An invite from a sender with no known connection to this database (spec/sync.md §3, invite
/// requests): nothing it names is fetched or dialed until `accept_invite`. It says nothing about
/// sender or thing: both would be the sender's unverified word, and a
/// request never comes from a node known to be connected, so a known name there would be a
/// spoof or a device not seen yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InviteId(osis_base::CommitId);

impl InviteId {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0.0
    }

    pub(crate) fn from_bytes(b: &[u8]) -> Result<InviteId> {
        Ok(InviteId(osis_base::CommitId(b.try_into().map_err(|_| Error::Invalid("invite id".into()))?)))
    }
}

fn bad(what: &str) -> impl Fn(osis_label::Error) -> Error + '_ {
    move |e| Error::Invalid(format!("{what}: {e}"))
}

/// A secret-bearing text form: checked when parsed, redacted in `Debug`.
macro_rules! text_type {
    ($(#[$m:meta])* $n:ident, $inner:ty, $parse:path, $what:literal) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $n(pub(crate) String);
        impl $n {
            pub(crate) fn parse(&self) -> Result<$inner> {
                $parse(&self.0).map_err(bad($what))
            }
        }
        impl std::str::FromStr for $n {
            type Err = Error;
            fn from_str(s: &str) -> Result<$n> {
                let s = s.trim();
                $parse(s).map_err(bad($what))?;
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

text_type!(
    /// A share link (`osis://link/...`): holds the link key's seed.
    ShareLink, osis_label::ShareLink, osis_label::ShareLink::from_text, "link"
);
impl ShareLink {
    /// The thing the link shares.
    pub fn target(&self) -> Result<Tid> {
        Ok(self.parse()?.target)
    }
}
text_type!(
    /// A contact card: a read link to the person's profile (spec/sync.md §3).
    ContactCard, osis_label::ShareLink, osis_label::ShareLink::from_text, "contact card"
);
text_type!(
    /// A recovery card (`osis://card/...`): holds the recovery seed; show or store it, osis
    /// keeps none of it.
    RecoveryCard, osis_label::RecoveryCard, osis_label::RecoveryCard::from_text, "recovery card"
);

/// A transport URL, such as `quic://example.org:4040`: where something listens or is dialed.
/// `FromStr` checks it; a `quic://` URL without a port gets `:4040` spelled out.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Url(String);

impl Url {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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

/// Where a node is reached: transport URL plus its key (`<url>#<base64url key>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostAddr(pub(crate) osis_label::Address);

impl std::str::FromStr for HostAddr {
    type Err = Error;
    /// A `quic://` URL without a port gets `:4040` spelled out, so one host has one address
    /// (`hosts rm` matches what `hosts add` stored).
    fn from_str(s: &str) -> Result<HostAddr> {
        let mut a = osis_label::address_from_text(s.trim()).map_err(bad("host address"))?;
        a.url = osis_transport::quic::explicit_port(&a.url);
        if a.url.len() > osis_base::format::MAX_URL_BYTES {
            return Err(Error::Invalid(format!("host address: URL over {} bytes", osis_base::format::MAX_URL_BYTES)));
        }
        Ok(HostAddr(a))
    }
}

impl std::fmt::Display for HostAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&osis_label::address_to_text(&self.0))
    }
}

impl HostAddr {
    /// From a transport URL and the node's 32-byte key.
    pub fn new(url: &Url, key: [u8; 32]) -> HostAddr {
        HostAddr(osis_label::Address { url: url.0.clone(), key })
    }

    pub fn url(&self) -> Url {
        Url(self.0.url.clone())
    }

    pub fn key(&self) -> [u8; 32] {
        self.0.key
    }
}

/// A device of the person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Device {
    pub node: Tid,
    pub role: Role,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SyncState {
    Synced,
    Syncing,
    Unreachable,
    NoHosts,
    /// A host does not admit it (yet: code 14, spec/wire.md §11.2; `GroupSync::not_admitted`
    /// names them) and no other host has it open; registered again after a back-off. Ranks
    /// above `NoHosts`, below `Stranded`.
    Refused,
    /// Waiting for a re-seal (spec/permissions.md §3). Ranks above `NoHosts` (a group shows
    /// its worst label's state; `wait_synced` judges each label on its own).
    Stranded,
    /// Held for commit headers only (`SyncMode::HeadersOnly`): not synced, what is here is stale.
    HeadersOnly,
    /// No label carries the thing to one of its holders (`GroupSync::unrouted`): it holds a role
    /// and reads nothing until `sync` gives the thing a label or a synced group it reads takes
    /// the thing in. Only on things with no label of their own, so never beside another state.
    NoRoute,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSync {
    pub state: SyncState,
    pub last_sync: Option<WallMs>,
    /// The labels this node syncs it under (several while one replaces another): what a host
    /// admits it by (`Hosting::labels`, `caps`).
    pub labels: Vec<LabelId>,
    /// Hosts that do not admit one of those labels (yet): state `Refused` when no other host
    /// has it open, else informational.
    pub not_admitted: Vec<HostAddr>,
    /// This node left the group and keeps it until a host has its removal (spec/permissions.md
    /// §3); stays set while no host takes it.
    pub leaving: bool,
    /// Holders of a role on the thing that read no live label carrying it, as this node knows
    /// labels (`Engine::unrouted`; the holder's own node and the granter's show the same): this
    /// person among them when it is the one without a route. Not this node's own clients on a
    /// thing this person owns: they read what this node holds.
    pub unrouted: Vec<Tid>,
}

/// Sync status: hosts connected and each synced group (`groups`: groups with a label this
/// node reads, and those it holds for receipts only).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub connected: usize,
    pub groups: BTreeMap<Tid, GroupSync>,
    /// The nodes this process is connected to, and those its routes name.
    pub remotes: Vec<crate::sources::RemoteStatus>,
    /// Things read at a route and also in a group that carries them elsewhere: writes on them are
    /// refused until one of the groups moves (`Osis::group_source`).
    pub split: BTreeSet<Tid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncScope {
    /// Every synced label with hosts (a hostless one has nothing to wait for) and every
    /// pending delivery.
    All,
    /// The labels holding this thing (its own, or those of groups containing it; a hostless one
    /// fails `Unsynced`) and the deliveries about it, what it holds or those groups.
    Thing(Tid),
}

/// One synced label's state.
fn label_state(s: &osis_node::sync::LabelStatus) -> SyncState {
    if s.hosts == 0 {
        SyncState::NoHosts
    } else if s.stranded {
        SyncState::Stranded
    } else if !s.not_admitted.is_empty() && s.open == 0 {
        SyncState::Refused
    } else if s.refused && s.open == 0 {
        SyncState::Unreachable
    } else if s.open > 0 && s.idle == s.open {
        SyncState::Synced
    } else if s.connected > 0 || s.open > 0 {
        SyncState::Syncing
    } else {
        SyncState::Unreachable
    }
}

/// The status from the sync engine's labels (a group with several labels shows the worst) and
/// the engine's routes; `me`: this database's person.
pub(crate) fn status_of(sync: &mut SyncEngine, me: Tid) -> Result<Status> {
    let mut groups: BTreeMap<Tid, GroupSync> = BTreeMap::new();
    for s in sync.label_status() {
        let state = label_state(&s);
        let last = s.last_sync.map(WallMs);
        let g = groups.entry(s.group).or_insert(GroupSync { state, last_sync: last, labels: Vec::new(), not_admitted: Vec::new(), leaving: false, unrouted: Vec::new() });
        g.state = g.state.max(state);
        g.last_sync = g.last_sync.max(last);
        g.labels.push(s.label);
        g.leaving |= s.leaving;
        for a in s.not_admitted {
            let a = HostAddr(a);
            if !g.not_admitted.contains(&a) {
                g.not_admitted.push(a);
            }
        }
    }
    for g in sync.receipts_only() {
        groups.insert(*g, GroupSync { state: SyncState::HeadersOnly, last_sync: None, labels: Vec::new(), not_admitted: Vec::new(), leaving: false, unrouted: Vec::new() });
    }
    // things a holder has a role on and no route to (spec/sync.md §2): none has a label of its
    // own, so none is listed above. On a thing this person administers (it can `sync` it) nobody
    // misses a route who reads only what this node holds: this person, its clients, and a group
    // of its own held by no one else
    let e = sync.engine_mut();
    let node = e.tid();
    // a store that cannot answer fails the status: none read here would list its clients as cut off
    let clients = e.get_typed(&node, &ct::CLIENTS)?.unwrap_or_default();
    let served: BTreeSet<Tid> = [me].into_iter().chain(clients.into_keys()).collect();
    for (t, holders) in e.unrouted().iter() {
        let t = *t;
        let own = e.core.role_now(&me, &t) == Some(Role::Admin);
        let local = |e: &osis_node::Engine, h: &Tid| served.contains(h) || (e.owner_chain(h).any(|x| x == me) && e.core.current_holders(h).iter().all(|(m, _, _)| served.contains(m)));
        let unrouted: Vec<Tid> = holders.iter().copied().filter(|h| !(own && local(e, h))).collect();
        if !unrouted.is_empty() && !groups.contains_key(&t) {
            groups.insert(t, GroupSync { state: SyncState::NoRoute, last_sync: None, labels: Vec::new(), not_admitted: Vec::new(), leaving: false, unrouted });
        }
    }
    Ok(Status { connected: sync.connected(), groups, remotes: Vec::new(), split: BTreeSet::new() })
}

fn edge(role: Role, o: GrantOpts) -> ct::Edge {
    ct::Edge { role, until: o.until, invite: o.invite, since: None, tied: None, keyset: None }
}

/// Whether a grant of `role` to `h`, with no grant on `t` now, would be written by an admin below
/// a role `h` lost with no explicit write since (it ended, or `h` left). That is a demotion to
/// receivers (spec/permissions.md §5.1 step 4), and one with no frontier undoes all `h` ever wrote
/// there, so it takes `set_role`. An invite grant judges nothing of the kind.
fn below_lost(e: &osis_node::Engine, t: &Tid, h: &Tid, role: Role) -> bool {
    e.role_on(t) == Some(Role::Admin) && e.lost_role(t, h).is_some_and(|r| role < r)
}

/// `UnknownActor` unless `h` is known here as an actor a grant can box: a thing with an owner,
/// or a key actor (a node, a recovery or link key) whose `keys.0` is held.
fn known_actor(e: &mut osis_node::Engine, h: Tid) -> Result<()> {
    if !e.knows(&h) || (e.owner(&h).is_none() && e.get_typed(&h, &ct::KEYS)?.is_none()) {
        return Err(Error::UnknownActor { tid: h });
    }
    Ok(())
}

fn needs_admin(e: osis_node::Error) -> Error {
    match e {
        osis_node::Error::Permission { tid } => Error::Permission { tid, needs: Role::Admin },
        e => e.into(),
    }
}

/// Whether everything carrying `t` here finished a pass: its groups' labels, none of them left to
/// answer for what they did not bring (a label with no hosts has nothing to bring). The seam for
/// partial fetch (issues/partial-history-fetch.md): a node that chose not to fetch says `false` too.
pub(crate) fn fetched(l: &mut crate::handle::Locked, t: Tid) -> bool {
    let e = l.sync.engine();
    let mut groups = e.groups_of(&t);
    groups.insert(t);
    let stale = l.sync.receipts_only().iter().any(|g| groups.contains(g));
    !stale && l.sync.label_status().iter().filter(|s| groups.contains(&s.group)).all(|s| matches!(label_state(s), SyncState::Synced | SyncState::NoHosts))
}

/// Synced groups holding any of `things` (the thing itself or its closure).
fn groups_holding(sync: &mut SyncEngine, status: &Status, things: &BTreeSet<Tid>) -> Vec<Tid> {
    status.groups.iter().filter(|(_, s)| !matches!(s.state, SyncState::HeadersOnly | SyncState::NoRoute)).map(|(g, _)| *g).filter(|g| things.contains(g) || sync.engine().closure(g).iter().any(|t| things.contains(t))).collect()
}

/// Whether a route to `t`, which no group here holds yet, may still arrive: a hint names its label,
/// or this node does not administer it (it could `sync` it itself, nothing is coming) and a label
/// it reads has more to bring (a grant or a copy not read yet, a first sync).
fn route_arriving(sync: &mut SyncEngine, t: &Tid) -> bool {
    if sync.hinted(t) {
        return true;
    }
    if sync.engine().role_on(t) == Some(Role::Admin) {
        return false;
    }
    let skip = sync.receipts_only().clone();
    sync.label_status().iter().any(|s| !skip.contains(&s.group) && matches!(label_state(s), SyncState::Syncing | SyncState::Unreachable))
}

/// The labels' check of `wait_synced(Group(t))`, over the groups holding `t` now and the
/// deliveries about `t`, what it holds or those groups; `Unsynced` when none holds it and none
/// will (`route_arriving`).
fn group_synced(sync: &mut SyncEngine, me: Tid, t: Tid) -> Option<Result<()>> {
    let st = match status_of(sync, me) {
        Ok(st) => st,
        Err(e) => return Some(Err(e)),
    };
    let groups = groups_holding(sync, &st, &[t].into_iter().collect());
    if groups.is_empty() {
        return (!route_arriving(sync, &t)).then(|| Err(Error::Unsynced { groups: vec![t] }));
    }
    let mut about: BTreeSet<Tid> = sync.engine().closure(&t).iter().copied().collect();
    about.insert(t);
    about.extend(groups.iter().copied());
    synced(sync, Some(&groups), &[], Some(&about), false)
}

/// The sync wait's check (`Osis::groups_synced`): one rule over the labels in scope, `groups`
/// (all their labels but a replaced hostless one beside another) or `None` (every label with hosts), then the pending deliveries about
/// `deliveries` (every one when `groups` is `None`). `late` (a `SyncFirst::Try` gives up): a refused
/// label's group fails `Unsynced` (else it may yet be admitted).
fn synced(sync: &mut SyncEngine, groups: Option<&[Tid]>, reads: &[Tid], deliveries: Option<&BTreeSet<Tid>>, late: bool) -> Option<Result<()>> {
    let skip = sync.receipts_only().clone();
    let all: Vec<_> = sync.label_status().into_iter().filter(|s| !skip.contains(&s.group) && groups.is_none_or(|gs| gs.contains(&s.group))).collect();
    // a replaced hostless label beside another of its group takes nothing (it retires after
    // ROLE_KEEP): left out, else `Group(t)` failed until then
    let gone = |s: &osis_node::sync::LabelStatus| s.hosts == 0 && s.replaced;
    let labels: Vec<(Tid, SyncState)> = all
        .iter()
        .filter(|s| !gone(s) || !all.iter().any(|x| x.group == s.group && !gone(x)))
        .map(|s| (s.group, label_state(s)))
        .filter(|(_, st)| groups.is_some() || *st != SyncState::NoHosts)
        .collect();
    let mut bad: BTreeSet<Tid> = labels.iter().filter(|(_, s)| matches!(s, SyncState::Stranded | SyncState::NoHosts) || late && *s == SyncState::Refused).map(|(g, _)| *g).collect();
    let read = sync.receipts_read(reads);
    if let Some(Err(b)) = &read {
        bad.extend(b);
    }
    if !bad.is_empty() {
        return Some(Err(Error::Unsynced { groups: bad.into_iter().collect() }));
    }
    let labeled = groups.is_none_or(|gs| gs.iter().all(|g| labels.iter().any(|(x, _)| x == g)));
    if read.is_none() || !labeled || labels.iter().any(|(_, s)| *s != SyncState::Synced) {
        return None;
    }
    if let Some(about) = deliveries
        && sync.deliveries_pending() > 0
        && (groups.is_none() || sync.pending_about().iter().any(|ts| ts.iter().any(|t| about.contains(t))))
    {
        return None;
    }
    Some(Ok(()))
}

/// Whether `g`'s labels are done now: nothing written here still waits (`Osis::group_source`).
pub(crate) fn synced_now(l: &mut crate::handle::Locked, g: Tid) -> Option<Result<()>> {
    let about: BTreeSet<Tid> = l.sync.engine().closure(&g).iter().copied().chain([g]).collect();
    synced(&mut l.sync, Some(&[g]), &[], Some(&about), false)
}

impl Osis {
    /// `Unsupported` when calls on `t` go to another node: a flow the port does not carry.
    pub(crate) fn not_routed(&self, what: &str, t: Tid) -> Result<()> {
        match self.route(t) {
            crate::sources::Source::Local => Ok(()),
            crate::sources::Source::Remote(_) => Err(Error::Unsupported(format!("{what} of a thing this node reads at another node: move its group home first"))),
        }
    }

    /// Persists the ephemeral things among `tids` with their owner chains by a content commit
    /// of their own (notes/ephemeral.md Persistence: a role operation on an ephemeral thing
    /// persists it first); durable ones are left alone.
    fn persist(&self, tids: &[Tid]) -> Result<()> {
        let me = self.me();
        self.guarded(tids, |e| persist_in(e, me, tids))
    }

    /// Grants `holder` `role` on `target`: adds a holder, raises a role, or changes `until` and
    /// `invite` (what `opts` leaves out goes). It never waits and never lowers a role: a role below
    /// the holder's present one, or below one it lost when its grant ended or it left, is `Invalid`
    /// and takes `set_role`, which keeps what the holder wrote.
    ///
    /// `set_role` also adds and raises, and this overlap is on purpose: `grant` is the call that
    /// does not block and takes no role away, for sync code and for callers that mean only that, and
    /// the only one that sets `until` and `invite`. One thing it does take: an `invite` below the
    /// present one undoes every grant the holder made by its invite.
    ///
    /// This records the permission and nothing else. The holder reads the target only once a synced
    /// group it reads holds the target, or the target's own `sync` carries it; until then `status`
    /// shows `SyncState::NoRoute` and names the holder (`GroupSync::unrouted`).
    ///
    /// Needs admin on the target (or an `invite` of at least `role`, for someone with no grant yet;
    /// a grant that ended above `role` counts as one until an admin takes it away), else `Permission`,
    /// and the holder's keys here (a contact card, a shared group, pairing), else `UnknownActor`.
    /// Each grant costs about 2.6 KB of keys: to share with many, grant one group. `Unsupported` on
    /// a client with its own actor.
    pub fn grant(&self, target: Tid, holder: Tid, role: Role, opts: GrantOpts) -> Result<()> {
        if let crate::sources::Source::Remote(r) = self.route_write(target)? {
            return r.call(crate::port::method::GRANT, vec![Value::Tid(target), Value::Tid(holder), crate::port::codec::role_v(role), crate::port::codec::grant_opts_v(&opts)]).map(drop);
        }
        if !self.holds(target) {
            return Err(Error::UnknownThing { tid: target });
        }
        self.persist(&[target])?;
        self.after_route();
        let done = self.locked(|l| {
            self.guard_local(l, &[target])?;
            let e = l.engine();
            known_actor(e, holder)?;
            // a change keeps the tie to a membership; a new hand grant has none
            let cur = e.roster(&target).get(&holder).copied();
            if cur.is_some_and(|x| role < x.role) || cur.is_none() && below_lost(e, &target, &holder, role) {
                return Err(Error::Invalid("a lower role takes set_role".into()));
            }
            let tied = cur.and_then(|x| x.tied).map(flows::tied::tie_ct);
            e.grant(&target, &holder, &ct::Edge { tied, ..edge(role, opts) }).map_err(needs_admin)
        })?;
        self.carry(done)
    }

    /// Adds `member` to `group` and grants the group `role` on it, tied together: the grant goes
    /// when the membership goes (`GroupWrite::remove`), so the group's holders
    /// reach what is in the group for as long as it is, through the group's sync. Being a member
    /// alone grants nothing, and a plain `grant` to the group stays when the membership goes.
    ///
    /// Already a member, nothing more is written to the group. A grant of the group at `role` or
    /// above stays as it is, tied or not, and a raise of a grant made by hand stays untied.
    ///
    /// Needs write on the group and admin on the thing (or an `invite` of at least `role`, the
    /// group having no grant yet), else `Permission` before anything is written. `Invalid`, as for
    /// `grant`, below a role the group lost. To add without granting: `Write::group`. `Unsupported` on a client with its own actor.
    pub fn add_with_grant(&self, member: Member, group: Tid, role: Role) -> Result<()> {
        let (tid, subgroup) = member.parts();
        if let crate::sources::Source::Remote(r) = self.route_write_all(&[tid, group])? {
            return r.call(crate::port::method::ADD_WITH_GRANT, vec![crate::port::codec::member_v(member), Value::Tid(group), crate::port::codec::role_v(role)]).map(drop);
        }
        for x in [tid, group] {
            if !self.holds(x) {
                return Err(Error::UnknownThing { tid: x });
            }
        }
        let existing = self.grants(tid)?.get(&group).copied();
        // a tied grant whose membership is gone here is tied again to the new one
        let retie = existing.is_some_and(|x| x.with_membership) && self.engine(|e| e.tie_dead(&tid, &group))?;
        let role = existing.filter(|_| retie).map_or(role, |x| x.role.max(role));
        let grant = retie || existing.is_none_or(|e| e.role < role);
        if grant && !self.engine(|e| e.may_grant(&tid, &group, role)) {
            return Err(Error::Permission { tid, needs: Role::Admin });
        }
        if grant && existing.is_none() && self.engine(|e| below_lost(e, &tid, &group, role)) {
            return Err(Error::Invalid("the group held a higher role: set_role first".into()));
        }
        let placed = self.read_local(|r| {
            let gs = r.groups_of(tid);
            if subgroup { gs.subgroup_of.contains(&group) } else { gs.item_of.contains(&group) }
        });
        if grant {
            // durable first, so the membership is too
            self.persist(&[tid])?;
        }
        if !placed {
            let mut w = self.write();
            w.sharing = true;
            w.group(group).add(member)?;
            w.commit()?;
        }
        if !grant {
            return Ok(());
        }
        // tied to the membership's live element (written above, or already there); a grant made
        // by hand stays untied
        let tied = existing.is_none_or(|x| x.with_membership);
        let done = self.guarded(&[tid, group], |e| {
            let tie = match tied {
                true => Some(e.placement(&tid, &group, subgroup)?.ok_or_else(|| Error::Invalid(format!("{tid} is not placed in {group} here")))?),
                false => None,
            };
            let edge = ct::Edge { role, until: None, invite: None, since: None, tied: tie.map(flows::tied::tie_ct), keyset: None };
            e.grant(&tid, &group, &edge).map_err(needs_admin)
        })?;
        self.carry(done)
    }

    /// Removes the grants of `pairs` (thing, group) tied to a membership gone here, where this
    /// node may as a self-removal (`Write::commit` after a removal). Otherwise, or on failure, a
    /// node that may remove it does so later (node-sync's obligation).
    pub(crate) fn untie_now(&self, pairs: &[(Tid, Tid)]) {
        for (t, g) in pairs {
            let done = self.engine(|e| {
                let due = e.may_remove(t, g) == Some(flows::Untie::SelfRemoval) && e.tie_dead(t, g).unwrap_or(false);
                if due { e.untie(t, g).ok() } else { None }
            });
            if let Some(done) = done {
                let _ = self.carry(done);
            }
        }
    }

    /// Everyone who holds a role on `target`, directly or through an actor that holds one (a person
    /// through a group, a joiner through a link), nearest first. An actor with several ways in is
    /// listed once per way: the shortest to each grant it holds them by, and a longer one when it
    /// gives more, so its best role and latest end are among its entries. Who holds through an actor:
    /// `holders` of that actor, or those here with it in `through`. Grants one level down, with
    /// `invite` and whether a grant goes with a membership: `grants`. On a client with its own actor,
    /// what that actor may read: nothing behind an actor it may not read.
    pub fn holders(&self, target: Tid) -> Result<Vec<Holder>> {
        if let crate::sources::Source::Remote(r) = self.route(target) {
            return crate::port::codec::holders(r.call(crate::port::method::HOLDERS, vec![Value::Tid(target)])?);
        }
        Ok(self.read_local(|r| {
            let mut out: Vec<Holder> = Vec::new();
            // the ways looked behind so far, per actor: a way none of them beats goes behind it too,
            // else a member's role through a nested actor is that of the actor's first way in
            let mut seen: BTreeMap<Tid, Vec<(Role, Option<WallMs>)>> = BTreeMap::new();
            let mut queue = std::collections::VecDeque::from([(target, None, None, Vec::new())]);
            while let Some((at, role, until, through)) = queue.pop_front() {
                let role: Option<Role> = role;
                let until: Option<WallMs> = until;
                let through: Vec<Tid> = through;
                for (actor, g) in r.grants(at) {
                    if actor == target || through.contains(&actor) {
                        continue;
                    }
                    let way = Holder {
                        actor,
                        role: role.map_or(g.role, |x| x.min(g.role)),
                        until: [until, g.until].into_iter().flatten().min(),
                        through: through.clone(),
                    };
                    let ways = seen.entry(actor).or_default();
                    let beaten = ways.iter().any(|(r, u)| *r >= way.role && (u.is_none() || way.until.is_some_and(|w| Some(w) <= *u)));
                    if !beaten {
                        ways.push((way.role, way.until));
                        let mut on = way.through.clone();
                        on.push(actor);
                        queue.push_back((actor, Some(way.role), way.until, on));
                    }
                    out.push(way);
                }
            }
            out
        }))
    }

    /// Runs the pre-sync of a demotion (spec/permissions.md §5.3) over the labels holding
    /// `things`, as `sync` says.
    async fn presync(&self, things: BTreeSet<Tid>, sync: SyncFirst) -> Result<PreSync> {
        let give_up = match sync {
            SyncFirst::Backdate(t) => return Ok(PreSync::Backdated(t)),
            SyncFirst::Skip => return Ok(PreSync::Unsynced { proceed: true }),
            SyncFirst::Required => None,
            SyncFirst::Try(d) => Some(d),
        };
        // groups held here are synced; those held for receipts only are read for receipts
        // (their commit headers, notes/sync.md Receipts-only reads)
        let (groups, reads) = self.locked(|l| {
            let st = l.status.clone();
            (groups_holding(&mut l.sync, &st, &things), l.sync.receipts_groups(&things))
        });
        if groups.is_empty() && reads.is_empty() {
            return Ok(PreSync::Synced);
        }
        self.act(|l| l.sync.read_receipts(&reads));
        // ended on a dropped future too: a daemon outlives a client gone midway
        let reading = ReceiptsGuard { db: self.downgrade(), groups: reads.clone() };
        self.sync_labels();
        let r = self.groups_synced(Some(groups.clone()), reads.clone(), give_up, None).await;
        drop(reading);
        let mut all = groups;
        all.extend(reads);
        match (r, sync) {
            (Ok(()), _) => Ok(PreSync::Synced),
            (Err(_), SyncFirst::Try(_)) => {
                self.engine(|e| e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Unsynced, tids: all, commit: None, peer: None, detail: "demotion proceeded without its pre-sync".into() }));
                Ok(PreSync::Unsynced { proceed: true })
            }
            (Err(_), _) => Err(Error::Unsynced { groups: all }),
        }
    }

    /// Resolves once every label in scope is `Synced` and the receipts-only reads of `reads`
    /// are done (with `deliveries`, also once no delivery about one of those things is
    /// pending, any delivery for `groups` `None`); fails `Unsynced` when a label in scope is
    /// stranded; after `give_up` (a `SyncFirst::Try`), `Unsynced` for a refused one, else `Network`.
    /// The scope: every label of `groups` (a hostless one fails `Unsynced`), or for `None` every
    /// label with hosts of a synced group.
    fn groups_synced(&self, groups: Option<Vec<Tid>>, reads: Vec<Tid>, give_up: Option<Duration>, deliveries: Option<BTreeSet<Tid>>) -> crate::net::Pending<Result<()>> {
        self.wait_until(give_up, Box::new(move |sync, _, late| synced(sync, groups.as_deref(), &reads, deliveries.as_ref(), late).or_else(|| late.then(|| Err(Error::Network("not caught up in time".into()))))))
    }

    /// Makes `holder`'s role on `target` this one: raises, lowers, or with `None` removes. The usual
    /// way to change a role (`grant` says why both exist). A role that does not change writes
    /// nothing. Someone with no role gets a `grant` with default options, or with `None` nothing is
    /// written. `until` and `invite` stay as they are (`invite` capped at the new role): `grant` sets
    /// those.
    ///
    /// A raise waits for nothing. Lowering or removing first does as `SetRoleOpts::sync` says, so that
    /// what the holder did while it could is kept; so does a role below one the holder lost when its
    /// grant ended or it left, which ends the old grant in a commit of its own (a failure between
    /// the two leaves the holder with no role, as it had: call again). `SetRoleOpts::keep` with a role
    /// is `Invalid`.
    ///
    /// A removal follows every way the holder has in (`holders`) until none is left: dropped or
    /// failed midway, the ways already removed stay so (call again). A holder who
    /// joined by a link of this account is removed together with the link's key, in one commit:
    /// it may have kept the link's text. The link then stops working for anyone who has not used
    /// it yet (make a new one), and its other joiners stay. A joiner's role cannot be changed, only
    /// removed (`Invalid`; `grant` gives it a role of its own). Nor can this call reach through
    /// another actor (a team, a link of another account): `Invalid`, naming the actor to set
    /// the role on.
    ///
    /// `Unsupported` on a client with its own actor, and on a thing this node reads at another node: move its group
    /// home first. A removal written to the copy here would never leave it.
    pub async fn set_role(&self, target: Tid, holder: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        keep_only_on_removal(role, o)?;
        if !self.has_store() {
            return self.rtask(crate::port::method::SET_ROLE, vec![Value::Tid(target), Value::Tid(holder), crate::port::codec::opt(role, crate::port::codec::role_v), crate::port::codec::set_role_v(&o)]).await.map(drop);
        }
        self.not_routed("set_role", target)?;
        // each round removes one way in; the bound only guards against grants that never settle
        for _ in 0..16 {
            let Some(way) = self.holders(target)?.into_iter().find(|h| h.actor == holder) else {
                let Some(r) = role else { return Ok(()) };
                // a role lost above `r`: its end made explicit first, with what that takes
                if self.engine(|e| below_lost(e, &target, &holder, r)) {
                    self.lower(target, holder, None, o, false).await?;
                }
                return self.grant(target, holder, r, GrantOpts::default());
            };
            match way.through.as_slice() {
                [] => {
                    let cur = self.grants(target)?.get(&holder).copied().ok_or(Error::Invalid(format!("{holder} is no holder of {target}")))?;
                    match role {
                        Some(r) if r == cur.role => return Ok(()),
                        Some(r) if r > cur.role => return self.grant(target, holder, r, GrantOpts { until: cur.until, invite: cur.invite }),
                        _ => self.lower(target, holder, role, o, false).await?,
                    }
                }
                [k] if self.held_links()?.iter().any(|h| h.k == *k && h.target == target) => {
                    if role.is_some() {
                        return Err(Error::Invalid(format!("{holder} joined {target} by a link: it can only be removed")));
                    }
                    self.remove_joiner(*k, holder, o).await?;
                }
                [k, ..] => return Err(Error::Invalid(format!("{holder} reaches {target} through {k}: set its role there"))),
            }
            if role.is_some() {
                return Ok(());
            }
        }
        Err(Error::Invalid(format!("{holder} still reaches {target}")))
    }

    /// `set_role` for one who locked everyone else out: a writer that replaced the keys of `target`
    /// and sealed the new ones to itself alone, so that `set_role` fails here. Also undoes, everywhere,
    /// that holder's key changes this device cannot open, and changes the keys from those before
    /// them; what was written under the undone keys stays readable only where they are already held.
    ///
    /// Only after a lockout: on a device that merely lacks a key someone has yet to send it, this
    /// discards an honest change. `holder` must hold a grant on `target` itself (else `Invalid`), and
    /// only that grant is touched; `role` can lower or remove, not raise. Nothing to undo: that grant
    /// changes as `set_role` would change it. `Unsupported` as for `set_role`.
    pub async fn repudiate(&self, target: Tid, holder: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        keep_only_on_removal(role, o)?;
        if !self.has_store() {
            return self.rtask(crate::port::method::REPUDIATE, vec![Value::Tid(target), Value::Tid(holder), crate::port::codec::opt(role, crate::port::codec::role_v), crate::port::codec::set_role_v(&o)]).await.map(drop);
        }
        self.not_routed("repudiate", target)?;
        match (self.holders(target)?.into_iter().find(|h| h.actor == holder), role) {
            (None, None) => return Ok(()),
            (None, Some(_)) => return Err(Error::Invalid(format!("{holder} is no holder of {target}"))),
            (Some(way), _) if !way.through.is_empty() => return Err(Error::Invalid("repudiating takes the holder's grant on the thing itself".into())),
            (Some(way), Some(r)) if r > way.role => return Err(Error::Invalid("repudiating cannot raise a role".into())),
            _ => {}
        }
        self.lower(target, holder, role, o, true).await
    }

    /// Lowers or removes the grant of `m` on `t`: the pre-sync of every label the lost authority
    /// wrote under, then the demotion with this node's frontier and the target's rotation, in one
    /// commit (spec/permissions.md §2, §3, §5).
    async fn lower(&self, t: Tid, m: Tid, role: Option<Role>, o: SetRoleOpts, repudiate: bool) -> Result<()> {
        let new = match role {
            Some(role) => {
                let cur = self.grants(t)?.get(&m).copied().ok_or(Error::Invalid(format!("{m} is no holder of {t}")))?;
                Some(ct::Edge { role, until: cur.until, invite: cur.invite.map(|i| i.min(role)), since: None, tied: self.engine(|e| e.roster(&t).get(&m).and_then(|x| x.tied)).map(flows::tied::tie_ct), keyset: None })
            }
            None => None,
        };
        let things = self.engine(|e| e.presync_scope(&t, &m, new.as_ref()));
        let presync = self.presync(things, o.sync).await?;
        // a person's default does not reach its devices (spec/permissions.md §2)
        let keep = o.keep.or((t == self.inner.me).then_some(false));
        let fd = flows::Demotion { holder: m, new, presync, keep };
        let done = self.guarded(&[t], |e| (if repudiate { e.demote_repudiating(&t, &fd) } else { e.demote(&t, &fd) }).map_err(needs_admin))?;
        self.carry(done)
    }

    /// Removes `holder`'s own grant on `target`, with no catching up. `holder` is `me()`, or a group
    /// or other actor this node is an admin of (as when a group's admin drops a thing that was shared
    /// into it). The keys change when the target's next writer or admin writes, or at once when this
    /// node is an admin of `target` by another way. No grant and no other way in writes nothing.
    ///
    /// `Invalid` when `holder` has no such grant but holds `target` through another actor (a team, a
    /// link's actor), naming it: leaving that actor is what ends the role. `Invalid` for another
    /// actor when this node is an admin of `target`: taking that role away is `set_role`'s, with its
    /// catching up. `Permission` when this node is no admin of `holder`; on a client with its own
    /// actor, for any `holder` but that actor.
    pub fn leave(&self, holder: Tid, target: Tid) -> Result<()> {
        let own = holder == self.me();
        // the flow below runs with the node's authority: a client ends only its own actor's role
        if self.acting.is_some() && !own {
            return Err(Error::Permission { tid: holder, needs: Role::Admin });
        }
        let route = if own { self.route_write(target)? } else { self.route_write_all(&[holder, target])? };
        if let crate::sources::Source::Remote(r) = route {
            return r.call(crate::port::method::LEAVE, vec![Value::Tid(holder), Value::Tid(target)]).map(drop);
        }
        if !self.grants(target)?.contains_key(&holder) {
            return match self.holders(target)?.into_iter().find(|h| h.actor == holder) {
                Some(h) => Err(Error::Invalid(format!("{holder} holds {target} through {}: leave that", h.through.last().copied().unwrap_or(target)))),
                None => Ok(()),
            };
        }
        let things = if own { vec![target] } else { vec![holder, target] };
        let done = self.guarded(&things, |e| match e.may_remove(&target, &holder) {
            Some(flows::Untie::Explicit) if !own => Err(Error::Invalid(format!("this node is an admin of {target}: use set_role"))),
            None if !own => Err(Error::Permission { tid: holder, needs: Role::Admin }),
            // this account's own grant, whichever way this node also holds the target
            _ => Ok(e.demote(&target, &flows::Demotion { holder, new: None, presync: PreSync::Synced, keep: None })?),
        })?;
        self.carry(done)
    }

    /// The actors whose read-only copy this node keeps after losing them (spec/permissions.md §3,
    /// Keep), for a client with its own actor those it reads. The copy reads as before; nothing syncs or writes
    /// it. `drop_kept` erases one (for this node's main actor).
    pub fn kept_copies(&self) -> Result<Vec<Tid>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::KEPT, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|x| crate::port::codec::Args::of(vec![x]).tid()).collect();
        }
        Ok(self.engine(|e| {
            let mut v = e.kept_copies();
            // acting as an actor: the copies it reads
            if let Some(a) = self.acting {
                v.retain(|x| e.copy_readable_by(&a, x));
            }
            v
        }))
    }

    /// Erases kept copy `actor`, and what it alone kept: its disk space is this user's.
    pub fn drop_kept(&self, actor: Tid) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::DROP_KEPT, vec![Value::Tid(actor)]).map(drop);
        }
        self.locked(|l| l.sync.drop_kept(&[actor]))?;
        Ok(())
    }

    /// Makes a share link to `target` with `role` (spec/permissions.md §8): its actor K and key L
    /// on this database's hosts. Anyone holding the link can redeem it until `until` or
    /// `revoke_link`. It also syncs `target` when it has no label of its own, the only place K
    /// can read it, so a link always works.
    pub fn make_link(&self, target: Tid, role: Role, opts: LinkOpts) -> Result<ShareLink> {
        if let crate::sources::Source::Remote(r) = self.route_write(target)? {
            let v = r.call(crate::port::method::MAKE_LINK, vec![Value::Tid(target), crate::port::codec::role_v(role), crate::port::codec::opt(opts.until, |w| Value::uint(w.0)), Value::Bool(opts.single_use), Value::Bool(opts.direct)])?;
            return Ok(ShareLink(crate::port::codec::Args::of(vec![v]).text()?));
        }
        let hosts = self.host_addrs();
        let me = self.me();
        if hosts.is_empty() && !opts.direct {
            return Err(Error::Invalid("this database has no hosts: a link reaches nobody unless it is direct (LinkOpts.direct)".into()));
        }
        if opts.direct && self.locked(|x| x.sync.own_reach()).is_none() {
            return Err(Error::Invalid("a direct link needs this device reachable: a runtime with Config.peers on".into()));
        }
        self.persist(&[target])?;
        self.after_route();
        let (mut link, keep, done) = self.locked(|l| {
            self.guard_local(l, &[target])?;
            // K reads the target's own label alone (spec/sync.md §2): a link syncs the target
            let label = !l.engine().labeled(&target);
            let made = l.engine().create_link(&me, &flows::LinkSpec { target, role, until: opts.until, hosts: hosts.clone(), peers: Vec::new(), single_use: opts.single_use }).map_err(needs_admin)?;
            // K is on it before the label's first pass: this device's `reach.0` never goes under
            // it, and nothing rotates (spec/permissions.md §4, §8)
            if label {
                self.make_label(l, target, hosts)?;
            }
            Ok::<_, Error>(made)
        })?;
        // the seed thing in the home group: every device of this person holds it and may
        // finalize the link (spec/permissions.md §8)
        let mut w = self.write();
        w.group(self.me()).add(Member::Item(keep))?;
        w.commit()?;
        let l = osis_node::Identity::from_seed(link.seed.clone()).tid();
        self.locked(|x| {
            x.links.insert(link.k, MadeLink { l, target, single_use: opts.single_use, direct: opts.direct, ended: false });
            save_links(x)
        })?;
        // K joining the target may rotate this device's reach (the target no longer qualifies,
        // spec/permissions.md §4): the link carries the key it listens with after that
        self.carry(done)?;
        if opts.direct {
            // only the dialable key and relays, never the lan secret (spec/permissions.md §8)
            let r = self.locked(|x| x.sync.own_reach()).ok_or(Error::Invalid("this device's reach is gone".into()))?;
            link.peers = vec![osis_label::Peer { dialable: r.dialable, relays: r.relays }];
            if let Some(until) = opts.until {
                // the link ends by expiry: `upkeep_links` rotates the key then
                let wait = Duration::from_millis(until.0.saturating_sub(self.inner.clock.now_wall_ms().0).saturating_add(1));
                let db = self.downgrade();
                self.inner.net.after(wait, Box::new(move || {
                    if let Some(db) = db.hold() {
                        db.locked(|x| db.upkeep_links(x));
                    }
                }));
            }
        }
        Ok(ShareLink(link.to_text().map_err(bad("link"))?))
    }

    /// Redeems a link (spec/permissions.md §8): reaches its label by the link key, waits until K's
    /// grant on the target is here, joins K as this person (removing the link key in the same
    /// commit when the link is single use). Returns the target. A link known to have ended (used,
    /// revoked, expired, its hosts no longer listing its key, K off the target) fails `Invalid` at
    /// once; so does, a while in, one whose K's label, read to its end, shows no grant on the target
    /// (the target is the link text's word: such a link joins nothing). With nobody answering it
    /// waits. The link key is forgotten on every outcome, a dropped future included; dropped once
    /// joined (the last moments, a commit here waiting for what it follows), the join stands.
    pub async fn redeem(&self, link: &ShareLink) -> Result<Tid> {
        if !self.has_store() {
            link.parse()?;
            let v = self.rtask(crate::port::method::REDEEM, vec![Value::Str(link.0.clone())]).await?;
            return crate::port::codec::Args::of(vec![v]).tid();
        }
        let link = link.parse()?;
        let (k, target) = (link.k, link.target);
        let key = self.follow_link(&link)?;
        let l = key.l;
        // L must be on K's roster in a view with nothing on K pending: a commit on K waiting
        // for its chain may be (or follow) an earlier redemption that removed L
        let label = link.k_label;
        self.wait_until(Some(LINK_VERDICT_WAIT), Box::new(move |s, _, late| {
            if s.static_entry_refused(&label) {
                return Some(Err(link_ended()));
            }
            // what judges K may still be in a later batch of its first sync
            if s.fill_before_passes() {
                return None;
            }
            let e = s.engine_mut();
            if pending_on(e, &k) {
                return None;
            }
            if e.edge_gone(&k, &l) {
                return Some(Err(link_ended()));
            }
            if !(e.roster(&k).contains_key(&l) && e.epochs(&k).is_some_and(|x| x.read.held().next().is_some())) {
                return None;
            }
            // Joining K gives what K holds and nothing says K holds the target but K's edge on it,
            // so the grant waits for that edge: a link pairing a target with another thing's K
            // joins nothing. K's label carries the edge (the sharer's delivery to K, then its
            // certificate copy there), so an honest link gets here with the target unknown too.
            if e.knows(&target) && e.roster(&target).contains_key(&k) {
                return Some(Ok(()));
            }
            if e.edge_gone(&target, &k) {
                return Some(Err(link_ended()));
            }
            if !late || pending_on(e, &target) || !s.complete_pass(&k) {
                return None;
            }
            // K's label read to its end: a cut-off node or a commit still waiting says nothing
            Some(Err(Error::Invalid("this link gives no access to what it names: ask for a new one".into())))
        }))
        .await?;
        let me = self.me();
        let done = self.engine(|e| e.redeem(&link, &me, link.single_use))?;
        // redeemed: the follow (hint, sharer node) stays
        let mut key = key;
        key.link = None;
        drop(key);
        self.carry(done)?;
        // joined: the grant stands in a view with nothing on K pending
        self.wait_until(None, Box::new(move |s, _, _| {
            let e = s.engine_mut();
            (e.roster(&k).contains_key(&me) && !pending_on(e, &k)).then_some(Ok(()))
        }))
        .await?;
        Ok(target)
    }

    /// Holds a link's key and follows K's label at its hosts and at the sharer's device when
    /// the link names it (first contact, spec/permissions.md §8: dialed at the link's dialable
    /// key and relays like a co-reader, for K and the target only, `follow_link_peer`); the key
    /// goes with the guard, and with it the follow unless the redemption went through.
    fn follow_link(&self, link: &osis_label::ShareLink) -> Result<KeyGuard> {
        let l = self.locked(|x| -> Result<Tid> {
            let l = x.engine().hold_key_actor(link.seed.clone())?;
            let peers = link.peers.iter().map(|p| osis_label::Address { url: osis_transport::peer_url(&p.relays), key: p.dialable }).collect();
            x.sync.follow_link_peer(link.k, link.target, peers);
            let acts = x.sync.follow(l, link.k, link.k_label, link.hosts.clone());
            self.inner.apply(acts);
            Ok(l)
        })?;
        Ok(KeyGuard { db: self.downgrade(), l, link: Some(link.k) })
    }

    /// The person's links that still work, whichever device made them (each holds the seed thing;
    /// one whose seed has not arrived is not listed); filter by `LinkInfo::target`. `Unsupported` on
    /// a client with its own actor, which is also why a node connected with a client secret adds none.
    pub fn links(&self) -> Result<Vec<LinkInfo>> {
        if !self.has_store() {
            return crate::port::codec::links(self.rcall(crate::port::method::LINKS, vec![])?);
        }
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

    /// The links whose seed thing is the person's and whose K it owns (a co-reader can place a
    /// seed thing in a shared group: it names no link of ours).
    fn held_links(&self) -> Result<Vec<flows::HeldLink>> {
        let me = self.me();
        self.engine(|e| person_links(e, me))
    }

    /// Link actor `k`'s key L (`held_links`).
    fn link_key(&self, k: Tid) -> Result<Tid> {
        self.held_links()?.iter().find(|h| h.k == k).map(|h| h.l).ok_or(Error::Invalid(format!("no link {k} of this person")))
    }

    /// Ends a link: nobody can use it from now on. Those who joined by it keep their role; to remove
    /// one, `set_role`. `sync` as for `set_role`: anyone holding the link's text may have used it.
    /// `Unsupported` on a client with its own actor.
    pub async fn revoke_link(&self, id: LinkId, sync: SyncFirst) -> Result<()> {
        if !self.has_store() {
            return self.rtask(crate::port::method::REVOKE_LINK, vec![Value::Tid(id.0), crate::port::codec::sync_first_v(sync)]).await.map(drop);
        }
        self.not_routed("revoke_link", id.0)?;
        let l = self.link_key(id.0)?;
        self.lower(id.0, l, None, SetRoleOpts { sync, keep: None }, false).await
    }

    /// Removes `joiner` from link actor `k` and ends the link in the same commit, under one rotation
    /// (spec/permissions.md §8: a joiner may keep the seed); the other joiners stay holders of K and
    /// need a new link to invite anyone. After the pre-sync.
    async fn remove_joiner(&self, k: Tid, joiner: Tid, o: SetRoleOpts) -> Result<()> {
        self.not_routed("set_role", k)?;
        let l = self.link_key(k)?;
        let things = self.engine(|e| {
            let mut s = e.presync_scope(&k, &joiner, None);
            s.extend(e.presync_scope(&k, &l, None));
            s
        });
        let presync = self.presync(things, o.sync).await?;
        let done = self.guarded(&[k], |e| e.revoke_joiner(&k, &l, &joiner, presync, o.keep).map_err(needs_admin))?;
        self.carry(done)
    }

    /// Rotates this device's dialable key when a direct link it made ended (spec/permissions.md
    /// §8): after every change, at open and at the link's expiry. Finalizing links is
    /// node-sync's (`SyncEngine::finalize_links`). `ended` is persisted.
    pub(crate) fn upkeep_links(&self, l: &mut Locked) {
        let mut any = false;
        // a direct link that ended (its key left K, or its edge expired) gave out this device's
        // dialable key: rotate it (spec/permissions.md §8), unless a single-use link ended by its
        // redemption (the one who could use it is now a holder and keeps the direct path)
        let now = l.engine().now();
        let direct: Vec<(Tid, MadeLink)> = l.links.iter().filter(|(_, m)| m.direct && !m.ended).map(|(k, m)| (*k, *m)).collect();
        let mut rotate = false;
        for (k, m) in direct {
            let r = l.engine().roster(&k);
            if r.get(&m.l).is_none_or(|e| e.until.is_some_and(|u| u <= now)) {
                // a used single-use link: its joiner is on K
                let redeemed = m.single_use && r.keys().any(|x| *x != m.l);
                rotate |= !redeemed;
                if let Some(m) = l.links.get_mut(&k) {
                    m.ended = true;
                    any = true;
                }
            }
        }
        if rotate {
            let acts = l.sync.rotate_reach();
            self.inner.apply(acts);
        }
        if any && let Err(e) = save_links(l) {
            l.engine().report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::BadInput, tids: Vec::new(), commit: None, peer: None, detail: format!("links record: {e}") });
        }
    }

    pub(crate) fn load_links(&self) -> Result<()> {
        let Some(b) = self.engine(|e| e.app_record(LINKS))? else { return Ok(()) };
        let v = osis_base::cbor::decode(&b, &osis_base::cbor::Limits { max_depth: 4, max_bytes: b.len() }).map_err(|_| Error::Storage("links record".into()))?;
        let Value::List(items) = v else { return Err(Error::Storage("links record".into())) };
        let mut links = BTreeMap::new();
        for i in items {
            if let Value::List(f) = i
                && let [Value::Tid(k), Value::Tid(l), Value::Tid(t), Value::Bool(s), rest @ ..] = f.as_slice()
            {
                let flag = |i: usize| matches!(rest.get(i), Some(Value::Bool(true)));
                let (direct, ended) = (flag(0), flag(1));
                links.insert(*k, MadeLink { l: *l, target: *t, single_use: *s, direct, ended });
            }
        }
        self.locked(|x| {
            x.links = links;
            self.upkeep_links(x);
        });
        Ok(())
    }

    /// This person's contact card (spec/sync.md §3): a read link to its profile P, a group of
    /// itself under its own label carrying the person's `created.0` and `keys.0` as certificates.
    /// Made once; later calls return the same card. `Invalid` on a database without hosts.
    pub fn contact_card(&self) -> Result<ContactCard> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::CONTACT_CARD, vec![])?;
            return Ok(ContactCard(crate::port::codec::Args::of(vec![v]).text()?));
        }
        if let Some(b) = self.engine(|e| e.app_record(CONTACT))? {
            return Ok(ContactCard(String::from_utf8(b).map_err(|_| Error::Storage("contact record".into()))?));
        }
        let me = self.me();
        let hosts = self.host_addrs();
        // checked before anything is written: the card's link needs hosts (`make_link`)
        if hosts.is_empty() {
            return Err(Error::Invalid("this database has no hosts: a contact card needs one".into()));
        }
        let mut w = self.write();
        let p = w.create()?;
        w.commit()?;
        self.persist(&[p])?;
        self.locked(|x| -> Result<()> {
            // secrets of its own before the label, as `sync()` does
            let done = x.engine().give_own_secrets(&p)?;
            let acts = x.sync.carry_out(done)?;
            self.inner.apply(acts);
            let (_, acts) = x.sync.create_label(&p, hosts.clone())?;
            self.inner.apply(acts);
            // the person's creation and `keys.0` commits, as certificates under P's label
            let e = x.engine();
            let created = Ak::new("created.0").map_err(|_| Error::Invalid("ak".into()))?;
            let keys = Ak::new("keys.0").map_err(|_| Error::Invalid("ak".into()))?;
            let mut certs = Vec::new();
            for id in e.commit_ids() {
                let Some(h) = e.header(&id) else { continue };
                let idx: BTreeSet<usize> = h.aspects.iter().enumerate().filter(|(_, a)| a.tid == me && (a.ak == created || a.ak == keys)).map(|(i, _)| i).collect();
                if !idx.is_empty() {
                    certs.push((id, idx));
                }
            }
            for (id, idx) in certs {
                let acts = x.sync.place_certificate(&p, &id, &idx)?;
                self.inner.apply(acts);
            }
            Ok(())
        })?;
        let link = self.make_link(p, Role::Read, LinkOpts::default())?;
        let card = ContactCard(link.0);
        self.engine(|e| e.set_app_record(CONTACT, card.0.as_bytes()))?;
        Ok(card)
    }

    /// This person's profile thing: the target of its contact card, made on first
    /// use. The person writes its profile aspects on it (`name.0`, `contact:*`); everyone holding
    /// the card reads them.
    pub fn profile(&self) -> Result<Tid> {
        let card = self.contact_card()?;
        Ok(card.parse()?.target)
    }

    /// The profile thing of a person whose card this database imported, if any.
    pub fn profile_of(&self, person: Tid) -> Result<Option<Tid>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::PROFILE_OF, vec![Value::Tid(person)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(|t| crate::port::codec::Args::of(vec![t]).tid()).transpose();
        }
        let Some(b) = self.engine(|e| e.app_record(&format!("{PROFILE_OF}{person}")))? else { return Ok(None) };
        let t = String::from_utf8(b).map_err(|_| Error::Storage("profile record".into()))?;
        t.parse().map(Some).map_err(|_| Error::Storage("profile record".into()))
    }

    /// Imports a contact card: reads the profile by the card's link key (bearer use, nothing
    /// written) until the person's `keys.0` is here and the key's actor K has its grant on the
    /// profile (as in `redeem`, the card's target is its text's word). Returns the person, usable
    /// in `grant`. `Invalid` as for `redeem`: a card known to have ended, or one whose K's label, read
    /// to its end, shows no grant on the profile. With nobody answering it waits. The card's key is
    /// forgotten on every outcome, a dropped future included.
    pub async fn import_contact(&self, card: &ContactCard) -> Result<Tid> {
        if !self.has_store() {
            card.parse()?;
            let v = self.rtask(crate::port::method::IMPORT_CONTACT, vec![Value::Str(card.0.clone())]).await?;
            return crate::port::codec::Args::of(vec![v]).tid();
        }
        let link = card.parse()?;
        let (k, p, label) = (link.k, link.target, link.k_label);
        let key = self.follow_link(&link)?;
        let found = std::sync::Arc::new(std::sync::Mutex::new(None));
        let f2 = found.clone();
        let r = self
            .wait_until(
                Some(LINK_VERDICT_WAIT),
                Box::new(move |s, _, late| {
                    if s.static_entry_refused(&label) {
                        return Some(Err(link_ended()));
                    }
                    let e = s.engine_mut();
                    let holds = e.roster(&p).contains_key(&k);
                    if let (true, Some(owner)) = (holds, e.owner(&p))
                        && e.get_typed(&owner, &ct::KEYS).ok().flatten().is_some()
                    {
                        *crate::watch::lock(&f2) = Some(owner);
                        return Some(Ok(()));
                    }
                    if holds || !late || s.fill_before_passes() || pending_on(s.engine_mut(), &k) || pending_on(s.engine_mut(), &p) || !s.complete_pass(&k) {
                        return None;
                    }
                    // K's label read to its end, as in `redeem`
                    Some(Err(Error::Invalid("this card gives no access to what it names: ask for a new one".into())))
                }),
            )
            .await;
        let mut key = key;
        // read: the follow stays (bearer use), as long as the link's key holds its role
        if r.is_ok() {
            key.link = None;
            self.engine(|e| e.keep_bearer(&key.l))?;
        }
        drop(key);
        r?;
        let who = *crate::watch::lock(&found);
        if let Some(who) = who {
            self.act(|l| l.sync.set_contact(who, true));
            self.engine(|e| e.set_app_record(&format!("{PROFILE_OF}{who}"), p.to_string().as_bytes()))?;
        }
        who.ok_or(Error::Invalid("contact card: no person".into()))
    }

    /// The invite requests waiting for the user (`InviteId`).
    pub fn invite_requests(&self) -> Result<Vec<InviteId>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::INVITE_REQUESTS, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|b| InviteId::from_bytes(&crate::port::codec::Args::of(vec![b]).bytes()?)).collect();
        }
        Ok(self.locked(|x| x.sync.invite_requests())?.into_iter().map(InviteId).collect())
    }

    /// Accepts an invite request: its grant applies and its thing's hosts are dialed (then
    /// joined as for any invite). `Invalid` when no such request waits (accepted, declined or
    /// expired).
    pub fn accept_invite(&self, id: InviteId) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::ACCEPT_INVITE, vec![Value::Bytes(id.bytes().to_vec())]).map(drop);
        }
        self.try_act(|x| {
            let (found, acts) = x.sync.accept_invite(id.0)?;
            if !found {
                return Err(Error::Invalid("no such invite request".into()));
            }
            Ok(acts)
        })
    }

    /// Declines an invite request: it is forgotten and never shown again (re-sends included).
    /// `Invalid` when no such request waits.
    pub fn decline_invite(&self, id: InviteId) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::DECLINE_INVITE, vec![Value::Bytes(id.bytes().to_vec())]).map(drop);
        }
        if !self.locked(|x| x.sync.decline_invite(id.0))? {
            return Err(Error::Invalid("no such invite request".into()));
        }
        Ok(())
    }

    /// The person's devices: nodes holding a role on the person actor.
    pub fn devices(&self) -> Result<Vec<Device>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::DEVICES, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|d| {
                let mut a = crate::port::codec::Args::new(d)?;
                Ok(Device { node: a.tid()?, role: crate::port::codec::role(&a.next()?)? })
            }).collect();
        }
        let me = self.me();
        let node_ak = Ak::new("node.0").map_err(|_| Error::Invalid("ak".into()))?;
        self.engine(|e| -> Result<Vec<Device>> {
            let mut out = Vec::new();
            for (m, edge) in e.roster(&me) {
                if m == e.tid() || e.get(&m, &node_ak)?.is_some() {
                    out.push(Device { node: m, role: edge.role });
                }
            }
            Ok(out)
        })
    }

    /// Removes a device from this account (a lost or stolen one: `SyncFirst::Skip` or
    /// `SyncFirst::Backdate`). This is `set_role(me, node, None, o)`, here because of what it
    /// returns, which is easy to forget: this account's links still working. The device keeps their
    /// keys, so whoever holds it can read and join through each until `revoke_link`, and ending
    /// them is the caller's choice. None when `node` was no device. `Unsupported` on a client with its own actor.
    pub async fn remove_device(&self, node: Tid, o: SetRoleOpts) -> Result<Vec<LinkInfo>> {
        let me = self.me();
        let was = self.grants(me)?.contains_key(&node);
        self.set_role(me, node, None, o).await?;
        if was { self.links() } else { Ok(Vec::new()) }
    }

    /// The hosts new labels go to (and kept connected). `Unsupported` on a client with its own actor: they are
    /// its node's.
    pub fn hosts(&self) -> Result<Vec<HostAddr>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::HOSTS, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|h| crate::port::codec::Args::of(vec![h]).text()?.parse()).collect();
        }
        Ok(self.host_addrs().into_iter().map(HostAddr).collect())
    }

    fn host_addrs(&self) -> Vec<osis_label::Address> {
        self.locked(|x| x.sync.config().hosts.clone())
    }

    /// Adds a host for new labels (links, `sync`) and keeps a connection to it. The person's
    /// inbox and existing labels on the database's hosts (those whose list equals it) move to
    /// the new list: the home label and groups the person owns (directly or through its
    /// actors) that this node administers; not links or the contact card (their text names
    /// their hosts), not groups owned by others. A database created without hosts becomes
    /// reachable once one is added. With `Runtime::None` the list is only stored, for the next open
    /// with a runtime: until then `status` shows nothing connected and `wait_synced` fails `Network`.
    pub fn add_host(&self, s: &HostAddr) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::ADD_HOST, vec![Value::Str(s.to_string())]).map(drop);
        }
        let mut v = self.hosts()?;
        if !v.contains(s) {
            v.push(s.clone());
        }
        self.set_hosts(v)
    }

    /// Removes a host, from the database's list and the labels that follow it (`add_host`);
    /// a group with holders besides the person's devices keeps its last host.
    pub fn remove_host(&self, s: &HostAddr) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::REMOVE_HOST, vec![Value::Str(s.to_string())]).map(drop);
        }
        let mut v = self.hosts()?;
        v.retain(|x| x != s);
        self.set_hosts(v)
    }

    fn set_hosts(&self, v: Vec<HostAddr>) -> Result<()> {
        let me = self.me();
        self.locked(|x| -> Result<()> {
            let old: BTreeSet<osis_label::Address> = x.sync.config().hosts.iter().cloned().collect();
            let new: Vec<osis_label::Address> = v.iter().map(|s| s.0.clone()).collect();
            // links, whichever device made them, and the contact card name their label's hosts in
            // their text: they stay; a routed group too: nothing written here leaves, and a stale
            // list would move it on the way home
            let links = person_links(x.engine(), me)?;
            let mut fixed: BTreeSet<Tid> = links.iter().map(|h| h.k).chain(x.routes.keys().copied()).collect();
            if let Some(card) = x.engine().app_record(CONTACT)?
                && let Ok(l) = ContactCard(String::from_utf8_lossy(&card).into_owned()).parse()
            {
                fixed.insert(l.target);
            }
            // the labels first: a failed commit leaves the list as it was, so a retry matches
            follow_labels(x.engine(), me, &fixed, &old, &new)?;
            save_hosts(x.engine(), &v)?;
            x.sync.set_hosts(new.clone());
            follow_inbox(x.engine(), me, &old, &new)
        })?;
        self.sync_now()
    }

    /// Makes `group` synced through `hosts` (default: this database's): its own label
    /// (spec/sync.md §2); needs admin on the group. A no-op when it has one, unless `hosts` names
    /// others: `Invalid`, for a group's label keeps its hosts.
    pub fn sync(&self, group: Tid, hosts: &[HostAddr]) -> Result<()> {
        if let crate::sources::Source::Remote(r) = self.route_write(group)? {
            return r.call(crate::port::method::SYNC, vec![Value::Tid(group), Value::List(hosts.iter().map(|h| Value::Str(h.to_string())).collect())]).map(drop);
        }
        self.sync_here(group, hosts, false)
    }

    /// Creates an ownerless thing (spec/permissions.md §1): no owner, so nobody holds
    /// owner-chain authority on it; its admins are holders of a grant, all equal, starting with `admin`
    /// (`me()`, or an actor this device is an admin of), fixed by its tid. It has secrets of its
    /// own at once; give it a label with `sync` or place it like any thing. Its grants are never
    /// compacted, and once no admin is left nobody can change it (members keep their roles).
    /// `Permission` (admin on `admin`), `UnknownActor` (no `keys.0` of `admin` here).
    // Removed with owners (issues/api-refactor.md Decided).
    #[doc(hidden)]
    pub fn create_ownerless(&self, admin: Tid) -> Result<Tid> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::CREATE_OWNERLESS, vec![Value::Tid(admin)])?;
            return crate::port::codec::tid(&v);
        }
        let (t, done) = self.locked(|l| {
            let e = l.engine();
            if admin != e.tid() && e.get_typed(&admin, &ct::KEYS)?.is_none() {
                return Err(Error::UnknownActor { tid: admin });
            }
            e.create_ownerless(&admin).map_err(needs_admin)
        })?;
        self.carry(done)?;
        Ok(t)
    }

    /// `sync` on this engine. `home`: `group_source` bringing it back, while its route still stands
    /// (calls keep going to the node until this engine caught up); else a move since the route was
    /// decided fails this, as any flow.
    pub(crate) fn sync_here(&self, group: Tid, hosts: &[HostAddr], home: bool) -> Result<()> {
        if !self.holds(group) {
            return Err(Error::UnknownThing { tid: group });
        }
        // this engine's role: the route, if any, would ask the node
        if self.read_local(|r| r.role_on(group)) != Some(Role::Admin) {
            return Err(Error::Permission { tid: group, needs: Role::Admin });
        }
        if home {
            let me = self.me();
            self.engine(|e| persist_in(e, me, &[group]))?;
        } else {
            self.persist(&[group])?;
        }
        let named: BTreeSet<osis_label::Address> = hosts.iter().map(|s| s.0.clone()).collect();
        let hosts = if hosts.is_empty() { self.host_addrs() } else { hosts.iter().map(|s| s.0.clone()).collect() };
        if !home {
            self.after_route();
        }
        self.locked(|x| -> Result<()> {
            if !home {
                self.guard_local(x, &[group])?;
            }
            if !named.is_empty() && x.engine().group_labels(&group)?.iter().any(|l| !l.replaced && !same_set(&l.hosts, &named)) {
                return Err(Error::Invalid(format!("{group} already syncs through other hosts")));
            }
            self.make_label(x, group, hosts)
        })
    }

    /// A live label for `g` unless it has one.
    fn make_label(&self, x: &mut crate::handle::Locked, g: Tid, hosts: Vec<osis_label::Address>) -> Result<()> {
        if x.engine().group_labels(&g)?.iter().any(|l| !l.replaced) {
            return Ok(());
        }
        // the label's keys derive from the group's own secrets from the start, so holders
        // granted later verify its whole path (notes/api.md Implementation)
        let done = x.engine().give_own_secrets(&g)?;
        let acts = x.sync.carry_out(done)?;
        self.inner.apply(acts);
        let (_, acts) = x.sync.create_label(&g, hosts)?;
        self.inner.apply(acts);
        Ok(())
    }

    /// Stops syncing `group` under its own labels (marks them replaced without a successor;
    /// the group stays in other synced groups it is placed in).
    pub fn unsync(&self, group: Tid) -> Result<()> {
        if let crate::sources::Source::Remote(r) = self.route_write(group)? {
            return r.call(crate::port::method::UNSYNC, vec![Value::Tid(group)]).map(drop);
        }
        self.guarded(&[group], |e| {
            let ls = e.group_labels(&group)?;
            let mut m = osis_node::Mutation::new();
            let mut any = false;
            for l in ls.iter().filter(|l| !l.replaced) {
                any = true;
                let path = vec![osis_crdt::PathSeg::Key(l.id.to_value()), osis_crdt::PathSeg::Field(3)];
                m.op(group, &ct::LABEL, osis_crdt::PathOp { path, op: osis_crdt::Op::Set(Value::Bool(true)) })?;
            }
            if any {
                e.commit(m).map_err(needs_admin)?;
            }
            Ok(())
        })
    }

    /// Sync status now.
    pub fn status(&self) -> Result<Status> {
        let acting = self.acting;
        let me = self.inner.me;
        let local = self.locked(|x| {
            let mut s = status_of(&mut x.sync, me)?;
            if let Some(a) = acting {
                s.groups.retain(|g, _| x.sync.engine().readable_by(&a, g));
            }
            Ok::<_, Error>(s)
        })?;
        if acting.is_some() {
            return Ok(local);
        }
        self.merged_status(local)
    }

    /// Calls `f` with the status now (through the dispatcher) and on every change, a node that
    /// cannot be reached shown as such (`Status::remotes`). `Err`: the store could not say; the
    /// next status that can be read follows.
    pub fn on_status_change(&self, mut f: impl FnMut(&Osis, Result<Status>) + Send + 'static) -> Result<Subscription> {
        if !self.has_store() {
            return self.remote_on_status_change(Box::new(f));
        }
        // a node with connections shows them too: not a watch of them, a status at each change here
        let first = self.status()?;
        Ok(self.subscribe(Filter::Status, true, move |_| {
            let mut first = Some(first);
            Box::new(move |db, d| match d {
                Delivery::Initial => {
                    if let Some(s) = first.take() {
                        f(db, Ok(s))
                    }
                }
                Delivery::Status(s) => f(db, s.and_then(|s| db.merged_status(s))),
                _ => {}
            })
        }))
    }

    /// Resolves once every label in scope finished a pass with nothing outstanding after the
    /// local commits so far (they are at a host) and every pending delivery in scope was
    /// taken. Fails `Unsynced` when it is known this cannot happen: a stranded label in scope, or
    /// `Thing(t)` with a hostless label; `Network` without a runtime. A host out of reach, or one that
    /// does not admit a label or take a delivery for now (`SyncState::Refused`), may yet: this waits
    /// (`status` shows them). `Thing(t)`: the labels of the groups holding `t` (a replaced hostless
    /// one beside another does not count) and the deliveries about `t`, a thing it holds or one of
    /// those groups (a grant on one, a non-writer's write under its label). With no group holding
    /// `t` it fails `Unsynced` at once, unless a route may still arrive: a grant named its label, or
    /// this node does not administer `t` and a label of its own has more to bring (a first sync).
    /// `All`: every label with hosts (`status` shows the `NoHosts` ones) and every delivery.
    ///
    /// On a thin client the node waits with the same outcomes.
    pub async fn wait_synced(&self, scope: SyncScope) -> Result<()> {
        let r = match scope {
            SyncScope::Thing(t) => self.route(t),
            SyncScope::All => self.route_scope(None)?,
        };
        if let crate::sources::Source::Remote(r) = r {
            return self.remote_task(&r, crate::port::method::WAIT_SYNCED, vec![crate::port::codec::sync_scope_v(scope)]).await.map(drop);
        }
        self.wait_synced_pending(scope).await
    }

    /// `wait_synced` as a future holding no handle (the client port serves it so).
    pub(crate) fn wait_synced_pending(&self, scope: SyncScope) -> crate::net::Pending<Result<()>> {
        let me = self.inner.me;
        use crate::net::Pending;
        match scope {
            SyncScope::All => {
                // nothing to wait for: done, also without a runtime
                let idle = self.locked(|x| {
                    let skip = x.sync.receipts_only().clone();
                    x.sync.deliveries_pending() == 0 && !x.sync.label_status().iter().any(|s| s.hosts > 0 && !skip.contains(&s.group))
                });
                if idle {
                    return Pending::ready(Ok(()));
                }
                self.sync_labels();
                self.groups_synced(None, Vec::new(), None, Some(BTreeSet::new()))
            }
            SyncScope::Thing(t) => {
                // first, so that a label with more to bring counts as such
                self.sync_labels();
                // a failure at once needs no runtime
                if let Some(Err(e)) = self.locked(|x| group_synced(&mut x.sync, me, t)).filter(Result::is_err) {
                    return Pending::ready(Err(e));
                }
                self.wait_until(None, Box::new(move |sync, _, _| group_synced(sync, me, t)))
            }
        }
    }

    /// Catches up now and waits for nothing: labels not live at a host sync, live ones (their host
    /// pushes what it gets) judge again what is left to send. Cheap at any rate, so an app may
    /// poll it. To wait until this node's writes are at a host: `wait_synced`.
    pub fn sync_now(&self) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::SYNC_NOW, vec![]).map(drop);
        }
        self.act(|x| x.sync.refresh());
        Ok(())
    }

    /// Every open label syncs at every connection, live or not (a wait's start).
    fn sync_labels(&self) {
        self.act(|x| x.sync.sync_now());
    }

    /// Writes a bundle of `groups`' labels (spec/sync.md §11) to `out`.
    pub fn export_bundle(&self, groups: &[Tid], mut out: impl std::io::Write) -> Result<()> {
        if !self.has_store() {
            use crate::port::{STREAM_CHUNK, codec::{Args, tids_v}, method};
            let len = Args::of(vec![self.rcall(method::EXPORT_BUNDLE, vec![tids_v(groups)])?]).uint()?;
            let mut off = 0;
            while off < len {
                let page = self.primary_call_big(method::BUNDLE_READ, vec![Value::uint(off), Value::uint(STREAM_CHUNK as u64)], STREAM_CHUNK.saturating_add(osis_proto::client::SMALL_REPLY))?;
                let page = Args::of(vec![page]).bytes()?;
                if page.is_empty() {
                    return Err(Error::Network("the connection to the node changed during an export: run it again".into()));
                }
                out.write_all(&page).map_err(|e| Error::Storage(e.to_string()))?;
                off += page.len() as u64;
            }
            return Ok(());
        }
        let bytes = self.locked(|x| -> Result<Vec<u8>> {
            let mut labels = Vec::new();
            for g in groups {
                let g = *g;
                labels.extend(x.engine().group_labels(&g)?.into_iter().filter(|l| !l.replaced).map(|l| l.id));
            }
            Ok(x.sync.export_bundle(&labels)?)
        })?;
        out.write_all(&bytes).map_err(|e| Error::Storage(e.to_string()))
    }

    /// Reads a bundle: what this node can open applies like synced content.
    pub fn import_bundle(&self, mut input: impl std::io::Read) -> Result<()> {
        let mut b = Vec::new();
        input.read_to_end(&mut b).map_err(|e| Error::Storage(e.to_string()))?;
        if !self.has_store() {
            use crate::port::{STREAM_CHUNK, method};
            for page in b.chunks(STREAM_CHUNK) {
                self.rcall(method::BUNDLE_WRITE, vec![Value::Bytes(page.to_vec())])?;
            }
            return self.rcall(method::IMPORT_BUNDLE, vec![Value::uint(b.len() as u64)]).map(drop);
        }
        self.try_act(|x| Ok(x.sync.import_bundle(&b)?))
    }
}

/// `SetRoleOpts::keep` is a removal's word.
fn keep_only_on_removal(role: Option<Role>, o: SetRoleOpts) -> Result<()> {
    if role.is_some() && o.keep.is_some() {
        return Err(Error::Invalid("keep is for removing a role: there is no copy to keep while a role remains".into()));
    }
    Ok(())
}

/// The commit of `Osis::persist`.
fn persist_in(e: &mut osis_node::Engine, me: Tid, tids: &[Tid]) -> Result<()> {
    let mut m = osis_node::Mutation::new();
    m.act_as(me);
    for t in tids {
        m.persist(*t);
    }
    e.write(m)?;
    Ok(())
}

/// `Osis::held_links`, on this engine.
fn person_links(e: &mut osis_node::Engine, me: Tid) -> Result<Vec<flows::HeldLink>> {
    let held = e.held_links()?.to_vec();
    Ok(held.into_iter().filter(|h| h.owner == me && e.owner(&h.k) == Some(me)).collect())
}

fn same_set(s: &[osis_label::Address], old: &BTreeSet<osis_label::Address>) -> bool {
    s.iter().cloned().collect::<BTreeSet<_>>() == *old
}

/// Moves the labels whose host list is `old` (as a set) to `new` (spec/sync.md §2 `label.0`
/// hosts; the sync engine registers a label's path at a host that does not know it): the
/// home label and the labels of groups in the person's own owner tree this node administers,
/// except `fixed` ones (links, the contact card) and groups with a holder of no owner here (a
/// person, a link's key actor). A group with holders besides the person and its
/// devices never loses its last host.
fn follow_labels(e: &mut osis_node::Engine, me: Tid, fixed: &BTreeSet<Tid>, old: &BTreeSet<osis_label::Address>, new: &[osis_label::Address]) -> Result<()> {
    let list = Codec::to_value(&new.to_vec());
    let devices: BTreeSet<Tid> = e.roster(&me).into_keys().collect();
    let mine = |e: &osis_node::Engine, g: Tid| e.owner_chain(&g).any(|c| c == me);
    let mut m = osis_node::Mutation::new();
    let mut any = false;
    for g in e.labeled_groups() {
        if fixed.contains(&g) || e.role_on(&g) != Some(Role::Admin) || !mine(e, g) {
            continue;
        }
        let holders: Vec<Tid> = e.roster(&g).into_keys().filter(|x| *x != me && !devices.contains(x)).collect();
        if holders.iter().any(|x| e.owner(x).is_none()) || new.is_empty() && !holders.is_empty() {
            continue;
        }
        for l in e.group_labels(&g)?.into_iter().filter(|l| !l.replaced && same_set(&l.hosts, old)) {
            any = true;
            let path = vec![osis_crdt::PathSeg::Key(l.id.to_value()), osis_crdt::PathSeg::Field(2)];
            m.op(g, &ct::LABEL, osis_crdt::PathOp { path, op: osis_crdt::Op::Set(list.clone()) })?;
        }
    }
    if any {
        e.commit(m)?;
    }
    Ok(())
}

/// Moves the person's inbox to `new` when it is on `old`.
fn follow_inbox(e: &mut osis_node::Engine, me: Tid, old: &BTreeSet<osis_label::Address>, new: &[osis_label::Address]) -> Result<()> {
    let list = Codec::to_value(&new.to_vec());
    if e.get_typed(&me, &ct::KEYS)?.and_then(|k| k.inbox).is_some_and(|i| same_set(&i.hosts, old)) {
        let mut m = osis_node::Mutation::new();
        m.op(me, &ct::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(4), osis_crdt::PathSeg::Case(1), osis_crdt::PathSeg::Field(1)], op: osis_crdt::Op::Set(list) })?;
        e.commit(m)?;
    }
    Ok(())
}

/// How long a link or card, whose K's label reads to its end with no grant on what its text names,
/// is given for that grant to arrive before it is `Invalid`: it may be on its way from the maker's
/// node. Minor: 0 fails an honest link racing its own upload, infinity leaves a bad one waiting
/// until dropped.
const LINK_VERDICT_WAIT: Duration = Duration::from_secs(60);

const CONTACT: &str = "contact";
/// App record prefix: `profile/<person tid>` -> profile tid text, written by `import_contact`.
const PROFILE_OF: &str = "profile/";

/// Stores the links made here (one local record).
fn save_links(l: &mut Locked) -> Result<()> {
    let v = Value::List(l.links.iter().map(|(k, m)| Value::List(vec![Value::Tid(*k), Value::Tid(m.l), Value::Tid(m.target), Value::Bool(m.single_use), Value::Bool(m.direct), Value::Bool(m.ended)])).collect());
    l.engine().set_app_record(LINKS, &osis_base::cbor::encode(&v))?;
    Ok(())
}

/// A held link or recovery key, forgotten when the guard goes: every outcome of a waiting call,
/// a dropped future included.
pub(crate) struct KeyGuard {
    pub db: crate::handle::WeakOsis,
    pub l: Tid,
    /// A link's K whose follow (hint, sharer node) goes with the key: set until the redemption.
    pub link: Option<Tid>,
}

impl Drop for KeyGuard {
    fn drop(&mut self) {
        if let Some(db) = self.db.hold() {
            db.engine(|e| e.drop_key_actor(&self.l));
            if let Some(k) = self.link {
                db.act(|x| x.sync.forget_link(k));
            }
        }
    }
}

/// A pre-sync's receipts-only reads, ended when it goes.
struct ReceiptsGuard {
    db: crate::handle::WeakOsis,
    groups: Vec<Tid>,
}

impl Drop for ReceiptsGuard {
    fn drop(&mut self) {
        if let Some(db) = self.db.hold() {
            db.locked(|l| l.sync.end_receipts(&self.groups));
        }
    }
}

fn link_ended() -> Error {
    Error::Invalid("this link no longer works: ask for a new one".into())
}

/// Whether a commit on `k` waits here (pending, not parked: spec/commits.md §4).
fn pending_on(e: &mut osis_node::Engine, k: &Tid) -> bool {
    let ids: Vec<osis_base::CommitId> = e.pending().into_iter().filter(|(_, r)| *r != osis_node::Reason::Parked).map(|(c, _)| c).collect();
    ids.iter().any(|c| e.commit_bytes(c).ok().flatten().and_then(|b| osis_commit::CommitBlob::decode_stored(&b).ok()).is_some_and(|cb| cb.header.aspects.iter().any(|a| a.tid == *k)))
}
