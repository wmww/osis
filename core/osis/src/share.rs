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

/// How long a `WaitForSync::Required` demotion waits for its pre-sync.
pub const PRESYNC_WAIT: Duration = Duration::from_secs(30);

/// `until` and `invite` of an edge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EdgeOpts {
    pub until: Option<WallMs>,
    pub invite: Option<Role>,
}

/// How `Osis::share_into` places.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareOpts {
    /// Place the thing (a group) as a subgroup, not as an item.
    pub subgroup: bool,
    /// When this node may not grant: place anyway (the thing is then excluded: holders of the
    /// group see its tid, not the thing) instead of failing `Permission`.
    pub place_anyway: bool,
}

/// How a group's holders reach a thing through that group (`Osis::reach`, `share_into`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Share {
    /// A tied edge (`share_into`): it goes when the placement goes.
    Tied(Role),
    /// An edge granted by hand (`grant`): it stays when the placement goes.
    Untied(Role),
    /// No edge: placed, but the group's holders do not reach the thing through it.
    Excluded,
}

/// One group's view of a thing (`Osis::reach`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupReach {
    pub group: Tid,
    /// The group lists the thing as an item or subgroup. A tied edge without it is on its way
    /// out (a node that may remove it does).
    pub placed: bool,
    pub share: Share,
}

/// Whether a demotion waits for its pre-sync (spec/permissions.md §5.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WaitForSync {
    /// Fail with `Unsynced` when a group cannot be synced (within `PRESYNC_WAIT`).
    #[default]
    Required,
    /// Proceed after the timeout, with a diagnostic.
    Try(Duration),
    /// Stamp now (a stolen device).
    Skip,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Demotion {
    pub sync: WaitForSync,
    /// An explicitly backdated revoke: no pre-sync; the frontier as of this time.
    pub backdate: Option<WallMs>,
    /// Also repudiate the demoted holder's rotations of the target this device cannot open (a
    /// writer that rotated it and sealed the new secrets to itself alone, locking everyone else
    /// out: a plain demotion then fails). Those rotations are undone everywhere and the target
    /// rotates from the secrets before them (spec/permissions.md §3); content under their
    /// epochs stays readable only where those secrets are already held. Only after a lockout:
    /// a device that merely lacks a re-seal would discard an honest rotation. A direct edge only.
    pub repudiate: bool,
    /// A removal's word (spec/permissions.md §3, Keep): the removed holder's devices keep a
    /// read-only copy, or erase. `None`: the thing's default (`required.0^`'s `keep`, `core::RequiredRules`); erase for a
    /// device leaving this person.
    pub keep: Option<bool>,
}

/// The role after a demotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lower {
    To(Role),
    Remove,
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

/// A link of this person (`links`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    /// The link's actor K: what `revoke_link` takes.
    pub id: Tid,
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

/// A host: transport URL plus its key (`<url>#<base64url key>`).
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
    /// From a transport URL and the host's 32-byte key.
    /// From a transport URL and the host's 32-byte key (a `quic://` URL's port spelled out,
    /// as `FromStr`).
    pub fn url(&self) -> &str {
        &self.0.url
    }

    pub fn key(&self) -> [u8; 32] {
        self.0.key
    }

    pub fn new(url: &str, key: [u8; 32]) -> HostAddr {
        HostAddr(osis_label::Address { url: osis_transport::quic::explicit_port(url), key })
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
    /// Held for receipts only (`GroupPolicy::receipts_only`): not synced, what is here is stale.
    ReceiptsOnly,
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
    /// This process's attachments to other nodes, and the nodes its routes name.
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
    /// The labels holding this thing (the group's own, or those of groups containing it; a
    /// hostless one fails `Unsynced`) and the deliveries about it, what it holds or those groups.
    Group(Tid),
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
        groups.insert(*g, GroupSync { state: SyncState::ReceiptsOnly, last_sync: None, labels: Vec::new(), not_admitted: Vec::new(), leaving: false, unrouted: Vec::new() });
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

fn edge(role: Role, o: EdgeOpts) -> ct::Edge {
    ct::Edge { role, until: o.until, invite: o.invite, since: None, tied: None, keyset: None }
}

fn share_of(e: crate::Edge) -> Share {
    if e.tied { Share::Tied(e.role) } else { Share::Untied(e.role) }
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
    status.groups.iter().filter(|(_, s)| !matches!(s.state, SyncState::ReceiptsOnly | SyncState::NoRoute)).map(|(g, _)| *g).filter(|g| things.contains(g) || sync.engine().closure(g).iter().any(|t| things.contains(t))).collect()
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
fn group_synced(sync: &mut SyncEngine, me: Tid, t: Tid, late: bool) -> Option<Result<()>> {
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
    synced(sync, Some(&groups), &[], Some(&about), late)
}

/// The sync wait's check (`Osis::groups_synced`): one rule over the labels in scope, `groups`
/// (all their labels but a replaced hostless one beside another) or `None` (every label with hosts), then the pending deliveries about
/// `deliveries` (every one when `groups` is `None`). `late` (the deadline passed): a refused
/// label's group fails `Unsynced` (before it, the label may yet be admitted).
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

    /// `holder` is this person or a client of this node: this node serves it, and the thing stays
    /// as local as it was.
    fn served_here(&self, holder: Tid) -> Result<bool> {
        Ok(holder == self.me() || self.at(self.node(), ct::CLIENTS).get()?.unwrap_or_default().contains_key(&holder))
    }

    /// Grants `holder` `role` on `target` (spec/permissions.md §2): needs admin on the target
    /// (or an invite edge) and the holder's `keys.0` (a contact card, a shared group, pairing),
    /// else `UnknownActor`. Records the permission and nothing else: the grant reaches the
    /// holder's devices through its inbox, a group holder's readers through the copy its admins
    /// place under its label, and the holder reads the target only through a label that carries
    /// it (spec/sync.md §2); with none it holds the role and no route, which `status` shows
    /// (`SyncState::NoRoute`, `GroupSync::unrouted`) until `sync` gives the target a label
    /// (`share` does both). Grants one by one each cost about 2.6 KB of boxes: share sets through
    /// a group. Adds, raises, or changes `until` and `invite`. A role below the holder's present
    /// one is `Invalid`: lowering takes `demote`, which syncs and rotates keys first.
    pub fn grant(&self, target: Tid, holder: Tid, role: Role, opts: EdgeOpts) -> Result<()> {
        if let crate::sources::Source::Remote(r) = self.route_write(target)? {
            return r.call(crate::port::method::GRANT, vec![Value::Tid(target), Value::Tid(holder), crate::port::codec::role_v(role), crate::port::codec::edge_opts_v(&opts)]).map(drop);
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
            // an edge change keeps its tie; a new hand grant is untied
            let cur = e.roster(&target).get(&holder).copied();
            if cur.is_some_and(|x| role < x.role) {
                return Err(Error::Invalid("a lower role needs demote".into()));
            }
            let tied = cur.and_then(|x| x.tied).map(flows::tied::tie_ct);
            e.grant(&target, &holder, &ct::Edge { tied, ..edge(role, opts) }).map_err(needs_admin)
        })?;
        self.carry(done)
    }

    /// `grant`, with a route: when `holder` reads no live label carrying `target` as this node
    /// knows them (`Engine::routed`), `target` is synced first (its own label on this database's
    /// hosts; needs admin, else `Permission`), then the edge is written. Not for `me()` or this
    /// node's own clients: they read what this node holds, and the thing stays as local as it
    /// was. `share_into` is the other way to a route: placing the thing in a synced group.
    pub fn share(&self, target: Tid, holder: Tid, role: Role, opts: EdgeOpts) -> Result<()> {
        if let crate::sources::Source::Remote(r) = self.route_write(target)? {
            return r.call(crate::port::method::SHARE, vec![Value::Tid(target), Value::Tid(holder), crate::port::codec::role_v(role), crate::port::codec::edge_opts_v(&opts)]).map(drop);
        }
        if !self.holds(target) {
            return Err(Error::UnknownThing { tid: target });
        }
        let served = self.served_here(holder)?;
        let routed = self.locked(|l| {
            let e = l.engine();
            known_actor(e, holder)?;
            Ok::<_, Error>(served || e.routed(&holder, &target))
        })?;
        if !routed {
            self.sync_here(target, &[], false)?;
        }
        self.grant(target, holder, role, opts)
    }

    /// Shares `tid` with the holders of `group` at `role` by placing it there (spec/permissions.md
    /// §2): the placement (skipped when the thing is already placed so) and a tied edge of the
    /// group on it, which goes when the placement goes (`Write::unplace`). An existing edge of the
    /// group at `role` or above is kept as it is, tied or not. Needs write on the group and admin
    /// on `tid` (or an invite edge of at least `role`, and no edge of the group yet), else
    /// `Permission` before anything is written, unless `opts.place_anyway` (then `Excluded`).
    pub fn share_into(&self, tid: Tid, group: Tid, role: Role, opts: ShareOpts) -> Result<Share> {
        if let crate::sources::Source::Remote(r) = self.route_write_all(&[tid, group])? {
            return crate::port::codec::share(r.call(crate::port::method::SHARE_INTO, vec![Value::Tid(tid), Value::Tid(group), crate::port::codec::role_v(role), Value::Bool(opts.subgroup), Value::Bool(opts.place_anyway)])?);
        }
        for x in [tid, group] {
            if !self.holds(x) {
                return Err(Error::UnknownThing { tid: x });
            }
        }
        let existing = self.roster(tid)?.get(&group).copied();
        // a tied edge whose placement is gone here is tied again to the new one
        let retie = existing.is_some_and(|x| x.tied) && self.engine(|e| e.tie_dead(&tid, &group))?;
        let role = existing.filter(|_| retie).map_or(role, |x| x.role.max(role));
        let grant = retie || existing.is_none_or(|e| e.role < role);
        let may = grant && self.engine(|e| e.may_grant(&tid, &group, role));
        if grant && !may && !opts.place_anyway {
            return Err(Error::Permission { tid, needs: Role::Admin });
        }
        let placed = self.read_local(|r| {
            let gs = r.groups_of(tid);
            if opts.subgroup { gs.subgroup_of.contains(&group) } else { gs.item_of.contains(&group) }
        });
        if may {
            // durable first, so the placement is too
            self.persist(&[tid])?;
        }
        if !placed {
            let mut w = self.write();
            w.sharing = true;
            if opts.subgroup { w.add_subgroup(group, tid)? } else { w.place(tid, group)? }
            w.commit()?;
        }
        if !grant {
            return Ok(existing.map_or(Share::Excluded, share_of));
        }
        if !may {
            return Ok(Share::Excluded);
        }
        // tied to the placement's live element (written above, or already there); an existing
        // hand edge stays untied
        let tied = existing.is_none_or(|x| x.tied);
        let done = self.guarded(&[tid, group], |e| {
            let tie = match tied {
                true => Some(e.placement(&tid, &group, opts.subgroup)?.ok_or_else(|| Error::Invalid(format!("{tid} is not placed in {group} here")))?),
                false => None,
            };
            let edge = ct::Edge { role, until: None, invite: None, since: None, tied: tie.map(flows::tied::tie_ct), keyset: None };
            e.grant(&tid, &group, &edge).map_err(needs_admin)
        })?;
        self.carry(done)?;
        Ok(if tied { Share::Tied(role) } else { Share::Untied(role) })
    }

    /// Removes the tied edges of `pairs` (thing, group) whose placement is gone here, where this
    /// node may as a self-removal (`Write::commit` after an unplace). Otherwise, or on failure, a
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

    /// Removes `group`'s edge on `target` as an admin of the group (a self-removal,
    /// spec/permissions.md §2: no pre-sync, no rotation; the target's next writer or admin
    /// rotates). `Invalid` when this node is an admin of `target` (use `demote`), `Permission`
    /// when it is no admin of `group`; nothing is written when there is no such edge.
    pub fn remove_edge_of(&self, group: Tid, target: Tid) -> Result<()> {
        if let crate::sources::Source::Remote(r) = self.route_write_all(&[group, target])? {
            return r.call(crate::port::method::REMOVE_EDGE_OF, vec![Value::Tid(group), Value::Tid(target)]).map(drop);
        }
        if !self.roster(target)?.contains_key(&group) {
            return Ok(());
        }
        let done = self.guarded(&[group, target], |e| match e.may_remove(&target, &group) {
            Some(flows::Untie::SelfRemoval) => Ok(e.demote(&target, &flows::Demotion { holder: group, new: None, presync: PreSync::Synced, keep: None })?),
            Some(flows::Untie::Explicit) => Err(Error::Invalid(format!("this node is an admin of {target}: use demote"))),
            None => Err(Error::Permission { tid: group, needs: Role::Admin }),
        })?;
        self.carry(done)
    }

    /// Per group, how its holders reach `tid` through it (spec/permissions.md §2): every group
    /// listing it as an item or subgroup (`Tied`, `Untied` or `Excluded`), and every group with
    /// a tied edge on it that no longer lists it (`placed: false`, until that edge goes).
    pub fn reach(&self, tid: Tid) -> Result<Vec<GroupReach>> {
        if let crate::sources::Source::Remote(r) = self.route(tid) {
            return crate::port::codec::reach(r.call(crate::port::method::REACH, vec![Value::Tid(tid)])?);
        }
        let (gs, roster) = self.read_local(|r| (r.groups_of(tid), r.roster(tid)));
        let placed: BTreeSet<Tid> = gs.item_of.into_iter().chain(gs.subgroup_of).collect();
        let mut out: Vec<GroupReach> = placed.iter().map(|g| GroupReach { group: *g, placed: true, share: roster.get(g).copied().map_or(Share::Excluded, share_of) }).collect();
        out.extend(roster.iter().filter(|(g, e)| e.tied && !placed.contains(g)).map(|(g, e)| GroupReach { group: *g, placed: false, share: Share::Tied(e.role) }));
        Ok(out)
    }

    /// Changes `until`/`invite` of an edge or raises its role (a lower role: `demote`).
    pub fn change_edge(&self, target: Tid, holder: Tid, role: Role, opts: EdgeOpts) -> Result<()> {
        if let crate::sources::Source::Remote(r) = self.route_write(target)? {
            return r.call(crate::port::method::CHANGE_EDGE, vec![Value::Tid(target), Value::Tid(holder), crate::port::codec::role_v(role), crate::port::codec::edge_opts_v(&opts)]).map(drop);
        }
        self.grant(target, holder, role, opts)
    }

    /// Runs the pre-sync of a demotion (spec/permissions.md §5.3) over the labels holding
    /// `things`, as `d` says.
    async fn presync(&self, things: BTreeSet<Tid>, d: Demotion) -> Result<PreSync> {
        if let Some(t) = d.backdate {
            return Ok(PreSync::Backdated(t));
        }
        if d.sync == WaitForSync::Skip {
            return Ok(PreSync::Unsynced { proceed: true });
        }
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
        // ended on a dropped future too: a daemon outlives a client gone mid-demote
        let reading = ReceiptsGuard { db: self.downgrade(), groups: reads.clone() };
        self.sync_labels();
        let wait = match d.sync {
            WaitForSync::Try(t) => t,
            _ => PRESYNC_WAIT,
        };
        let r = self.groups_synced(Some(groups.clone()), reads.clone(), wait, None).await;
        drop(reading);
        let mut all = groups;
        all.extend(reads);
        match (r, d.sync) {
            (Ok(()), _) => Ok(PreSync::Synced),
            (Err(_), WaitForSync::Try(_)) => {
                self.engine(|e| e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Unsynced, tids: all, commit: None, peer: None, detail: "demotion proceeded without its pre-sync".into() }));
                Ok(PreSync::Unsynced { proceed: true })
            }
            (Err(_), _) => Err(Error::Unsynced { groups: all }),
        }
    }

    /// Resolves once every label in scope is `Synced` and the receipts-only reads of `reads`
    /// are done (with `deliveries`, also once no delivery about one of those things is
    /// pending, any delivery for `groups` `None`); fails `Unsynced` when a label in scope is
    /// stranded (refused: at `wait`), `Network` after `wait`. The scope: every label of `groups` (a hostless one
    /// fails `Unsynced`), or for `None` every label with hosts of a synced group.
    fn groups_synced(&self, groups: Option<Vec<Tid>>, reads: Vec<Tid>, wait: Duration, deliveries: Option<BTreeSet<Tid>>) -> crate::net::Pending<Result<()>> {
        self.wait_until(Some(wait), Box::new(move |sync, _, late| synced(sync, groups.as_deref(), &reads, deliveries.as_ref(), late)))
    }

    /// The edges through which `actor` is a holder of `target` (spec/permissions.md §2): the
    /// (thing, holder) pairs from `target` down to `actor` of a shortest chain, e.g. `[(target,
    /// K), (K, actor)]` for a link joiner; empty when it is none.
    pub fn holder_path(&self, target: Tid, actor: Tid) -> Result<Vec<(Tid, Tid)>> {
        if let crate::sources::Source::Remote(r) = self.route(target) {
            return crate::port::codec::pairs(r.call(crate::port::method::HOLDER_PATH, vec![Value::Tid(target), Value::Tid(actor)])?);
        }
        Ok(self.read_local(|r| {
            let mut via: BTreeMap<Tid, Tid> = BTreeMap::from([(target, target)]);
            let mut queue = std::collections::VecDeque::from([target]);
            while let Some(x) = queue.pop_front() {
                for m in r.roster(x).into_keys() {
                    if via.contains_key(&m) {
                        continue;
                    }
                    via.insert(m, x);
                    if m == actor {
                        let mut path = vec![(x, m)];
                        let mut cur = x;
                        while cur != target {
                            let Some(p) = via.get(&cur).copied() else { break };
                            path.push((p, cur));
                            cur = p;
                        }
                        path.reverse();
                        return path;
                    }
                    queue.push_back(m);
                }
            }
            Vec::new()
        }))
    }

    /// Lowers or removes `holder`'s edge on `target` (spec/permissions.md §2, §3, §5): first the
    /// pre-sync of every label the demoted authority wrote under, as `d` says; then the
    /// demotion with this node's frontier and the target's rotation, in one commit.
    ///
    /// A removal follows every way the holder reaches `target` (`holder_path`) until none is
    /// left; removing a holder that reaches it no more writes nothing. A holder that joined by
    /// a link made on this device is removed from the link's actor K together with the link key
    /// in one commit (`revoke_joiner`; the joiner may keep the seed, spec/permissions.md §8): the
    /// link stops working for anyone who has not redeemed it, K's other joiners stay. A link
    /// joiner's role cannot be lowered (it could act as the link key), only removed. A holder
    /// reaching `target` through another actor (a team, or a link made on another device) is
    /// `Invalid`: demote it there.
    ///
    /// `Unsupported` on a thing this node reads at another node: move its group home first. A
    /// revocation written to the copy here would never leave it.
    pub async fn demote(&self, target: Tid, holder: Tid, to: Lower, d: Demotion) -> Result<()> {
        if self.is_attached() {
            let role = crate::port::codec::opt(match to { Lower::To(r) => Some(r), Lower::Remove => None }, crate::port::codec::role_v);
            return self.rtask(crate::port::method::DEMOTE, vec![Value::Tid(target), Value::Tid(holder), role, crate::port::codec::demotion_v(&d)]).await.map(drop);
        }
        self.not_routed("demote", target)?;
        // each round removes one way in; the bound only guards against a roster that never settles
        for _ in 0..16 {
            let path = self.holder_path(target, holder)?;
            let via = match (path.as_slice(), to) {
                ([], Lower::Remove) => return Ok(()),
                ([], Lower::To(_)) => return Err(Error::Invalid(format!("{holder} is no holder of {target}"))),
                ([_], _) => None,
                ([(_, k), (_, _)], _) => Some(*k),
                ([(_, k), ..], _) => return Err(Error::Invalid(format!("{holder} reaches {target} through {k}: demote it there"))),
            };
            match via {
                None => self.demote_edge(target, holder, to, d).await?,
                Some(k) => {
                    if !self.held_links()?.iter().any(|h| h.k == k && h.target == target) {
                        return Err(Error::Invalid(format!("{holder} reaches {target} through {k}, a group actor: demote it there")));
                    }
                    if to != Lower::Remove {
                        return Err(Error::Invalid(format!("{holder} joined {target} by a link: it can only be removed")));
                    }
                    self.revoke_joiner(k, holder, d).await?;
                }
            }
            if to != Lower::Remove {
                return Ok(());
            }
        }
        Err(Error::Invalid(format!("{holder} still reaches {target}")))
    }

    async fn demote_edge(&self, t: Tid, m: Tid, to: Lower, d: Demotion) -> Result<()> {
        let new = match to {
            Lower::To(role) => {
                let cur = self.roster(t)?.get(&m).copied().ok_or(Error::Invalid(format!("{m} is no holder of {t}")))?;
                Some(ct::Edge { role, until: cur.until, invite: cur.invite.map(|i| i.min(role)), since: None, tied: self.engine(|e| e.roster(&t).get(&m).and_then(|x| x.tied)).map(flows::tied::tie_ct), keyset: None })
            }
            Lower::Remove => None,
        };
        let things = self.engine(|e| e.presync_scope(&t, &m, new.as_ref()));
        let presync = self.presync(things, d).await?;
        // a person's default does not reach its devices (spec/permissions.md §2)
        let keep = d.keep.or((t == self.inner.me).then_some(false));
        let fd = flows::Demotion { holder: m, new, presync, keep };
        let done = self.guarded(&[t], |e| (if d.repudiate { e.demote_repudiating(&t, &fd) } else { e.demote(&t, &fd) }).map_err(needs_admin))?;
        self.carry(done)
    }

    /// Removes this person's own edge on `target` (a self-removal; no pre-sync).
    pub fn leave(&self, target: Tid) -> Result<()> {
        if let crate::sources::Source::Remote(r) = self.route_write(target)? {
            return r.call(crate::port::method::LEAVE, vec![Value::Tid(target)]).map(drop);
        }
        let me = self.me();
        let done = self.guarded(&[target], |e| Ok(e.demote(&target, &flows::Demotion { holder: me, new: None, presync: PreSync::Synced, keep: None })?))?;
        self.carry(done)
    }

    /// The actors whose read-only copy this node keeps after losing them (spec/permissions.md §3,
    /// Keep), for a thin client those it reads. The copy reads as before; nothing syncs or writes
    /// it. `drop_kept` erases one (the database owner's call).
    pub fn kept_copies(&self) -> Result<Vec<Tid>> {
        if self.is_attached() {
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
        if self.is_attached() {
            return self.rcall(crate::port::method::DROP_KEPT, vec![Value::Tid(actor)]).map(drop);
        }
        self.locked(|l| l.sync.drop_kept(&[actor]))?;
        Ok(())
    }

    /// Makes a share link to `target` with `role` (spec/permissions.md §8): its actor K and key L
    /// on this database's hosts. Anyone holding the link can redeem it until `until` or
    /// `revoke_link`. A composite like `share`: it syncs `target` when it has no label of its own,
    /// the only place K can read it.
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
        w.place(keep, self.me())?;
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
    /// edge on the target is here, joins K as this person (removing the link key in the same
    /// commit when the link is single use). Returns the target. A link known to have ended (used,
    /// revoked, expired, its hosts no longer listing its key, K off the target) fails `Invalid` at
    /// once; so does, at `Config::wait_timeout`, one whose K's label, read to its end, shows no
    /// edge on the target (the target is the link text's word: such a link joins nothing). Other
    /// waits fail `Network` then, nobody having answered in time. The link key is forgotten on
    /// every outcome, a dropped future included.
    pub async fn redeem(&self, link: &ShareLink) -> Result<Tid> {
        if self.is_attached() {
            link.parse()?;
            let v = self.rtask(crate::port::method::REDEEM, vec![Value::Str(link.0.clone())]).await?;
            return crate::port::codec::Args::of(vec![v]).tid();
        }
        let link = link.parse()?;
        let (k, target) = (link.k, link.target);
        let key = self.follow_link(&link)?;
        let l = key.l;
        let t = Some(self.inner.wait_timeout);
        // L must be on K's roster in a view with nothing on K pending: a commit on K waiting
        // for its chain may be (or follow) an earlier redemption that removed L
        let label = link.k_label;
        self.wait_until(t, Box::new(move |s, _, late| {
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
        self.wait_until(t, Box::new(move |s, _, _| {
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
    /// one whose seed has not arrived is not listed), and those at each attached node; filter by
    /// `LinkInfo::target`. `Unsupported` on a thin client; beside a store of its own, a node this
    /// handle reaches as a thin client lists none. `Network` while an attached node cannot be reached.
    pub fn links(&self) -> Result<Vec<LinkInfo>> {
        let mut all = if self.is_attached() { Vec::new() } else { self.live_links()? };
        for r in self.locked(|l| l.remotes.clone()) {
            match r.call(crate::port::method::LINKS, vec![]).and_then(crate::port::codec::links) {
                Err(Error::Unsupported(_)) if !self.is_attached() => {}
                got => all.extend(got?),
            }
        }
        Ok(all)
    }

    /// The links of this process's person at its own node.
    pub(crate) fn own_links(&self) -> Result<Vec<LinkInfo>> {
        if self.is_attached() {
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
                Some(LinkInfo { id: h.k, target: h.target, role: e.role, until: e.until, single_use: h.single_use })
            })
            .collect())
    }

    /// The links whose seed thing is the person's and whose K it owns (a co-reader can place a
    /// seed thing in a shared group: it names no link of ours).
    fn held_links(&self) -> Result<Vec<flows::HeldLink>> {
        let me = self.me();
        self.engine(|e| person_links(e, me))
    }

    /// Link `id`'s key L (`held_links`).
    fn link_key(&self, id: Tid) -> Result<Tid> {
        self.held_links()?.iter().find(|h| h.k == id).map(|h| h.l).ok_or(Error::Invalid(format!("no link {id} of this person")))
    }

    /// Ends a link (spec/permissions.md §8): removes its key from K (joiners stay holders of K;
    /// one that kept the seed is revoked only with a new link for the others).
    pub async fn revoke_link(&self, id: Tid, d: Demotion) -> Result<()> {
        if self.is_attached() {
            return self.rtask(crate::port::method::REVOKE_LINK, vec![Value::Tid(id), crate::port::codec::demotion_v(&d)]).await.map(drop);
        }
        self.not_routed("revoke_link", id)?;
        let l = self.link_key(id)?;
        self.demote_edge(id, l, Lower::Remove, d).await
    }

    /// Removes `joiner` from link `id`'s actor K and ends the link in the same commit, under one
    /// rotation (spec/permissions.md §8: a joiner may keep the seed); the other joiners stay
    /// holders of K and need a new link to invite anyone. After the pre-sync `demote` does.
    pub async fn revoke_joiner(&self, id: Tid, joiner: Tid, d: Demotion) -> Result<()> {
        if self.is_attached() {
            return self.rtask(crate::port::method::REVOKE_JOINER, vec![Value::Tid(id), Value::Tid(joiner), crate::port::codec::demotion_v(&d)]).await.map(drop);
        }
        self.not_routed("revoke_joiner", id)?;
        if d.repudiate {
            return Err(Error::Invalid("repudiating rotations needs the holder's direct edge".into()));
        }
        let l = self.link_key(id)?;
        let things = self.engine(|e| {
            let mut s = e.presync_scope(&id, &joiner, None);
            s.extend(e.presync_scope(&id, &l, None));
            s
        });
        let say = d.keep;
        let presync = self.presync(things, d).await?;
        let done = self.guarded(&[id], |e| e.revoke_joiner(&id, &l, &joiner, presync, say).map_err(needs_admin))?;
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
        if self.is_attached() {
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
        let p = w.create(me)?;
        w.make_group(p)?;
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
        if self.is_attached() {
            let v = self.rcall(crate::port::method::PROFILE_OF, vec![Value::Tid(person)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(|t| crate::port::codec::Args::of(vec![t]).tid()).transpose();
        }
        let Some(b) = self.engine(|e| e.app_record(&format!("{PROFILE_OF}{person}")))? else { return Ok(None) };
        let t = String::from_utf8(b).map_err(|_| Error::Storage("profile record".into()))?;
        t.parse().map(Some).map_err(|_| Error::Storage("profile record".into()))
    }

    /// Imports a contact card: reads the profile by the card's link key (bearer use, nothing
    /// written) until the person's `keys.0` is here and the key's actor K has its edge on the
    /// profile (as in `redeem`, the card's target is its text's word). Returns the person, usable
    /// in `grant`. Fails `Network` after `Config::wait_timeout`; the card's key is forgotten on
    /// every outcome.
    pub async fn import_contact(&self, card: &ContactCard) -> Result<Tid> {
        if self.is_attached() {
            card.parse()?;
            let v = self.rtask(crate::port::method::IMPORT_CONTACT, vec![Value::Str(card.0.clone())]).await?;
            return crate::port::codec::Args::of(vec![v]).tid();
        }
        let link = card.parse()?;
        let (k, p) = (link.k, link.target);
        let key = self.follow_link(&link)?;
        let found = std::sync::Arc::new(std::sync::Mutex::new(None));
        let f2 = found.clone();
        let r = self
            .wait_until(
                Some(self.inner.wait_timeout),
                Box::new(move |s, _, _| {
                    let e = s.engine_mut();
                    let owner = e.owner(&p)?;
                    e.roster(&p).contains_key(&k).then_some(())?;
                    e.get_typed(&owner, &ct::KEYS).ok().flatten()?;
                    *crate::watch::lock(&f2) = Some(owner);
                    Some(Ok(()))
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
        if self.is_attached() {
            let v = self.rcall(crate::port::method::INVITE_REQUESTS, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|b| InviteId::from_bytes(&crate::port::codec::Args::of(vec![b]).bytes()?)).collect();
        }
        Ok(self.locked(|x| x.sync.invite_requests())?.into_iter().map(InviteId).collect())
    }

    /// Accepts an invite request: its grant applies and its thing's hosts are dialed (then
    /// joined as for any invite). `Invalid` when no such request waits (accepted, declined or
    /// expired).
    pub fn accept_invite(&self, id: InviteId) -> Result<()> {
        if self.is_attached() {
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
        if self.is_attached() {
            return self.rcall(crate::port::method::DECLINE_INVITE, vec![Value::Bytes(id.bytes().to_vec())]).map(drop);
        }
        if !self.locked(|x| x.sync.decline_invite(id.0))? {
            return Err(Error::Invalid("no such invite request".into()));
        }
        Ok(())
    }

    /// The person's devices: nodes with an edge on the person actor.
    pub fn devices(&self) -> Result<Vec<Device>> {
        if self.is_attached() {
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

    /// Removes a device from the person (a lost or stolen one: `Demotion { sync: Skip, .. }` or a
    /// backdate; spec/permissions.md §5.3). Returns the person's links still working: the device
    /// keeps their seeds, so whoever holds it can read and join through each until `revoke_link`
    /// (spec/permissions.md §8). Those are links shared in advance too: ending them is the
    /// caller's choice. None when `node` was no device.
    pub async fn remove_device(&self, node: Tid, d: Demotion) -> Result<Vec<LinkInfo>> {
        let me = self.me();
        let was = self.roster(me)?.contains_key(&node);
        self.demote(me, node, Lower::Remove, d).await?;
        if was { self.own_links() } else { Ok(Vec::new()) }
    }

    /// The hosts new labels go to (and kept connected). `Unsupported` on a thin client: they are
    /// its node's.
    pub fn hosts(&self) -> Result<Vec<HostAddr>> {
        if self.is_attached() {
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
        if self.is_attached() {
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
        if self.is_attached() {
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
    /// owner-chain authority on it; its admins are edges, all equal, starting with `admin`
    /// (`me()`, or an actor this device is an admin of), fixed by its tid. It has secrets of its
    /// own at once; give it a label with `sync` or place it like any thing. Its roster is never
    /// compacted, and once no admin is left nobody can change it (members keep their roles).
    /// `Permission` (admin on `admin`), `UnknownActor` (no `keys.0` of `admin` here).
    pub fn create_ownerless(&self, admin: Tid) -> Result<Tid> {
        if self.is_attached() {
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
    /// cannot be reached shown as such (`Status::remotes`) rather than failing the watch.
    pub fn watch_status(&self, mut f: impl FnMut(&Osis, Status) + Send + 'static) -> Result<Subscription> {
        if self.is_attached() {
            return self.remote_watch_status(Box::new(f));
        }
        // a node with attachments shows them too: not a watch of them, a status at each change here
        let me = self.inner.me;
        let first = match self.status() {
            Ok(s) => s,
            Err(_) => self.locked(|x| status_of(&mut x.sync, me))?,
        };
        Ok(self.subscribe(Filter::Status, true, move |_| {
            let mut first = Some(first);
            Box::new(move |db, d| match d {
                Delivery::Initial => {
                    if let Some(s) = first.take() {
                        f(db, s)
                    }
                }
                Delivery::Status(s) => f(db, db.merged_status(s.clone()).unwrap_or(s)),
                _ => {}
            })
        }))
    }

    /// Resolves once every label in scope finished a pass with nothing outstanding after the
    /// local commits so far (they are at a host) and every pending delivery in scope was
    /// taken (a grant to a recipient whose inbox host refuses it for now keeps it waiting);
    /// fails `Unsynced` for a stranded label in scope (a refused one: at `timeout`), `Network`
    /// after `timeout` or without a
    /// runtime. `Group(t)`: the labels of the groups holding `t` (a hostless one fails
    /// `Unsynced`, unless replaced beside another) and the deliveries about `t`, a thing it holds or one of those groups (a
    /// grant on one, a non-writer's write under its label). With no group holding `t` it fails
    /// `Unsynced` at once, unless a route may still arrive: a grant named its label, or this node
    /// does not administer `t` and a label of its own has more to bring (a first sync). `All`:
    /// every label with hosts (`status` shows the `NoHosts` ones) and every delivery.
    ///
    /// On an attached handle the node waits with the
    /// same outcomes.
    pub async fn wait_synced(&self, scope: SyncScope, timeout: Duration) -> Result<()> {
        let r = match scope {
            SyncScope::Group(t) => self.route(t),
            SyncScope::All => self.route_scope(None)?,
        };
        if let crate::sources::Source::Remote(r) = r {
            let ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
            return self.remote_task(&r, crate::port::method::WAIT_SYNCED, vec![crate::port::codec::sync_scope_v(scope), Value::uint(ms)]).await.map(drop);
        }
        self.wait_synced_pending(scope, timeout).await
    }

    /// `wait_synced` as a future holding no handle (the client port serves it so).
    pub(crate) fn wait_synced_pending(&self, scope: SyncScope, timeout: Duration) -> crate::net::Pending<Result<()>> {
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
                self.groups_synced(None, Vec::new(), timeout, Some(BTreeSet::new()))
            }
            SyncScope::Group(t) => {
                // first, so that a label with more to bring counts as such
                self.sync_labels();
                // a failure at once needs no runtime
                if let Some(Err(e)) = self.locked(|x| group_synced(&mut x.sync, me, t, false)).filter(Result::is_err) {
                    return Pending::ready(Err(e));
                }
                self.wait_until(Some(timeout), Box::new(move |sync, _, late| group_synced(sync, me, t, late)))
            }
        }
    }

    /// Catches up now and waits for nothing: labels not live at a host sync, live ones (their host
    /// pushes what it gets) judge again what is left to send. Cheap at any rate, so an app may
    /// poll it. To wait until this node's writes are at a host: `wait_synced`.
    pub fn sync_now(&self) -> Result<()> {
        if self.is_attached() {
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
        if self.is_attached() {
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
        if self.is_attached() {
            use crate::port::{STREAM_CHUNK, method};
            for page in b.chunks(STREAM_CHUNK) {
                self.rcall(method::BUNDLE_WRITE, vec![Value::Bytes(page.to_vec())])?;
            }
            return self.rcall(method::IMPORT_BUNDLE, vec![Value::uint(b.len() as u64)]).map(drop);
        }
        self.try_act(|x| Ok(x.sync.import_bundle(&b)?))
    }
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
