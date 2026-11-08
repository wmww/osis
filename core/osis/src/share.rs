//! Sharing, links, cards, nodes, peers and sync (notes/api.md Sharing and roles, Sync
//! configuration and status) over role flows and the sync engine: each sharing call is
//! one role commit made locally (spec/permissions.md §2), whose deliveries the sync engine
//! carries out; calls that wait for another node are `async` (runtime-agnostic futures).

use crate::error::{Error, Result};
use crate::handle::{LINKS, Locked, MadeLink, Osis, SERVING_PEER, save_peers};
use crate::watch::{Delivery, Filter, Subscription};
use osis_base::{Ak, Role, Tid, Value, Time};
use osis_node::flows;
use osis_node::sync::{HostStatus, SyncEngine};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// When a grant ends and what its holder may grant others (`Osis::grant`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrantOpts {
    /// The grant ends at this time.
    pub until: Option<Time>,
    /// The highest role the holder may grant others, at most its own.
    pub may_grant: Option<Role>,
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
    /// The actor holding the role.
    pub actor: Tid,
    /// The role this way gives: the least along it.
    pub role: Role,
    /// When this way ends: the earliest end along it. One that has ended is not listed.
    pub until: Option<Time>,
    /// The actors between the thing and this holder, nearest the thing first: empty for a grant
    /// on the thing itself, the link's actor for someone who joined by a link, a team for its
    /// members.
    pub through: Vec<Tid>,
}

/// How `Osis::set_role` takes a role away.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetRoleOpts {
    /// On removal: whether the holder's nodes retain a read-only copy of what it could read (`true`)
    /// or erase it (`false`). `None`: the thing's default (`core::RequiredRules::retain_copies`), and
    /// erase for a node leaving its account. `Invalid` when a role remains.
    pub retain_copy: Option<bool>,
}

/// How a link made by `Osis::make_link` ends and is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkOpts {
    /// The link expires. It closes when one of your nodes next syncs after `until`: until then
    /// anyone holding the link can still join.
    pub until: Option<Time>,
    /// The first redemption ends the link.
    pub single_use: bool,
    /// Opt-in: the link text says how to reach this node directly, so a redeemer that shares no saved
    /// peer with it reaches it while it is online. Anyone holding the link can dial this node until
    /// the link ends by revocation or expiry, when the node's address changes (a single-use link's
    /// redemption keeps it: the redeemer keeps the direct path). Needs a runtime and
    /// `Config::direct_sync`; a node with no saved peers can only make direct links.
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

/// A link of this account (`links`).
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

/// An invite from a stranger: nothing it names is fetched or dialed until `accept_invite`. It says
/// nothing about sender or thing, as both would be the sender's unverified word.
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
    /// A share link (`osis://link/...`): whoever holds this text can redeem it, so hand it over as a
    /// secret.
    ShareLink, osis_label::ShareLink, osis_label::ShareLink::from_text, "link"
);
impl ShareLink {
    /// The thing the link shares.
    pub fn target(&self) -> Result<Tid> {
        Ok(self.parse()?.target)
    }
}
text_type!(
    /// A contact card: a read link to an account's profile.
    ContactCard, osis_label::ShareLink, osis_label::ShareLink::from_text, "contact card"
);

/// A transport URL, such as `quic://example.org:4040`: where something listens or is dialed.
/// `FromStr` checks it; a `quic://` URL without a port gets `:4040` spelled out.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Url(String);

impl Url {
    /// Its text.
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

/// How to reach a node: a transport URL and the node's key (`<url>#<base64url key>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub(crate) osis_label::Address);

impl std::str::FromStr for Address {
    type Err = Error;
    /// A `quic://` URL without a port gets `:4040` spelled out, so one node has one address.
    fn from_str(s: &str) -> Result<Address> {
        let mut a = osis_label::address_from_text(s.trim()).map_err(bad("address"))?;
        a.url = osis_transport::quic::explicit_port(&a.url);
        if a.url.len() > osis_base::format::MAX_URL_BYTES {
            return Err(Error::Invalid(format!("address: URL over {} bytes", osis_base::format::MAX_URL_BYTES)));
        }
        Ok(Address(a))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&osis_label::address_to_text(&self.0))
    }
}

impl Address {
    /// From a transport URL and the node's 32-byte key.
    pub fn new(url: &Url, key: [u8; 32]) -> Address {
        Address(osis_label::Address { url: url.0.clone(), key })
    }

    /// This address as a `peer://` relay item (`<hex key>@<socket address>`), when its URL is
    /// `peer://` and one socket address.
    pub(crate) fn relay_item(&self) -> Option<String> {
        let it = osis_transport::p2p::items(&self.0.url).ok()?;
        let [addr] = it.direct.as_slice() else { return None };
        it.relays.is_empty().then(|| osis_transport::p2p::Relay { key: self.0.key, addr: *addr }.item())
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

/// A node of this account and its role on the account (`Osis::nodes`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct AccountNode {
    pub node: Tid,
    pub role: Role,
}

/// How a group's sync stands here (`GroupSync::state`), best first. A group syncing several ways at
/// once, as when moving from one to another, shows the worst of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SyncState {
    /// Nothing left to send or fetch.
    Synced,
    /// Sending or fetching.
    Syncing,
    /// No saved peer, but other readers have it open with this node: commits go to them as they
    /// happen, and nothing says either side holds all the other does.
    Connected,
    /// No saved peer of it answers now (a node that does not serve never does). It keeps trying.
    Unreachable,
    /// No saved peer, and no other node has it open with this node now: what is written here stays
    /// here for now.
    NoPeers,
    /// A saved peer does not take it (yet; `GroupSync::refused_by` names them) and no other has it open.
    /// It keeps asking.
    Refused,
    /// This node holds no key to read what its peers hold now (lost, or not given yet), and can read
    /// nothing new until another holder gives them again.
    Stranded,
    /// Only the log of its commits is held (`SyncMode::LogOnly`): not synced, what is here is stale.
    LogOnly,
    /// A holder of a role on this thing gets none of its data (`GroupSync::not_carried_to`): the role
    /// stands, and it reads nothing until `sync` syncs the thing or a synced group the holder reads
    /// takes it in.
    NotCarried,
}

/// How one group syncs here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSync {
    /// Where its sync has got to.
    pub state: SyncState,
    /// When it was last caught up.
    pub last_sync: Option<Time>,
    /// Saved peers that do not take it (yet): state `Refused` when no other has it open, else
    /// informational.
    pub refused_by: Vec<Address>,
    /// This node left the group and keeps it until a saved peer has its removal; stays set while none
    /// takes it.
    pub leaving: bool,
    /// Holders of a role on the thing that no sync carries it to, as far as this node knows: this
    /// account among them when it is the one cut off. Not this node's own clients on a thing of this
    /// account's: they read what this node holds.
    pub not_carried_to: Vec<Tid>,
}

/// How sync stands: connections, each group this node syncs or holds the log of, and each thing shared
/// with no sync to carry it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Sync connections up now, whichever side dialed.
    pub connected: usize,
    /// How each group stands.
    pub groups: BTreeMap<Tid, GroupSync>,
    /// The nodes this process is a client of, and those a group's source names.
    pub node_connections: Vec<crate::sources::NodeConnection>,
    /// Things read at a connected node and also in a group that carries them to another source:
    /// writes on them are refused until one of the groups moves (`Osis::group_source`).
    pub two_sources: BTreeSet<Tid>,
}

/// What `Osis::wait_synced` waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncScope {
    /// Every synced group with a saved peer, and every pending delivery. A group with none is left
    /// out, so `Ok` says nothing of it: what was written there may have reached nobody (`status` shows
    /// such a group as `NoPeers` or `Connected`). There is no scope that waits on other readers.
    AllWithSavedPeers,
    /// The sync of this thing (its own, or of groups containing it; one with no saved peer fails
    /// `Unsynced`) and the deliveries about it, what it holds or those groups.
    Thing(Tid),
}

/// Nothing a wait can judge by: a group with no saved peer (issues/net-honest-status.md).
fn no_saved_peer(s: SyncState) -> bool {
    matches!(s, SyncState::NoPeers | SyncState::Connected)
}

/// One synced label's state.
fn label_state(s: &osis_node::sync::LabelStatus) -> SyncState {
    if s.hosts == 0 {
        if s.peers_connected > 0 { SyncState::Connected } else { SyncState::NoPeers }
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
/// the engine's routes; `me`: this node's account.
pub(crate) fn status_of(sync: &mut SyncEngine, me: Tid) -> Result<Status> {
    let mut groups: BTreeMap<Tid, GroupSync> = BTreeMap::new();
    for s in sync.label_status() {
        let state = label_state(&s);
        let last = s.last_sync.map(Time);
        let g = groups.entry(s.group).or_insert(GroupSync { state, last_sync: last, refused_by: Vec::new(), leaving: false, not_carried_to: Vec::new() });
        g.state = g.state.max(state);
        g.last_sync = g.last_sync.max(last);
        g.leaving |= s.leaving;
        for a in s.not_admitted {
            let a = Address(a);
            if !g.refused_by.contains(&a) {
                g.refused_by.push(a);
            }
        }
    }
    for g in sync.receipts_only() {
        groups.insert(*g, GroupSync { state: SyncState::LogOnly, last_sync: None, refused_by: Vec::new(), leaving: false, not_carried_to: Vec::new() });
    }
    // things a holder has a role on and no route to (spec/sync.md §2): none has a label of its
    // own, so none is listed above. On a thing this account administers (it can `sync` it) nobody
    // misses a route who reads only what this node holds: this account, its clients, and a group
    // of its own (up record edges standing here) held by no one else
    let e = sync.engine_mut();
    let node = e.tid();
    // a store that cannot answer fails the status: none read here would list its clients as cut off
    let clients = e.get_typed(&node, &ct::CLIENTS)?.unwrap_or_default();
    let served: BTreeSet<Tid> = [me].into_iter().chain(clients.into_keys()).collect();
    for (t, holders) in e.unrouted().iter() {
        let t = *t;
        let own = e.core.role_now(&me, &t) == Some(Role::Admin);
        let local = |e: &osis_node::Engine, h: &Tid| served.contains(h) || (e.core.standing_chain(h).contains(&me) && e.core.current_holders(h).iter().all(|(m, _, _)| served.contains(m)));
        let not_carried_to: Vec<Tid> = holders.iter().copied().filter(|h| !(own && local(e, h))).collect();
        if !not_carried_to.is_empty() && !groups.contains_key(&t) {
            groups.insert(t, GroupSync { state: SyncState::NotCarried, last_sync: None, refused_by: Vec::new(), leaving: false, not_carried_to });
        }
    }
    Ok(Status { connected: sync.connected(), groups, node_connections: Vec::new(), two_sources: BTreeSet::new() })
}

fn edge(role: Role, o: GrantOpts) -> ct::Edge {
    ct::Edge { role, until: o.until, invite: o.may_grant, tied: None }
}

/// Whether an admin's grant of `role` to `h` on `t` would lower `h`'s grant still in the state (a
/// present one, or one past its `until` not yet removed): `h`'s departure, whose rotation only a
/// demotion carries (spec/permissions.md §3), so it takes `set_role`.
fn below_held(e: &osis_node::Engine, t: &Tid, h: &Tid, role: Role) -> bool {
    e.role_on(t) == Some(Role::Admin) && e.key_role(t, h).is_some_and(|r| role < r)
}

/// `UnknownActor` unless `h` is known here as an actor a grant can box: a thing with a first
/// admin, or a key actor (a node or a link key) whose `keys.0` is held.
fn known_actor(e: &mut osis_node::Engine, h: Tid) -> Result<()> {
    if !e.knows(&h) || (e.first_admin(&h).is_none() && e.get_typed(&h, &ct::KEYS)?.is_none()) {
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
    !stale && l.sync.label_status().iter().filter(|s| groups.contains(&s.group)).all(|s| matches!(label_state(s), SyncState::Synced | SyncState::Connected | SyncState::NoPeers))
}

/// Synced groups holding any of `things` (the thing itself or its closure).
fn groups_holding(sync: &mut SyncEngine, status: &Status, things: &BTreeSet<Tid>) -> Vec<Tid> {
    status.groups.iter().filter(|(_, s)| !matches!(s.state, SyncState::LogOnly | SyncState::NotCarried)).map(|(g, _)| *g).filter(|g| things.contains(g) || sync.engine().closure(g).iter().any(|t| things.contains(t))).collect()
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

/// The labels' check of `wait_synced(Thing(t))`, over the groups holding `t` now and the
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
    synced(sync, Some(&groups), Some(&about))
}

/// The sync wait's check (`Osis::groups_synced`): one rule over the labels in scope, `groups`
/// (all their labels but a replaced hostless one beside another) or `None` (every label with hosts), then the pending deliveries about
/// `deliveries` (every one when `groups` is `None`).
fn synced(sync: &mut SyncEngine, groups: Option<&[Tid]>, deliveries: Option<&BTreeSet<Tid>>) -> Option<Result<()>> {
    let skip = sync.receipts_only().clone();
    let all: Vec<_> = sync.label_status().into_iter().filter(|s| !skip.contains(&s.group) && groups.is_none_or(|gs| gs.contains(&s.group))).collect();
    let labels: Vec<(Tid, SyncState)> = live_labels(&all)
        .map(|s| (s.group, label_state(s)))
        .filter(|(_, st)| groups.is_some() || !no_saved_peer(*st))
        .collect();
    let bad: BTreeSet<Tid> = labels.iter().filter(|(_, s)| *s == SyncState::Stranded || no_saved_peer(*s)).map(|(g, _)| *g).collect();
    if !bad.is_empty() {
        return Some(Err(Error::Unsynced { groups: bad.into_iter().collect() }));
    }
    let labeled = groups.is_none_or(|gs| gs.iter().all(|g| labels.iter().any(|(x, _)| x == g)));
    if !labeled || labels.iter().any(|(_, s)| *s != SyncState::Synced) {
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

/// Whether `t` reads here as at a node that has it: it has a label here, and each of its labels
/// finished a pass with nothing outstanding at some node it syncs with (a peer, or a co-reader
/// dialed: a direct link's sharer). A link makes its target a label of its own (`make_link`).
/// `Unsynced` on a stranded label, as every sync wait (`synced`).
fn arrived(sync: &mut SyncEngine, t: Tid) -> Option<Result<()>> {
    let all: Vec<_> = sync.label_status().into_iter().filter(|s| s.group == t).collect();
    if live_labels(&all).any(|s| label_state(s) == SyncState::Stranded) {
        return Some(Err(Error::Unsynced { groups: vec![t] }));
    }
    (!all.is_empty() && live_labels(&all).all(|s| s.idle > 0 || s.peers_idle > 0)).then_some(Ok(()))
}

/// `all` but a replaced label with no peer beside another of its group: it takes nothing (it
/// retires after ROLE_KEEP), and waiting on it would fail until then.
fn live_labels(all: &[osis_node::sync::LabelStatus]) -> impl Iterator<Item = &osis_node::sync::LabelStatus> {
    let gone = |s: &osis_node::sync::LabelStatus| s.hosts == 0 && s.replaced;
    all.iter().filter(move |s| !gone(s) || !all.iter().any(|x| x.group == s.group && !gone(x)))
}

/// Whether `g`'s labels are done now: nothing written here still waits (`Osis::group_source`).
pub(crate) fn synced_now(l: &mut crate::handle::Locked, g: Tid) -> Option<Result<()>> {
    let about: BTreeSet<Tid> = l.sync.engine().closure(&g).iter().copied().chain([g]).collect();
    synced(&mut l.sync, Some(&[g]), Some(&about))
}

impl Osis {
    /// `Unsupported` when calls on `t` go to another node: a flow the port does not carry.
    pub(crate) fn not_routed(&self, what: &str, t: Tid) -> Result<()> {
        match self.source(t) {
            crate::sources::Source::Local => Ok(()),
            crate::sources::Source::Node(_) => Err(Error::Unsupported(format!("{what} of a thing this node reads at another node: move its group home first"))),
        }
    }

    /// Grants `holder` `role` on `target`: adds a holder, raises a role, or changes `until` and
    /// `may_grant` (what `opts` leaves out goes). It never waits and never lowers a role: a role below
    /// the holder's present one, or below one whose grant ended and is still on record, is `Invalid`
    /// and takes `set_role`.
    ///
    /// `set_role` also adds and raises, and this overlap is on purpose: `grant` is the call that
    /// does not block and takes no role away, for sync code and for callers that mean only that, and
    /// the only one that sets `until` and `may_grant`. What it does take away, it takes as `set_role`
    /// does: a `may_grant` below the present one undoes the grants the
    /// holder made by it that this node had not received, and a role below one the holder had before
    /// (it left, or its grant ended and was removed) undoes what it wrote with that role that this
    /// node had not received.
    ///
    /// This records the permission and nothing else. The holder reads the target only once a synced
    /// group it reads holds the target, or the target's own `sync` carries it; until then `status`
    /// shows `SyncState::NotCarried` and names the holder (`GroupSync::not_carried_to`).
    ///
    /// Needs admin on the target (or a `may_grant` of at least `role`, for someone with no grant yet;
    /// a grant that ended above `role` counts as one until an admin takes it away), else `Permission`,
    /// and the holder's keys here (a contact card, a shared group, pairing), else `UnknownActor`.
    /// Each grant costs about 2.6 KB of keys: to share with many, grant one group. `Unsupported` on
    /// a client with its own actor.
    pub fn grant(&self, target: Tid, holder: Tid, role: Role, opts: GrantOpts) -> Result<()> {
        if let crate::sources::Source::Node(r) = self.source_write(target)? {
            return r.call(crate::port::method::GRANT, vec![Value::Tid(target), Value::Tid(holder), crate::port::codec::role_v(role), crate::port::codec::grant_opts_v(&opts)]).map(drop);
        }
        if !self.holds(target) {
            return Err(Error::UnknownThing { tid: target });
        }
        self.after_source();
        let done = self.locked(|l| {
            self.guard_local(l, &[target])?;
            let e = l.engine();
            known_actor(e, holder)?;
            // a change keeps the tie to a membership; a new hand grant has none
            let cur = e.roster(&target).get(&holder).copied();
            if cur.is_some_and(|x| role < x.role) || below_held(e, &target, &holder, role) {
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
    /// Two commits, not one: the membership, the grant. A crash between them
    /// leaves the earlier ones, and calling this again finishes the rest.
    ///
    /// Needs write on the group and admin on the thing (or a `may_grant` of at least `role`, the
    /// group having no grant yet), else `Permission` before anything is written. `Invalid`, as for
    /// `grant`, below a grant of the group ended and still on record. To add without granting: `Write::group`. `Unsupported` on a client with its own actor.
    pub fn add_with_grant(&self, member: Member, group: Tid, role: Role) -> Result<()> {
        let (tid, subgroup) = member.parts();
        if let crate::sources::Source::Node(r) = self.source_write_all(&[tid, group])? {
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
        if grant && existing.is_none() && self.engine(|e| below_held(e, &tid, &group, role)) {
            return Err(Error::Invalid("the group held a higher role: set_role first".into()));
        }
        let listed = self.read_local(|r| {
            let gs = r.groups_of(tid);
            if subgroup { gs.subgroup_of.contains(&group) } else { gs.item_of.contains(&group) }
        });
        if !listed {
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
                true => Some(e.placement(&tid, &group, subgroup)?.ok_or_else(|| Error::Invalid(format!("{tid} is not in {group} here")))?),
                false => None,
            };
            let edge = ct::Edge { role, until: None, invite: None, tied: tie.map(flows::tied::tie_ct) };
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

    /// Everyone who holds a role on `target`, directly or through an actor that holds one (an account
    /// through a group, a joiner through a link), nearest first. An actor with several ways in is
    /// listed once per way: the shortest to each grant it holds them by, and a longer one when it
    /// gives more, so its best role and latest end are among its entries. Who holds through an actor:
    /// `holders` of that actor, or those here with it in `through`. Grants one level down, with
    /// `may_grant` and whether a grant goes with a membership: `grants`. On a client with its own actor,
    /// what that actor may read: nothing behind an actor it may not read.
    pub fn holders(&self, target: Tid) -> Result<Vec<Holder>> {
        if let crate::sources::Source::Node(r) = self.source(target) {
            return crate::port::codec::holders(r.call(crate::port::method::HOLDERS, vec![Value::Tid(target)])?);
        }
        Ok(self.read_local(|r| {
            let mut out: Vec<Holder> = Vec::new();
            // the ways looked behind so far, per actor: a way none of them beats goes behind it too,
            // else a member's role through a nested actor is that of the actor's first way in
            let mut seen: BTreeMap<Tid, Vec<(Role, Option<Time>)>> = BTreeMap::new();
            let mut queue = std::collections::VecDeque::from([(target, None, None, Vec::new())]);
            while let Some((at, role, until, through)) = queue.pop_front() {
                let role: Option<Role> = role;
                let until: Option<Time> = until;
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

    /// Resolves once every label in scope is `Synced` (with `deliveries`, also once no delivery
    /// about one of those things is pending, any delivery for `groups` `None`); fails `Unsynced`
    /// when a label in scope is stranded. The scope: every label of `groups` (one with no peer
    /// fails `Unsynced`), or for `None` every label with hosts of a synced group.
    fn groups_synced(&self, groups: Option<Vec<Tid>>, deliveries: Option<BTreeSet<Tid>>) -> crate::net::Pending<Result<()>> {
        self.wait_until(Box::new(move |sync, _| synced(sync, groups.as_deref(), deliveries.as_ref())))
    }

    /// Makes `holder`'s role on `target` this one: raises, lowers, or with `None` removes. The usual
    /// way to change a role (`grant` says why both exist). A role that does not change writes
    /// nothing. Someone with no role gets a `grant` with default options, or with `None` nothing is
    /// written. `until` and `may_grant` stay as they are (`may_grant` capped at the new role): `grant`
    /// sets those.
    ///
    /// Lowering or removing a role writes at once, keeping what this node has received of the
    /// holder's work and what any other writer had received before the removal (each vouches for
    /// it in an addendum, spec/permissions.md §5.2). What reached no writer in time (an offline
    /// device, a reader or a host alone) is undone until the holder is granted the role again. To
    /// keep more, sync first: `wait_synced(SyncScope::Thing(target))` under your runtime's timeout,
    /// removing anyway when it times out or fails `Unsynced` (crate docs, Sharing). A raise waits
    /// for nothing.
    ///
    /// A role below one whose grant ended and is still on record ends the old grant in a commit of
    /// its own (a failure between the two leaves the holder with no role, as it had: call again).
    /// `SetRoleOpts::retain_copy` with a role is `Invalid`.
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
    /// A writer that changed the keys so only it can read locks the others out; removing it (or
    /// lowering it below write) here recovers: the new keys replace the ones it made. Lacking keys
    /// made by a writer it keeps, the lowering applies without changing the keys, and nothing is
    /// written under the thing here until that writer changes them (or is removed too).
    ///
    /// `Unsupported` on a client with its own actor, and on a thing this node reads at another node: move its group
    /// home first. A removal written to the copy here would never leave it.
    pub fn set_role(&self, target: Tid, holder: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        retain_only_on_removal(role, o)?;
        if !self.has_store() {
            return self.rcall(crate::port::method::SET_ROLE, vec![Value::Tid(target), Value::Tid(holder), crate::port::codec::opt(role, crate::port::codec::role_v), crate::port::codec::set_role_v(&o)]).map(drop);
        }
        self.not_routed("set_role", target)?;
        self.change_role(target, holder, role, o)
    }

    /// `set_role`'s writes.
    fn change_role(&self, target: Tid, holder: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        // each round removes one way in; the bound only guards against grants that never settle
        for _ in 0..16 {
            let Some(way) = self.holders(target)?.into_iter().find(|h| h.actor == holder) else {
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
                        Some(r) if r > cur.role => return self.grant(target, holder, r, GrantOpts { until: cur.until, may_grant: cur.may_grant }),
                        _ => self.lower(target, holder, role, o)?,
                    }
                }
                [k] if self.held_links()?.iter().any(|h| h.k == *k && h.target == target) => {
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

    /// The edge `m` holds on `t` after lowering it to `role` (`None`: removed): `until` kept,
    /// `may_grant` capped, the tie kept.
    fn lowered_edge(&self, t: Tid, m: Tid, role: Option<Role>) -> Result<Option<ct::Edge>> {
        let Some(role) = role else { return Ok(None) };
        let cur = self.grants(t)?.get(&m).copied().ok_or(Error::Invalid(format!("{m} is no holder of {t}")))?;
        Ok(Some(ct::Edge { role, until: cur.until, invite: cur.may_grant.map(|i| i.min(role)), tied: self.engine(|e| e.roster(&t).get(&m).and_then(|x| x.tied)).map(flows::tied::tie_ct) }))
    }

    /// Lowers or removes the grant of `m` on `t`: the demotion with this node's frontier and the
    /// target's rotation, in one commit (spec/permissions.md §2, §3, §5).
    fn lower(&self, t: Tid, m: Tid, role: Option<Role>, o: SetRoleOpts) -> Result<()> {
        let new = self.lowered_edge(t, m, role)?;
        // an account's default does not reach its nodes (spec/permissions.md §2)
        let retain = o.retain_copy.or((t == self.inner.me).then_some(false));
        let fd = flows::Demotion { holder: m, new, retain };
        let done = self.guarded(&[t], |e| e.demote(&t, &fd).map_err(needs_admin))?;
        self.carry(done)
    }

    /// Removes `holder`'s own grant on `target`. `holder` is `me()`, or a group
    /// or other actor this node is an admin of (as when a group's admin drops a thing that was shared
    /// into it). The keys change when the target's next writer or admin writes, or at once when this
    /// node is an admin of `target` by another way. No grant and no other way in writes nothing.
    ///
    /// `Invalid` when `holder` has no such grant but holds `target` through another actor (a team, a
    /// link's actor), naming it: leaving that actor is what ends the role. `Invalid` for another
    /// actor when this node is an admin of `target`: taking that role away is `set_role`'s.
    /// `Permission` when this node is no admin of `holder`; on a client with its own
    /// actor, for any `holder` but that actor.
    pub fn leave(&self, holder: Tid, target: Tid) -> Result<()> {
        let own = holder == self.me();
        // the flow below runs with the node's authority: a client ends only its own actor's role
        if self.acting.is_some() && !own {
            return Err(Error::Permission { tid: holder, needs: Role::Admin });
        }
        let source = if own { self.source_write(target)? } else { self.source_write_all(&[holder, target])? };
        if let crate::sources::Source::Node(r) = source {
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
            _ => Ok(e.demote(&target, &flows::Demotion { holder, new: None, retain: None })?),
        })?;
        self.carry(done)
    }

    /// The actors this node retains a read-only copy of after being removed from them (for a client
    /// with its own actor, those it reads). A copy reads as before, and nothing syncs or writes it.
    /// `drop_retained_copy` erases one.
    pub fn retained_copies(&self) -> Result<Vec<Tid>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::RETAINED_COPIES, vec![])?;
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

    /// Erases the retained copy of `actor`, and what only it retained: its disk space is this user's.
    pub fn drop_retained_copy(&self, actor: Tid) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::DROP_RETAINED_COPY, vec![Value::Tid(actor)]).map(drop);
        }
        self.locked(|l| l.sync.drop_kept(&[actor]))?;
        Ok(())
    }

    /// Makes a share link to `target` with `role`, reached through this node's saved peers. Anyone holding the link
    /// can redeem it until `until` or `revoke_link`. It also syncs `target` when it does not sync on
    /// its own, or the link could not work.
    pub fn make_link(&self, target: Tid, role: Role, opts: LinkOpts) -> Result<ShareLink> {
        if let crate::sources::Source::Node(r) = self.source_write(target)? {
            let v = r.call(crate::port::method::MAKE_LINK, vec![Value::Tid(target), crate::port::codec::role_v(role), crate::port::codec::opt(opts.until, |w| Value::uint(w.0)), Value::Bool(opts.single_use), Value::Bool(opts.direct)])?;
            return Ok(ShareLink(crate::port::codec::Args::of(vec![v]).text()?));
        }
        let hosts = self.host_addrs();
        let me = self.me();
        if hosts.is_empty() && !opts.direct {
            return Err(Error::Invalid("this node has no saved peers: a link reaches nobody unless it is direct (LinkOpts.direct)".into()));
        }
        if opts.direct && self.locked(|x| x.sync.own_reach()).is_none() {
            return Err(Error::Invalid("a direct link needs this node reachable: a runtime with Config.direct_sync on".into()));
        }
        self.after_source();
        let (mut link, keep, done) = self.locked(|l| {
            self.guard_local(l, &[target])?;
            // K reads the target's own label alone (spec/sync.md §2): a link syncs the target
            let label = !l.engine().labeled(&target);
            let made = l.engine().create_link(&me, &flows::LinkSpec { target, role, until: opts.until, hosts: hosts.clone(), peers: Vec::new(), single_use: opts.single_use }).map_err(needs_admin)?;
            // K is on it before the label's first pass: this node's `reach.0` never goes under
            // it, and nothing rotates (spec/permissions.md §4, §7)
            if label {
                self.make_label(l, target, hosts)?;
            }
            Ok::<_, Error>(made)
        })?;
        // the seed thing in the home group: every node of this account holds it and may
        // finalize the link (spec/permissions.md §7)
        let mut w = self.write();
        w.group(self.me()).add(Member::Item(keep))?;
        w.commit()?;
        let l = osis_node::Identity::from_seed(link.seed.clone()).tid();
        self.locked(|x| {
            x.links.insert(link.k, MadeLink { l, target, single_use: opts.single_use, direct: opts.direct, ended: false });
            save_links(x)
        })?;
        self.carry(done)?;
        if opts.direct {
            // only the dialable key and relays, never direct addresses or the lan secret
            // (spec/permissions.md §7)
            let r = self.locked(|x| x.sync.own_reach()).ok_or(Error::Invalid("this node's reach is gone".into()))?;
            let relays = r.items.iter().filter(|i| osis_transport::p2p::Relay::parse(i).is_some()).cloned().collect();
            link.peers = vec![osis_label::Peer { dialable: r.dialable, relays }];
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

    /// Redeems a link: reaches what it names and joins it, returning the thing. A link known to have
    /// ended (used, revoked, expired, its peers no longer knowing it) fails `Invalid` at once. A link
    /// that cannot be judged yet, its maker's upload on the way or nobody answering, waits until
    /// dropped: nothing says it will not work, and calling again is safe. What the link holds is
    /// forgotten on every outcome, a dropped future included; dropped once joined, the join stands.
    /// A link to a thing this account already reaches at the link's role or above returns the thing
    /// and joins nothing: its maker or a participant pasting it, a joiner pasting it again, a used
    /// single-use link of its own; a lower role is raised as the link says. Returns once the role is
    /// of use, `role_on` reporting it (a write or admin role once the thing's keys are here), and,
    /// joining, once the thing is here: a read sees what a node that has it holds. Joined but the thing stranded
    /// here (`SyncState::Stranded`): `Unsynced`, as `wait_synced`; the join stands, and calling
    /// again after a re-seal returns the thing.
    pub async fn redeem(&self, link: &ShareLink) -> Result<Tid> {
        if !self.has_store() {
            link.parse()?;
            let v = self.rtask(crate::port::method::REDEEM, vec![Value::Str(link.0.clone())]).await?;
            return crate::port::codec::Args::of(vec![v]).tid();
        }
        let link = link.parse()?;
        let (k, target) = (link.k, link.target);
        // nothing to join when this account reaches the target at the link's role already: no link
        // is followed or judged
        let held = self.engine(|e| reaches(e, &target, &k)) || self.join_link(&link).await?;
        let me = self.me();
        // joined: the grant stands in a view with nothing on K pending, and the role is of use
        // (`read::usable`: a direct link's grant comes under K's label with no inbox hint, the
        // target's delete keys after it), so the first write goes through; and the target is
        // here, so the first read sees what it holds
        self.wait_until(Box::new(move |s, _| {
            let e = s.engine_mut();
            if !held && (!e.roster(&k).contains_key(&me) || pending_on(e, &k)) {
                return None;
            }
            let role = e.role_on(&target);
            match crate::read::usable(e, &target, role) {
                // reached before: it is here already (a used single-use link of its own: a call
                // dropped while waiting for the delete keys)
                Ok(r) if r == role && held => Some(Ok(())),
                Ok(r) if r == role => arrived(s, target),
                Ok(_) => None,
                Err(x) => Some(Err(x)),
            }
        }))
        .await?;
        Ok(target)
    }

    /// `redeem`'s join: follows the link, waits until it can be judged, and redeems it. `true`:
    /// this account came to reach the target meanwhile, and joined nothing.
    async fn join_link(&self, link: &osis_label::ShareLink) -> Result<bool> {
        let (k, target) = (link.k, link.target);
        let key = self.follow_link(link)?;
        // its sharer node is redialed at a host's pace until this call ends, whatever the outcome
        let _redeeming = Redeeming { db: self.downgrade(), k };
        let l = key.l;
        // L must be on K's roster in a view with nothing on K pending: a commit on K waiting
        // for its chain may be (or follow) an earlier redemption that removed L
        let label = link.k_label;
        let me = self.me();
        self.wait_until(Box::new(move |s, _| {
            // another node of this account joined (a used single-use link too)
            if reaches(s.engine_mut(), &target, &k) {
                return Some(Ok(()));
            }
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
            // no such edge yet: it may be on its way from the maker's node, so nothing here is sure
            None
        }))
        .await?;
        // reached meanwhile (another node of this account joined): nothing to redeem
        let held = self.engine(|e| reaches(e, &target, &k));
        if !held {
            let done = self.engine(|e| e.redeem(link, &me, link.single_use))?;
            self.carry(done)?;
        }
        // joined, by this call or another node: the follow (hint, sharer node) stays
        if self.engine(|e| e.roster(&k).contains_key(&me)) {
            let mut key = key;
            key.link = None;
            drop(key);
        }
        Ok(held)
    }

    /// Holds a link's key and follows K's label at its hosts and at the sharer's node when
    /// the link names it (first contact, spec/permissions.md §7: dialed at the link's dialable
    /// key and relays like a co-reader, for K and the target only, `follow_link_peer`); the key
    /// goes with the guard, and with it the follow unless the redemption went through.
    fn follow_link(&self, link: &osis_label::ShareLink) -> Result<KeyGuard> {
        if link.hosts.is_empty() && !self.inner.dials_peers {
            return Err(Error::Network("this link names no peer and this node does not dial others directly".into()));
        }
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

    /// The account's links that still work, whichever node made them (one that has not yet synced here
    /// from the node that made it is not listed); filter by `LinkInfo::target`. `Unsupported` on
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

    /// The links whose seed thing is the account's and whose K's first admin it is (a co-reader can place a
    /// seed thing in a shared group: it names no link of ours).
    fn held_links(&self) -> Result<Vec<flows::HeldLink>> {
        let me = self.me();
        self.engine(|e| person_links(e, me))
    }

    /// Link actor `k`'s key L (`held_links`).
    fn link_key(&self, k: Tid) -> Result<Tid> {
        self.held_links()?.iter().find(|h| h.k == k).map(|h| h.l).ok_or(Error::Invalid(format!("no link {k} of this account")))
    }

    /// Ends a link: nobody can use it from now on. Those who joined by it keep their role; to remove
    /// one, `set_role`. Writes at once: a join this node has not received yet is undone (one another
    /// writer received stands, as `set_role` says). `Unsupported` on a client with its own actor.
    pub fn revoke_link(&self, id: LinkId) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::REVOKE_LINK, vec![Value::Tid(id.0)]).map(drop);
        }
        self.not_routed("revoke_link", id.0)?;
        let l = self.link_key(id.0)?;
        self.lower(id.0, l, None, SetRoleOpts::default())
    }

    /// Removes `joiner` from link actor `k` and ends the link in the same commit, under one rotation
    /// (spec/permissions.md §7: a joiner may keep the seed); the other joiners stay holders of K and
    /// need a new link to invite anyone.
    fn remove_joiner(&self, k: Tid, joiner: Tid, o: SetRoleOpts) -> Result<()> {
        self.not_routed("set_role", k)?;
        let l = self.link_key(k)?;
        let done = self.guarded(&[k], |e| e.revoke_joiner(&k, &l, &joiner, o.retain_copy).map_err(needs_admin))?;
        self.carry(done)
    }

    /// Rotates this node's dialable key when a direct link it made ended (spec/permissions.md
    /// §7): after every change, at open and at the link's expiry. Finalizing links is
    /// node-sync's (`SyncEngine::finalize_links`). `ended` is persisted.
    pub(crate) fn upkeep_links(&self, l: &mut Locked) {
        let mut any = false;
        // a direct link that ended (its key left K, or its edge expired) gave out this node's
        // dialable key: rotate it (spec/permissions.md §7), unless a single-use link ended by its
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

    /// This account's contact card: a read link to its profile, a thing that also carries what others
    /// need to grant this account a role. Made once; later calls return the same card. `Invalid` on a node with no saved peers.
    /// `Unsupported` on a client with its own actor.
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
            return Err(Error::Invalid("this node has no saved peers: a contact card needs one".into()));
        }
        let mut w = self.write();
        let p = w.create()?;
        w.commit()?;
        self.locked(|x| -> Result<()> {
            // secrets of its own before the label, as `sync()` does
            let done = x.engine().give_own_secrets(&p)?;
            let acts = x.sync.carry_out(done)?;
            self.inner.apply(acts);
            let (_, acts) = x.sync.create_label(&p, hosts.clone())?;
            self.inner.apply(acts);
            // the account's creation and `keys.0` commits, as certificates under P's label
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

    /// This account's profile thing: the target of its contact card, made on first
    /// use. The account writes its profile aspects on it (`name.0`, `contact:*`); everyone holding
    /// the card reads them.
    /// `Unsupported` on a client with its own actor.
    pub fn profile(&self) -> Result<Tid> {
        let card = self.contact_card()?;
        Ok(card.parse()?.target)
    }

    /// The profile thing of an account whose card this node imported, if any.
    /// `Unsupported` on a client with its own actor.
    pub fn profile_of(&self, account: Tid) -> Result<Option<Tid>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::PROFILE_OF, vec![Value::Tid(account)])?;
            return crate::port::codec::Args::of(vec![v]).opt()?.map(|t| crate::port::codec::Args::of(vec![t]).tid()).transpose();
        }
        let Some(b) = self.engine(|e| e.app_record(&format!("{PROFILE_OF}{account}")))? else { return Ok(None) };
        let t = String::from_utf8(b).map_err(|_| Error::Storage("profile record".into()))?;
        t.parse().map(Some).map_err(|_| Error::Storage("profile record".into()))
    }

    /// Imports a contact card: reads the profile by the card, nothing written, until the account's keys
    /// are here. Returns the account, usable in `grant`. `Invalid` as for `redeem` when the card is known to have ended; otherwise it waits
    /// until dropped, and calling again is safe. The card's key is forgotten on every outcome, a
    /// dropped future included.
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
                Box::new(move |s, _| {
                    if s.static_entry_refused(&label) {
                        return Some(Err(link_ended()));
                    }
                    let e = s.engine_mut();
                    let holds = e.roster(&p).contains_key(&k);
                    if let (true, Some(first)) = (holds, e.first_admin(&p))
                        && e.get_typed(&first, &ct::KEYS).ok().flatten().is_some()
                    {
                        *crate::watch::lock(&f2) = Some(first);
                        return Some(Ok(()));
                    }
                    // as in `redeem`: nothing here says it will not come
                    None
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
        who.ok_or(Error::Invalid("contact card: no account".into()))
    }

    /// The invite requests waiting for the user (`InviteId`).
    /// `Unsupported` on a client with its own actor.
    pub fn invite_requests(&self) -> Result<Vec<InviteId>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::INVITE_REQUESTS, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|b| InviteId::from_bytes(&crate::port::codec::Args::of(vec![b]).bytes()?)).collect();
        }
        Ok(self.locked(|x| x.sync.invite_requests())?.into_iter().map(InviteId).collect())
    }

    /// Accepts an invite request: its grant applies and its thing's peers are dialed (then joined as
    /// for any invite). `Invalid` when no such request waits (accepted, declined or
    /// expired).
    /// `Unsupported` on a client with its own actor.
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
    /// `Unsupported` on a client with its own actor.
    pub fn decline_invite(&self, id: InviteId) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::DECLINE_INVITE, vec![Value::Bytes(id.bytes().to_vec())]).map(drop);
        }
        if !self.locked(|x| x.sync.decline_invite(id.0))? {
            return Err(Error::Invalid("no such invite request".into()));
        }
        Ok(())
    }

    /// This account's nodes: those holding a role on it.
    /// `Unsupported` on a client with its own actor.
    pub fn nodes(&self) -> Result<Vec<AccountNode>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::NODES, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|d| {
                let mut a = crate::port::codec::Args::new(d)?;
                Ok(AccountNode { node: a.tid()?, role: crate::port::codec::role(&a.next()?)? })
            }).collect();
        }
        let me = self.me();
        let node_ak = Ak::new("node.0").map_err(|_| Error::Invalid("ak".into()))?;
        self.engine(|e| -> Result<Vec<AccountNode>> {
            let mut out = Vec::new();
            for (m, edge) in e.roster(&me) {
                if m == e.tid() || e.get(&m, &node_ak)?.is_some() {
                    out.push(AccountNode { node: m, role: edge.role });
                }
            }
            Ok(out)
        })
    }

    /// Removes a node from this account. This is `set_role(me, node, None, o)`, here because of
    /// what it returns, which is easy to forget: this account's links still working. The node keeps
    /// their keys, so whoever holds it can read and join through each until `revoke_link`, and
    /// ending them is the caller's choice. None when `node` was not one of this account's.
    /// `Unsupported` on a client with its own actor.
    pub fn remove_node(&self, node: Tid, o: SetRoleOpts) -> Result<Vec<LinkInfo>> {
        let me = self.me();
        let was = self.grants(me)?.contains_key(&node);
        self.set_role(me, node, None, o)?;
        if was { self.links() } else { Ok(Vec::new()) }
    }

    /// The peers this node saved with `add_peer`, and its own `serving_address` while it serves: it
    /// stays connected to them, and groups sync with them unless `sync` names others. `Unsupported` on a client with its own actor: they are its
    /// node's.
    pub fn saved_peers(&self) -> Result<Vec<Address>> {
        if !self.has_store() {
            let v = self.rcall(crate::port::method::SAVED_PEERS, vec![])?;
            return crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|h| crate::port::codec::Args::of(vec![h]).text()?.parse()).collect();
        }
        Ok(self.host_addrs().into_iter().map(Address).collect())
    }

    /// Whom `group` syncs with, as far as this node knows: the peers saved on the group, then the
    /// other readers that published an address and that this node would dial. Empty for a group that
    /// does not sync here, and for one nobody else is known for. `Unsupported` on a client with its
    /// own actor.
    pub fn peers(&self, group: Tid) -> Result<Vec<Address>> {
        let parse = |v: Value| -> Result<Vec<Address>> { crate::port::codec::Args::of(vec![v]).list()?.into_iter().map(|h| crate::port::codec::Args::of(vec![h]).text()?.parse()).collect() };
        if !self.has_store() {
            return parse(self.rcall(crate::port::method::PEERS, vec![Value::Tid(group)])?);
        }
        if let crate::sources::Source::Node(r) = self.source(group) {
            return parse(r.call(crate::port::method::PEERS, vec![Value::Tid(group)])?);
        }
        Ok(self.locked(|l| l.sync.group_peers(&group)).into_iter().map(Address).collect())
    }

    fn host_addrs(&self) -> Vec<osis_label::Address> {
        self.locked(|x| x.sync.config().hosts.clone())
    }

    /// Saves a peer: a node serving at this address (`set_serving`, its `serving_address`), whether or
    /// not it can read what it gets. This node stays connected to it, and what syncs from now on syncs
    /// with it (links, `sync`). What already syncs with all the saved peers moves to the new list: the home group and
    /// groups made under this account (their record chain reaches it) that this node administers; not links or the contact card (their text
    /// names their peers), not others' groups. With `Runtime::None` the list is only stored, for the
    /// next open with a runtime: until then `status` shows nothing connected and `wait_synced` fails
    /// `Network`.
    /// `Unsupported` on a client with its own actor.
    pub fn add_peer(&self, peer: &Address) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::ADD_PEER, vec![Value::Str(peer.to_string())]).map(drop);
        }
        let mut v = self.saved_peers()?;
        if !v.contains(peer) {
            v.push(peer.clone());
        }
        self.set_hosts(v)
    }

    /// Removes a saved peer, from the list and the groups that follow it (`add_peer`); a group with
    /// holders besides this account's nodes keeps its last one. Its own `serving_address` stays
    /// while it serves. `Unsupported` on a client with its own actor.
    pub fn remove_peer(&self, peer: &Address) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::REMOVE_PEER, vec![Value::Str(peer.to_string())]).map(drop);
        }
        let mut v = self.saved_peers()?;
        v.retain(|x| x != peer);
        self.set_hosts(v)
    }

    fn set_hosts(&self, v: Vec<Address>) -> Result<()> {
        let me = self.me();
        self.locked(|x| {
            // its own serving address stays while it serves (`upkeep_serving_peer`)
            let mut v = v;
            if let Some(p) = x.serving_peer.as_ref().filter(|p| !v.contains(p)) {
                v.push(p.clone());
            }
            move_hosts(x, me, &v)
        })?;
        self.nudge_sync()
    }

    /// A serving node syncs with its own serving address as with any saved peer (notes/api.md
    /// Serving): once it listens, that address is in the saved list (`remove_peer` keeps it); a new
    /// address replaces the one it added, and stopping removes it. Starting up or failing to listen changes nothing: the address it had stays. Under the lock, after every call.
    pub(crate) fn upkeep_serving_peer(&self, l: &mut Locked) {
        let want = match (l.sync.host_key(), l.sync.host_status()) {
            (None, _) => None,
            (Some(k), HostStatus::Listening(a)) => match a.first() {
                Some(a) if a.key == k => Some(Address(a.clone())),
                _ => return,
            },
            _ => return,
        };
        if l.serving_peer == want && want.as_ref().is_none_or(|w| l.sync.config().hosts.contains(&w.0)) {
            return;
        }
        let mut v: Vec<Address> = l.sync.config().hosts.iter().cloned().map(Address).collect();
        if let Some(p) = l.serving_peer.as_ref().filter(|p| Some(*p) != want.as_ref()) {
            v.retain(|x| x != p);
        }
        if let Some(w) = want.as_ref().filter(|w| !v.contains(w)) {
            v.push(w.clone());
        }
        let me = self.inner.me;
        let r = move_hosts(l, me, &v).and_then(|()| {
            let text = want.as_ref().map(ToString::to_string).unwrap_or_default();
            Ok(l.engine().set_app_record(SERVING_PEER, text.as_bytes())?)
        });
        match r {
            Ok(()) => l.serving_peer = want,
            Err(e) => l.engine().report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Storage, tids: Vec::new(), commit: None, peer: None, detail: format!("own serving address as a saved peer: {e}") }),
        }
        let mut acts = l.sync.handle(osis_node::sync::Event::Local);
        acts.extend(l.sync.refresh());
        self.inner.apply(acts);
    }

    /// Makes `group` synced with `peers` (empty: the saved peers), needing admin on the group; other
    /// readers it publishes an address to sync with it as well. Any thing can be a group of itself, but
    /// prefer sets: share many things through one group, as each thing synced alone costs its own keys
    /// and its own sync. A no-op when it syncs already, unless `peers` names others: `Invalid`, for a
    /// group keeps its peers.
    /// `Unsupported` on a client with its own actor.
    pub fn sync(&self, group: Tid, peers: &[Address]) -> Result<()> {
        if let crate::sources::Source::Node(r) = self.source_write(group)? {
            return r.call(crate::port::method::SYNC, vec![Value::Tid(group), Value::List(peers.iter().map(|h| Value::Str(h.to_string())).collect())]).map(drop);
        }
        self.sync_here(group, peers, false)
    }

    /// `sync` on this engine. `home`: `group_source` bringing it back, while its source still stands
    /// (calls keep going to the node until this engine caught up); else a move since the source was
    /// decided fails this, as any flow.
    pub(crate) fn sync_here(&self, group: Tid, hosts: &[Address], home: bool) -> Result<()> {
        if !self.holds(group) {
            return Err(Error::UnknownThing { tid: group });
        }
        // this engine's role: the source, if any, would ask the node
        if self.read_local(|r| r.role_on(group))? != Some(Role::Admin) {
            return Err(Error::Permission { tid: group, needs: Role::Admin });
        }
        let named: BTreeSet<osis_label::Address> = hosts.iter().map(|s| s.0.clone()).collect();
        let hosts = if hosts.is_empty() { self.host_addrs() } else { hosts.iter().map(|s| s.0.clone()).collect() };
        if !home {
            self.after_source();
        }
        self.locked(|x| -> Result<()> {
            if !home {
                self.guard_local(x, &[group])?;
            }
            if !named.is_empty() && x.engine().group_labels(&group)?.iter().any(|l| !l.replaced && !same_set(&l.hosts, &named)) {
                return Err(Error::Invalid(format!("{group} already syncs with other peers")));
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

    /// Stops syncing `group` for all its holders (it stays in other synced groups it is a member of).
    /// `Unsupported` on a client with its own actor.
    pub fn unsync(&self, group: Tid) -> Result<()> {
        if let crate::sources::Source::Node(r) = self.source_write(group)? {
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

    /// How sync stands now.
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
    /// cannot be reached shown as such (`Status::node_connections`). `Err`: the store could not say; the
    /// next status that can be read follows.
    pub fn on_status_change(&self, mut f: impl FnMut(&Osis, Result<Status>) + Send + 'static) -> Result<Subscription> {
        if !self.has_store() {
            return self.node_on_status_change(Box::new(f));
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

    /// Resolves once this node's writes so far in scope reached a saved peer, nothing more is
    /// outstanding, and every pending delivery in scope was taken. Fails `Unsynced` at once on a
    /// stranded group in scope (`SyncState::Stranded`, for now), and for `Thing(t)` on a group with no
    /// saved peer; `Network` without a runtime. A peer out of reach, or one that does not take a group
    /// or a delivery for now (`SyncState::Refused`), may yet: this waits (`status` shows them). `Thing(t)`: the groups
    /// holding `t` and the deliveries about `t`, a thing it holds or one of those groups. With no group
    /// holding `t` it fails `Unsynced` at once, unless one may still arrive: a grant named it, or this
    /// node does not administer `t` and something it syncs has more to bring (a first sync).
    /// `AllWithSavedPeers`: every group with a saved peer and every delivery. Groups with none are left out,
    /// and `Ok` says nothing of them: look at `status`.
    ///
    /// On a thin client the node waits with the same outcomes.
    pub async fn wait_synced(&self, scope: SyncScope) -> Result<()> {
        let r = match scope {
            SyncScope::Thing(t) => self.source(t),
            SyncScope::AllWithSavedPeers => self.source_scope(None)?,
        };
        if let crate::sources::Source::Node(r) = r {
            return self.node_task(&r, crate::port::method::WAIT_SYNCED, vec![crate::port::codec::sync_scope_v(scope)]).await.map(drop);
        }
        self.wait_synced_pending(scope).await
    }

    /// `wait_synced` as a future holding no handle (the client port serves it so).
    pub(crate) fn wait_synced_pending(&self, scope: SyncScope) -> crate::net::Pending<Result<()>> {
        let me = self.inner.me;
        use crate::net::Pending;
        match scope {
            SyncScope::AllWithSavedPeers => {
                // nothing to wait for: done, also without a runtime
                let idle = self.locked(|x| {
                    let skip = x.sync.receipts_only().clone();
                    x.sync.deliveries_pending() == 0 && !x.sync.label_status().iter().any(|s| s.hosts > 0 && !skip.contains(&s.group))
                });
                if idle {
                    return Pending::ready(Ok(()));
                }
                self.sync_labels();
                self.groups_synced(None, Some(BTreeSet::new()))
            }
            SyncScope::Thing(t) => {
                // first, so that a label with more to bring counts as such
                self.sync_labels();
                // a failure at once needs no runtime
                if let Some(Err(e)) = self.locked(|x| group_synced(&mut x.sync, me, t)).filter(Result::is_err) {
                    return Pending::ready(Err(e));
                }
                self.wait_until(Box::new(move |sync, _| group_synced(sync, me, t)))
            }
        }
    }

    /// Asks sync to catch up now, and waits for nothing. Cheap at any rate, so an app may poll it. To
    /// wait until this node's writes reached a peer: `wait_synced`.
    pub fn nudge_sync(&self) -> Result<()> {
        if !self.has_store() {
            return self.rcall(crate::port::method::NUDGE_SYNC, vec![]).map(drop);
        }
        self.act(|x| x.sync.refresh());
        Ok(())
    }

    /// Every open label syncs at every connection, live or not (a wait's start).
    fn sync_labels(&self) {
        self.act(|x| x.sync.sync_now());
    }

    /// Writes `groups` as a bundle to `out`, for another node's `import_bundle`: sync by hand, carried
    /// any way you like.
    /// `Unsupported` on a client with its own actor.
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
    /// `Unsupported` on a client with its own actor.
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

/// `SetRoleOpts::retain_copy` is a removal's word.
fn retain_only_on_removal(role: Option<Role>, o: SetRoleOpts) -> Result<()> {
    if role.is_some() && o.retain_copy.is_some() {
        return Err(Error::Invalid("retain_copy is for removing a role: there is no copy to retain while a role remains".into()));
    }
    Ok(())
}

/// `Osis::held_links`, on this engine.
fn person_links(e: &mut osis_node::Engine, me: Tid) -> Result<Vec<flows::HeldLink>> {
    let held = e.held_links()?.to_vec();
    Ok(held.into_iter().filter(|h| h.first_admin == me && e.first_admin(&h.k) == Some(me)).collect())
}

fn same_set(s: &[osis_label::Address], old: &BTreeSet<osis_label::Address>) -> bool {
    s.iter().cloned().collect::<BTreeSet<_>>() == *old
}

/// Moves the labels whose host list is `old` (as a set) to `new` (spec/sync.md §2 `label.0`
/// hosts; the sync engine registers a label's path at a host that does not know it): the
/// home label and the labels of groups in the account's own record tree (`standing_chain`) this node administers,
/// except `fixed` ones (links, the contact card) and groups with a key-actor holder (an
/// account's node, a link's key actor). A group with holders besides the account and its
/// nodes never loses its last one.
fn follow_labels(e: &mut osis_node::Engine, me: Tid, fixed: &BTreeSet<Tid>, old: &BTreeSet<osis_label::Address>, new: &[osis_label::Address]) -> Result<()> {
    let list = Codec::to_value(&new.to_vec());
    let nodes: BTreeSet<Tid> = e.roster(&me).into_keys().collect();
    let mine = |e: &osis_node::Engine, g: Tid| e.core.standing_chain(&g).contains(&me);
    let mut m = osis_node::Mutation::new();
    let mut any = false;
    for g in e.labeled_groups() {
        if fixed.contains(&g) || e.role_on(&g) != Some(Role::Admin) || !mine(e, g) {
            continue;
        }
        let holders: Vec<Tid> = e.roster(&g).into_keys().filter(|x| *x != me && !nodes.contains(x)).collect();
        if holders.iter().any(|x| e.first_admin(x).is_none()) || new.is_empty() && !holders.is_empty() {
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

/// Saves `v` as the saved peers, moving what follows them (`Osis::add_peer`).
fn move_hosts(x: &mut Locked, me: Tid, v: &[Address]) -> Result<()> {
    let old: BTreeSet<osis_label::Address> = x.sync.config().hosts.iter().cloned().collect();
    let new: Vec<osis_label::Address> = v.iter().map(|s| s.0.clone()).collect();
    // links, whichever node made them, and the contact card name their label's hosts in
    // their text: they stay; a routed group too: nothing written here leaves, and a stale
    // list would move it on the way home
    let links = person_links(x.engine(), me)?;
    let mut fixed: BTreeSet<Tid> = links.iter().map(|h| h.k).chain(x.group_sources.keys().copied()).collect();
    if let Some(card) = x.engine().app_record(CONTACT)?
        && let Ok(l) = ContactCard(String::from_utf8_lossy(&card).into_owned()).parse()
    {
        fixed.insert(l.target);
    }
    // the labels first: a failed commit leaves the list as it was, so a retry matches
    follow_labels(x.engine(), me, &fixed, &old, &new)?;
    save_peers(x.engine(), v)?;
    x.sync.set_hosts(new.clone());
    follow_inbox(x.engine(), me, &old, &new)
}

/// Moves the account's inbox to `new` when it is on `old`.
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
/// App record prefix: `profile/<account tid>` -> profile tid text, written by `import_contact`.
const PROFILE_OF: &str = "profile/";

/// Stores the links made here (one local record).
fn save_links(l: &mut Locked) -> Result<()> {
    let v = Value::List(l.links.iter().map(|(k, m)| Value::List(vec![Value::Tid(*k), Value::Tid(m.l), Value::Tid(m.target), Value::Bool(m.single_use), Value::Bool(m.direct), Value::Bool(m.ended)])).collect());
    l.engine().set_app_record(LINKS, &osis_base::cbor::encode(&v))?;
    Ok(())
}

/// A held link key, forgotten when the guard goes: every outcome of a waiting call,
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

/// A link redemption under way (`SyncEngine::link_redeemed` when it goes).
struct Redeeming {
    db: crate::handle::WeakOsis,
    k: Tid,
}

impl Drop for Redeeming {
    fn drop(&mut self) {
        if let Some(db) = self.db.hold() {
            db.locked(|x| x.sync.link_redeemed(&self.k));
        }
    }
}

fn link_ended() -> Error {
    Error::Invalid("this link no longer works: ask for a new one".into())
}

/// Whether a commit on `k` waits here (pending, not parked: spec/commits.md §4).
/// This node reaches `target` at the role link actor `k` holds on it, or above: a link to it joins
/// nothing.
fn reaches(e: &osis_node::Engine, target: &Tid, k: &Tid) -> bool {
    e.knows(target) && e.roster(target).get(k).is_some_and(|g| e.role_on(target) >= Some(g.role))
}

fn pending_on(e: &mut osis_node::Engine, k: &Tid) -> bool {
    let ids: Vec<osis_base::CommitId> = e.pending().into_iter().filter(|(_, r)| *r != osis_node::Reason::Parked).map(|(c, _)| c).collect();
    ids.iter().any(|c| e.commit_bytes(c).ok().flatten().and_then(|b| osis_commit::CommitBlob::decode_stored(&b).ok()).is_some_and(|cb| cb.header.aspects.iter().any(|a| a.tid == *k)))
}
