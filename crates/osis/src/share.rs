//! Sharing, links, cards, devices, servers and sync (notes/api.md Sharing and membership, Sync
//! configuration and status) over membership flows and the sync engine: each sharing call is
//! one membership commit made locally (spec/permissions.md §2), whose deliveries the sync engine
//! carries out; calls that wait for another node are `async` (runtime-agnostic futures).

use crate::error::{Error, Result};
use crate::handle::{LINKS, MadeLink, Osis, save_servers};
use crate::watch::{Delivery, Filter, Subscription};
use crate::write::Place;
use osis_core::{Ak, Role, Tid, Value, WallMs};
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
}

/// The role after a demotion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lower {
    To(Role),
    Remove,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkOpts {
    pub until: Option<WallMs>,
    /// The first redemption ends the link: the link says so (`flags`, spec/wire.md §10), the
    /// redeemer removes the link key in its redemption, and this node finalizes the link when it
    /// sees that (spec/permissions.md §9).
    pub single_use: bool,
}

/// A link this node made (`links`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    /// The link's actor K: what `revoke_link` takes.
    pub id: Tid,
    pub target: Tid,
    pub role: Role,
    pub until: Option<WallMs>,
    pub single_use: bool,
}

macro_rules! text_type {
    ($(#[$m:meta])* $n:ident, $check:expr) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $n(pub(crate) String);
        impl std::str::FromStr for $n {
            type Err = Error;
            fn from_str(s: &str) -> Result<$n> {
                let s = s.trim();
                let check: fn(&str) -> Result<()> = $check;
                check(s)?;
                Ok($n(s.to_string()))
            }
        }
        impl std::fmt::Display for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

fn bad(what: &str) -> impl Fn(osis_label::Error) -> Error + '_ {
    move |e| Error::Invalid(format!("{what}: {e}"))
}

text_type!(
    /// A share link (`osis://link/...`): holds the link key's seed.
    ShareLink,
    |s| osis_label::ShareLink::from_text(s).map(|_| ()).map_err(bad("link"))
);
text_type!(
    /// A contact card: a read link to the person's profile (spec/sync.md §3).
    ContactCard,
    |s| osis_label::ShareLink::from_text(s).map(|_| ()).map_err(bad("contact card"))
);
text_type!(
    /// A recovery card (`osis://card/...`): holds the recovery seed; show or store it, osis
    /// keeps none of it.
    RecoveryCard,
    |s| osis_label::RecoveryCard::from_text(s).map(|_| ()).map_err(bad("recovery card"))
);

macro_rules! redacted {
    ($($n:ident),*) => {$(
        impl std::fmt::Debug for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($n), "(..)"))
            }
        }
    )*};
}
redacted!(ShareLink, ContactCard, RecoveryCard);

impl ShareLink {
    pub(crate) fn parse(&self) -> Result<osis_label::ShareLink> {
        osis_label::ShareLink::from_text(&self.0).map_err(bad("link"))
    }
}

impl RecoveryCard {
    pub(crate) fn parse(&self) -> Result<osis_label::RecoveryCard> {
        osis_label::RecoveryCard::from_text(&self.0).map_err(bad("recovery card"))
    }
}

/// A server: transport URL plus its key (`<url>#<base64url key>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServerAddr(pub(crate) osis_label::Address);

impl std::str::FromStr for ServerAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<ServerAddr> {
        osis_label::address_from_text(s.trim()).map(ServerAddr).map_err(bad("server address"))
    }
}

impl std::fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&osis_label::address_to_text(&self.0))
    }
}

impl ServerAddr {
    /// From a transport URL and the server's 32-byte key.
    pub fn new(url: &str, key: [u8; 32]) -> ServerAddr {
        ServerAddr(osis_label::Address { url: url.into(), key })
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
    /// Waiting for a re-seal (spec/permissions.md §3).
    Stranded,
    NoServers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupSync {
    pub state: SyncState,
    pub last_sync: Option<WallMs>,
}

/// Sync status: servers connected and each synced group (`groups`: groups with a label this
/// node reads).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub connected: usize,
    pub groups: BTreeMap<Tid, GroupSync>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncScope {
    All,
    /// The labels holding this thing (the group's own, or those of groups containing it).
    Group(Tid),
}

/// The status from the sync engine's labels (a group with several labels shows the worst).
pub(crate) fn status_of(sync: &mut SyncEngine) -> Status {
    let mut groups: BTreeMap<Tid, GroupSync> = BTreeMap::new();
    for s in sync.label_status() {
        let state = if s.servers == 0 {
            SyncState::NoServers
        } else if s.stranded {
            SyncState::Stranded
        } else if s.open > 0 && s.idle == s.open {
            SyncState::Synced
        } else if s.connected > 0 || s.open > 0 {
            SyncState::Syncing
        } else {
            SyncState::Unreachable
        };
        let last = s.last_sync.map(WallMs);
        groups
            .entry(s.group)
            .and_modify(|g| {
                g.state = g.state.max(state);
                g.last_sync = g.last_sync.max(last);
            })
            .or_insert(GroupSync { state, last_sync: last });
    }
    Status { connected: sync.connected(), groups }
}

fn edge(role: Role, o: EdgeOpts) -> ct::Edge {
    ct::Edge { role, until: o.until, invite: o.invite, since: None }
}

fn needs_admin(e: osis_node::Error) -> Error {
    match e {
        osis_node::Error::Permission { tid } => Error::Permission { tid, needs: Role::Admin },
        e => e.into(),
    }
}

/// Synced groups holding any of `things` (the thing itself or its closure).
fn groups_holding(sync: &mut SyncEngine, status: &Status, things: &BTreeSet<Tid>) -> Vec<Tid> {
    status.groups.keys().copied().filter(|g| things.contains(g) || sync.engine().closure(g).iter().any(|t| things.contains(t))).collect()
}

impl Osis {
    fn resolved(&self, t: Tid) -> Tid {
        self.read(|r| r.resolve(t))
    }

    /// Grants `member` `role` on `target` (spec/permissions.md §2): needs admin on the target
    /// (or an invite edge) and the member's `/keys` (a contact card, a shared group, pairing),
    /// else `UnknownActor`. The grant reaches the member's devices through its inbox.
    pub fn grant(&self, target: Tid, member: Tid, role: Role, opts: EdgeOpts) -> Result<()> {
        let (target, member) = (self.resolved(target), self.resolved(member));
        if !self.knows(target) {
            return Err(Error::UnknownThing { tid: target });
        }
        let done = self.engine(|e| -> Result<_> {
            // unknown, or a key actor (a node, a recovery or link key) whose `/keys` is not held
            if !e.knows(&member) || (e.owner(&member).is_none() && e.get_typed(&member, &ct::KEYS)?.is_none()) {
                return Err(Error::UnknownActor { tid: member });
            }
            e.grant(&target, &member, &edge(role, opts)).map_err(needs_admin)
        })?;
        self.carry(done)
    }

    /// Changes `until`/`invite` of an edge or raises its role (a lower role: `demote`).
    pub fn change_edge(&self, target: Tid, member: Tid, role: Role, opts: EdgeOpts) -> Result<()> {
        let (t, m) = (self.resolved(target), self.resolved(member));
        if let Some(e) = self.roster(t).get(&m)
            && role < e.role
        {
            return Err(Error::Invalid("a lower role is a demotion: use demote".into()));
        }
        self.grant(t, m, role, opts)
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
        let groups = self.locked(|l| {
            let st = l.status.clone();
            groups_holding(&mut l.sync, &st, &things)
        });
        if groups.is_empty() {
            return Ok(PreSync::Synced);
        }
        self.sync_now()?;
        let wait = match d.sync {
            WaitForSync::Try(t) => t,
            _ => PRESYNC_WAIT,
        };
        match (self.groups_synced(groups.clone(), wait, false).await, d.sync) {
            (Ok(()), _) => Ok(PreSync::Synced),
            (Err(_), WaitForSync::Try(_)) => {
                self.engine(|e| e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Unsynced, tids: groups, commit: None, peer: None, detail: "demotion proceeded without its pre-sync".into() }));
                Ok(PreSync::Unsynced { proceed: true })
            }
            (Err(_), _) => Err(Error::Unsynced { groups }),
        }
    }

    /// Resolves once every group in `groups` is `Synced` (with `deliveries`, also once no inbox
    /// blob is unanswered); fails `Unsynced` when one is stranded or has no servers, `Network`
    /// after `wait`.
    fn groups_synced(&self, groups: Vec<Tid>, wait: Duration, deliveries: bool) -> crate::net::Pending<Result<()>> {
        self.wait_until(
            Some(wait),
            Box::new(move |sync, st| {
                if deliveries && sync.deliveries_pending() > 0 {
                    return None;
                }
                let bad: Vec<Tid> = groups.iter().copied().filter(|g| st.groups.get(g).is_some_and(|s| matches!(s.state, SyncState::Stranded | SyncState::NoServers))).collect();
                if !bad.is_empty() {
                    return Some(Err(Error::Unsynced { groups: bad }));
                }
                groups.iter().all(|g| st.groups.get(g).is_some_and(|s| s.state == SyncState::Synced)).then_some(Ok(()))
            }),
        )
    }

    /// Lowers or removes `member`'s edge on `target` (spec/permissions.md §2, §3, §5): first the
    /// pre-sync of every label the demoted authority wrote under, as `d` says; then the
    /// demotion with this node's frontier and the target's rotation, in one commit.
    pub async fn demote(&self, target: Tid, member: Tid, to: Lower, d: Demotion) -> Result<()> {
        let (t, m) = (self.resolved(target), self.resolved(member));
        let new = match to {
            Lower::To(role) => {
                let cur = self.roster(t).get(&m).copied().ok_or(Error::Invalid(format!("{m} is no member of {t}")))?;
                Some(ct::Edge { role, until: cur.until, invite: cur.invite.map(|i| i.min(role)), since: None })
            }
            Lower::Remove => None,
        };
        let things = self.engine(|e| e.presync_scope(&t, &m, new.as_ref()));
        let presync = self.presync(things, d).await?;
        let done = self.engine(|e| e.demote(&t, &flows::Demotion { member: m, new, presync })).map_err(needs_admin)?;
        self.carry(done)
    }

    /// Removes this person's own edge on `target` (a self-removal; no pre-sync).
    pub fn leave(&self, target: Tid) -> Result<()> {
        let t = self.resolved(target);
        let me = self.me();
        let done = self.engine(|e| e.demote(&t, &flows::Demotion { member: me, new: None, presync: PreSync::Synced }))?;
        self.carry(done)
    }

    /// Makes a share link to `target` with `role` (spec/permissions.md §9): its actor K and key L
    /// on this database's servers. Anyone holding the link can redeem it until `until` or
    /// `revoke_link`.
    pub fn make_link(&self, target: Tid, role: Role, opts: LinkOpts) -> Result<ShareLink> {
        let t = self.resolved(target);
        let servers: Vec<osis_label::Address> = self.servers()?.into_iter().map(|s| s.0).collect();
        let me = self.me();
        let (link, done) = self.engine(|e| e.create_link(&me, &flows::LinkSpec { target: t, role, until: opts.until, servers, peers: Vec::new(), single_use: opts.single_use }).map(|(l, _, d)| (l, d))).map_err(needs_admin)?;
        let l = osis_node::Identity::from_seed(link.seed.clone()).tid();
        self.locked(|x| {
            x.links.insert(link.k, MadeLink { l, target: t, single_use: opts.single_use, finalized: false });
        });
        self.save_links()?;
        self.carry(done)?;
        Ok(ShareLink(link.to_text().map_err(bad("link"))?))
    }

    /// Redeems a link (spec/permissions.md §9): reaches its label by the link key, joins its actor
    /// as this person (removing the link key in the same commit when the link is single use), then
    /// waits until the target is here. Returns the target. Each wait fails `Network` after
    /// `Config::wait_timeout`; a used single-use link is refused that way (its key is no member
    /// of K any more). The link key is forgotten on every outcome, a dropped future included.
    pub async fn redeem(&self, link: &ShareLink) -> Result<Tid> {
        let link = link.parse()?;
        let (k, target) = (link.k, link.target);
        let key = self.follow_link(&link)?;
        let l = key.l;
        let t = Some(self.inner.wait_timeout);
        self.wait_until(t, Box::new(move |s, _| {
            let e = s.engine_mut();
            (e.roster(&k).contains_key(&l) && e.epochs(&k).is_some_and(|x| x.read.held().next().is_some())).then_some(Ok(()))
        }))
        .await?;
        let me = self.me();
        let done = self.engine(|e| e.redeem(&link, &me, link.single_use))?;
        drop(key);
        self.carry(done)?;
        self.wait_until(t, Box::new(move |s, _| s.engine().knows(&target).then_some(Ok(())))).await?;
        Ok(target)
    }

    /// Holds a link's key and follows K's label; the key goes with the guard.
    fn follow_link(&self, link: &osis_label::ShareLink) -> Result<KeyGuard> {
        let l = self.locked(|x| -> Result<Tid> {
            let l = x.engine().hold_key_actor(link.seed.clone())?;
            let acts = x.sync.follow(l, link.k, link.k_label, link.servers.clone());
            self.inner.net.apply(acts);
            Ok(l)
        })?;
        Ok(KeyGuard { db: self.downgrade(), l })
    }

    /// The links this node made to `target` that still work.
    pub fn links(&self, target: Tid) -> Vec<LinkInfo> {
        let t = self.resolved(target);
        self.locked(|x| {
            let made: Vec<(Tid, MadeLink)> = x.links.iter().filter(|(_, m)| m.target == t).map(|(k, m)| (*k, *m)).collect();
            made.into_iter()
                .filter_map(|(k, m)| {
                    let e = x.engine().roster(&k).get(&m.l).copied()?;
                    Some(LinkInfo { id: k, target: m.target, role: e.role, until: e.until, single_use: m.single_use })
                })
                .collect()
        })
    }

    /// Ends a link (spec/permissions.md §9): removes its key from K (joiners stay members of K;
    /// one that kept the seed is revoked only with a new link for the others).
    pub async fn revoke_link(&self, id: Tid, d: Demotion) -> Result<()> {
        let l = self.locked(|x| x.links.get(&id).map(|m| m.l)).ok_or(Error::Invalid(format!("no link {id} made here")))?;
        self.demote(id, l, Lower::Remove, d).await
    }

    /// Removes `joiner` from link `id`'s actor K and ends the link in the same commit, under one
    /// rotation (spec/permissions.md §9: a joiner may keep the seed); the other joiners stay
    /// members of K and need a new link to invite anyone. After the pre-sync `demote` does.
    pub async fn revoke_joiner(&self, id: Tid, joiner: Tid, d: Demotion) -> Result<()> {
        let l = self.locked(|x| x.links.get(&id).map(|m| m.l)).ok_or(Error::Invalid(format!("no link {id} made here")))?;
        let m = self.resolved(joiner);
        let things = self.engine(|e| {
            let mut s = e.presync_scope(&id, &m, None);
            s.extend(e.presync_scope(&id, &l, None));
            s
        });
        let presync = self.presync(things, d).await?;
        let done = self.engine(|e| e.revoke_joiner(&id, &l, &m, presync)).map_err(needs_admin)?;
        self.carry(done)
    }

    /// Finalizes single-use links whose redemption removed the link key (spec/permissions.md
    /// §9), on a roster change of K and for every link at open (`all`). The trigger is K's roster
    /// itself, so a restart re-arms it; `finalized` is persisted.
    pub(crate) fn upkeep_links(&self, l: &mut crate::handle::Locked, changed: &BTreeSet<Tid>, all: bool) {
        let me = self.me();
        let due: Vec<(Tid, Tid)> = l.links.iter().filter(|(k, m)| m.single_use && !m.finalized && (all || changed.contains(k))).map(|(k, m)| (*k, m.l)).collect();
        let mut any = false;
        for (k, lk) in due {
            let r = l.engine().roster(&k);
            if r.contains_key(&lk) || !r.keys().any(|x| *x != me) {
                continue;
            }
            match l.engine().finalize_link(&k, &lk).and_then(|d| l.sync.carry_out(d)) {
                Ok(acts) => {
                    self.inner.net.apply(acts);
                    if let Some(m) = l.links.get_mut(&k) {
                        m.finalized = true;
                        any = true;
                    }
                }
                Err(e) => l.engine().report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::BadInput, tids: vec![k], commit: None, peer: None, detail: format!("finalizing a single-use link: {e}") }),
            }
        }
        if any {
            let v = osis_core::cbor::encode(&links_value(&l.links));
            if let Err(e) = l.engine().set_app_record(LINKS, &v) {
                l.engine().report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::BadInput, tids: Vec::new(), commit: None, peer: None, detail: format!("links record: {e}") });
            }
        }
    }

    pub(crate) fn save_links(&self) -> Result<()> {
        let v = self.locked(|x| links_value(&x.links));
        self.engine(|e| e.set_app_record(LINKS, &osis_core::cbor::encode(&v)))?;
        Ok(())
    }

    pub(crate) fn load_links(&self) -> Result<()> {
        let Some(b) = self.engine(|e| e.app_record(LINKS))? else { return Ok(()) };
        let v = osis_core::cbor::decode(&b, &osis_core::cbor::Limits { max_depth: 4, max_bytes: b.len() }).map_err(|_| Error::Storage("links record".into()))?;
        let Value::List(items) = v else { return Err(Error::Storage("links record".into())) };
        let mut links = BTreeMap::new();
        for i in items {
            if let Value::List(f) = i
                && let [Value::Tid(k), Value::Tid(l), Value::Tid(t), Value::Bool(s), rest @ ..] = f.as_slice()
            {
                let finalized = matches!(rest, [Value::Bool(true)]);
                links.insert(*k, MadeLink { l: *l, target: *t, single_use: *s, finalized });
            }
        }
        self.locked(|x| {
            x.links = links;
            self.upkeep_links(x, &BTreeSet::new(), true);
        });
        Ok(())
    }

    /// This person's contact card (spec/sync.md §3): a read link to its profile P, a group of
    /// itself under its own label carrying the person's `/created` and `/keys` as certificates.
    /// Made once; later calls return the same card.
    pub fn contact_card(&self) -> Result<ContactCard> {
        if let Some(b) = self.engine(|e| e.app_record(CONTACT))? {
            return Ok(ContactCard(String::from_utf8(b).map_err(|_| Error::Storage("contact record".into()))?));
        }
        let me = self.me();
        let servers: Vec<osis_label::Address> = self.servers()?.into_iter().map(|s| s.0).collect();
        let p = self.write_with_tid(|w| {
            let p = w.create(me, Place::Unsynced)?;
            w.make_group(p)?;
            Ok(p)
        })?;
        self.locked(|x| -> Result<()> {
            // secrets of its own before the label, as `sync()` does
            let done = x.engine().give_own_secrets(&p)?;
            let acts = x.sync.carry_out(done)?;
            self.inner.net.apply(acts);
            let (_, acts) = x.sync.create_label(&p, servers.clone())?;
            self.inner.net.apply(acts);
            // the person's creation and `/keys` commits, as certificates under P's label
            let e = x.engine();
            let created = Ak::new("/created").map_err(|_| Error::Invalid("ak".into()))?;
            let keys = Ak::new("/keys").map_err(|_| Error::Invalid("ak".into()))?;
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
                self.inner.net.apply(acts);
            }
            Ok(())
        })?;
        let link = self.make_link(p, Role::Read, LinkOpts::default())?;
        let card = ContactCard(link.0);
        self.engine(|e| e.set_app_record(CONTACT, card.0.as_bytes()))?;
        Ok(card)
    }

    /// Imports a contact card: reads the profile by the card's link key (bearer use, nothing
    /// written) until the person's `/keys` is here. Returns the person, usable in `grant`. Fails
    /// `Network` after `Config::wait_timeout`; the card's key is forgotten on every outcome.
    pub async fn import_contact(&self, card: &ContactCard) -> Result<Tid> {
        let link = osis_label::ShareLink::from_text(&card.0).map_err(bad("contact card"))?;
        let p = link.target;
        let key = self.follow_link(&link)?;
        let found = std::sync::Arc::new(std::sync::Mutex::new(None));
        let f2 = found.clone();
        let r = self
            .wait_until(
                Some(self.inner.wait_timeout),
                Box::new(move |s, _| {
                    let e = s.engine_mut();
                    let owner = e.owner(&p)?;
                    e.get_typed(&owner, &ct::KEYS).ok().flatten()?;
                    *crate::watch::lock(&f2) = Some(owner);
                    Some(Ok(()))
                }),
            )
            .await;
        drop(key);
        r?;
        let who = *crate::watch::lock(&found);
        who.ok_or(Error::Invalid("contact card: no person".into()))
    }

    /// The person's devices: nodes with an edge on the person actor.
    pub fn devices(&self) -> Result<Vec<Device>> {
        let me = self.me();
        let node_ak = Ak::new("/node").map_err(|_| Error::Invalid("ak".into()))?;
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
    /// backdate; spec/permissions.md §5.3).
    pub async fn remove_device(&self, node: Tid, d: Demotion) -> Result<()> {
        self.demote(self.me(), node, Lower::Remove, d).await
    }

    /// The servers new labels go to (and kept connected).
    pub fn servers(&self) -> Result<Vec<ServerAddr>> {
        Ok(self.locked(|x| x.sync.config().servers.iter().cloned().map(ServerAddr).collect()))
    }

    /// Adds a server for new labels (links, `sync`) and keeps a connection to it. Labels made
    /// before keep their own server lists.
    pub fn add_server(&self, s: &ServerAddr) -> Result<()> {
        let mut v = self.servers()?;
        if !v.contains(s) {
            v.push(s.clone());
        }
        self.set_servers(v)
    }

    pub fn remove_server(&self, s: &ServerAddr) -> Result<()> {
        let mut v = self.servers()?;
        v.retain(|x| x != s);
        self.set_servers(v)
    }

    fn set_servers(&self, v: Vec<ServerAddr>) -> Result<()> {
        self.locked(|x| -> Result<()> {
            save_servers(x.engine(), &v)?;
            x.sync.set_servers(v.iter().map(|s| s.0.clone()).collect());
            Ok(())
        })?;
        self.sync_now()
    }

    /// Makes `group` synced through `servers` (default: this database's): its own label
    /// (spec/sync.md §2); needs admin on the group. A no-op when it has one.
    pub fn sync(&self, group: Tid, servers: &[ServerAddr]) -> Result<()> {
        let g = self.resolved(group);
        if !self.knows(g) {
            return Err(Error::UnknownThing { tid: g });
        }
        if self.role_on(g) != Some(Role::Admin) {
            return Err(Error::Permission { tid: g, needs: Role::Admin });
        }
        let servers: Vec<osis_label::Address> = if servers.is_empty() { self.servers()?.into_iter().map(|s| s.0).collect() } else { servers.iter().map(|s| s.0.clone()).collect() };
        self.locked(|x| -> Result<()> {
            if x.engine().group_labels(&g)?.iter().any(|l| !l.replaced) {
                return Ok(());
            }
            // the label's keys derive from the group's own secrets from the start, so members
            // granted later verify its whole path (notes/api.md Implementation)
            let done = x.engine().give_own_secrets(&g)?;
            let acts = x.sync.carry_out(done)?;
            self.inner.net.apply(acts);
            let (_, acts) = x.sync.create_label(&g, servers)?;
            self.inner.net.apply(acts);
            Ok(())
        })
    }

    /// Stops syncing `group` under its own labels (marks them replaced without a successor;
    /// the group stays in other synced groups it is placed in).
    pub fn unsync(&self, group: Tid) -> Result<()> {
        let g = self.resolved(group);
        self.engine(|e| -> Result<()> {
            let ls = e.group_labels(&g)?;
            let mut m = osis_node::Mutation::new();
            let mut any = false;
            for l in ls.iter().filter(|l| !l.replaced) {
                any = true;
                let path = vec![osis_crdt::PathSeg::Key(l.id.to_value()), osis_crdt::PathSeg::Field(3)];
                m.op(g, &ct::LABEL, osis_crdt::PathOp { path, op: osis_crdt::Op::Set(Value::Bool(true)) })?;
            }
            if any {
                e.commit(m).map_err(needs_admin)?;
            }
            Ok(())
        })
    }

    /// Sync status now.
    pub fn status(&self) -> Result<Status> {
        Ok(self.locked(|x| status_of(&mut x.sync)))
    }

    /// Calls `f` with the status now (through the dispatcher) and on every change.
    pub fn watch_status(&self, mut f: impl FnMut(&Osis, Status) + Send + 'static) -> Subscription {
        let first = self.locked(|x| status_of(&mut x.sync));
        self.subscribe(Filter::Status, true, move |_| {
            let mut first = Some(first);
            Box::new(move |db, d| match d {
                Delivery::Initial => {
                    if let Some(s) = first.take() {
                        f(db, s)
                    }
                }
                Delivery::Status(s) => f(db, s),
                _ => {}
            })
        })
    }

    /// Resolves once every label in scope finished a pass with nothing outstanding after the
    /// local commits so far (they are at a server); fails `Unsynced` for a stranded or
    /// server-less group in scope, `Network` after `timeout` or without a runtime.
    pub async fn wait_synced(&self, scope: SyncScope, timeout: Duration) -> Result<()> {
        let groups = self.locked(|x| {
            let st = status_of(&mut x.sync);
            match scope {
                SyncScope::All => st.groups.keys().copied().collect::<Vec<_>>(),
                SyncScope::Group(t) => {
                    let t = x.engine().resolve(&t, &t);
                    groups_holding(&mut x.sync, &st, &[t].into_iter().collect())
                }
            }
        });
        if groups.is_empty() {
            return match scope {
                SyncScope::All => Ok(()),
                SyncScope::Group(t) => Err(Error::Unsynced { groups: vec![t] }),
            };
        }
        self.sync_now()?;
        self.groups_synced(groups, timeout, true).await
    }

    /// Asks every server to sync every open label now.
    pub fn sync_now(&self) -> Result<()> {
        self.locked(|x| {
            let acts = x.sync.sync_now();
            self.inner.net.apply(acts);
        });
        Ok(())
    }

    /// Writes a bundle of `groups`' labels (spec/sync.md §11) to `out`.
    pub fn export_bundle(&self, groups: &[Tid], mut out: impl std::io::Write) -> Result<()> {
        let bytes = self.locked(|x| -> Result<Vec<u8>> {
            let mut labels = Vec::new();
            for g in groups {
                let g = x.engine().resolve(g, g);
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
        self.locked(|x| -> Result<()> {
            let acts = x.sync.import_bundle(&b)?;
            self.inner.net.apply(acts);
            Ok(())
        })
    }

    /// Moves `tid` to `owner` (spec/permissions.md §7): a copy with a new tid and the held
    /// history imported, `/was` on the copy, `/moved` on the old thing when this node is its
    /// admin, every current member of the old thing re-granted on the copy; the copy is placed
    /// per `place`. Reads and writes through the old tid then reach the copy.
    pub fn move_thing(&self, tid: Tid, owner: Tid, place: Place) -> Result<Tid> {
        let tid = self.resolved(tid);
        if !self.knows(owner) {
            return Err(Error::UnknownThing { tid: owner });
        }
        let (copy, done) = self.engine(|e| e.move_to(&tid, &owner))?;
        self.carry(done)?;
        let groups = match place {
            Place::In(g) => vec![g],
            Place::InAll(gs) => gs,
            Place::Unsynced => Vec::new(),
        };
        if !groups.is_empty() {
            self.write_with(|w| {
                for g in groups {
                    w.place(copy, g)?;
                }
                Ok(())
            })?;
        }
        Ok(copy)
    }
}

const CONTACT: &str = "contact";

fn links_value(links: &BTreeMap<Tid, MadeLink>) -> Value {
    Value::List(links.iter().map(|(k, m)| Value::List(vec![Value::Tid(*k), Value::Tid(m.l), Value::Tid(m.target), Value::Bool(m.single_use), Value::Bool(m.finalized)])).collect())
}

/// A held link or recovery key, forgotten when the guard goes: every outcome of a waiting call,
/// a dropped future included.
pub(crate) struct KeyGuard {
    pub db: crate::handle::WeakOsis,
    pub l: Tid,
}

impl Drop for KeyGuard {
    fn drop(&mut self) {
        if let Some(db) = self.db.upgrade() {
            db.engine(|e| e.drop_key_actor(&self.l));
        }
    }
}
