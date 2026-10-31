//! Sharing, links, cards, devices, servers and sync (notes/api.md Sharing and membership, Sync
//! configuration and status) over membership flows and the sync engine: each sharing call is
//! one membership commit made locally (spec/permissions.md §2), whose deliveries the sync engine
//! carries out; calls that wait for another node are `async` (runtime-agnostic futures).

use crate::error::{Error, Result};
use crate::handle::{LINKS, Locked, MadeLink, Osis, save_servers};
use crate::watch::{Delivery, Filter, Subscription};
use osis_base::{Ak, Role, Tid, Value, WallMs};
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
    /// When this node may not grant: place anyway (the thing is then excluded: members of the
    /// group see its tid, not the thing) instead of failing `Permission`.
    pub place_anyway: bool,
}

/// How a group's members reach a thing through that group (`Osis::reach`, `share_into`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Share {
    /// A tied edge (`share_into`): it goes when the placement goes.
    Tied(Role),
    /// An edge granted by hand (`grant`): it stays when the placement goes.
    Untied(Role),
    /// No edge: placed, but the group's members do not reach the thing through it.
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
    /// label synced (spec/permissions.md §9). An expiring link closes when one of your devices
    /// next syncs after `until`: until then anyone holding the link can still join.
    pub until: Option<WallMs>,
    /// The first redemption ends the link: the link says so (`flags`, spec/wire.md §10), the
    /// redeemer removes the link key in its redemption, and a device of this person finalizes
    /// the link when it sees that (spec/permissions.md §9).
    pub single_use: bool,
    /// Opt-in: the link text carries this device's dialable key and relays (never its lan
    /// secret; spec/permissions.md §9), so a redeemer that shares no server with it reaches it
    /// directly while it is online. Anyone holding the link can dial this device until the link
    /// ends by revocation or expiry, when the key rotates (a single-use link's redemption keeps
    /// it: the redeemer keeps the direct path). Needs this device reachable (a runtime, `Config.peers`); a
    /// database without servers can only make direct links.
    pub direct: bool,
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

/// An invite from a sender with no known connection to this database (spec/sync.md §3, invite
/// requests): nothing it names is fetched or dialed until `accept_invite`. It says nothing about
/// sender or thing: both would be the sender's unverified word (notes/api.md Attribution), and a
/// request never comes from a node known to be connected, so a known name there would be a
/// spoof or a device not seen yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InviteId(osis_base::CommitId);

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
text_type!(
    /// A contact card: a read link to the person's profile (spec/sync.md §3).
    ContactCard, osis_label::ShareLink, osis_label::ShareLink::from_text, "contact card"
);
text_type!(
    /// A recovery card (`osis://card/...`): holds the recovery seed; show or store it, osis
    /// keeps none of it.
    RecoveryCard, osis_label::RecoveryCard, osis_label::RecoveryCard::from_text, "recovery card"
);

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
    ct::Edge { role, until: o.until, invite: o.invite, since: None, tied: None }
}

fn share_of(e: crate::Edge) -> Share {
    if e.tied { Share::Tied(e.role) } else { Share::Untied(e.role) }
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

    /// Persists the ephemeral things among `tids` with their owner chains by a content commit
    /// of their own (notes/ephemeral.md Persistence: a membership operation, or a move, on an
    /// ephemeral thing persists it first); durable ones are left alone.
    fn persist(&self, tids: &[Tid]) -> Result<()> {
        let me = self.me();
        self.engine(|e| {
            let mut m = osis_node::Mutation::new();
            m.act_as(me);
            for t in tids {
                m.persist(*t);
            }
            e.write(m)
        })?;
        Ok(())
    }

    /// Grants `member` `role` on `target` (spec/permissions.md §2): needs admin on the target
    /// (or an invite edge) and the member's `/keys` (a contact card, a shared group, pairing),
    /// else `UnknownActor`. The grant reaches the member's devices through its inbox.
    pub fn grant(&self, target: Tid, member: Tid, role: Role, opts: EdgeOpts) -> Result<()> {
        let (target, member) = (self.resolved(target), self.resolved(member));
        if !self.holds(target) {
            return Err(Error::UnknownThing { tid: target });
        }
        self.persist(&[target])?;
        let done = self.engine(|e| -> Result<_> {
            // unknown, or a key actor (a node, a recovery or link key) whose `/keys` is not held
            if !e.knows(&member) || (e.owner(&member).is_none() && e.get_typed(&member, &ct::KEYS)?.is_none()) {
                return Err(Error::UnknownActor { tid: member });
            }
            // an edge change keeps its tie; a new hand grant is untied
            let tied = e.roster(&target).get(&member).and_then(|x| x.tied).map(flows::tied::tie_ct);
            e.grant(&target, &member, &ct::Edge { tied, ..edge(role, opts) }).map_err(needs_admin)
        })?;
        self.carry(done)
    }

    /// Shares `tid` with the members of `group` at `role` by placing it there (spec/permissions.md
    /// §2): the placement (skipped when the thing is already placed so) and a tied edge of the
    /// group on it, which goes when the placement goes (`Write::unplace`). An existing edge of the
    /// group at `role` or above is kept as it is, tied or not. Needs write on the group and admin
    /// on `tid` (or an invite edge of at least `role`, and no edge of the group yet), else
    /// `Permission` before anything is written, unless `opts.place_anyway` (then `Excluded`).
    pub fn share_into(&self, tid: Tid, group: Tid, role: Role, opts: ShareOpts) -> Result<Share> {
        let (t, g) = (self.resolved(tid), self.resolved(group));
        for x in [t, g] {
            if !self.holds(x) {
                return Err(Error::UnknownThing { tid: x });
            }
        }
        let existing = self.roster(t).get(&g).copied();
        // a tied edge whose placement is gone here is tied again to the new one
        let retie = existing.is_some_and(|x| x.tied) && self.engine(|e| e.tie_dead(&t, &g))?;
        let role = existing.filter(|_| retie).map_or(role, |x| x.role.max(role));
        let grant = retie || existing.is_none_or(|e| e.role < role);
        let may = grant && self.engine(|e| e.may_grant(&t, &g, role));
        if grant && !may && !opts.place_anyway {
            return Err(Error::Permission { tid: t, needs: Role::Admin });
        }
        let placed = self.read(|r| {
            let gs = r.groups_of(t);
            if opts.subgroup { gs.subgroup_of.contains(&g) } else { gs.item_of.contains(&g) }
        });
        if may {
            // durable first, so the placement is too
            self.persist(&[t])?;
        }
        if !placed {
            self.write_with(|w| if opts.subgroup { w.add_subgroup(g, t) } else { w.place(t, g) })?;
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
        let done = self.engine(|e| {
            let tie = match tied {
                true => Some(e.placement(&t, &g, opts.subgroup)?.ok_or_else(|| Error::Invalid(format!("{t} is not placed in {g} here")))?),
                false => None,
            };
            let edge = ct::Edge { role, until: None, invite: None, since: None, tied: tie.map(flows::tied::tie_ct) };
            e.grant(&t, &g, &edge).map_err(needs_admin)
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
        let (g, t) = (self.resolved(group), self.resolved(target));
        if !self.roster(t).contains_key(&g) {
            return Ok(());
        }
        let done = self.engine(|e| match e.may_remove(&t, &g) {
            Some(flows::Untie::SelfRemoval) => Ok(e.demote(&t, &flows::Demotion { member: g, new: None, presync: PreSync::Synced })?),
            Some(flows::Untie::Explicit) => Err(Error::Invalid(format!("this node is an admin of {t}: use demote"))),
            None => Err(Error::Permission { tid: g, needs: Role::Admin }),
        })?;
        self.carry(done)
    }

    /// Per group, how its members reach `tid` through it (spec/permissions.md §2): every group
    /// listing it as an item or subgroup (`Tied`, `Untied` or `Excluded`), and every group with
    /// a tied edge on it that no longer lists it (`placed: false`, until that edge goes).
    pub fn reach(&self, tid: Tid) -> Vec<GroupReach> {
        let t = self.resolved(tid);
        let (gs, roster) = self.read(|r| (r.groups_of(t), r.roster(t)));
        let placed: BTreeSet<Tid> = gs.item_of.into_iter().chain(gs.subgroup_of).collect();
        let mut out: Vec<GroupReach> = placed.iter().map(|g| GroupReach { group: *g, placed: true, share: roster.get(g).copied().map_or(Share::Excluded, share_of) }).collect();
        out.extend(roster.iter().filter(|(g, e)| e.tied && !placed.contains(g)).map(|(g, e)| GroupReach { group: *g, placed: false, share: Share::Tied(e.role) }));
        out
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
        self.sync_now()?;
        let wait = match d.sync {
            WaitForSync::Try(t) => t,
            _ => PRESYNC_WAIT,
        };
        let r = self.groups_synced(groups.clone(), reads.clone(), wait, false).await;
        self.locked(|l| l.sync.end_receipts(&reads));
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

    /// Resolves once every group in `groups` is `Synced` and the receipts-only reads of `reads`
    /// are done (with `deliveries`, also once no inbox blob is unanswered); fails `Unsynced` when one is stranded or has no servers, `Network` after
    /// `wait`.
    fn groups_synced(&self, groups: Vec<Tid>, reads: Vec<Tid>, wait: Duration, deliveries: bool) -> crate::net::Pending<Result<()>> {
        self.wait_until(
            Some(wait),
            Box::new(move |sync, st| {
                if deliveries && sync.deliveries_pending() > 0 {
                    return None;
                }
                let mut bad: Vec<Tid> = groups.iter().copied().filter(|g| st.groups.get(g).is_some_and(|s| matches!(s.state, SyncState::Stranded | SyncState::NoServers))).collect();
                let read = sync.receipts_read(&reads);
                if let Some(Err(b)) = &read {
                    bad.extend(b);
                }
                if !bad.is_empty() {
                    return Some(Err(Error::Unsynced { groups: bad }));
                }
                (read.is_some() && groups.iter().all(|g| st.groups.get(g).is_some_and(|s| s.state == SyncState::Synced))).then_some(Ok(()))
            }),
        )
    }

    /// The edges through which `actor` is a member of `target` (spec/permissions.md §2): the
    /// (thing, member) pairs from `target` down to `actor` of a shortest chain, e.g. `[(target,
    /// K), (K, actor)]` for a link joiner; empty when it is none.
    pub fn member_path(&self, target: Tid, actor: Tid) -> Vec<(Tid, Tid)> {
        let (t, a) = (self.resolved(target), self.resolved(actor));
        self.read(|r| {
            let mut via: BTreeMap<Tid, Tid> = BTreeMap::from([(t, t)]);
            let mut queue = std::collections::VecDeque::from([t]);
            while let Some(x) = queue.pop_front() {
                for m in r.roster(x).into_keys() {
                    if via.contains_key(&m) {
                        continue;
                    }
                    via.insert(m, x);
                    if m == a {
                        let mut path = vec![(x, m)];
                        let mut cur = x;
                        while cur != t {
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
        })
    }

    /// Lowers or removes `member`'s edge on `target` (spec/permissions.md §2, §3, §5): first the
    /// pre-sync of every label the demoted authority wrote under, as `d` says; then the
    /// demotion with this node's frontier and the target's rotation, in one commit.
    ///
    /// A removal follows every way the member reaches `target` (`member_path`) until none is
    /// left; removing a member that reaches it no more writes nothing. A member that joined by
    /// a link made on this device is removed from the link's actor K together with the link key
    /// in one commit (`revoke_joiner`; the joiner may keep the seed, spec/permissions.md §9): the
    /// link stops working for anyone who has not redeemed it, K's other joiners stay. A link
    /// joiner's role cannot be lowered (it could act as the link key), only removed. A member
    /// reaching `target` through another actor (a team, or a link made on another device) is
    /// `Invalid`: demote it there.
    pub async fn demote(&self, target: Tid, member: Tid, to: Lower, d: Demotion) -> Result<()> {
        let (t, m) = (self.resolved(target), self.resolved(member));
        // each round removes one way in; the bound only guards against a roster that never settles
        for _ in 0..16 {
            let path = self.member_path(t, m);
            let via = match (path.as_slice(), to) {
                ([], Lower::Remove) => return Ok(()),
                ([], Lower::To(_)) => return Err(Error::Invalid(format!("{m} is no member of {t}"))),
                ([_], _) => None,
                ([(_, k), (_, _)], _) => Some(*k),
                ([(_, k), ..], _) => return Err(Error::Invalid(format!("{m} reaches {t} through {k}: demote it there"))),
            };
            match via {
                None => self.demote_edge(t, m, to, d).await?,
                Some(k) => {
                    if !self.locked(|x| x.links.get(&k).is_some_and(|l| l.target == t)) {
                        return Err(Error::Invalid(format!("{m} reaches {t} through {k} (a group actor, or a link made on another device): demote or revoke it there")));
                    }
                    if to != Lower::Remove {
                        return Err(Error::Invalid(format!("{m} joined {t} by a link: it can only be removed")));
                    }
                    self.revoke_joiner(k, m, d).await?;
                }
            }
            if to != Lower::Remove {
                return Ok(());
            }
        }
        Err(Error::Invalid(format!("{m} still reaches {t}")))
    }

    async fn demote_edge(&self, t: Tid, m: Tid, to: Lower, d: Demotion) -> Result<()> {
        let new = match to {
            Lower::To(role) => {
                let cur = self.roster(t).get(&m).copied().ok_or(Error::Invalid(format!("{m} is no member of {t}")))?;
                Some(ct::Edge { role, until: cur.until, invite: cur.invite.map(|i| i.min(role)), since: None, tied: self.engine(|e| e.roster(&t).get(&m).and_then(|x| x.tied)).map(flows::tied::tie_ct) })
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
        let servers = self.server_addrs();
        let me = self.me();
        if servers.is_empty() && !opts.direct {
            return Err(Error::Invalid("this database has no servers: a link reaches nobody unless it is direct (LinkOpts.direct)".into()));
        }
        if opts.direct && self.locked(|x| x.sync.own_reach()).is_none() {
            return Err(Error::Invalid("a direct link needs this device reachable: a runtime with Config.peers on".into()));
        }
        self.persist(&[t])?;
        let (mut link, keep, done) = self.engine(|e| e.create_link(&me, &flows::LinkSpec { target: t, role, until: opts.until, servers, peers: Vec::new(), single_use: opts.single_use })).map_err(needs_admin)?;
        // the seed thing in the home group: every device of this person holds it and may
        // finalize the link (spec/permissions.md §9)
        let home = self.home();
        self.write_with(|w| w.place(keep, home))?;
        let l = osis_node::Identity::from_seed(link.seed.clone()).tid();
        self.locked(|x| {
            x.links.insert(link.k, MadeLink { l, target: t, single_use: opts.single_use, direct: opts.direct, ended: false });
            save_links(x)
        })?;
        // K joining the target may rotate this device's reach (the target no longer qualifies,
        // spec/permissions.md §4): the link carries the key it listens with after that
        self.carry(done)?;
        if opts.direct {
            // only the dialable key and relays, never the lan secret (spec/permissions.md §9)
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
        // L must be on K's roster in a view with nothing on K pending: a commit on K waiting
        // for its chain may be (or follow) an earlier redemption that removed L
        self.wait_until(t, Box::new(move |s, _| {
            let e = s.engine_mut();
            (e.roster(&k).contains_key(&l) && e.epochs(&k).is_some_and(|x| x.read.held().next().is_some()) && !pending_on(e, &k)).then_some(Ok(()))
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
        self.wait_until(t, Box::new(move |s, _| {
            let e = s.engine_mut();
            (e.knows(&target) && e.roster(&k).contains_key(&me) && !pending_on(e, &k)).then_some(Ok(()))
        }))
        .await?;
        Ok(target)
    }

    /// Holds a link's key and follows K's label at its servers and at the sharer's device when
    /// the link names it (first contact, spec/permissions.md §9: dialed at the link's dialable
    /// key and relays like a co-reader, for K and the target only, `follow_link_peer`); the key
    /// goes with the guard, and with it the follow unless the redemption went through.
    fn follow_link(&self, link: &osis_label::ShareLink) -> Result<KeyGuard> {
        let l = self.locked(|x| -> Result<Tid> {
            let l = x.engine().hold_key_actor(link.seed.clone())?;
            let peers = link.peers.iter().map(|p| osis_label::Address { url: osis_transport::peer_url(&p.relays), key: p.dialable }).collect();
            x.sync.follow_link_peer(link.k, link.target, peers);
            let acts = x.sync.follow(l, link.k, link.k_label, link.servers.clone());
            self.inner.net.apply(acts);
            Ok(l)
        })?;
        Ok(KeyGuard { db: self.downgrade(), l, link: Some(link.k) })
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
        self.demote_edge(id, l, Lower::Remove, d).await
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

    /// Rotates this device's dialable key when a direct link it made ended (spec/permissions.md
    /// §9): after every change, at open and at the link's expiry. Finalizing links is
    /// node-sync's (`SyncEngine::finalize_links`). `ended` is persisted.
    pub(crate) fn upkeep_links(&self, l: &mut Locked) {
        let mut any = false;
        // a direct link that ended (its key left K, or its edge expired) gave out this device's
        // dialable key: rotate it (spec/permissions.md §9), unless a single-use link ended by its
        // redemption (the one who could use it is now a member and keeps the direct path)
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
            self.inner.net.apply(acts);
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
    /// itself under its own label carrying the person's `/created` and `/keys` as certificates.
    /// Made once; later calls return the same card.
    pub fn contact_card(&self) -> Result<ContactCard> {
        if let Some(b) = self.engine(|e| e.app_record(CONTACT))? {
            return Ok(ContactCard(String::from_utf8(b).map_err(|_| Error::Storage("contact record".into()))?));
        }
        let me = self.me();
        let servers = self.server_addrs();
        let p = self.write_with(|w| {
            let p = w.create(me)?;
            w.make_group(p)?;
            Ok(p)
        })?;
        self.persist(&[p])?;
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

    /// This person's profile thing (notes/std.md): the target of its contact card, made on first
    /// use. The person writes its profile aspects on it (`/name`, `/contact/*`); everyone holding
    /// the card reads them.
    pub fn profile(&self) -> Result<Tid> {
        let card = self.contact_card()?;
        Ok(card.parse()?.target)
    }

    /// The profile thing of a person whose card this database imported, if any.
    pub fn profile_of(&self, person: Tid) -> Result<Option<Tid>> {
        let Some(b) = self.engine(|e| e.app_record(&format!("{PROFILE_OF}{person}")))? else { return Ok(None) };
        let t = String::from_utf8(b).map_err(|_| Error::Storage("profile record".into()))?;
        t.parse().map(Some).map_err(|_| Error::Storage("profile record".into()))
    }

    /// Imports a contact card: reads the profile by the card's link key (bearer use, nothing
    /// written) until the person's `/keys` is here. Returns the person, usable in `grant`. Fails
    /// `Network` after `Config::wait_timeout`; the card's key is forgotten on every outcome.
    pub async fn import_contact(&self, card: &ContactCard) -> Result<Tid> {
        let link = card.parse()?;
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
        let mut key = key;
        // read: the follow stays (bearer use)
        if r.is_ok() {
            key.link = None;
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
        Ok(self.locked(|x| x.sync.invite_requests())?.into_iter().map(InviteId).collect())
    }

    /// Accepts an invite request: its grant applies and its thing's servers are dialed (then
    /// joined as for any invite). `Invalid` when no such request waits (accepted, declined or
    /// expired).
    pub fn accept_invite(&self, id: InviteId) -> Result<()> {
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
        if !self.locked(|x| x.sync.decline_invite(id.0))? {
            return Err(Error::Invalid("no such invite request".into()));
        }
        Ok(())
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
    pub fn servers(&self) -> Vec<ServerAddr> {
        self.server_addrs().into_iter().map(ServerAddr).collect()
    }

    fn server_addrs(&self) -> Vec<osis_label::Address> {
        self.locked(|x| x.sync.config().servers.clone())
    }

    /// Adds a server for new labels (links, `sync`) and keeps a connection to it. The person's
    /// inbox and existing labels on the database's servers (those whose list equals it) move to
    /// the new list: the home label and groups the person owns (directly or through its
    /// actors) that this node administers; not links or the contact card (their text names
    /// their servers), not groups owned by others. A database created without servers becomes
    /// reachable once one is added.
    pub fn add_server(&self, s: &ServerAddr) -> Result<()> {
        let mut v = self.servers();
        if !v.contains(s) {
            v.push(s.clone());
        }
        self.set_servers(v)
    }

    /// Removes a server, from the database's list and the labels that follow it (`add_server`);
    /// a group with members besides the person's devices keeps its last server.
    pub fn remove_server(&self, s: &ServerAddr) -> Result<()> {
        let mut v = self.servers();
        v.retain(|x| x != s);
        self.set_servers(v)
    }

    fn set_servers(&self, v: Vec<ServerAddr>) -> Result<()> {
        let me = self.me();
        self.locked(|x| -> Result<()> {
            let old: BTreeSet<osis_label::Address> = x.sync.config().servers.iter().cloned().collect();
            let new: Vec<osis_label::Address> = v.iter().map(|s| s.0.clone()).collect();
            // links and the contact card name their label's servers in their text: they stay
            let mut fixed: BTreeSet<Tid> = x.links.keys().copied().collect();
            if let Some(card) = x.engine().app_record(CONTACT)?
                && let Ok(l) = ContactCard(String::from_utf8_lossy(&card).into_owned()).parse()
            {
                fixed.insert(l.target);
            }
            // the labels first: a failed commit leaves the list as it was, so a retry matches
            follow_labels(x.engine(), me, &fixed, &old, &new)?;
            save_servers(x.engine(), &v)?;
            x.sync.set_servers(new.clone());
            follow_inbox(x.engine(), me, &old, &new)
        })?;
        self.sync_now()
    }

    /// Makes `group` synced through `servers` (default: this database's): its own label
    /// (spec/sync.md §2); needs admin on the group. A no-op when it has one.
    pub fn sync(&self, group: Tid, servers: &[ServerAddr]) -> Result<()> {
        let g = self.resolved(group);
        if !self.holds(g) {
            return Err(Error::UnknownThing { tid: g });
        }
        if self.role_on(g) != Some(Role::Admin) {
            return Err(Error::Permission { tid: g, needs: Role::Admin });
        }
        self.persist(&[g])?;
        let servers = if servers.is_empty() { self.server_addrs() } else { servers.iter().map(|s| s.0.clone()).collect() };
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
    /// server-less group in scope, `Network` after `timeout` or without a runtime. Also waits
    /// for every queued deposit (any scope): a grant to a recipient whose inbox server refuses
    /// it for now (not registered yet, budget full) keeps it waiting until taken.
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
        self.groups_synced(groups, Vec::new(), timeout, true).await
    }

    /// Asks every server to sync every open label now.
    pub fn sync_now(&self) -> Result<()> {
        self.act(|x| x.sync.sync_now());
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
        self.try_act(|x| Ok(x.sync.import_bundle(&b)?))
    }

    /// Moves `tid` to `owner` (spec/permissions.md §7): a copy with a new tid and the held
    /// history imported, `/was` on the copy, `/moved` on the old thing when this node is its
    /// admin, every current member of the old thing re-granted on the copy; the copy is placed
    /// into `groups` in one more write. Reads and writes through the old tid then reach the copy.
    pub fn move_thing(&self, tid: Tid, owner: Tid, groups: &[Tid]) -> Result<Tid> {
        let tid = self.resolved(tid);
        if !self.holds(owner) {
            return Err(Error::UnknownThing { tid: owner });
        }
        // the thing and the new owner are durable first (the copy's history is)
        self.persist(&[tid, owner])?;
        let (copy, done) = self.engine(|e| e.move_to(&tid, &owner))?;
        self.carry(done)?;
        if !groups.is_empty() {
            self.write_with(|w| {
                for g in groups {
                    w.place(copy, *g)?;
                }
                Ok(())
            })?;
        }
        Ok(copy)
    }
}

fn same_set(s: &[osis_label::Address], old: &BTreeSet<osis_label::Address>) -> bool {
    s.iter().cloned().collect::<BTreeSet<_>>() == *old
}

/// Moves the labels whose server list is `old` (as a set) to `new` (spec/sync.md §2 `/label`
/// servers; the sync engine registers a label's path at a server that does not know it): the
/// home label and the labels of groups in the person's own owner tree this node administers,
/// except `fixed` ones (links, the contact card) and link actors made elsewhere (a key-actor
/// member that is no device of the person). A group with members besides the person and its
/// devices never loses its last server.
fn follow_labels(e: &mut osis_node::Engine, me: Tid, fixed: &BTreeSet<Tid>, old: &BTreeSet<osis_label::Address>, new: &[osis_label::Address]) -> Result<()> {
    let list = Codec::to_value(&new.to_vec());
    let devices: BTreeSet<Tid> = e.roster(&me).into_keys().collect();
    let mine = |e: &osis_node::Engine, g: Tid| {
        let mut cur = g;
        for _ in 0..16 {
            if cur == me {
                return true;
            }
            match e.owner(&cur) {
                Some(o) => cur = o,
                None => return false,
            }
        }
        false
    };
    let mut m = osis_node::Mutation::new();
    let mut any = false;
    for g in e.labeled_groups() {
        if fixed.contains(&g) || e.role_on(&g) != Some(Role::Admin) || !mine(e, g) {
            continue;
        }
        let members: Vec<Tid> = e.roster(&g).into_keys().filter(|x| *x != me && !devices.contains(x)).collect();
        if members.iter().any(|x| e.owner(x).is_none()) || new.is_empty() && !members.is_empty() {
            continue;
        }
        for l in e.group_labels(&g)?.into_iter().filter(|l| !l.replaced && same_set(&l.servers, old)) {
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
    if e.get_typed(&me, &ct::KEYS)?.and_then(|k| k.inbox).is_some_and(|i| same_set(&i.servers, old)) {
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

/// Whether a commit on `k` waits here (pending, not parked: spec/commits.md §4).
fn pending_on(e: &mut osis_node::Engine, k: &Tid) -> bool {
    let ids: Vec<osis_base::CommitId> = e.pending().into_iter().filter(|(_, r)| *r != osis_node::Reason::Parked).map(|(c, _)| c).collect();
    ids.iter().any(|c| e.commit_bytes(c).ok().flatten().and_then(|b| osis_commit::CommitBlob::decode(&b).ok()).is_some_and(|cb| cb.header.aspects.iter().any(|a| a.tid == *k)))
}
