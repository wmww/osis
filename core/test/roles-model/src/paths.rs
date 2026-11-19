//! Stated paths and signers as members (notes/write-path-design.md §1-§2, §5,
//! notes/account-membership-design.md §2, §4; not built, not in spec): an oracle of those notes,
//! greenfield, sharing nothing with `joint` (whose authority is a maximum over every path).
//! Findings: notes/path-model-findings.md. README.md, Paths: what is assumed where the notes are
//! open, sizes, how to run.
//!
//! The rule under test.
//! - **Things and edges.** Signers and independent things share one namespace; an edge is
//!   (holder, target) with a role and an optional `until`; record edges stand at the start.
//!   Dependent things are not modelled (a descent of one step is the direct edge).
//! - **Commits.** One signer, a `ts`, the thing written (`on`) and a stated path [A1..Ak]: the
//!   commit uses the edges joining [signer, A1, .., Ak, on] and no other. Kinds: content, an
//!   edge write (setting a holder's edge on `on`; a lowering carries a frontier, a leaf of commit
//!   IDs per thing; it may name the remaining admin it relies on, or carry the mark that lets
//!   its thing go adminless), an addendum (plain content naming a removal and commits it
//!   vouches for), a vouch (the same for role writes: `Vouch`).
//! - **Edges in time.** An edge gives its role at `ts` while its `until` is later; a write
//!   giving no role at its own `ts` (none, or an `until` passed) is a removal.
//! - **Hops.** Consecutive members of [signer, A1..Ak, end] are joined by descent (the record
//!   edges down the mint chain) where the first is a mint ancestor of the second, else by their
//!   direct edge. The end is the thing written, except for an edge write whose path ends at the
//!   holder of the edge it sets: a **self-removal**, needing admin on the holder (a signer
//!   leaving by itself states no hop).
//! - **Walk** (§5.1 along one path). Edge-class commits (edge writes, vouches) in key order
//!   (`ts`, signer, ID), skipping the drop set D. One applies iff every edge of its path gives
//!   admin at its `ts`; a self-removal only lowers. An applied explicit write taking an edge h
//!   from admin, **as restored** (the highest role since the last explicit write on h, values an
//!   `until` or a self-removal took included), to below puts in question every earlier held
//!   edge-class commit whose path holds h, not dropped and not void (`Rules::audit_held`, as the
//!   seeds); those its list does not name (`listed`) join D and the walk restarts from the
//!   earliest. A self-removal audits nothing. D only grows until a pass adds nothing.
//! - **Each lowering judged once, at its key** (`Rules::self_void`; finding 16): nothing is
//!   exempt from a lowering's drops and no entry of its list is read as absent. A lowering (an
//!   explicit edge write giving below admin at its `ts`) is judged the first time a pass reaches
//!   it holding its right (its path giving admin, the last-admin rule passed) and taking its edge
//!   from admin: where its own drops would take its authority (`keeps`: its path's edges read back
//!   along the writes that set them, passing over its own drops) it is **void**; else it applies.
//!   The verdict stands for the rest of the walk: a restart neither re-judges nor re-audits it,
//!   and an applied lowering applies in every later pass unless a later lowering drops it. One
//!   without its right, or taking nothing, has no verdict and is judged by a later pass. D only
//!   grows: nothing is undropped.
//! - **Last admin** (`Rules::last_admin`): an unmarked write taking a **standing** admin edge
//!   (admin, no `until`) of T to anything else applies only where the remaining admin it relies
//!   on is, as the walk stands, a standing admin edge of T other than the one it lowers: the
//!   last edge of its own path where that is one, else the edge of the holder it names.
//! - **Content.** A commit on T with path P is valid iff every edge of P gave write just before
//!   its position (the start of its `ts`) and no applied lowering of an edge of P below write is
//!   ordered after it; else iff such a lowering's list names it, a valid addendum by a writer
//!   of T against such a lowering ordered between them lists it (least fixpoint), or P is
//!   re-granted (every edge gives write in the final state, every `until` counted removed) and
//!   the commit is ordered after the first point P gave write (`Regrant`).
//! - **Trust sets.** A trusted lowering R of edge h seeds D with the held edge-class commits
//!   ordered before R whose path holds h and R's list does not name; a trusted write the
//!   settled walk does not apply is void and loses its seeds, all void ones at once, and the
//!   walk is redone.
//! - **Disputes** (`disputes`): a held lowering of another holder's edge, not trusted, whose
//!   trust changes the reading.
//! - **Leaves.** A node sees a frontier's leaf for a thing only where its view says so
//!   (`View::leaves`); an entry in a leaf it does not see is not listed for it.
//! - **Invites and finalizes.** An edge write without admin on its path applies as an invite
//!   grant where it adds a grant below admin to a holder with none current, within the path's
//!   invite; a finalize ends a grant past its `until`. Neither is explicit: neither audits. A
//!   lowering is judged where it takes its edge down in role or invite (`Rules::any_fall`), and
//!   drops the writes whose need there the edge no longer meets (`need`).
//! - **Purge authors.** A commit states its purge author (an index into [signer, path..]); a
//!   purge request by author P, valid as content along its path, holds the right over the earlier
//!   deltas on its thing naming exactly P where P is on its chain (`purges`).
//! - **Covers.** A compaction snapshot carries content commits; a list naming it names them; a
//!   valid cover's copy of a write shows it whatever the write's own validity (spec/permissions.md
//!   §5.2 Copies, §5.3), so a cover made by a writer not yet holding a removal carries the removed
//!   party's late write for good: the accepted window. `Rules::cover_facts` is the alternative.
//! - **Evidence** (`evidence`): the least set holding a unit's commits, every edge write on an
//!   edge of a held commit's path or on the edge a held lowering names as the admin it relies
//!   on, and the vouches against held removals.
//!
//! `Sim` plays the stolen-node story over that rule (parties, ticks, honest writing and the
//! properties: `Sim::build`, `check`); `rotations` is a small keys layer for A's epochs under a
//! standing dispute.

use crate::{Rng, Role};
use std::collections::{BTreeMap, BTreeSet};

pub type Thing = u8;
pub type Id = usize;
pub type Edge = (Thing, Thing);
pub type Set = BTreeSet<Id>;
pub type Key = (u32, Thing, Id);
pub type Things = BTreeSet<Thing>;
/// An edge's value: its role and its `until`.
pub type Val = (Role, Option<u32>);

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Content,
    Edge {
        holder: Thing,
        role: Role,
        until: Option<u32>,
        frontier: BTreeMap<Thing, Set>,
        /// The holder of the remaining admin edge this write relies on (notes/write-path-design.md
        /// §5, The last admin); read only where its own path's last edge is not one.
        relies: Option<Thing>,
        /// The mark that lets the thing go adminless.
        adminless: bool,
        /// The invite it carries (spec/permissions.md §2), at most its role; an admin edge gives
        /// every invite whatever this says.
        invite: Role,
        /// A finalize: a removal carrying no frontier, ending a grant past its `until`
        /// (spec/permissions.md §2).
        finalize: bool,
    },
    Addendum { removal: Id, list: Set },
    Vouch { removal: Id, list: Set },
    /// A purge request by author (spec/commits.md §5 Purge; notes/write-path-design.md §1, The
    /// purge author): it names the earlier deltas on its thing whose purge author is `author`.
    /// Content-class, judged as a content write along its path.
    Purge { author: Thing },
    /// A compaction snapshot of its thing (spec/commits.md §5 Covered), carrying the content
    /// commits on it that showed at its writer. Content-class, judged as a content write along its
    /// path. A list or addendum naming it names what it carries (an own cover).
    Cover { carries: Set },
}

impl Kind {
    /// An edge write setting `holder`'s edge to `role`, standing, listing nothing.
    pub fn set(holder: Thing, role: Role) -> Kind {
        Kind::Edge { holder, role, until: None, frontier: BTreeMap::new(), relies: None, adminless: false, invite: Role::None, finalize: false }
    }
    /// A finalize of `holder`'s ended grant.
    pub fn finalize(holder: Thing) -> Kind {
        let mut k = Kind::set(holder, Role::None);
        if let Kind::Edge { finalize, .. } = &mut k {
            *finalize = true;
        }
        k
    }
    pub fn inviting(mut self, r: Role) -> Kind {
        if let Kind::Edge { invite, .. } = &mut self {
            *invite = r;
        }
        self
    }
    fn with(mut self, f: impl FnOnce(&mut Option<u32>, &mut BTreeMap<Thing, Set>, &mut Option<Thing>, &mut bool)) -> Kind {
        if let Kind::Edge { until, frontier, relies, adminless, .. } = &mut self {
            f(until, frontier, relies, adminless);
        }
        self
    }
    pub fn until(self, t: u32) -> Kind {
        self.with(|u, _, _, _| *u = Some(t))
    }
    pub fn listing(self, f: BTreeMap<Thing, Set>) -> Kind {
        self.with(|_, l, _, _| *l = f)
    }
    pub fn relying(self, n: Thing) -> Kind {
        self.with(|_, _, r, _| *r = Some(n))
    }
}

#[derive(Clone, Debug)]
pub struct Commit {
    pub signer: Thing,
    pub ts: u32,
    pub path: Vec<Thing>,
    pub on: Thing,
    pub kind: Kind,
    /// The edges the stated path uses (`World::hops`).
    hops: Vec<Edge>,
    /// The path names no thing twice.
    well: bool,
    /// An edge write whose path ends at its holder: a self-removal.
    leave: bool,
    /// The purge author: an index into [signer, path..] (notes/write-path-design.md §1).
    pa: usize,
}

/// How role writes a removal does not list are vouched for (issues/actors-one-mechanism.md,
/// "Role writes of a removed node must be kept on the same terms as its content").
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Vouch {
    /// Nothing vouches for a role write.
    Off,
    /// The simplest reading: a vouch counts when its path gives admin on its thing at its key
    /// in the walk it changes.
    SameWalk,
    /// A vouch counts when its path gives admin on its thing at its key in the walk with no
    /// vouch counting.
    BaseWalk,
}

/// Where a re-granted path's writes count from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Regrant {
    /// spec/permissions.md §5.2: the first point the settled walk gave the role.
    FirstApplied,
    /// notes/account-membership-design.md §1 (the collateral grantee): the first chained grant
    /// of each edge (spec/permissions.md §4 Chained writes), dropped or not.
    FirstChained,
}

/// What a lowering of an admin edge must leave (notes/write-path-design.md §5, The last admin).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LastAdmin {
    Off,
    /// Control (the first round's reading): a lowering from admin that would leave its target no
    /// admin edge alive, of all the walk holds, does not apply unless marked.
    AnyEdge,
    /// The rule: the remaining admin it relies on (its path's last edge, else the one it names)
    /// is a standing admin edge (admin, no `until`) other than the lowered one.
    Named,
    /// Control: as `Named`, a timed admin edge alive at the write counting as standing.
    NamedTimed,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rules {
    pub vouch: Vouch,
    pub regrant: Regrant,
    /// Control (notes/write-path-design.md §1, Rejected): a lowering never puts in question the
    /// grants its own path rests on, read from the held writes, closed (`chain`).
    pub exempt_chain: bool,
    pub last_admin: LastAdmin,
    /// An addendum vouches for no commit of its own signer (spec/permissions.md §5.2 Addenda
    /// asks only that its writer holds write on the thing, by any path).
    pub no_own_addendum: bool,
    /// A vouch counts for no commit of its own signer.
    pub no_own_vouch: bool,
    /// A node sees a frontier's leaf for every thing an edge write it holds as evidence is on,
    /// besides the things it syncs (finding 5).
    pub evidence_leaves: bool,
    /// Honest writing in `Sim` (a policy, not a judging rule): the state-based rule, writing
    /// whenever the node's own walk shows an owed commit it could write named by nothing of its
    /// own that counts; false, a node answers only the first time its walk applies a removal.
    pub rewrite: bool,
    /// A self-removal of edge h is put in question by a lowering of h like a write through h
    /// (finding 14): else the removed node's backdated leave, which no audit reaches, voids its
    /// own role writes ordered after it.
    pub leave_in_question: bool,
    /// A lowering whose own drops would take its authority is void: it does not apply and drops
    /// nothing (notes/write-path-design.md §1). False (control `-no-void`): it applies and drops.
    pub self_void: bool,
    /// Reading of the audit: a lowering puts in
    /// question the held writes before it resting on its edge, as a trusted write's seeds do, in
    /// place of the applied ones.
    pub audit_held: bool,
    /// Honest writing in `Sim` (a policy, not a judging rule): a remover and a voucher name what
    /// they had received in the order received, leaving out a role write with which their own
    /// walk no longer applies the removal.
    pub stands: bool,
    /// Control of `stands`: the writer keeps the role writes in key order, not in the order it
    /// received them.
    pub key_order: bool,
    /// An invite grant needs its level as an invite on its path's last edge (spec/permissions.md
    /// §2, along one path: notes/write-path-design.md §1, Edge writes). False (control
    /// `-invite-role`): a role there suffices, so any writer grants.
    pub invite_check: bool,
    /// A lowering is judged, and audits, when it takes its edge as restored down in role or in
    /// invite, dropping the writes whose need the edge no longer meets (an invite grant falls with
    /// a writer's edge). False (control `-admin-falls`): only a fall from admin is judged.
    pub any_fall: bool,
    /// A purge request holds the author right over a delta only where its own chain ([signer,
    /// path..]) holds the delta's purge author (notes/write-path-design.md §1, What a purger must
    /// hold). False (control `-purge-any-path`): its path giving write on the thing suffices.
    pub purge_chain: bool,
    /// A request by author matches the deltas naming exactly that purge author. False (control
    /// `-purge-contains`): every delta whose chain holds it.
    pub purge_exact: bool,
    /// The variant `-facts`, not the design: a carried write is judged by its own facts (signer,
    /// `ts`, path, ID), a valid cover only standing in for its body, which closes the window a
    /// cover by a writer not yet holding a removal opens but makes every snapshot state those
    /// facts per carried commit. False (the rule, spec/permissions.md §5.2 Copies, §5.3): a valid
    /// cover's copy of a write shows it whatever the write's own validity.
    pub cover_facts: bool,
}

impl Rules {
    /// The first round's reading of the notes, simplest: the findings are its failures.
    pub fn design() -> Rules {
        Rules {
            vouch: Vouch::Off,
            regrant: Regrant::FirstApplied,
            exempt_chain: false,
            last_admin: LastAdmin::AnyEdge,
            no_own_addendum: false,
            no_own_vouch: false,
            evidence_leaves: false,
            rewrite: false,
            leave_in_question: false,
            self_void: false,
            audit_held: false,
            stands: false,
            key_order: false,
            invite_check: true,
            any_fall: true,
            purge_chain: true,
            purge_exact: true,
            cover_facts: false,
        }
    }
    /// The design: every fix the notes state, a removal judged in the world its list makes
    /// (notes/write-path-design.md §1) included.
    pub fn fixed() -> Rules {
        Rules {
            vouch: Vouch::BaseWalk,
            regrant: Regrant::FirstChained,
            exempt_chain: false,
            last_admin: LastAdmin::Named,
            no_own_addendum: true,
            no_own_vouch: true,
            evidence_leaves: true,
            rewrite: true,
            leave_in_question: true,
            self_void: true,
            audit_held: true,
            stands: true,
            key_order: false,
            invite_check: true,
            any_fall: true,
            purge_chain: true,
            purge_exact: true,
            cover_facts: false,
        }
    }
}

/// The role a value gives at `ts`.
pub fn alive(v: Val, ts: u32) -> Role {
    if v.1.is_some_and(|u| u <= ts) {
        Role::None
    } else {
        v.0
    }
}

/// A standing admin edge's value: admin, no `until` (`timed`: or an `until` later than `ts`).
fn standing(v: Option<Val>, ts: u32, timed: bool) -> bool {
    v.is_some_and(|v| v.0 == Role::Admin && if timed { alive(v, ts) == Role::Admin } else { v.1.is_none() })
}

#[derive(Clone, Debug, Default)]
pub struct World {
    pub records: Vec<Edge>,
    pub commits: Vec<Commit>,
}

impl World {
    /// Record edges, each admin.
    pub fn new(records: &[Edge]) -> World {
        World { records: records.to_vec(), commits: vec![] }
    }
    /// A commit; its hops are read from its stated path once, here (`World::hops`).
    pub fn push(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, kind: Kind) -> Id {
        let mut all = vec![signer];
        all.extend(path);
        // the path's end decides the class: an edge write whose path ends at the holder is a
        // self-removal; any other ends at the thing written
        let leave = matches!(&kind, Kind::Edge { holder, .. } if all.last() == Some(holder));
        if !leave {
            all.push(on);
        }
        let well = all.iter().collect::<BTreeSet<_>>().len() == all.len();
        let hops = if well { all.windows(2).flat_map(|p| self.joins(p[0], p[1])).collect() } else { vec![] };
        self.commits.push(Commit { signer, ts, path: path.to_vec(), on, kind, hops, well, leave, pa: 0 });
        self.commits.len() - 1
    }
    /// The mint admin of `t`: the holder of its record edge.
    fn mint_of(&self, t: Thing) -> Option<Thing> {
        self.records.iter().find(|e| e.1 == t).map(|e| e.0)
    }
    /// The edges joining consecutive path members `p`, `q`: by descent (the record edges down the
    /// mint chain) where `p` is a mint ancestor of `q`, else their direct edge.
    fn joins(&self, p: Thing, q: Thing) -> Vec<Edge> {
        let mut down = vec![];
        let mut t = q;
        while let Some(m) = self.mint_of(t) {
            down.push((m, t));
            if m == p {
                down.reverse();
                return down;
            }
            if down.len() > self.records.len() {
                break;
            }
            t = m;
        }
        vec![(p, q)]
    }
    pub fn content(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing) -> Id {
        self.push(signer, ts, path, on, Kind::Content)
    }
    /// Content stating `ix` (into [signer, path..]) as its purge author.
    pub fn content_as(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, ix: usize) -> Id {
        let i = self.content(signer, ts, path, on);
        self.authored(i, ix);
        i
    }
    pub fn authored(&mut self, i: Id, ix: usize) {
        assert!(ix <= self.commits[i].path.len(), "a purge author index past the path is bad input");
        self.commits[i].pa = ix;
    }
    /// A purge request by `author` on `on`, along `path`.
    pub fn purge(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, author: Thing) -> Id {
        self.push(signer, ts, path, on, Kind::Purge { author })
    }
    /// [signer, path..]: the things a commit acts as.
    pub fn chain(&self, i: Id) -> Vec<Thing> {
        let c = &self.commits[i];
        std::iter::once(c.signer).chain(c.path.iter().copied()).collect()
    }
    /// The thing a commit names as its purge author.
    pub fn purge_author(&self, i: Id) -> Thing {
        self.chain(i)[self.commits[i].pa]
    }
    /// A frontier listing `ids`, cut per thing.
    pub fn cut(&self, ids: &[Id]) -> BTreeMap<Thing, Set> {
        let mut f: BTreeMap<Thing, Set> = BTreeMap::new();
        for &i in ids {
            f.entry(self.commits[i].on).or_default().insert(i);
        }
        f
    }
    /// An edge write setting `holder`'s edge on `on`, standing; `frontier` is cut per thing.
    pub fn edge(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, holder: Thing, role: Role, frontier: &[Id]) -> Id {
        let f = self.cut(frontier);
        self.push(signer, ts, path, on, Kind::set(holder, role).listing(f))
    }
    pub fn addendum(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, removal: Id, list: &[Id]) -> Id {
        self.push(signer, ts, path, on, Kind::Addendum { removal, list: list.iter().copied().collect() })
    }
    pub fn vouch(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, removal: Id, list: &[Id]) -> Id {
        self.push(signer, ts, path, on, Kind::Vouch { removal, list: list.iter().copied().collect() })
    }
    pub fn edit(&mut self, i: Id, f: impl FnOnce(Kind) -> Kind) {
        let k = std::mem::replace(&mut self.commits[i].kind, Kind::Content);
        self.commits[i].kind = f(k);
    }
    pub fn mark_adminless(&mut self, i: Id) {
        self.edit(i, |k| k.with(|_, _, _, a| *a = true));
    }
    pub fn set_until(&mut self, i: Id, t: u32) {
        self.edit(i, |k| k.until(t));
    }
    /// Names `holder` as the remaining admin edge write `i` relies on.
    pub fn rely(&mut self, i: Id, holder: Thing) {
        self.edit(i, |k| k.relying(holder));
    }
    pub fn key(&self, i: Id) -> Key {
        (self.commits[i].ts, self.commits[i].signer, i)
    }
    /// A content-class commit's position: the start of its `ts`.
    pub fn pos(&self, i: Id) -> Key {
        (self.commits[i].ts, 0, 0)
    }
    /// The edges a commit's stated path uses; none for a path naming a thing twice (bad input).
    pub fn hops(&self, i: Id) -> &[Edge] {
        &self.commits[i].hops
    }
    /// A path naming no thing twice (else bad input: the commit applies nowhere).
    pub fn well(&self, i: Id) -> bool {
        self.commits[i].well
    }
    /// A self-removal: an edge write whose stated path ends at the holder of the edge it sets.
    pub fn leave(&self, i: Id) -> bool {
        self.commits[i].leave
    }
    pub fn edge_class(&self, i: Id) -> bool {
        matches!(self.commits[i].kind, Kind::Edge { .. } | Kind::Vouch { .. })
    }
    /// The edge an edge write sets.
    pub fn sets(&self, i: Id) -> Option<Edge> {
        match &self.commits[i].kind {
            Kind::Edge { holder, .. } => Some((*holder, self.commits[i].on)),
            _ => None,
        }
    }
    /// An edge write setting its edge to below admin at its own `ts`, but a finalize (which ends
    /// a grant already ended).
    pub fn lowers(&self, i: Id) -> Option<Edge> {
        match &self.commits[i].kind {
            Kind::Edge { holder, role, until, finalize: false, .. } if alive((*role, *until), self.commits[i].ts) < Role::Admin => Some((*holder, self.commits[i].on)),
            _ => None,
        }
    }
    fn in_frontier(&self, r: Id, j: Id) -> bool {
        match &self.commits[r].kind {
            Kind::Edge { frontier, .. } => frontier.get(&self.commits[j].on).is_some_and(|l| l.iter().any(|&c| self.names(c, j))),
            _ => false,
        }
    }
    /// A list entry `c` names commit `j`: it is `j`, or a cover carrying `j`.
    pub fn names(&self, c: Id, j: Id) -> bool {
        c == j || matches!(&self.commits[c].kind, Kind::Cover { carries } if carries.contains(&j))
    }
    /// The honest frontier of a lowering of `edge`: every commit resting on it (through it, or a
    /// self-removal of it) that `received`.
    pub fn through(&self, edge: Edge, received: impl Fn(Id) -> bool) -> Vec<Id> {
        (0..self.commits.len()).filter(|&i| received(i) && (self.hops(i).contains(&edge) || (self.leave(i) && self.sets(i) == Some(edge)))).collect()
    }
}

/// What a node judges from: the commits it holds, the frontier leaves it sees (None: every
/// leaf), its trust set.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct View {
    pub held: Set,
    pub leaves: Option<Things>,
    pub trust: Set,
}

impl View {
    pub fn all(w: &World) -> View {
        View { held: (0..w.commits.len()).collect(), leaves: None, trust: Set::new() }
    }
    pub fn trusting(mut self, t: &[Id]) -> View {
        self.trust = t.iter().copied().collect();
        self
    }
    pub fn trusting_also(mut self, r: Id) -> View {
        self.trust.insert(r);
        self
    }
    pub fn without(mut self, drop: &[Id]) -> View {
        for i in drop {
            self.held.remove(i);
        }
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reading {
    /// Edge-class commits the settled walk applies.
    pub applied: Set,
    /// Applied edge writes that lowered their edge.
    pub lowered: Set,
    /// Valid content-class commits.
    pub valid: Set,
    /// Held content a valid purge request holding the right over it names.
    pub purged: Set,
    /// Writes shown only by a valid cover's copy (none under `Rules::cover_facts`).
    pub copied: Set,
    /// Final roles, every `until` counted removed.
    pub roles: BTreeMap<Edge, Role>,
    /// The settled walk's edge values, and the first walk's (no vouch counting).
    pub state: BTreeMap<Edge, Val>,
    pub first: BTreeMap<Edge, Val>,
    /// Vouches counting (applied in the first walk after their removal), addenda vouching
    /// (valid, their writer holding write at their key).
    pub counting: Set,
    pub vouching: Set,
    pub dropped: Set,
    /// What dropped each dropped commit: the lowering whose audit did, or the trusted write
    /// whose seeds did.
    pub dropper: BTreeMap<Id, Id>,
    /// Trusted writes the settled walk does not apply.
    pub void: Set,
    /// Lowerings judged void (their own drops would take their authority) and not dropped later.
    pub voided: Set,
    /// Dropped commits whose drop the reading does not justify: the dropper is not applied (or,
    /// for a seed, not trusted and applied), is no explicit lowering ordered after the commit, the
    /// commit does not rest on the edge it lowers, or its list names the commit. Checked from the
    /// reading alone (`unjustified`), apart from how the walk reached it.
    pub stray: Set,
    /// Restarts (one per applying lowering that dropped something, and one per round of void
    /// trusted writes), passes walked, edge-class commits visited from each pass's restart point
    /// on, and setters read by the void checks (`keeps`), over the whole reading.
    pub rounds: u32,
    pub passes: u64,
    pub walked: u64,
    pub checked: u64,
    /// The vouch iteration did not settle (`Vouch::SameWalk`).
    pub circle: bool,
}

impl Reading {
    pub fn role(&self, holder: Thing, target: Thing) -> Role {
        self.roles.get(&(holder, target)).copied().unwrap_or(Role::None)
    }
    /// A commit shows: valid content, or an applied edge-class commit.
    pub fn shows(&self, i: Id) -> bool {
        self.valid.contains(&i) || self.applied.contains(&i) || self.copied.contains(&i)
    }
}

#[derive(Clone, Debug)]
struct Low {
    id: Id,
    /// An explicit write (it audits, and cuts the content through its edge before it).
    explicit: bool,
    edge: Edge,
    before: Role,
    after: Role,
}

#[derive(Default)]
struct Pass {
    state: BTreeMap<Edge, Val>,
    /// The edge as restored: the highest role each edge held since the last explicit write on it
    /// (values an `until` or a self-removal took included).
    restored: BTreeMap<Edge, Role>,
    /// Each edge's invite field, and its invite as restored (as `restored`, of `invite_at`).
    inv: BTreeMap<Edge, Role>,
    rinv: BTreeMap<Edge, Role>,
    hist: BTreeMap<Edge, Vec<(Key, Val)>>,
    applied: Vec<Id>,
    /// The applied invite grants (attributed to invite, not to admin: spec/permissions.md §5.1
    /// step 3, admin before invite).
    invited: Set,
    lows: Vec<Low>,
}

impl Pass {
    fn at(&self, e: Edge, ts: u32) -> Role {
        self.state.get(&e).map_or(Role::None, |&v| alive(v, ts))
    }
    /// The invite edge `e` gives at `ts`: every invite where it gives admin, else its invite
    /// field, at most its role.
    fn invite_at(&self, e: Edge, ts: u32) -> Role {
        give_invite(self.at(e, ts), self.inv.get(&e).copied().unwrap_or(Role::None))
    }
}

/// The invite a value gives: every invite at admin, else its field at most its role.
fn give_invite(role: Role, field: Role) -> Role {
    if role == Role::Admin {
        Role::Admin
    } else {
        field.min(role)
    }
}

/// What a write needs of one edge of its path: a role there, or (the last edge of an invite
/// grant's path) an invite there.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Need {
    Role(Role),
    Invite(Role),
}

impl Need {
    fn met(self, role: Role, invite: Role) -> bool {
        match self {
            Need::Role(r) => role >= r,
            Need::Invite(r) => invite >= r,
        }
    }
}

/// An edge write adding a grant below admin (no self-removal, no finalize): one that may apply
/// as an invite grant. Its level is its role (its invite is at most its role).
fn invite_grant(w: &World, i: Id) -> Option<Role> {
    let c = &w.commits[i];
    match &c.kind {
        Kind::Edge { role, until, invite, finalize: false, .. } if !c.leave && *invite <= *role && alive((*role, *until), c.ts) > Role::None && *role < Role::Admin => Some(*role),
        _ => None,
    }
}

/// What write `i` needs of edge `e` (where its path holds `e`; a self-removal of `e` needs admin
/// there): admin, unless it is an invite grant (`as_invite`: applied as one, or, for a held write
/// this pass did not apply, one that may), which needs its level as a role on its path's edges
/// before the last and as an invite on the last (`Rules::invite_check`; else as a role there too).
fn need(w: &World, rules: &Rules, i: Id, e: Edge, as_invite: bool) -> Need {
    let hops = w.hops(i);
    match (as_invite, invite_grant(w, i)) {
        (true, Some(r)) if rules.invite_check && hops.last() == Some(&e) => Need::Invite(r),
        (true, Some(r)) => Need::Role(r),
        _ if matches!(w.commits[i].kind, Kind::Edge { finalize: true, .. }) => Need::Role(Role::Write),
        _ => Need::Role(Role::Admin),
    }
}

struct Walk {
    pass: Pass,
    dropped: Set,
    dropper: BTreeMap<Id, Id>,
    voided: Set,
    rounds: u32,
    passes: u64,
    walked: u64,
    checked: u64,
}

type Vouched = BTreeSet<(Id, Id)>;

/// R's list names `j`: its frontier, in a leaf the node sees, or a counting vouch against it.
fn listed(w: &World, v: &View, vouched: &Vouched, r: Id, j: Id) -> bool {
    let seen = v.leaves.as_ref().is_none_or(|l| l.contains(&w.commits[j].on));
    (seen && w.in_frontier(r, j)) || vouched.contains(&(r, j))
}

/// Control `exempt_chain`: the grants R's own authority rests on, as the held writes give them:
/// those giving admin on an edge of its path, and so on along their paths.
fn chain(w: &World, held: &Set, r: Id) -> Set {
    let mut edges: BTreeSet<Edge> = w.hops(r).iter().copied().collect();
    let mut out = Set::new();
    loop {
        let gives = |j: Id| matches!(&w.commits[j].kind, Kind::Edge { role: Role::Admin, .. });
        let more: Vec<Id> = held.iter().copied().filter(|&j| !out.contains(&j) && w.key(j) < w.key(r) && gives(j) && w.sets(j).is_some_and(|e| edges.contains(&e))).collect();
        if more.is_empty() {
            return out;
        }
        for j in more {
            edges.extend(w.hops(j));
            out.insert(j);
        }
    }
}

/// Whether a lowering of edge `e` puts commit `j` in question: its path holds `e`, or (with
/// `leave_in_question`) it is a self-removal of `e`.
fn rests_on(w: &World, rules: &Rules, j: Id, e: Edge) -> bool {
    w.hops(j).contains(&e) || (rules.leave_in_question && w.leave(j) && w.sets(j) == Some(e))
}

fn order(w: &World, held: &Set) -> Vec<Id> {
    let mut o: Vec<Id> = held.iter().copied().filter(|&i| w.edge_class(i)).collect();
    o.sort_by_key(|&i| w.key(i));
    o
}

/// Whether the last-admin rule refuses edge write `i` setting `e` to `new` against `p`.
fn refused(w: &World, rules: &Rules, p: &Pass, i: Id, e: Edge, new: Val) -> bool {
    let c = &w.commits[i];
    let Kind::Edge { relies, adminless, .. } = &c.kind else { return false };
    if *adminless {
        return false;
    }
    let old = p.state.get(&e).copied();
    match rules.last_admin {
        LastAdmin::Off => false,
        LastAdmin::AnyEdge => {
            p.at(e, c.ts) == Role::Admin && alive(new, c.ts) < Role::Admin && !p.state.keys().any(|&k| k.1 == c.on && k != e && p.at(k, c.ts) == Role::Admin)
        }
        LastAdmin::Named | LastAdmin::NamedTimed => {
            let timed = rules.last_admin == LastAdmin::NamedTimed;
            if !standing(old, c.ts, timed) || standing(Some(new), c.ts, timed) {
                return false;
            }
            let ok = |x: Edge| x != e && standing(p.state.get(&x).copied(), c.ts, timed);
            let last = (*c.path.last().unwrap_or(&c.signer), c.on);
            !(ok(last) || relies.is_some_and(|n| ok((n, c.on))))
        }
    }
}

/// A lowering's verdict, given the first time a pass reaches it holding the right (its path
/// giving admin, the last-admin rule passed) and taking its edge from admin, as restored, to
/// below; kept for the rest of the walk. One that does not hold the right, or takes nothing (its
/// edge below admin already), has no verdict and is walked like any write: a restart reaching it
/// judges it again.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Verdict {
    Applied,
    /// Its own drops would take its authority: it does not apply and drops nothing.
    Void,
}

/// Whether write `i`, applied in `p`, still holds the right its path needs at its key once the
/// writes `gone` names are dropped: each edge of its path is read back along the applied writes
/// setting it before `i`, latest first, skipping those gone and grants that do not keep in turn;
/// the first left decides (a lowering or a self-removal as it stands), a record edge at the
/// bottom. No later write is read and nothing is walked again: the cost is the setters read.
fn keeps(w: &World, p: &Pass, gone: &dyn Fn(Id) -> bool, i: Id, memo: &mut BTreeMap<Id, bool>, checked: &mut u64) -> bool {
    if let Some(&k) = memo.get(&i) {
        return k;
    }
    let (key, ts) = (w.key(i), w.commits[i].ts);
    let mut ok = true;
    for &e in w.hops(i) {
        let mut admin = None;
        for &(k, v) in p.hist.get(&e).into_iter().flatten().rev().filter(|x| x.0 < key) {
            *checked += 1;
            let j = k.2;
            if gone(j) {
                continue;
            }
            if w.lowers(j).is_some() || w.leave(j) || keeps(w, p, gone, j, memo, checked) {
                admin = Some(alive(v, ts) == Role::Admin);
                break;
            }
        }
        if !admin.unwrap_or_else(|| w.records.contains(&e)) {
            ok = false;
            break;
        }
    }
    memo.insert(i, ok);
    ok
}

/// The walk from the seeds `d0` (notes/write-path-design.md §1): edge-class commits in key
/// order, skipping D. A lowering is judged the first time a pass reaches it holding its right and
/// taking its edge from admin (`Verdict`), and keeps that verdict: in every later pass an applied
/// one applies unjudged and unaudited, a void one is skipped. An applied lowering whose audit drops something adds its drops to D and restarts
/// the walk from the earliest of them, once; the commits before that point replay unchanged and
/// are not counted in `walked`.
fn walk(w: &World, rules: &Rules, v: &View, d0: &Set, vouched: &Vouched) -> Walk {
    let order = order(w, &v.held);
    let pos: BTreeMap<Id, usize> = order.iter().enumerate().map(|(k, &i)| (i, k)).collect();
    let mut dropped = d0.clone();
    let mut dropper = BTreeMap::new();
    let mut verdict: BTreeMap<Id, Verdict> = BTreeMap::new();
    let (mut rounds, mut passes, mut walked, mut checked, mut from) = (0, 0, 0, 0, 0);
    loop {
        passes += 1;
        let mut p = Pass::default();
        for &e in &w.records {
            p.state.insert(e, (Role::Admin, None));
            p.restored.insert(e, Role::Admin);
            p.rinv.insert(e, Role::Admin);
        }
        let mut restart = None;
        for (k, &i) in order.iter().enumerate() {
            if dropped.contains(&i) {
                continue;
            }
            if k >= from {
                walked += 1;
            }
            let c = &w.commits[i];
            let lowering = w.lowers(i).is_some() && !w.leave(i);
            let judged = if lowering { verdict.get(&i).copied() } else { None };
            // how it applies: by admin along its path (or its verdict), as an invite grant, or as
            // a finalize (spec/permissions.md §2, along its stated path)
            let mut as_invite = false;
            let mut as_finalize = false;
            match judged {
                // applied for good where it lowers; where its edge as restored in this pass is below
                // its value, in role or invite, it would raise the edge: it applies there only as
                // any write does, by admin along its path (finding 27)
                Some(Verdict::Applied) => {
                    if let Kind::Edge { holder, role, until, invite, .. } = &c.kind {
                        let e = (*holder, c.on);
                        let after = alive((*role, *until), c.ts);
                        let raises = after > p.restored.get(&e).copied().unwrap_or(Role::None).max(p.at(e, c.ts))
                            || give_invite(after, *invite) > p.rinv.get(&e).copied().unwrap_or(Role::None).max(p.invite_at(e, c.ts));
                        if raises && !w.hops(i).iter().all(|&h| p.at(h, c.ts) == Role::Admin) {
                            continue;
                        }
                    }
                }
                Some(Verdict::Void) => continue,
                None => {
                    if !w.well(i) {
                        continue;
                    }
                    let hops = w.hops(i);
                    let path_role = hops.iter().map(|&e| p.at(e, c.ts)).min().unwrap_or(Role::Admin);
                    match &c.kind {
                        Kind::Edge { holder, finalize: true, .. } => {
                            // it ends a grant past its `until`, by a writer holding a role at
                            // least the grant's; else it applies nothing
                            let old = p.state.get(&(*holder, c.on)).copied();
                            let ended = old.is_some_and(|v| v.0 > Role::None && v.1.is_some_and(|u| u <= c.ts));
                            if !(ended && path_role >= old.map_or(Role::None, |v| v.0).max(Role::Write)) {
                                continue;
                            }
                            as_finalize = true;
                        }
                        _ if path_role == Role::Admin => {}
                        Kind::Edge { holder, .. } => {
                            // an invite grant: a holder with no current grant, its level within
                            // the path's invite (roles before the last edge, the last's invite)
                            let Some(lvl) = invite_grant(w, i) else { continue };
                            let (last, before) = hops.split_last().expect("a grant states a hop");
                            let gives = if rules.invite_check { p.invite_at(*last, c.ts) } else { p.at(*last, c.ts) };
                            if p.at((*holder, c.on), c.ts) > Role::None || !before.iter().all(|&e| p.at(e, c.ts) >= lvl) || gives < lvl {
                                continue;
                            }
                            as_invite = true;
                        }
                        _ => continue,
                    }
                }
            }
            let Kind::Edge { holder, role, until, invite, .. } = &c.kind else {
                p.applied.push(i);
                continue;
            };
            let e = (*holder, c.on);
            let new = (*role, *until);
            let leave = w.leave(i);
            // an explicit write: attributed to admin (spec/permissions.md §5.1 step 2); a
            // self-removal, an invite grant and a finalize are not, and audit nothing
            let explicit = !leave && !as_invite && !as_finalize;
            if judged.is_none() && !as_invite && !as_finalize && refused(w, rules, &p, i, e, new) {
                continue;
            }
            let old = p.state.get(&e).copied().unwrap_or((Role::None, None));
            // a self-removal only lowers: no component above the grant's
            if leave && (new.0 > old.0 || old.1.is_some_and(|u| new.1.is_none_or(|n| n > u))) {
                continue;
            }
            let restored = p.restored.get(&e).copied().unwrap_or(Role::None).max(p.at(e, c.ts));
            let rinv = p.rinv.get(&e).copied().unwrap_or(Role::None).max(p.invite_at(e, c.ts));
            let (before, after) = (if explicit { restored } else { p.at(e, c.ts) }, alive(new, c.ts));
            let after_inv = give_invite(after, *invite);
            // an explicit write audits against the edge as restored, once, when judged: where it
            // takes the edge down (`any_fall`: in role or invite; else from admin)
            let falls = if rules.any_fall { restored > after || rinv > after_inv } else { restored == Role::Admin && after < Role::Admin };
            let mut q = vec![];
            if judged.is_none() && explicit && falls {
                let exempt = if rules.exempt_chain { chain(w, &v.held, i) } else { Set::new() };
                // in question: a write resting on the edge whose need there the edge as restored
                // met and its new value does not
                let gone = |j: Id| {
                    let n = need(w, rules, j, e, p.invited.contains(&j) || !p.applied.contains(&j));
                    rests_on(w, rules, j, e) && !exempt.contains(&j) && !listed(w, v, vouched, i, j) && n.met(restored, rinv) && !n.met(after, after_inv)
                };
                // in question: the applied writes before it (`audit_held`: the held ones not yet
                // dropped or void) resting on its edge
                let before = || -> Vec<Id> {
                    if rules.audit_held {
                        order[..k].iter().copied().filter(|j| !dropped.contains(j) && verdict.get(j) != Some(&Verdict::Void)).collect()
                    } else {
                        p.applied.clone()
                    }
                };
                // void: its own drops would take its authority (read back from the state, before
                // any drop is listed)
                if rules.self_void && !keeps(w, &p, &gone, i, &mut BTreeMap::new(), &mut checked) {
                    verdict.insert(i, Verdict::Void);
                    continue;
                }
                q = before().into_iter().filter(|&j| gone(j)).collect();
                verdict.insert(i, Verdict::Applied);
            }
            p.state.insert(e, new);
            p.inv.insert(e, *invite);
            if explicit {
                p.restored.insert(e, new.0);
                p.rinv.insert(e, after_inv);
            } else if as_invite {
                let r = p.restored.entry(e).or_insert(Role::None);
                *r = (*r).max(new.0);
                let r = p.rinv.entry(e).or_insert(Role::None);
                *r = (*r).max(after_inv);
                p.invited.insert(i);
            }
            p.hist.entry(e).or_default().push((w.key(i), new));
            p.applied.push(i);
            if after < before {
                p.lows.push(Low { id: i, explicit, edge: e, before, after });
            }
            if !q.is_empty() {
                restart = q.iter().map(|j| pos[j]).min();
                for j in q {
                    dropped.insert(j);
                    dropper.insert(j, i);
                }
                break;
            }
        }
        if let Some(r) = restart {
            (from, rounds) = (r, rounds + 1);
            continue;
        }
        let voided = verdict.iter().filter(|(i, x)| **x == Verdict::Void && !dropped.contains(*i)).map(|(i, _)| *i).collect();
        return Walk { pass: p, dropped, dropper, voided, rounds, passes, walked, checked };
    }
}

/// A trusted lowering's seeds: each held edge-class commit ordered before it, resting on its
/// edge, that its list does not name, with the trusted write that drops it.
fn seeds(w: &World, rules: &Rules, v: &View, active: &Set, vouched: &Vouched) -> BTreeMap<Id, Id> {
    let mut d = BTreeMap::new();
    for &r in active {
        let Some(h) = w.sets(r) else { continue };
        let exempt = if rules.exempt_chain { chain(w, &v.held, r) } else { Set::new() };
        for &j in &v.held {
            if w.edge_class(j) && w.key(j) < w.key(r) && rests_on(w, rules, j, h) && !exempt.contains(&j) && !listed(w, v, vouched, r, j) {
                d.entry(j).or_insert(r);
            }
        }
    }
    d
}

/// The vouches a walk applies after their removal, where it applies that removal too
/// (notes/account-membership-design.md §4, It counts), and the (removal, role write) pairs they
/// name.
fn counting(w: &World, rules: &Rules, wk: &Walk) -> (Set, Vouched) {
    let (mut ids, mut out) = (Set::new(), Vouched::new());
    for &i in &wk.pass.applied {
        if let Kind::Vouch { removal, list } = &w.commits[i].kind {
            if w.key(*removal) < w.key(i) && wk.pass.applied.contains(removal) {
                ids.insert(i);
                let own = |j: Id| rules.no_own_vouch && w.commits[j].signer == w.commits[i].signer;
                out.extend(list.iter().filter(|&&j| w.edge_class(j) && w.commits[j].on == w.commits[i].on && !own(j)).map(|&j| (*removal, j)));
            }
        }
    }
    (ids, out)
}

/// The settled walk under the active trusted writes (its rounds and passes counting every walk
/// made), the seeds with their trusted writes, the first walk's state, the counting vouches, and
/// whether the vouches settled.
fn settle(w: &World, rules: &Rules, v: &View, active: &Set) -> (Walk, BTreeMap<Id, Id>, BTreeMap<Edge, Val>, Set, bool) {
    let none = Vouched::new();
    let (mut rounds, mut passes, mut walked, mut checked) = (0, 0, 0, 0);
    let mut run = |vouched: &Vouched| {
        let d0 = seeds(w, rules, v, active, vouched);
        let mut wk = walk(w, rules, v, &d0.keys().copied().collect(), vouched);
        rounds += wk.rounds;
        passes += wk.passes;
        walked += wk.walked;
        checked += wk.checked;
        (wk.rounds, wk.passes, wk.walked, wk.checked) = (rounds, passes, walked, checked);
        (wk, d0)
    };
    match rules.vouch {
        Vouch::Off => {
            let (wk, d0) = run(&none);
            let first = wk.pass.state.clone();
            (wk, d0, first, Set::new(), false)
        }
        Vouch::BaseWalk => {
            let base = run(&none).0;
            let (ids, vouched) = counting(w, rules, &base);
            let (wk, d0) = run(&vouched);
            (wk, d0, base.pass.state, ids, false)
        }
        Vouch::SameWalk => {
            let mut seen = vec![none.clone()];
            let mut vouched = none;
            loop {
                let (wk, d0) = run(&vouched);
                let (ids, next) = counting(w, rules, &wk);
                if next == vouched || seen.contains(&next) {
                    let circle = next != vouched;
                    let first = wk.pass.state.clone();
                    return (wk, d0, first, ids, circle);
                }
                seen.push(next.clone());
                vouched = next;
            }
        }
    }
}

fn role_at(w: &World, p: &Pass, e: Edge, pos: Key) -> Role {
    let rec = if w.records.contains(&e) { (Role::Admin, None) } else { (Role::None, None) };
    alive(p.hist.get(&e).and_then(|h| h.iter().rev().find(|(k, _)| *k < pos)).map_or(rec, |x| x.1), pos.0)
}

/// The first key after which every edge gives write in the settled walk (KEY0: from the start).
fn first_applied(w: &World, p: &Pass, edges: &[Edge]) -> Option<Key> {
    let mut keys: Vec<Key> = vec![(0, 0, 0)];
    keys.extend(edges.iter().filter_map(|e| p.hist.get(e)).flatten().map(|x| x.0));
    keys.sort();
    keys.into_iter().find(|k| edges.iter().all(|&e| role_at(w, p, e, (k.0, k.1, k.2 + 1)) >= Role::Write))
}

/// Per edge, the key of the first chained write giving it write or above (spec/permissions.md
/// §4 Chained writes, along the write's stated path, `until` disregarded).
fn first_chained(w: &World, held: &Set) -> BTreeMap<Edge, Key> {
    let mut max: BTreeMap<Edge, Role> = w.records.iter().map(|&e| (e, Role::Admin)).collect();
    let mut inv: BTreeMap<Edge, Role> = w.records.iter().map(|&e| (e, Role::Admin)).collect();
    let mut first: BTreeMap<Edge, Key> = w.records.iter().map(|&e| (e, (0, 0, 0))).collect();
    let get = |m: &BTreeMap<Edge, Role>, e: &Edge| m.get(e).copied().unwrap_or(Role::None);
    for i in order(w, held) {
        let hops = w.hops(i);
        let (Some(e), Kind::Edge { role, invite, finalize, .. }) = (w.sets(i), &w.commits[i].kind) else { continue };
        // a self-removal and a finalize set no edge here (spec/permissions.md §4 Chained writes)
        if !w.well(i) || w.leave(i) || *finalize {
            continue;
        }
        // by admin on its target, or by an invite there for an invite grant
        let admin = hops.iter().all(|h| get(&max, h) == Role::Admin);
        let invited = invite_grant(w, i).is_some_and(|lvl| hops.split_last().is_some_and(|(l, b)| get(&inv, l) >= lvl && b.iter().all(|h| get(&max, h) >= lvl)));
        if !admin && !invited {
            continue;
        }
        if *role >= Role::Write {
            first.entry(e).or_insert(w.key(i));
        }
        let m = max.entry(e).or_insert(Role::None);
        *m = (*m).max(*role);
        let m = inv.entry(e).or_insert(Role::None);
        *m = (*m).max(give_invite(*role, *invite));
    }
    first
}

/// The final role of each edge, every `until` counted removed.
fn finals(p: &Pass) -> BTreeMap<Edge, Role> {
    p.state.iter().map(|(&e, &(r, u))| (e, if u.is_some() { Role::None } else { r })).collect()
}

/// The commits a node judges: those it holds, and under `Rules::cover_facts` those a held cover
/// carries (judged by the facts the cover states, its body forgotten or never received, where the
/// cover is valid). Under copies a node judges only the commits it holds; a carried one shows by
/// the cover's copy.
fn known(w: &World, rules: &Rules, v: &View) -> Set {
    let mut k = v.held.clone();
    for &c in v.held.iter().filter(|_| rules.cover_facts) {
        if let Kind::Cover { carries } = &w.commits[c].kind {
            k.extend(carries);
        }
    }
    k
}

/// Valid content-class commits, and the addenda among them that vouch.
fn content(w: &World, rules: &Rules, v: &View, p: &Pass) -> (Set, Set) {
    let chained = first_chained(w, &v.held);
    let fin = finals(p);
    let none = Vouched::new();
    let vouches = |a: Id| w.hops(a).iter().all(|&e| role_at(w, p, e, w.pos(a)) >= Role::Write);
    let mut valid = Set::new();
    loop {
        let mut next = Set::new();
        let known = known(w, rules, v);
        for &i in known.iter().filter(|&&i| !w.edge_class(i)) {
            let hops = w.hops(i);
            // a write not held is judged by the facts a valid cover carrying it states; carried
            // only by covers that are not valid it counts as never received
            let stated = v.held.contains(&i) || valid.iter().any(|&c| matches!(&w.commits[c].kind, Kind::Cover { carries } if carries.contains(&i)));
            if !w.well(i) || !stated {
                continue;
            }
            let pos = w.pos(i);
            let cuts: Vec<&Low> = p.lows.iter().filter(|l| l.explicit && hops.contains(&l.edge) && l.before >= Role::Write && l.after < Role::Write).collect();
            let held = hops.iter().all(|&e| role_at(w, p, e, pos) >= Role::Write);
            let ok = (held && !cuts.iter().any(|l| w.key(l.id) > pos))
                || cuts.iter().any(|l| listed(w, v, &none, l.id, i))
                // an addendum vouches for no purge request (spec/permissions.md §6)
                || valid.iter().any(|&a| match &w.commits[a].kind {
                    Kind::Addendum { removal, list } if !matches!(w.commits[i].kind, Kind::Purge { .. }) => {
                        w.commits[a].on == w.commits[i].on
                            && list.iter().any(|&c| w.names(c, i))
                            && !(rules.no_own_addendum && w.commits[a].signer == w.commits[i].signer)
                            && cuts.iter().any(|l| l.id == *removal && w.key(l.id) > pos && w.key(l.id) < w.pos(a))
                            && vouches(a)
                    }
                    _ => false,
                })
                || (hops.iter().all(|e| fin.get(e).is_some_and(|r| *r >= Role::Write)) && {
                    let from = match rules.regrant {
                        Regrant::FirstApplied => first_applied(w, p, &hops),
                        Regrant::FirstChained => hops.iter().map(|e| chained.get(e).copied()).collect::<Option<Vec<Key>>>().and_then(|k| k.into_iter().max()),
                    };
                    from.is_some_and(|k| k == (0, 0, 0) || pos > k)
                });
            if ok {
                next.insert(i);
            }
        }
        if next == valid {
            let vouching = valid.iter().copied().filter(|&a| matches!(w.commits[a].kind, Kind::Addendum { .. }) && vouches(a)).collect();
            return (valid, vouching);
        }
        valid = next;
    }
}

/// The held content a valid purge request holds the author right over (notes/write-path-design.md
/// §1, What a purger must hold): a request by author P on T names the deltas on T of commits with
/// a smaller `ts` whose purge author is exactly P; it holds the right iff it is valid (judged as a
/// content write along its own path at its position) and its chain holds P.
fn purges(w: &World, rules: &Rules, v: &View, valid: &Set) -> Set {
    let mut out = Set::new();
    for &q in valid {
        let Kind::Purge { author } = w.commits[q].kind else { continue };
        if rules.purge_chain && !w.chain(q).contains(&author) {
            continue;
        }
        let (on, ts) = (w.commits[q].on, w.commits[q].ts);
        let names = |d: Id| if rules.purge_exact { w.purge_author(d) == author } else { w.chain(d).contains(&author) };
        out.extend(v.held.iter().copied().filter(|&d| matches!(w.commits[d].kind, Kind::Content) && w.commits[d].on == on && w.commits[d].ts < ts && names(d)));
    }
    out
}

/// A node's reading: a function of the world's rules, what it holds, the leaves it sees and
/// its trust set.
pub fn judge(w: &World, rules: &Rules, v: &View) -> Reading {
    let mut active: Set = v.trust.iter().copied().filter(|i| v.held.contains(i) && w.sets(*i).is_some()).collect();
    let mut void = Set::new();
    let (mut rounds, mut passes, mut walked, mut checked) = (0, 0, 0, 0);
    loop {
        let (wk, d0, first, counting, circle) = settle(w, rules, v, &active);
        rounds += wk.rounds;
        passes += wk.passes;
        walked += wk.walked;
        checked += wk.checked;
        let applied: Set = wk.pass.applied.iter().copied().collect();
        let gone: Vec<Id> = active.iter().copied().filter(|r| !applied.contains(r)).collect();
        if !gone.is_empty() {
            rounds += 1;
            for r in gone {
                active.remove(&r);
                void.insert(r);
            }
            continue;
        }
        let (valid, vouching) = content(w, rules, v, &wk.pass);
        let purged = purges(w, rules, v, &valid);
        let copied = if !rules.cover_facts {
            valid.iter().filter_map(|&c| match &w.commits[c].kind { Kind::Cover { carries } => Some(carries.iter().copied().filter(|j| !valid.contains(j))), _ => None }).flatten().collect()
        } else {
            Set::new()
        };
        let mut dropper = wk.dropper;
        dropper.extend(d0);
        let mut rd = Reading {
            lowered: wk.pass.lows.iter().map(|l| l.id).collect(),
            valid,
            purged,
            copied,
            roles: finals(&wk.pass),
            state: wk.pass.state.clone(),
            first,
            counting,
            vouching,
            applied,
            dropped: wk.dropped,
            dropper,
            void,
            voided: wk.voided,
            stray: Set::new(),
            rounds,
            passes,
            walked,
            checked,
            circle,
        };
        rd.stray = unjustified(w, rules, v, &rd);
        return rd;
    }
}

/// The dropped commits whose drop the reading does not justify (`Reading::stray`): read from
/// the reading's applied set, trust set, lists and counting vouches alone.
fn unjustified(w: &World, rules: &Rules, v: &View, rd: &Reading) -> Set {
    let mut vouched = Vouched::new();
    for &a in &rd.counting {
        if let Kind::Vouch { removal, list } = &w.commits[a].kind {
            let own = |j: Id| rules.no_own_vouch && w.commits[j].signer == w.commits[a].signer;
            vouched.extend(list.iter().filter(|&&j| w.edge_class(j) && w.commits[j].on == w.commits[a].on && !own(j)).map(|&j| (*removal, j)));
        }
    }
    rd.dropped
        .iter()
        .copied()
        .filter(|&j| {
            let Some(&r) = rd.dropper.get(&j) else { return true };
            let seed = v.trust.contains(&r) && !rd.void.contains(&r);
            let Some(h) = w.sets(r) else { return true };
            let lowering = seed || (w.lowers(r).is_some() && !w.leave(r));
            !(rd.applied.contains(&r) && lowering && w.key(j) < w.key(r) && rests_on(w, rules, j, h) && !listed(w, v, &vouched, r, j))
        })
        .collect()
}

/// Disputes: the held lowerings (edge writes giving below admin at their `ts`) of another
/// holder's edge, not trusted and not dropped by a trusted write's seeds, whose trust changes the
/// reading (what applies, what is valid, the roles). spec/permissions.md §5.1 asks instead that
/// the walk not apply it, that it apply once trusted and lower its edge (finding 21); a removal
/// that applies but whose reach-back the walk cannot undo (its drops of a lowering that dropped in
/// turn, or of a grant a lowering applied under) changes the reading once trusted and is shown
/// only by this rule (finding 16). A grant is never one: trusted, its seeds drop its holder's
/// earlier writes, so an honest re-grant would be shown.
pub fn disputes(w: &World, rules: &Rules, v: &View) -> Vec<Id> {
    let rd = judge(w, rules, v);
    let mut out = vec![];
    for &r in &v.held {
        let Kind::Edge { holder, .. } = &w.commits[r].kind else { continue };
        if *holder == w.commits[r].signer || w.lowers(r).is_none() || v.trust.contains(&r) || rd.dropper.get(&r).is_some_and(|d| v.trust.contains(d)) {
            continue;
        }
        let t = judge(w, rules, &v.clone().trusting_also(r));
        if t.applied != rd.applied || t.valid != rd.valid || t.roles != rd.roles {
            out.push(r);
        }
    }
    out
}

/// The edges whose edge writes are evidence of commit `i`: its path's, and the remaining admin
/// edge it names.
fn evidence_edges(w: &World, i: Id) -> Vec<Edge> {
    let mut e = w.hops(i).to_vec();
    if let Kind::Edge { relies: Some(n), .. } = &w.commits[i].kind {
        e.push((*n, w.commits[i].on));
    }
    e
}

/// The evidence closure of `unit` over `avail` (notes/write-path-design.md §2): the commits in
/// `unit`, every available edge write on an edge of a held commit's path or on the remaining
/// admin edge a held lowering names, every available vouch against a held removal.
pub fn evidence(w: &World, unit: &Set, avail: &Set) -> Set {
    let mut s = unit.clone();
    loop {
        let edges: BTreeSet<Edge> = s.iter().flat_map(|&i| evidence_edges(w, i)).collect();
        let more: Vec<Id> = avail
            .iter()
            .copied()
            .filter(|i| !s.contains(i))
            .filter(|&i| match &w.commits[i].kind {
                Kind::Edge { .. } => w.sets(i).is_some_and(|e| edges.contains(&e)),
                Kind::Vouch { removal, .. } => s.contains(removal),
                _ => false,
            })
            .collect();
        if more.is_empty() {
            return s;
        }
        s.extend(more);
    }
}

// ---- The keys layer: A's epochs under a standing dispute (spec/crypto.md §4) ----

/// What one node's reading gives the keys layer: A's admins and the departures it knows.
#[derive(Clone, Debug, PartialEq)]
pub struct Side {
    pub node: Thing,
    pub admins: Things,
    pub departures: Set,
}

impl Side {
    pub fn of(w: &World, rd: &Reading, node: Thing, a: Thing) -> Side {
        Side {
            node,
            admins: rd.roles.iter().filter(|(e, r)| e.1 == a && **r == Role::Admin).map(|(e, _)| e.0).collect(),
            departures: rd.lowered.iter().copied().filter(|&i| w.commits[i].on == a).collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Withdraw {
    /// spec/crypto.md §4 as written: a valid rotation is current whatever it covers; the
    /// knowing re-key answers a current epoch not covering a known departure; a node withdraws
    /// an epoch not current whose maker may not rotate.
    AsWritten,
    /// The fix: an epoch covering a departure the node's walk does not apply is the other
    /// side's: it is read, never current, supersedes nothing and is not answered.
    SideOnly,
}

#[derive(Clone, Debug)]
pub struct Epoch {
    pub maker: Thing,
    pub covers: Set,
    pub boxes: Things,
    pub supersedes: BTreeSet<usize>,
}

/// Every node holds every epoch; each pass, each node in turn rotates A when the rule says so.
/// Returns the epochs (0 the first, valid everywhere) and the rotations made per pass.
pub fn rotations(passes: usize, rule: Withdraw, sides: impl Fn(usize) -> Vec<Side>) -> (Vec<Epoch>, Vec<usize>) {
    let mut eps = vec![Epoch { maker: 0, covers: Set::new(), boxes: Things::new(), supersedes: BTreeSet::new() }];
    let mut per = vec![];
    for pass in 0..passes {
        let mut made = 0;
        for s in sides(pass) {
            let cur = current(&eps, &s, rule);
            let counted = |i: usize| counts(&eps, i, &s, rule);
            let superseded = |i: usize| (0..eps.len()).any(|f| counted(f) && eps[f].supersedes.contains(&i));
            let withdrawn: Vec<usize> = (1..eps.len()).filter(|&i| !counted(i) && !superseded(i) && (eps[i].maker == s.node || !s.admins.contains(&eps[i].maker))).collect();
            if !s.admins.contains(&s.node) || (!cur.is_empty() && cur.iter().all(|&i| eps[i].covers.is_superset(&s.departures)) && withdrawn.is_empty()) {
                continue;
            }
            let supersedes = cur.into_iter().chain(withdrawn).collect();
            eps.push(Epoch { maker: s.node, covers: s.departures.clone(), boxes: s.admins.clone(), supersedes });
            made += 1;
        }
        per.push(made);
    }
    (eps, per)
}

fn counts(eps: &[Epoch], i: usize, s: &Side, rule: Withdraw) -> bool {
    i == 0 || (s.admins.contains(&eps[i].maker) && (rule == Withdraw::AsWritten || eps[i].covers.is_subset(&s.departures)))
}

/// The epochs current at a node: counting, superseded by no counting epoch.
pub fn current(eps: &[Epoch], s: &Side, rule: Withdraw) -> Vec<usize> {
    (0..eps.len()).filter(|&i| counts(eps, i, s, rule) && !(0..eps.len()).any(|f| counts(eps, f, s, rule) && eps[f].supersedes.contains(&i))).collect()
}

mod story;
pub use story::*;

#[cfg(test)]
mod tests;
