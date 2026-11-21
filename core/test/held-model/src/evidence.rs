//! Evidence completeness (notes/redesign-plan.md M2; notes/write-path-design.md §2, §6): a model
//! of what each sync ID carries as evidence for the writes whose bodies it carries, and of whether
//! a reader holding one sync ID alone judges those writes as a node holding everything does.
//! Properties in tests/it/spec_evidence.rs, findings in notes/evidence-model-findings.md.
//!
//! Judging is roles-model `paths` (`Rules::fixed`, the rule A1 builds): a commit states a path,
//! judged along it; a lowering lists a frontier; addenda, re-grants as there. On top:
//! - **Pending** (`pend`): a commit pends at a node while an edge of its path (or the remaining
//!   admin edge it names) that is no record edge has no held edge write ordered before it, or the
//!   latest such write pends (notes/write-path-design.md §2 What follows, its smallest reading).
//! - **Sync IDs and units.** Signers have no sync ID; every other thing in `sids` has its own, and
//!   a unit per sync ID: the thing and the members `Ev::Join`/`Ev::Leave` give it. Which things a
//!   unit holds is the closure model's question (`closure::unit`), so here it is an input in time.
//!   A thing outside `sids` (a dependent thing) is carried only in the units holding it.
//! - **Bodies.** A commit's body is under every sync ID whose unit holds the thing it writes
//!   (roles-model commits write one thing: a copy per (commit, thing) is per commit here).
//! - **The required set** of sync ID S over a held set H (`World::req`): the evidence closure
//!   (`paths::evidence`: every held edge write on an edge of a seed's path or on the remaining
//!   admin edge a lowering names, closed under the same for what it adds) of the seeds: the bodies; the grants naming S's thing as holder (a holder's
//!   grants travel under its sync ID: taken-ness is not modelled, every grant counts); and every
//!   held removal of an edge (h, t) taking write away (`Rule::removals`), with its witness, whose
//!   **reach** (held edge writes giving write or above and record edges, at any time, joining t to
//!   a thing of the unit) is held, with that reach (`Rule::reach`: the drafted A3 delivery, parked
//!   until held-model is restated at stage D: notes/a3-spec/README.md, Far delivery). What of it
//!   lies on things outside the unit is a copy, the rest bodies.
//! - **Delivery** (`Placement`): nodes sync sync IDs (`Node::syncs`, closed under the standing duty:
//!   a node syncing S syncs every sync ID of a thing in S's unit) and hold what those carry and what
//!   they wrote. An honest node logs under each sync ID it syncs what its own view requires there;
//!   an entry no syncing node requires is deleted (a delete-key holder deletes, a holder whose view
//!   requires it logs again: the union). The thief logs its own bodies and the grants they rest on,
//!   never a lowering. The remover's errand (`Errand`, parked with reach): it logs its lowering under
//!   the own sync ID of the lowered edge's target and of the things that target holds grants on
//!   (`Direct`, read from the target's taken grants), or of everything reached by taken grants
//!   (`Transitive`).
//! - **Readers.** A reader holding one sync ID holds its entries, sees frontier leaves for its
//!   unit's things and (`Leaves::Evidence`) for every thing a held edge write is on, and trusts
//!   what the world trusts that it holds. The node holding everything sees every leaf.
//!
//! - **List leaves** (`Lists::Travels`, A3): a lowering's content entries in a leaf per thing,
//!   evidence of the bodies on that thing whose verdict reads it (`LeafKeep`), held and logged
//!   as any evidence; a body lacking a leaf a held root shows pends (`pend_leaf`). Addenda leave
//!   with the last held commit they can keep (`addendum_live`).
//! - **Promoting** (`promotions`, `p8_promotions`): a reader promotes a body it judges valid after a
//!   complete pass of its sync ID or (the control) on any partial arrival. A body judged invalid
//!   is dropped at once (spec/commits.md §5 Invalid): no act waits for it.
//!
//! Left out: records (static, `paths::World::records`), keys and sealing, rotations, `@` signals,
//! covers, the deposit path, invites as a reach (a removal's reach is write), taken-ness of a grant,
//! multi-thing role commits, how units are computed (an input: `closure` checks the walk).

use roles_model::paths::{self, Edge, Id, Kind, Rules, Set, Thing, Things, View};
use roles_model::Role;
use std::collections::{BTreeMap, BTreeSet};

pub type Sid = Thing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Pending,
    Valid,
    Invalid,
}

/// When copies are logged and when they leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// The design (notes/write-path-design.md §2: "a function of the commits U holds", "logged
    /// by any node holding them and U"): every honest syncing node logs what its view requires
    /// now, and what nobody requires leaves.
    Function,
    /// The literal "logged with the commit that needs it, leaving with it": a commit's copies are
    /// placed when the commit is logged under the sync ID (by the node logging it, from its view
    /// then; a body where the thing is in the unit then, else a copy) and leave once every commit
    /// they were placed for left; nothing is placed again when a unit changes.
    AtLog,
}

/// Where the remover logs its lowering besides the sync IDs it syncs (the drafted A3 delivery,
/// parked with `Rule::reach` until stage D).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errand {
    Off,
    /// The target's own sync ID and those of the things it holds grants on (its taken grants,
    /// under its own sync ID).
    Direct,
    /// Every thing reached from the target by taken grants, each read under the reached thing's
    /// own sync ID, held for the errand.
    Transitive,
}

/// Which leaves of a lowering stay with it wherever it is a body (under its own thing's sync ID
/// and each enclosing one), while it is held, besides where a body they read is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Home {
    /// None: a leaf only where a body it reads is (the control of finding 30).
    None,
    /// Its leaves for other things than its own: a node holding the removal holds the leaf a write
    /// it judges elsewhere needs (finding 30). Its own thing's leaf is read only by bodies on that
    /// thing, which are in every unit the lowering is a body of, so it leaves with the last of
    /// them (finding 34).
    Far,
    /// Every leaf, its own thing's too: kept for good where the lowering is a body (the control
    /// of finding 34).
    All,
}

/// What travels by errand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Lowerings only ("only removals travel at once").
    Lowerings,
    /// A lowering, and every later edge write on its edge (a re-grant), written by any honest
    /// node holding the lowering, to the same sync IDs.
    Edge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaves {
    /// A reader sees the leaves of its unit's things and of every thing a held edge write is on.
    Evidence,
    /// Its unit's things only.
    Unit,
}

/// Where a lowering's content entries (frontier entries naming commits with no edge-class part)
/// live (issues/zero-growth.md, Proposals 1; roles-model `forget` `Policy::Travels`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lists {
    /// In the lowering itself, travelling with it for good (A1's frontier).
    Whole,
    /// In a leaf per (lowering, thing) that the lowering's root commits to; the role entries stay
    /// in the lowering. A leaf is evidence: logged under a sync ID with the commits it is evidence
    /// of, forgotten with the last of them; a commit a held leaf would judge, held without it,
    /// waits (the reader learns from the root which things have a leaf, not what a leaf names).
    Travels(LeafKeep),
}

/// Which commits a leaf is evidence of (it is required while one of them is held).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafKeep {
    /// The commits it names (the growth study's literal rule).
    Named,
    /// The commits whose verdict reads it: on its thing, without edge-class parts, resting on the
    /// lowered edge (named or not, in any order).
    Judged,
    /// `Judged`, where the lowering takes away what the commit needs on its edge (a list is read
    /// only for a cut, spec/permissions.md §5.2): for content, write, so a held chained write on
    /// the lowered edge giving write or above is ordered before it (its witness, as reach reads
    /// it), or the edge is a record edge (`World::cuts_write`). A lowering cutting nothing has a
    /// leaf read by no verdict, waited on by nobody (notes/evidence-model-findings.md 27).
    Cuts,
}

/// Which edge-class commits the evidence closure takes beyond the bodies (notes/a2-spec/README.md
/// OPEN 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Takes {
    /// Every held one on a closure edge, whatever its validity (the draft; `paths::evidence`).
    All,
    /// Chained ones only (spec/permissions.md §4 Chained writes, `World::chained`): what no
    /// non-admin can make, and a superset of what any walk applies.
    Chained,
    /// Those the logging node's own walk over its holdings applies (non-monotone: a write may
    /// apply over a smaller set and not over a larger, and the reverse).
    Applied,
}

/// The evidence closure (`World::closure`): which writes it takes and which edges a member brings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Closure {
    pub takes: Takes,
    /// Today's chain certificates (spec/permissions.md §4 Chain certificates, as main builds
    /// them: `osis_perm` `Timeline::certificates`) in place of stated paths: a member brings every
    /// taken write on an edge between two things of its signer's **chain** to its thing (the
    /// signer and the things on any path from it to the thing over record edges and edges chained
    /// grants set, at any time), and an edge write also its signer's chain to its holder (closed
    /// under authors). `joined` is read for stated paths only.
    pub any_path: bool,
    /// A member brings the writes on its stated path's edges only where the path is **joined**:
    /// each edge of it that is no record edge holds a held chained grant (`World::grants`) ordered
    /// before the member.
    pub joined: bool,
    /// What an edge write in the set brings of the other edges its commit writes on its thing
    /// (finding 9: a commit's edge writes apply together, and a part resetting an entry waits for
    /// that entry's creation, `World::creations`).
    pub commit_edges: CommitEdges,
}

/// `Closure::commit_edges`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitEdges {
    /// Nothing (`paths::evidence`: the commit's other parts on its thing alone).
    Off,
    /// The creation (`World::creation`) of each entry the commit's parts on its thing reset.
    Creations,
    /// Every taken edge write on each edge the commit's parts on its thing set (the draft's
    /// words, notes/a2-spec/permissions.md §4).
    AllWrites,
}

impl Closure {
    /// The draft (notes/a2-spec/permissions.md §4 Evidence of a commit): `paths::evidence` with
    /// finding 9's clause in the draft's words.
    pub fn drafted() -> Closure {
        Closure { takes: Takes::All, any_path: false, joined: false, commit_edges: CommitEdges::AllWrites }
    }
    /// OPEN 10 (b): chained writes, along joined paths.
    pub fn joined() -> Closure {
        Closure { takes: Takes::Chained, any_path: false, joined: true, commit_edges: CommitEdges::Creations }
    }
}

/// When a commit pends for want of evidence (`World::pend`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pend {
    /// An edge it reads has no held edge write ordered before it, or the latest such pends (the
    /// draft: notes/a2-spec/commits.md §4 Unjudgeable).
    Any,
    /// An edge it reads has no held chained grant ordered before it, or the latest held chained
    /// edge write ordered before it pends: a write no chained write reaches waits, as one no write
    /// reaches does (A1's Unjudgeable: "a removal leads nowhere").
    Granted,
}

/// What joins a hop of a stated path under `Pend::Granted`, for joined paths (`World::joined`)
/// and pending (`World::pend`) alike (notes/a2-spec/README.md OPEN 16, finding 23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Join {
    /// J1: any held chained grant ordered before the part.
    Any,
    /// J2: a held chained grant ordered before the part giving what the part needs on that hop
    /// (`World::need`: write for content, admin for an edge write, its level for an invite
    /// grant), `until` disregarded: a hop holding only a grant giving too little joins nothing,
    /// so the part waits at every node, as one through a hop nobody granted.
    Needed,
    /// J3: joined as `Any`; a hop holding no held chained grant ordered before the part is
    /// judged as the walk judges it (invalid), never pending.
    Refused,
    /// J4: joined as `Any` (the closure takes a path any grant joins), pending as `Needed`.
    PendNeeded,
}

impl Join {
    pub const ALL: [Join; 4] = [Join::Any, Join::Needed, Join::Refused, Join::PendNeeded];
    pub fn name(self) -> &'static str {
        match self {
            Join::Any => "j1-any",
            Join::Needed => "j2-needed",
            Join::Refused => "j3-refused",
            Join::PendNeeded => "j4-pend-needed",
        }
    }
}

/// The OPEN 10 variants, each a closure with the pending rule judging goes with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Open10 {
    /// (i) the draft: every edge write on a stated path, any validity; pending on any write.
    Drafted,
    /// (ii) chained writes only; pending on any write.
    Chained,
    /// (iii) chained writes along joined paths; pending on any write.
    Joined,
    /// (iv) chained writes along joined paths; pending on chained grants.
    Granted,
    /// (v) chained writes on every stated path (unjoined too); pending on chained grants.
    ChainedGranted,
    /// (vi) applied writes (the logging node's walk), along joined paths; pending on chained
    /// grants: the fixpoint the walk's own verdict gives.
    Applied,
}

impl Open10 {
    pub const ALL: [Open10; 6] = [Open10::Drafted, Open10::Chained, Open10::Joined, Open10::Granted, Open10::ChainedGranted, Open10::Applied];
    pub fn name(self) -> &'static str {
        match self {
            Open10::Drafted => "i-drafted",
            Open10::Chained => "ii-chained",
            Open10::Joined => "iii-joined",
            Open10::Granted => "iv-granted",
            Open10::ChainedGranted => "v-chained-granted",
            Open10::Applied => "vi-applied",
        }
    }
    pub fn closure(self) -> Closure {
        if self == Open10::Drafted {
            return Closure::drafted();
        }
        let (takes, joined) = match self {
            Open10::Drafted => unreachable!(),
            Open10::Chained | Open10::ChainedGranted => (Takes::Chained, false),
            Open10::Joined | Open10::Granted => (Takes::Chained, true),
            Open10::Applied => (Takes::Applied, true),
        };
        Closure { takes, any_path: false, joined, commit_edges: CommitEdges::Creations }
    }
    pub fn pend(self) -> Pend {
        match self {
            Open10::Drafted | Open10::Chained | Open10::Joined => Pend::Any,
            _ => Pend::Granted,
        }
    }
    /// `rule` with this closure, and `w` judging with its pending rule
    /// and with entry creations (`World::creations`).
    pub fn set(self, w: &mut World, rule: Rule) -> Rule {
        w.pend = self.pend();
        w.creations = true;
        Rule { closure: self.closure(), ..rule }
    }
}

/// The delivery rules OPEN 14 compares (notes/a2-spec/README.md), each over OPEN 10's (iv)
/// closure and judge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The drafted A3 delivery: removals with their reach, the remover's errand followed to the
    /// end (`Rule::fixed`), and Role changes travel whole. Not the decided design (no eager
    /// delivery: notes/handoff.md): kept while the properties below rest on it (notes/a3-spec
    /// README.md, The model).
    A3,
    /// The derivation as built (`osis_engine::evidence`): no reach, no errand, Role changes travel;
    /// with `Rule::listed` A3's leaves.
    A2,
    /// Brief 3 as the built derivation computes it alone: no reach, no errand, the actor seed
    /// (Role changes travel's keys-open half left out).
    A2Actor,
    /// Main today: chain certificates on any path, closed under authors, the account's chain
    /// under each sync ID it logs to (spec/permissions.md §4 Logging certificates: read as the
    /// chain of each signer of a body there), Role changes travel; no errand.
    Today,
    /// Brief 3 with today's any-path chains kept for removals alone (`Rule::author_reach`).
    A2AuthorReach,
}

impl Stage {
    pub const ALL: [Stage; 5] = [Stage::A3, Stage::A2, Stage::A2Actor, Stage::Today, Stage::A2AuthorReach];
    pub fn name(self) -> &'static str {
        match self {
            Stage::A3 => "a3",
            Stage::A2 => "a2",
            Stage::A2Actor => "a2-actor",
            Stage::Today => "today",
            Stage::A2AuthorReach => "a2-author-reach",
        }
    }
    /// `rule` under (iv) with this stage's delivery; `w` judging as (iv).
    pub fn set(self, w: &mut World, rule: Rule) -> Rule {
        let r = Rule { errand: Errand::Off, reach: false, keys_open: true, ..Open10::Granted.set(w, rule) };
        match self {
            Stage::A3 => Rule { errand: Errand::Transitive, reach: true, ..r },
            Stage::A2 => r,
            Stage::A2Actor => Rule { keys_open: false, ..r },
            Stage::Today => Rule { closure: Closure { any_path: true, joined: false, ..r.closure }, ..r },
            Stage::A2AuthorReach => Rule { author_reach: true, ..r },
        }
    }
}

/// Which removals are reach seeds (notes/a2-spec/README.md OPEN 16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removals {
    /// Every held removal (`World::removes`: an edge write giving below write at its `ts`, a fresh
    /// grant of read and a reader's removal included).
    Any,
    /// A removal that takes write away: one ordered (by key) after a held taken edge write on its
    /// own edge giving write or above, or on a record edge (standing admin from the thing's
    /// creation). With it, its **witness** (the first such write by key, none for a record edge)
    /// is a seed too, so a reader holding the removal requires it as the node does. Monotone in the
    /// held set: a write grant arriving later with an earlier key makes a held removal one.
    TakesWrite,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rule {
    pub placement: Placement,
    pub errand: Errand,
    /// (The drafted A3 delivery, parked until stage D: notes/a3-spec/README.md, Far delivery.)
    /// Each held removal of (h, t) whose reach under S is held (taken write grants joining t to a
    /// thing of the unit) is a seed, with that reach. Off: a removal goes under S as Role changes
    /// travel says.
    pub reach: bool,
    /// Role changes travel's keys-open half: an edge write naming holder h is a seed also of the
    /// sync ID of each thing whose keys open h (holding read or above on h through taken grants,
    /// at any time: `ROLE_KEEP` read as for good). The half naming S's own thing is always on.
    pub keys_open: bool,
    /// Today's any-path chains kept for removals alone: a held taken removal of (h, t) is a seed
    /// of S where h signs a held body of S and t lies on h's chain to that body's thing (a path
    /// from h to it over record edges and chained grants, any time), with the writes of that
    /// chain's edges.
    pub author_reach: bool,
    /// Record edges are edges of the reach graph and of the read graph and steps of the errand
    /// (each a mint admin's admin edge on the thing it minted, at any time: `World::reach`,
    /// `World::opened`): today's keys open through them (spec/sync-set.md §2) and its chains
    /// climb them. False: the control (grants only), which under-reads today (README OPEN 17).
    pub records: bool,
    /// Which held removals reach (`World::reach_removal`; README OPEN 16).
    pub removals: Removals,
    pub scope: Scope,
    pub leaves: Leaves,
    /// The errand is a standing duty: the remover logs again whenever its view shows a new
    /// target (a holder raised later); false, once, as the lowering is written.
    pub standing: bool,
    pub lists: Lists,
    pub closure: Closure,
    /// Which of a lowering's leaves are required with it wherever it is a body (findings 30, 34).
    pub leaves_home: Home,
}

impl Rule {
    /// The plan's reading (notes/redesign-plan.md A2, A3).
    pub fn design() -> Rule {
        Rule { placement: Placement::Function, errand: Errand::Direct, reach: true, keys_open: false, author_reach: false, records: true, removals: Removals::TakesWrite, scope: Scope::Lowerings, leaves: Leaves::Evidence, standing: true, lists: Lists::Whole, closure: Closure::drafted(), leaves_home: Home::None }
    }
    /// The design with the findings' fixes (notes/evidence-model-findings.md): the errand follows
    /// taken grants to the end.
    pub fn fixed() -> Rule {
        Rule { errand: Errand::Transitive, ..Rule::design() }
    }
    /// `fixed` with content entries in leaves that travel as evidence of the commits they judge
    /// (notes/evidence-model-findings.md 6), read only where their lowering takes write away (27),
    /// and those for other things kept with their lowering wherever it is a body (30, 34): A3's
    /// list rule (`Stage::A3` adds Role changes travel's keys-open half, finding 31).
    pub fn listed() -> Rule {
        Rule { lists: Lists::Travels(LeafKeep::Cuts), leaves_home: Home::Far, ..Rule::fixed() }
    }
}

/// The chained writes of a held set, computed when first read (`World::chained`).
pub type Chained = std::cell::OnceCell<Set>;

/// A frontier leaf: (lowering, thing).
pub type Leaf = (Id, Thing);
pub type Leafs = std::collections::BTreeSet<Leaf>;

/// What a node judges from: a view, and under `Lists::Travels` the leaves it holds (None: every
/// leaf, the frontiers whole).
#[derive(Clone, Debug)]
pub struct Seen {
    pub v: View,
    pub lists: Option<Leafs>,
    /// Which bodies a leaf is read for (`Lists::Travels`' keep).
    pub keep: LeafKeep,
}

/// When a reader promotes (spec/sync-inbox.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromoteWhen {
    /// Only on the sync ID's whole entries: after a complete pass.
    AfterPass,
    /// Control: on any partial arrival where the verdict does not pend.
    WhenNothingPends,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub honest: bool,
    pub syncs: Things,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ev {
    /// The commit is written by its node (`World::by`).
    Write(Id),
    /// The thing joins the sync ID's unit (a strong added), or leaves it.
    Join(Thing, Sid),
    Leave(Thing, Sid),
}

#[derive(Clone, Debug)]
pub struct World {
    pub w: paths::World,
    pub rules: Rules,
    pub sids: Things,
    /// The units before the first event (a sync ID's own thing is always in its unit).
    pub units: BTreeMap<Sid, Things>,
    pub events: Vec<Ev>,
    pub nodes: Vec<Node>,
    /// The node writing each commit.
    pub by: Vec<usize>,
    pub trust: Set,
    /// The pending rule judging uses (an OPEN 10 variant sets it with its closure).
    pub pend: Pend,
    /// What joins a hop under `Pend::Granted`, for joined paths and pending alike.
    pub join: Join,
    /// A removal waits for the creation of the entry it resets, and a commit's edge writes on a
    /// thing apply together (spec/permissions.md §2 Edge writes; engine `add_role_commit`): an
    /// edge-class part pends while a part of its commit on its thing leaving its holder no grant
    /// (`ends_grant`) resets an entry whose creation (`creation`) is not held. False: the walk
    /// alone (paths has no entries).
    pub creations: bool,
    /// `creation` of every commit, computed once the world is written (`creations_of`).
    pub creation_memo: std::sync::OnceLock<Vec<Option<Id>>>,
    /// Content parts whose path entry opens late (notes/path-form.md, the split form's waiting
    /// paths), each with the commit opening it (a key arriving: a content commit on its thing by
    /// its mint admin): a node holding the part without it knows no path for it, so the part
    /// brings nothing and pends (`World::hidden`). `usize::MAX`: not opened (yet).
    pub opens: BTreeMap<Id, Id>,
}

/// Where the model stands after some events.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub step: usize,
    pub written: Set,
    /// Commits released or covered at every node (`World::forget`).
    pub forgotten: Set,
    pub units: BTreeMap<Sid, Things>,
    pub entries: BTreeMap<Sid, Set>,
    /// Per node what it holds (`Placement::Function`: kept while a sync ID it syncs requires it).
    pub held: Vec<Set>,
    /// `Placement::AtLog`: what errands logged, never unplaced.
    pub errands: BTreeMap<Sid, Set>,
    /// `Placement::AtLog`: per (sync ID, copy), the commits it was placed for.
    pub placed: BTreeMap<(Sid, Id), Set>,
    /// `Lists::Travels`: the leaves logged under each sync ID, and per node the leaves it holds.
    pub leaves: BTreeMap<Sid, Leafs>,
    pub held_leaves: Vec<Leafs>,
    /// A settle that did not reach a fixpoint.
    pub unsettled: bool,
    /// Logging rounds over all settles (cost).
    pub rounds: usize,
}

const ROUNDS: usize = 40;

impl World {
    pub fn new(w: paths::World, sids: &[Thing]) -> World {
        let sids: Things = sids.iter().copied().collect();
        let units = sids.iter().map(|&s| (s, Things::from([s]))).collect();
        World { w, rules: Rules::fixed(), sids, units, events: vec![], nodes: vec![], by: vec![], trust: Set::new(), pend: Pend::Any, join: join_default(), creations: false, creation_memo: Default::default(), opens: BTreeMap::new() }
    }
    pub fn node(&mut self, honest: bool, syncs: &[Thing]) -> usize {
        self.nodes.push(Node { honest, syncs: syncs.iter().copied().collect() });
        self.nodes.len() - 1
    }
    /// A commit written now by node `n` (`f` pushes it to the paths world).
    pub fn write(&mut self, n: usize, f: impl FnOnce(&mut paths::World) -> Id) -> Id {
        self.write_parts(n, |w| vec![f(w)])[0]
    }
    /// A commit of several parts (one per thing, `paths::World::split`) written now by node `n`:
    /// one event per part, consecutive.
    pub fn write_parts(&mut self, n: usize, f: impl FnOnce(&mut paths::World) -> Vec<Id>) -> Vec<Id> {
        let ids = f(&mut self.w);
        for &i in &ids {
            assert_eq!(i, self.by.len(), "parts in order");
            // a node writes only what it holds: it syncs the thing written and its path's things
            let c = &self.w.commits[i];
            let mine: Vec<Thing> = c.path.iter().copied().chain([c.on]).filter(|x| self.sids.contains(x)).collect();
            self.nodes[n].syncs.extend(mine);
            self.by.push(n);
            self.events.push(Ev::Write(i));
        }
        ids
    }
    pub fn join(&mut self, x: Thing, s: Sid) {
        self.events.push(Ev::Join(x, s));
    }
    pub fn leave(&mut self, x: Thing, s: Sid) {
        self.events.push(Ev::Leave(x, s));
    }
    /// In the unit from the start.
    pub fn member(&mut self, x: Thing, s: Sid) {
        self.units.get_mut(&s).unwrap().insert(x);
    }
    pub fn on(&self, i: Id) -> Thing {
        self.w.commits[i].on
    }
    fn holder(&self, i: Id) -> Option<Thing> {
        match &self.w.commits[i].kind {
            Kind::Edge { holder, .. } => Some(*holder),
            _ => None,
        }
    }
    /// A removal: an edge write giving below write at its own `ts` (none, read, or an `until`
    /// passed), but a finalize. (`paths::World::lowers` counts every write below admin, a fresh
    /// grant of write included.) A demotion from admin to write is not one here.
    pub fn removes(&self, i: Id) -> Option<Edge> {
        match &self.w.commits[i].kind {
            Kind::Edge { holder, role, until, finalize: false, .. } if paths::alive((*role, *until), self.w.commits[i].ts) < Role::Write => Some((*holder, self.on(i))),
            _ => None,
        }
    }
    /// A held edge write giving write or above (any `until`): a reach.
    pub fn gives_write(&self, i: Id) -> Option<Edge> {
        match &self.w.commits[i].kind {
            Kind::Edge { holder, role, .. } if *role >= Role::Write => Some((*holder, self.on(i))),
            _ => None,
        }
    }

    // ---- What a sync ID requires ----

    /// The held grants (write or above, any time) joining `t` to a thing of `unit`, record edges
    /// counting as such grants (a mint admin's admin edge, standing since the thing's creation:
    /// read at any time as grants are); None when none joins it. Empty when `t` is in the unit.
    /// Returns the grants on the ways (record edges are no copies).
    pub fn reach(&self, rule: &Rule, t: Thing, unit: &Things, h: &Set) -> Option<Set> {
        if unit.contains(&t) {
            return Some(Set::new());
        }
        let grants: Vec<(Option<Id>, Edge)> = self.records(rule).map(|e| (None, e)).chain(h.iter().filter_map(|&i| self.gives_write(i).map(|e| (Some(i), e)))).collect();
        let mut fwd = Things::from([t]);
        loop {
            let n = fwd.len();
            fwd.extend(grants.iter().filter(|(_, e)| fwd.contains(&e.0)).map(|(_, e)| e.1).collect::<Vec<_>>());
            if fwd.len() == n {
                break;
            }
        }
        let mut back: Things = unit.clone();
        loop {
            let n = back.len();
            back.extend(grants.iter().filter(|(_, e)| back.contains(&e.1)).map(|(_, e)| e.0).collect::<Vec<_>>());
            if back.len() == n {
                break;
            }
        }
        if !fwd.iter().any(|x| unit.contains(x)) {
            return None;
        }
        Some(grants.iter().filter(|(_, e)| fwd.contains(&e.0) && back.contains(&e.1)).filter_map(|(i, _)| *i).collect())
    }
    /// The seeds of S's required set over `h`, its unit `unit`: the bodies, and of the edge-class
    /// commits the closure takes (`takes`), the grants naming S's thing and the removals with
    /// their reach.
    /// And the edges whose taken writes are seeds too (`Stage::Today`'s account chains).
    fn seeds(&self, rule: &Rule, s: Sid, unit: &Things, h: &Set) -> (Set, BTreeSet<Edge>) {
        let takes = self.takes(rule, h);
        let ok = |i: &Id| takes.as_ref().is_none_or(|t| t.contains(i));
        let hr: Set = h.iter().copied().filter(ok).collect();
        // the things whose holder roles travel under S: its own, and under Role changes travel
        // those S's thing holds read or above on, through taken grants at any time
        let open = self.opened(rule, s, &hr);
        let mut seed: Set = h.iter().copied().filter(|&i| unit.contains(&self.on(i)) || (self.holder(i).is_some_and(|hd| open.contains(&hd)) && ok(&i))).collect();
        if let Lists::Travels(_) = rule.lists {
            // an addendum is evidence of the commits it lists, and leaves with the last of them
            seed.retain(|&i| self.addendum_live(i, h));
        }
        if rule.reach {
            for &l in &hr {
                if let Some((hd, t)) = self.removes(l) {
                    if !self.reach_removal(rule, l, &hr) {
                        continue;
                    }
                    if let Some(r) = self.reach(rule, t, unit, &hr) {
                        seed.insert(l);
                        seed.extend(r);
                        seed.extend(self.witness(rule, l, &hr));
                        if rule.scope == Scope::Edge {
                            seed.extend(hr.iter().copied().filter(|&j| self.w.sets(j) == Some((hd, t)) && self.w.key(l) < self.w.key(j)));
                        }
                    }
                }
            }
        }
        let mut edges = BTreeSet::new();
        if rule.closure.any_path || rule.author_reach {
            let ch = self.chained(h);
            let bodies: Vec<Id> = h.iter().copied().filter(|&i| unit.contains(&self.on(i)) && !self.hidden(h, i)).collect();
            for &b in &bodies {
                let a = self.w.commits[b].signer;
                if rule.closure.any_path {
                    // the account's chain for S's thing, logged by each node logging there
                    edges.extend(self.edges_among(h, &self.chain_things(h, &ch, a, s)));
                }
                if rule.author_reach {
                    // with the chain's taken writes, so a reader holding them requires it too
                    let among = self.edges_among(h, &self.chain_things(h, &ch, a, self.on(b)));
                    if hr.iter().any(|&l| self.removes(l).is_some_and(|e| among.contains(&e))) {
                        seed.extend(hr.iter().copied().filter(|&l| self.w.sets(l).is_some_and(|e| among.contains(&e))));
                    }
                }
            }
        }
        (seed, edges)
    }
    /// S's required set over held set `h` with units `units`: bodies and copies.
    pub fn req(&self, rule: &Rule, s: Sid, units: &BTreeMap<Sid, Things>, h: &Set) -> Set {
        let (seeds, edges) = self.seeds(rule, s, &units[&s], h);
        self.closure_with(rule, &seeds, edges, h)
    }
    /// The things whose holder roles travel under S over taken writes `hr`: S's own, and under
    /// `keys_open` those S's thing holds read or above on through them and through record edges,
    /// at any time. A record edge opens as a grant of admin from the mint admin to the thing it
    /// minted (spec/sync-set.md §2 T's keys open: effective role over paths that climb record
    /// edges; a dependent's secrets derive from its mint admin's), standing since the thing's
    /// creation, ordered before every write (spec/crypto.md §4 Key access), and read at any time as
    /// grants are: a record edge removed later still opens (as a grant removed later does).
    pub fn opened(&self, rule: &Rule, s: Sid, hr: &Set) -> Things {
        let mut open = Things::from([s]);
        if rule.keys_open {
            let edges: Vec<Edge> = self.records(rule).chain(hr.iter().filter_map(|&i| self.gives_read(i))).collect();
            loop {
                let more: Vec<Thing> = edges.iter().filter(|e| open.contains(&e.0) && !open.contains(&e.1)).map(|e| e.1).collect();
                if more.is_empty() {
                    break;
                }
                open.extend(more);
            }
        }
        open
    }
    /// The record edges reach, keys-open travel and the errand step along (`Rule::records`).
    fn records<'a>(&'a self, rule: &Rule) -> impl Iterator<Item = Edge> + 'a {
        let on = rule.records;
        self.w.records.iter().copied().filter(move |_| on)
    }
    /// Removal `l` (`removes`) is a reach seed over taken writes `hr` (`Rule::removals`).
    pub fn reach_removal(&self, rule: &Rule, l: Id, hr: &Set) -> bool {
        let Some(e) = self.removes(l) else { return false };
        match rule.removals {
            Removals::Any => true,
            Removals::TakesWrite => self.w.records.contains(&e) || self.witness(rule, l, hr).is_some(),
        }
    }
    /// Under `Removals::TakesWrite`, removal `l`'s witness over taken writes `hr`: the first (by
    /// key) write on its own edge giving write or above ordered before it; none on a record edge
    /// (the record, which every reader holds, is its witness).
    pub fn witness(&self, rule: &Rule, l: Id, hr: &Set) -> Option<Id> {
        let e = self.removes(l)?;
        if rule.removals == Removals::Any || self.w.records.contains(&e) {
            return None;
        }
        hr.iter().copied().filter(|&j| self.gives_write(j) == Some(e) && self.w.key(j) < self.w.key(l)).min_by_key(|&j| self.w.key(j))
    }
    /// A held edge write giving read or above (any `until`): a link by which keys open.
    fn gives_read(&self, i: Id) -> Option<Edge> {
        match &self.w.commits[i].kind {
            Kind::Edge { holder, role, .. } if *role >= Role::Read && !self.w.leave(i) => Some((*holder, self.on(i))),
            _ => None,
        }
    }
    /// The things of `a`'s chain to `t` over `h` (spec/permissions.md §4 Chain certificates, as
    /// main builds them): `a` and the things on any path from `a` to `t` over record edges and
    /// edges chained grants of `ch` set, at any time.
    pub fn chain_things(&self, h: &Set, ch: &Set, a: Thing, t: Thing) -> Things {
        let edges: Vec<Edge> = self.w.records.iter().copied().chain(h.iter().filter(|&&i| ch.contains(&i) && self.grant(i)).filter_map(|&i| self.w.sets(i))).collect();
        let grow = |mut x: Things, fwd: bool| loop {
            let n = x.len();
            x.extend(edges.iter().filter(|e| x.contains(if fwd { &e.0 } else { &e.1 })).map(|e| if fwd { e.1 } else { e.0 }).collect::<Vec<_>>());
            if x.len() == n {
                return x;
            }
        };
        let (fwd, back) = (grow(Things::from([a]), true), grow(Things::from([t]), false));
        let mut out: Things = fwd.intersection(&back).copied().collect();
        out.insert(a);
        out
    }
    /// The edges of `h`'s edge writes joining two of `things`.
    fn edges_among(&self, h: &Set, things: &Things) -> BTreeSet<Edge> {
        h.iter().filter_map(|&i| self.w.sets(i)).filter(|e| things.contains(&e.0) && things.contains(&e.1)).collect()
    }
    /// Part `i`'s stated path is not known over `h`: its entry opens late (`World::opens`) and
    /// `h` lacks what opens it.
    pub fn hidden(&self, h: &Set, i: Id) -> bool {
        self.opens.get(&i).is_some_and(|o| !h.contains(o))
    }

    // ---- The closure (OPEN 10) ----

    /// The edge-class commits of `h` the closure may take under `rule` (None: all).
    pub fn takes(&self, rule: &Rule, h: &Set) -> Option<Set> {
        match rule.closure.takes {
            Takes::All => None,
            Takes::Chained => Some(self.chained(h)),
            Takes::Applied => {
                let trust = self.trust.intersection(h).copied().collect();
                Some(paths::judge(&self.w, &self.rules, &View { held: h.clone(), leaves: None, trust }).applied)
            }
        }
    }
    /// The chained edge-class commits of `h` (spec/permissions.md §4 Chained writes, read with
    /// `paths::first_chained`'s authority): in key order, each whose author has, over record
    /// edges and the edges earlier chained writes set (applied or not, at the highest role and
    /// invite each set, `until` disregarded), admin on its target; an invite on its target for an
    /// invite grant (`paths` `invite_grant`); admin on its holder for a self-removal; write on its
    /// target for a finalize. Only the first two set an edge.
    /// Grows with `h`; every write any walk over `h` applies is in it.
    pub fn chained(&self, h: &Set) -> Set {
        let mut max: BTreeMap<Edge, Role> = self.w.records.iter().map(|&e| (e, Role::Admin)).collect();
        let mut inv = max.clone();
        let get = |m: &BTreeMap<Edge, Role>, e: &Edge| m.get(e).copied().unwrap_or(Role::None);
        let mut order: Vec<Id> = h.iter().copied().filter(|&i| self.w.edge_class(i)).collect();
        order.sort_by_key(|&i| self.w.key(i));
        let mut out = Set::new();
        for i in order {
            let c = &self.w.commits[i];
            if !self.w.well(i) {
                continue;
            }
            let hops = self.w.hops(i);
            let least = hops.iter().map(|e| get(&max, e)).min().unwrap_or(Role::Admin);
            match &c.kind {
                Kind::Edge { finalize: true, .. } if least >= Role::Write => {
                    out.insert(i);
                }
                Kind::Edge { .. } if self.w.leave(i) && least == Role::Admin => {
                    out.insert(i);
                }
                Kind::Edge { holder, role, until, invite, finalize: false, .. } if !self.w.leave(i) => {
                    let lvl = (*invite <= *role && paths::alive((*role, *until), c.ts) > Role::None && *role < Role::Admin).then_some(*role);
                    let invited = lvl.is_some_and(|lvl| hops.split_last().is_some_and(|(l, b)| get(&inv, l) >= lvl && b.iter().all(|e| get(&max, e) >= lvl)));
                    if least == Role::Admin || invited {
                        out.insert(i);
                        let e = (*holder, c.on);
                        let m = max.entry(e).or_insert(Role::None);
                        *m = (*m).max(*role);
                        let m = inv.entry(e).or_insert(Role::None);
                        *m = (*m).max(give_invite(*role, *invite));
                    }
                }
                _ => {}
            }
        }
        out
    }
    /// A grant: an edge write setting its edge (no self-removal, no finalize) to a role, `until`
    /// disregarded.
    pub fn grant(&self, i: Id) -> bool {
        matches!(&self.w.commits[i].kind, Kind::Edge { role, finalize: false, .. } if *role > Role::None) && !self.w.leave(i)
    }
    /// Edge write `i` leaves its holder no grant (no role, or `until` 0: a removal, a self-removal,
    /// a finalize): a commit with one applies none of its edge writes on its thing until the
    /// creation of the entry it resets is held; a reset beside a put of a live grant is not waited
    /// for (spec/permissions.md §2 Edge writes; finding 25).
    pub fn ends_grant(&self, i: Id) -> bool {
        matches!(&self.w.commits[i].kind, Kind::Edge { role, until, .. } if *role == Role::None || *until == Some(0))
    }
    /// The creation of the entry edge write `i` resets: the first grant on its edge in key order
    /// before it that is chained over everything written (an entry no walk creates is none); None
    /// where `i` creates it.
    pub fn creation(&self, i: Id) -> Option<Id> {
        let n = self.w.commits.len();
        let compute = || {
            let ch = self.chained(&(0..n).collect());
            (0..n).map(|i| {
                let e = self.w.sets(i)?;
                (0..n).filter(|&j| self.w.sets(j) == Some(e) && self.grant(j) && ch.contains(&j) && self.w.key(j) < self.w.key(i)).min_by_key(|&j| self.w.key(j))
            }).collect::<Vec<_>>()
        };
        let memo = self.creation_memo.get_or_init(compute);
        if memo.len() == n { memo[i] } else { compute()[i] }
    }
    /// `j` is ordered before `i` as `i`'s verdict reads it: by key for an edge-class `i`, by `ts`
    /// (the start of its `ts`) for content.
    fn before(&self, j: Id, i: Id) -> bool {
        if self.w.edge_class(i) {
            self.w.key(j) < self.w.key(i)
        } else {
            self.w.commits[j].ts < self.w.commits[i].ts
        }
    }
    /// `m`'s stated path is joined over `h`: each edge of it that is no record edge holds a
    /// chained grant of `ch` ordered before `m` (under `Join::Needed`, one giving what `m` needs
    /// there).
    pub fn joined(&self, h: &Set, ch: &Set, m: Id) -> bool {
        self.w.hops(m).iter().filter(|e| !self.w.records.contains(e)).all(|&e| h.iter().any(|&j| self.w.sets(j) == Some(e) && ch.contains(&j) && self.joins(j, m, e, false) && self.before(j, m)))
    }
    /// Edge write `j` on edge `e` can join `e` for part `m` (`World::join`): a grant, and under
    /// `Join::Needed` with `Pend::Granted` one giving at least what `m` needs of `e`, `until`
    /// disregarded.
    fn joins(&self, j: Id, m: Id, e: Edge, pending: bool) -> bool {
        if !self.grant(j) {
            return false;
        }
        let needed = self.join == Join::Needed || (pending && self.join == Join::PendNeeded);
        if !needed || self.pend != Pend::Granted {
            return true;
        }
        let Kind::Edge { role, invite, .. } = &self.w.commits[j].kind else { return false };
        match self.need(m, e) {
            (r, true) => give_invite(*role, *invite) >= r,
            (r, false) => *role >= r,
        }
    }
    /// The least part `m` needs of edge `e` its verdict reads (roles-model `paths` `need`, for a
    /// write no pass applied): a role, or (true) an invite. Content-class parts write; an edge
    /// write admin, a finalize write, an invite grant its level (on its path's last edge as an
    /// invite, under `invite_check`).
    pub fn need(&self, m: Id, e: Edge) -> (Role, bool) {
        let c = &self.w.commits[m];
        match &c.kind {
            Kind::Edge { .. } if !self.w.hops(m).contains(&e) => (Role::Admin, false),
            Kind::Edge { finalize: true, .. } => (Role::Write, false),
            Kind::Edge { role, until, invite, .. } if !self.w.leave(m) && *invite <= *role && paths::alive((*role, *until), c.ts) > Role::None && *role < Role::Admin => (*role, self.rules.invite_check && self.w.hops(m).last() == Some(&e)),
            Kind::Edge { .. } => (Role::Admin, false),
            _ => (Role::Write, false),
        }
    }
    /// The evidence closure of `seeds` over `avail` under `rule.closure`: the seeds, the other
    /// parts of a member's commit on its thing, the taken edge writes on an edge of a member's
    /// stated path (where joined, under `joined`).
    /// The draft is `paths::evidence`.
    pub fn closure(&self, rule: &Rule, seeds: &Set, avail: &Set) -> Set {
        self.closure_with(rule, seeds, BTreeSet::new(), avail)
    }
    /// `closure`, with `edges` brought from the start.
    fn closure_with(&self, rule: &Rule, seeds: &Set, mut edges: BTreeSet<Edge>, avail: &Set) -> Set {
        let c = rule.closure;
        if c == (Closure { commit_edges: CommitEdges::Off, ..Closure::drafted() }) && edges.is_empty() && self.opens.is_empty() {
            return paths::evidence(&self.w, seeds, avail);
        }
        let takes = self.takes(rule, avail);
        let ok = |i: Id| takes.as_ref().is_none_or(|t| t.contains(&i));
        let ch = if c.joined || c.any_path { self.chained(avail) } else { Set::new() };
        let mut s = seeds.clone();
        let mut done = Set::new();
        let mut brought = Set::new();
        loop {
            for &m in s.difference(&done.clone()) {
                done.insert(m);
                if self.hidden(avail, m) {
                    // a part whose path entry has not opened brings nothing
                } else if c.any_path {
                    let a = self.w.commits[m].signer;
                    edges.extend(self.edges_among(avail, &self.chain_things(avail, &ch, a, self.on(m))));
                    if let Some(hd) = self.holder(m) {
                        edges.extend(self.edges_among(avail, &self.chain_things(avail, &ch, a, hd)));
                    }
                } else if !c.joined || self.joined(avail, &ch, m) {
                    edges.extend(self.w.hops(m).iter().copied());
                }
                if self.w.edge_class(m) {
                    let parts: Vec<Id> = self.w.part_ids(self.w.cid(m)).filter(|&p| self.on(p) == self.on(m)).collect();
                    match c.commit_edges {
                        CommitEdges::Off => {}
                        CommitEdges::Creations => brought.extend(parts.iter().filter_map(|&p| self.creation(p)).filter(|j| avail.contains(j))),
                        CommitEdges::AllWrites => edges.extend(parts.iter().filter(|&&p| p != m).filter_map(|&p| self.w.sets(p))),
                    }
                }
            }
            let cids: std::collections::BTreeSet<(Id, Thing)> = s.iter().map(|&i| (self.w.cid(i), self.on(i))).collect();
            let more: Vec<Id> = avail
                .iter()
                .copied()
                .filter(|i| !s.contains(i))
                .filter(|&i| {
                    cids.contains(&(self.w.cid(i), self.on(i)))
                        || brought.contains(&i)
                        || ok(i)
                            && match &self.w.commits[i].kind {
                                Kind::Edge { .. } => self.w.sets(i).is_some_and(|e| edges.contains(&e)),
                                _ => false,
                            }
                })
                .collect();
            if more.is_empty() {
                return s;
            }
            s.extend(more);
        }
    }
    /// The bodies S carries of `h`.
    pub fn bodies(&self, s: Sid, units: &BTreeMap<Sid, Things>, h: &Set) -> Set {
        h.iter().copied().filter(|&i| units[&s].contains(&self.on(i))).collect()
    }
    /// The copies among S's entries: commits on things outside its unit.
    pub fn copies(&self, st: &State, s: Sid) -> Set {
        st.entries[&s].iter().copied().filter(|&i| !st.units[&s].contains(&self.on(i))).collect()
    }

    // ---- Leaves (`Lists::Travels`) ----

    /// `r`'s content entries on `t`: frontier entries naming commits with no edge-class part.
    pub fn content_entries(&self, r: Id, t: Thing) -> Set {
        match &self.w.commits[r].kind {
            Kind::Edge { frontier, .. } => frontier.get(&t).map(|l| l.iter().copied().filter(|&c| !self.w.edge_class(c)).collect()).unwrap_or_default(),
            _ => Set::new(),
        }
    }
    /// The leaves `r`'s root commits to: a thing per non-empty content entry set.
    pub fn leaves_of(&self, r: Id) -> Leafs {
        match &self.w.commits[r].kind {
            Kind::Edge { frontier, .. } => frontier.keys().filter(|&&t| !self.content_entries(r, t).is_empty()).map(|&t| (r, t)).collect(),
            _ => Leafs::new(),
        }
    }
    /// Leaf `l`'s verdict reads commit `j` over held set `h` (`ch` its chained writes): `j` on its
    /// thing, with no edge-class part, resting on the lowered edge, in any order (a list keeps what
    /// its writer received, stamped after the lowering or not), and under `LeafKeep::Cuts` the
    /// lowering taking write away there (`cuts_write`). What a reader without the leaf waits on.
    pub fn reads(&self, keep: LeafKeep, l: Leaf, j: Id, h: &Set, ch: &Chained) -> bool {
        let (r, t) = l;
        self.on(j) == t && !self.w.edge_class(j) && self.w.sets(r).is_some_and(|e| self.w.hops(j).contains(&e)) && (keep != LeafKeep::Cuts || self.cuts_write(r, h, ch))
    }
    /// Lowering `r` takes write away over held set `h` (`ch` its chained writes): it gives its
    /// edge below write at its `ts` (`removes`), and the edge is a record edge or a held chained
    /// write on it giving write or above is ordered before it. What content resting on the edge
    /// needs is write, so this is when its list is read for content (a superset of the walk's
    /// cuts: every write the walk applies is chained). The same test as reach's
    /// `Removals::TakesWrite`, so a leaf waited on travels with the errand.
    pub fn cuts_write(&self, r: Id, h: &Set, ch: &Chained) -> bool {
        let Some(e) = self.removes(r) else { return false };
        self.w.records.contains(&e) || h.iter().any(|&j| self.gives_write(j) == Some(e) && self.w.key(j) < self.w.key(r) && ch.get_or_init(|| self.chained(h)).contains(&j))
    }
    /// Leaf `l` is evidence of `j` under `keep` over `h` (`ch` its chained writes).
    fn evidence_of(&self, keep: LeafKeep, l: Leaf, j: Id, h: &Set, ch: &Chained) -> bool {
        match keep {
            LeafKeep::Named => self.on(j) == l.1 && self.content_entries(l.0, l.1).iter().any(|&c| self.w.names(c, j)),
            LeafKeep::Judged | LeafKeep::Cuts => self.reads(keep, l, j, h, ch),
        }
    }
    /// The leaves S requires over held set `h`: of each lowering in S's required set, the leaf
    /// for a thing where it is evidence of a commit S requires.
    pub fn req_leaves(&self, rule: &Rule, s: Sid, units: &BTreeMap<Sid, Things>, h: &Set) -> Leafs {
        let Lists::Travels(keep) = rule.lists else { return Leafs::new() };
        let req = self.req(rule, s, units, h);
        let ch = Chained::new();
        let home = |l: Leaf| {
            let kept = match rule.leaves_home {
                Home::None => false,
                Home::Far => l.1 != self.on(l.0),
                Home::All => true,
            };
            kept && units[&s].contains(&self.on(l.0))
        };
        req.iter().flat_map(|&r| self.leaves_of(r)).filter(|&l| home(l) || req.iter().any(|&j| self.evidence_of(keep, l, j, h, &ch))).collect()
    }
    /// Not an addendum, or one listing a held commit its list can keep (no edge-class part and no
    /// addendum, resting on its removal's edge): an addendum is evidence of those and leaves with
    /// the last. (An addendum listing an addendum would keep its writer's own unlogged one alive.)
    pub fn addendum_live(&self, i: Id, h: &Set) -> bool {
        match &self.w.commits[i].kind {
            Kind::Addendum { list, removal } => list.iter().any(|&j| h.contains(&j) && !matches!(self.w.commits[j].kind, Kind::Edge { .. } | Kind::Addendum { .. }) && self.w.sets(*removal).is_some_and(|e| self.w.hops(j).contains(&e))),
            _ => true,
        }
    }
    /// The reading world of a node holding leaves `l`: each lowering's frontier keeps its role
    /// entries and the content entries of the leaves held.
    fn listed_world(&self, l: &Leafs) -> paths::World {
        let mut w = self.w.clone();
        for r in 0..w.commits.len() {
            let ec: Set = (0..w.commits.len()).filter(|&c| self.w.edge_class(c)).collect();
            w.edit(r, |k| match k {
                Kind::Edge { holder, role, until, mut frontier, invite, finalize } => {
                    for (t, list) in frontier.iter_mut() {
                        if !l.contains(&(r, *t)) {
                            list.retain(|c| ec.contains(c));
                        }
                    }
                    Kind::Edge { holder, role, until, frontier, invite, finalize }
                }
                k => k,
            });
        }
        w
    }

    // ---- Delivery ----

    /// The sync IDs node `n` syncs: its own, closed under the standing duty.
    pub fn syncs(&self, n: usize, units: &BTreeMap<Sid, Things>) -> Things {
        let mut sy: Things = self.nodes[n].syncs.iter().copied().filter(|s| self.sids.contains(s)).collect();
        loop {
            let more: Vec<Thing> = sy.iter().flat_map(|s| units[s].iter().copied()).filter(|x| self.sids.contains(x) && !sy.contains(x)).collect();
            if more.is_empty() {
                return sy;
            }
            sy.extend(more);
        }
    }
    fn own(&self, st: &State, n: usize) -> Set {
        st.written.iter().copied().filter(|&i| self.by[i] == n && !st.forgotten.contains(&i)).collect()
    }
    /// What the thief logs under S: its own bodies there and the grants (no lowering) they rest on.
    fn thief_logs(&self, rule: &Rule, s: Sid, units: &BTreeMap<Sid, Things>, held: &Set, own: &Set) -> Set {
        let mine: Set = own.iter().copied().filter(|&i| units[&s].contains(&self.on(i))).collect();
        // it knows its own paths, opened or not
        let known: Set = held.iter().chain(own.iter().filter_map(|i| self.opens.get(i)).filter(|&&o| o < self.by.len())).copied().collect();
        self.closure(rule, &mine, &known).into_iter().filter(|&i| held.contains(&i) && (own.contains(&i) || self.removes(i).is_none())).collect()
    }
    /// The commits node `n`'s errand carries: its own lowerings, and under `Scope::Edge` its own
    /// later edge writes on a held lowering's edge; each with the target whose sync IDs it goes
    /// to.
    fn errand_items(&self, rule: &Rule, own: &Set, held: &Set, fresh: &Set) -> Vec<(Id, Thing)> {
        let mut out = vec![];
        for &i in own {
            if !rule.standing && !fresh.contains(&i) {
                continue;
            }
            if let Some((_, t)) = self.removes(i) {
                out.push((i, t));
                continue;
            }
            if rule.scope != Scope::Edge {
                continue;
            }
            let lowered = |e: Edge, after: Option<Id>| held.iter().any(|&l| self.removes(l) == Some(e) && after.is_none_or(|a| self.w.key(l) < self.w.key(a)));
            match &self.w.commits[i].kind {
                Kind::Edge { .. } if lowered(self.w.sets(i).unwrap(), Some(i)) => out.push((i, self.on(i))),
                _ => {}
            }
        }
        out
    }
    /// Where an errand for target `t` logs, and what node `n` holds once it held each of those
    /// for the errand: the target's own sync ID and those its taken grants (grants naming it,
    /// under its own sync ID) reach, one level (`Direct`) or all (`Transitive`).
    fn errand_targets(&self, rule: &Rule, st: &State, t: Thing, held: &Set) -> (Things, Set) {
        let mut seen = Things::new();
        let mut todo = vec![(t, 0)];
        let mut h = held.clone();
        while let Some((x, depth)) = todo.pop() {
            if !seen.insert(x) {
                continue;
            }
            if let Some(e) = st.entries.get(&x) {
                h.extend(e.iter().copied());
            }
            if rule.errand == Errand::Direct && depth >= 1 {
                continue;
            }
            // the grants the closure takes (a write no walk applies leads nowhere)
            let takes = self.takes(rule, &h);
            let steps: Vec<Edge> = self.records(rule).chain(h.iter().filter(|j| takes.as_ref().is_none_or(|t| t.contains(j))).filter_map(|&j| self.gives_write(j))).collect();
            for (hd, y) in steps {
                if hd == x {
                    todo.push((y, depth + 1));
                }
            }
        }
        (seen.into_iter().filter(|x| self.sids.contains(x)).collect(), h)
    }
    /// Runs node `n`'s errands over `held`: what each sync ID gains, and under `Lists::Travels`
    /// the leaves of its lowerings that are evidence there (a lowering's copy carries its leaves
    /// for the target unit's things).
    fn errands(&self, rule: &Rule, st: &State, n: usize, held: &Set, fresh: &Set) -> (BTreeMap<Sid, Set>, BTreeMap<Sid, Leafs>) {
        let mut out: BTreeMap<Sid, Set> = BTreeMap::new();
        let mut lv: BTreeMap<Sid, Leafs> = BTreeMap::new();
        if !self.nodes[n].honest {
            return (out, lv);
        }
        let own = self.own(st, n);
        // what the closure takes (a write no walk applies is nobody's evidence)
        let takes = self.takes(rule, held);
        let taken = |i: &Id| takes.as_ref().is_none_or(|t| t.contains(i));
        // a grant naming a holder goes under the holder's sync ID by its granter (spec/sync-inbox.md
        // §5 Delivery of a grant)
        for &i in own.iter().filter(|i| taken(i)) {
            if let Some(hd) = self.holder(i).filter(|hd| self.sids.contains(hd)) {
                out.entry(hd).or_default().extend(self.closure(rule, &Set::from([i]), held));
            }
        }
        if rule.errand == Errand::Off {
            return (out, lv);
        }
        for (i, t, targets, h, hr) in self.errand_plan(rule, st, n, held, fresh) {
            for x in targets {
                let reach = self.reach(rule, t, &st.units[&x], &hr).unwrap_or_default();
                let mut seed = reach;
                seed.insert(i);
                seed.extend(self.witness(rule, i, &hr));
                out.entry(x).or_default().extend(self.closure(rule, &seed, &h));
                if let Lists::Travels(keep) = rule.lists {
                    let bodies = self.bodies(x, &st.units, &h);
                    let ch = Chained::new();
                    lv.entry(x).or_default().extend(self.leaves_of(i).into_iter().filter(|&l| bodies.iter().any(|&j| self.evidence_of(keep, l, j, &h, &ch))));
                }
            }
        }
        (out, lv)
    }
    /// What node `n`'s errand runs for over `held`: each item (`errand_items`, taken) with the
    /// thing its targets start from, its target sync IDs, what the remover held once it read them
    /// (`errand_targets`) and the taken writes among that; a removal taking no write away is left
    /// out (it travels as any edge write, Role changes travel).
    #[allow(clippy::type_complexity)]
    fn errand_plan(&self, rule: &Rule, st: &State, n: usize, held: &Set, fresh: &Set) -> Vec<(Id, Thing, Things, Set, Set)> {
        let takes = self.takes(rule, held);
        let taken = |i: &Id| takes.as_ref().is_none_or(|t| t.contains(i));
        let mut out = vec![];
        for (i, t) in self.errand_items(rule, &self.own(st, n), held, fresh).into_iter().filter(|(i, _)| taken(i)) {
            let (targets, h) = self.errand_targets(rule, st, t, held);
            let hr: Set = match self.takes(rule, &h) {
                Some(t) => h.iter().copied().filter(|i| t.contains(i) || !self.w.edge_class(*i)).collect(),
                None => h.clone(),
            };
            if self.removes(i).is_some() && !self.reach_removal(rule, i, &hr) {
                continue;
            }
            out.push((i, t, targets, h, hr));
        }
        out
    }

    /// The state before any event.
    pub fn start(&self) -> State {
        let entries = self.sids.iter().map(|&s| (s, Set::new())).collect();
        let leaves = self.sids.iter().map(|&s| (s, Leafs::new())).collect();
        State { units: self.units.clone(), entries, leaves, held: vec![Set::new(); self.nodes.len()], held_leaves: vec![Leafs::new(); self.nodes.len()], ..State::default() }
    }
    /// Applies event `k`, then lets the nodes log until nothing moves.
    pub fn apply(&self, rule: &Rule, st: &mut State, k: usize) {
        let mut fresh = Set::new();
        match self.events[k] {
            Ev::Write(i) => {
                st.written.insert(i);
                fresh.insert(i);
            }
            Ev::Join(x, s) => {
                st.units.get_mut(&s).unwrap().insert(x);
            }
            Ev::Leave(x, s) => {
                st.units.get_mut(&s).unwrap().remove(&x);
                if rule.placement == Placement::AtLog {
                    self.unplace(st, s, |i| self.on(i) == x);
                }
            }
        }
        st.step = k + 1;
        self.settle(rule, st, &fresh);
    }
    /// `AtLog`: removes S's bodies matching `gone` and every copy left placed for nothing.
    fn unplace(&self, st: &mut State, s: Sid, gone: impl Fn(Id) -> bool) {
        let bodies: Vec<Id> = st.entries[&s].iter().copied().filter(|&i| gone(i) && !st.placed.contains_key(&(s, i))).collect();
        let e = st.entries.get_mut(&s).unwrap();
        for b in &bodies {
            e.remove(b);
        }
        let mut drop = vec![];
        for ((s2, c), by) in st.placed.iter_mut() {
            if *s2 != s {
                continue;
            }
            for b in &bodies {
                by.remove(b);
            }
            if gone(*c) {
                by.clear();
            }
            if by.is_empty() {
                drop.push(*c);
            }
        }
        for c in drop {
            st.placed.remove(&(s, c));
            if !st.errands.get(&s).is_some_and(|e| e.contains(&c)) {
                st.entries.get_mut(&s).unwrap().remove(&c);
            }
        }
    }
    /// Every event in order; `each` sees the state after each.
    pub fn run(&self, rule: &Rule, mut each: impl FnMut(&State)) -> State {
        let mut st = self.start();
        for k in 0..self.events.len() {
            self.apply(rule, &mut st, k);
            each(&st);
        }
        st
    }
    /// The commit `i` released or covered at every node: it and what only it needed leave.
    pub fn forget(&self, rule: &Rule, st: &mut State, i: Id) {
        st.forgotten.insert(i);
        for h in st.held.iter_mut() {
            h.remove(&i);
        }
        for e in st.errands.values_mut() {
            e.remove(&i);
        }
        if rule.placement == Placement::AtLog {
            for s in self.sids.clone() {
                self.unplace(st, s, |c| c == i);
            }
        } else {
            for e in st.entries.values_mut() {
                e.remove(&i);
            }
        }
        self.settle(rule, st, &Set::new());
    }
    fn settle(&self, rule: &Rule, st: &mut State, fresh: &Set) {
        let mut fresh = fresh.clone();
        for _ in 0..ROUNDS {
            st.rounds += 1;
            let before = (st.entries.clone(), st.held.clone(), st.leaves.clone(), st.held_leaves.clone());
            match rule.placement {
                Placement::Function => self.round_function(rule, st, &fresh),
                Placement::AtLog => {
                    assert_eq!(rule.lists, Lists::Whole, "leaves are modelled with Placement::Function only");
                    self.round_atlog(rule, st, &fresh)
                }
            }
            // an errand at writing runs in the first round only
            fresh.clear();
            if (st.entries.clone(), st.held.clone(), st.leaves.clone(), st.held_leaves.clone()) == before {
                return;
            }
        }
        st.unsettled = true;
    }
    fn round_function(&self, rule: &Rule, st: &mut State, fresh: &Set) {
        // nothing is kept for its past: an errand's entry stays while a holder's view requires it
        let mut new: BTreeMap<Sid, Set> = self.sids.iter().map(|&s| (s, Set::new())).collect();
        let mut new_leaves: BTreeMap<Sid, Leafs> = self.sids.iter().map(|&s| (s, Leafs::new())).collect();
        for n in 0..self.nodes.len() {
            let sy = self.syncs(n, &st.units);
            let own = self.own(st, n);
            let mut held: Set = st.held[n].iter().chain(&own).copied().chain(sy.iter().flat_map(|s| st.entries[s].iter().copied())).filter(|i| !st.forgotten.contains(i)).collect();
            // keep only what a synced sync ID requires, and its own writes
            loop {
                let keep: Set = sy.iter().flat_map(|&s| self.req(rule, s, &st.units, &held)).chain(own.iter().copied()).filter(|i| held.contains(i)).collect();
                if keep == held {
                    break;
                }
                held = keep;
            }
            for &s in &sy {
                let logs = if self.nodes[n].honest { self.req(rule, s, &st.units, &held) } else { self.thief_logs(rule, s, &st.units, &held, &own) };
                new.get_mut(&s).unwrap().extend(logs);
            }
            // leaves: a node holds those it was given (a synced sync ID's, its own lowerings') while
            // a synced sync ID requires them over its holdings, and logs them there; the thief none
            let mine: Leafs = own.iter().flat_map(|&r| self.leaves_of(r)).collect();
            let avail: Leafs = st.held_leaves[n].iter().chain(&mine).copied().chain(sy.iter().flat_map(|s| st.leaves[s].iter().copied())).filter(|l| held.contains(&l.0)).collect();
            let mut keep = mine.clone();
            for &s in &sy {
                let req = self.req_leaves(rule, s, &st.units, &held);
                let logs: Leafs = req.intersection(&avail).copied().collect();
                keep.extend(logs.iter().copied());
                if self.nodes[n].honest {
                    new_leaves.get_mut(&s).unwrap().extend(logs);
                }
            }
            let (items, lv) = self.errands(rule, st, n, &held, fresh);
            for (s, items) in items {
                new.get_mut(&s).unwrap().extend(items);
            }
            // an errand carries the leaves its remover holds
            for (s, l) in lv {
                new_leaves.get_mut(&s).unwrap().extend(l.intersection(&avail));
            }
            st.held[n] = held;
            st.held_leaves[n] = keep;
        }
        st.entries = new;
        st.leaves = new_leaves;
    }
    fn round_atlog(&self, rule: &Rule, st: &mut State, fresh: &Set) {
        for n in 0..self.nodes.len() {
            let sy = self.syncs(n, &st.units);
            let own = self.own(st, n);
            let honest = self.nodes[n].honest;
            let held: Set = own.iter().copied().chain(sy.iter().flat_map(|s| st.entries[s].iter().copied())).filter(|i| !st.forgotten.contains(i)).collect();
            for &s in &sy {
                let unit = st.units[&s].clone();
                for &c in &held {
                    let body = unit.contains(&self.on(c)) || self.holder(c) == Some(s);
                    if !body || st.entries[&s].contains(&c) || (!honest && !own.contains(&c)) {
                        continue;
                    }
                    st.entries.get_mut(&s).unwrap().insert(c);
                    for e in paths::evidence(&self.w, &Set::from([c]), &held) {
                        if e == c || unit.contains(&self.on(e)) || (!honest && self.removes(e).is_some()) {
                            continue;
                        }
                        st.entries.get_mut(&s).unwrap().insert(e);
                        st.placed.entry((s, e)).or_default().insert(c);
                    }
                }
            }
            st.held[n] = held.clone();
            for (s, items) in self.errands(rule, st, n, &held, fresh).0 {
                st.errands.entry(s).or_default().extend(items.iter().copied());
                st.entries.get_mut(&s).unwrap().extend(items);
            }
        }
    }

    // ---- Judging ----

    /// The edges a commit's verdict reads edge writes of: its path's.
    pub fn edges_of(&self, i: Id) -> Vec<Edge> {
        self.w.hops(i).to_vec()
    }
    /// `i` pends over `h`: an edge it reads, no record edge, has no held edge write ordered before
    /// it, or the latest such write pends.
    pub fn pend(&self, h: &Set, i: Id) -> bool {
        let ch = (self.pend == Pend::Granted).then(|| self.chained(h));
        self.pend_with(h, ch.as_ref(), i)
    }
    /// `pend` with `h`'s chained writes given under `Pend::Granted`.
    fn pend_with(&self, h: &Set, ch: Option<&Set>, i: Id) -> bool {
        if self.hidden(h, i) {
            return true;
        }
        if self.creations && self.w.edge_class(i) && self.w.part_ids(self.w.cid(i)).any(|p| self.on(p) == self.on(i) && self.ends_grant(p) && self.creation(p).is_some_and(|c| !h.contains(&c))) {
            return true;
        }
        // under J3 a hop no chained grant joins is judged, not waited on
        let refused = ch.is_some() && self.join == Join::Refused;
        self.edges_of(i).into_iter().filter(|e| !self.w.records.contains(e)).any(|e| {
            let on_e = || h.iter().copied().filter(|&j| self.w.sets(j) == Some(e) && self.before(j, i) && ch.is_none_or(|c| c.contains(&j)));
            if ch.is_some() && !refused && !on_e().any(|j| self.joins(j, i, e, true)) {
                return true;
            }
            match on_e().max_by_key(|&j| self.w.key(j)) {
                None => !refused,
                Some(j) => self.pend_with(h, ch, j),
            }
        })
    }
    /// Under `Lists::Travels`: `i` has no edge-class part and a held lowering's root shows a leaf
    /// for `i`'s thing that would read `i`, not held: `i` waits for it.
    pub fn pend_leaf(&self, keep: LeafKeep, h: &Set, ch: &Chained, l: &Leafs, i: Id) -> bool {
        !self.w.edge_class(i) && h.iter().any(|&r| self.w.lowers(r).is_some() && self.leaves_of(r).contains(&(r, self.on(i))) && self.reads(keep, (r, self.on(i)), i, h, ch) && !l.contains(&(r, self.on(i))))
    }
    /// The verdict on each of `ids` at a node judging from `s`.
    pub fn verdicts(&self, s: &Seen, ids: &Set) -> BTreeMap<Id, Verdict> {
        let (rd, lw);
        match &s.lists {
            None => rd = paths::judge(&self.w, &self.rules, &s.v),
            Some(l) => {
                lw = self.listed_world(l);
                rd = paths::judge(&lw, &self.rules, &View { leaves: None, ..s.v.clone() });
            }
        }
        let ch = (self.pend == Pend::Granted).then(|| self.chained(&s.v.held));
        let leaf_ch = Chained::new();
        if let Some(c) = &ch {
            let _ = leaf_ch.set(c.clone());
        }
        ids.iter()
            .map(|&i| {
                let ok = if self.w.edge_class(i) { rd.applied.contains(&i) } else { rd.valid.contains(&i) || rd.copied.contains(&i) };
                let waits = self.pend_with(&s.v.held, ch.as_ref(), i) || s.lists.as_ref().is_some_and(|l| self.pend_leaf(s.keep, &s.v.held, &leaf_ch, l, i));
                (i, if waits { Verdict::Pending } else if ok { Verdict::Valid } else { Verdict::Invalid })
            })
            .collect()
    }
    /// What a reader holding sync ID `s` alone judges from (its held set minus `without`).
    pub fn reader(&self, rule: &Rule, st: &State, s: Sid, without: &Set) -> Seen {
        let held: Set = st.entries[&s].difference(without).copied().collect();
        let mut seen = self.reader_of(rule, &st.units[&s], held);
        if let Lists::Travels(keep) = rule.lists {
            seen.lists = Some(st.leaves[&s].iter().copied().filter(|l| seen.v.held.contains(&l.0)).collect());
            seen.keep = keep;
            seen.v.leaves = None;
        }
        seen
    }
    fn reader_of(&self, rule: &Rule, unit: &Things, held: Set) -> Seen {
        let mut leaves = unit.clone();
        if rule.leaves == Leaves::Evidence {
            leaves.extend(held.iter().filter(|&&i| self.w.edge_class(i)).map(|&i| self.on(i)));
        }
        let trust = self.trust.intersection(&held).copied().collect();
        Seen { v: View { held, leaves: Some(leaves), trust }, lists: None, keep: LeafKeep::Judged }
    }
    /// What the node holding everything written (and not forgotten) judges from.
    pub fn full(&self, st: &State, without: &Set) -> Seen {
        let held: Set = st.written.iter().copied().filter(|i| !st.forgotten.contains(i) && !without.contains(i)).collect();
        let trust = self.trust.intersection(&held).copied().collect();
        Seen { v: View { held, leaves: None, trust }, lists: None, keep: LeafKeep::Judged }
    }
    /// What S should carry as bodies: every written commit on its unit's things.
    pub fn owed_bodies(&self, st: &State, s: Sid) -> Set {
        self.bodies(s, &st.units, &self.full(st, &Set::new()).v.held)
    }
    /// What S should carry under `rule`: the owed bodies, less (`Lists::Travels`) an addendum
    /// listing no held commit (evidence of nothing held).
    pub fn owed(&self, rule: &Rule, st: &State, s: Sid) -> Set {
        let all = self.full(st, &Set::new()).v.held;
        let mut b = self.bodies(s, &st.units, &all);
        if let Lists::Travels(_) = rule.lists {
            b.retain(|&i| self.addendum_live(i, &all));
        }
        b
    }
}

/// The `Join` a new world judges by: `Join::Needed` (README OPEN 16, *proposed*), or by hand
/// `OSIS_EV_JOIN` naming one (`Join::name`), so every property and search runs under it.
fn join_default() -> Join {
    match std::env::var("OSIS_EV_JOIN") {
        Ok(n) if !n.is_empty() => Join::ALL.into_iter().find(|j| j.name() == n).unwrap_or_else(|| panic!("OSIS_EV_JOIN {n}: one of j1-any, j2-needed, j3-refused, j4-pend-needed")),
        _ => Join::Needed,
    }
}

/// The invite a value gives: every invite at admin, else its field at most its role (`paths`).
fn give_invite(role: Role, field: Role) -> Role {
    if role == Role::Admin {
        Role::Admin
    } else {
        field.min(role)
    }
}

// ---- Properties: failures, each named ----

#[derive(Clone, Debug, PartialEq)]
pub struct Fail {
    pub prop: &'static str,
    pub step: usize,
    pub sid: Sid,
    pub id: Id,
    pub reader: Option<Verdict>,
    pub full: Option<Verdict>,
}

impl World {
    /// P1 (and P2 for commits under several sync IDs): the reader of each sync ID judges every
    /// body it should carry as the node holding everything does (a body it lacks is judged
    /// absent: `None`).
    pub fn p1(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        self.p1_trusting(rule, st, &self.trust, "P1")
    }
    /// `p1` (`prop` naming its failures) for readers and a node holding everything that trust
    /// `trust` (each what of it it holds) in place of the world's: evidence carries no trust, so a
    /// reader trusting otherwise must still hold everything its own walk reads.
    pub fn p1_trusting(&self, rule: &Rule, st: &State, trust: &Set, prop: &'static str) -> Vec<Fail> {
        let trusting = |mut s: Seen| {
            s.v.trust = trust.intersection(&s.v.held).copied().collect();
            s
        };
        let fv = self.verdicts(&trusting(self.full(st, &Set::new())), &st.written);
        let mut out = vec![];
        let mut seen: BTreeMap<Id, Vec<(Sid, Option<Verdict>)>> = BTreeMap::new();
        for &s in &self.sids {
            let owed = self.owed(rule, st, s);
            let v = trusting(self.reader(rule, st, s, &Set::new()));
            let rv = self.verdicts(&v, &owed.intersection(&v.v.held).copied().collect());
            for &i in &owed {
                let r = rv.get(&i).copied();
                seen.entry(i).or_default().push((s, r));
                if r.is_none() && !self.nodes[self.by[i]].honest {
                    // the thief logs its own writes where it likes
                    continue;
                }
                if r != Some(fv[&i]) {
                    out.push(Fail { prop: if r.is_none() { "P1-carried" } else { prop }, step: st.step, sid: s, id: i, reader: r, full: Some(fv[&i]) });
                }
            }
        }
        for (i, per) in seen {
            let per: Vec<_> = per.into_iter().filter(|x| x.1.is_some()).collect();
            if per.len() > 1 && per.iter().any(|x| x.1 != per[0].1) {
                out.push(Fail { prop: "P2", step: st.step, sid: per[0].0, id: i, reader: per[0].1, full: per.iter().find(|x| x.1 != per[0].1).unwrap().1 });
            }
        }
        out
    }
    /// What each honest node logs under each sync ID it syncs at `st`: (node, sync ID, logs).
    fn honest_logs(&self, rule: &Rule, st: &State) -> Vec<(usize, Sid, Set)> {
        let mut out = vec![];
        for n in (0..self.nodes.len()).filter(|&n| self.nodes[n].honest) {
            for s in self.syncs(n, &st.units) {
                out.push((n, s, self.req(rule, s, &st.units, &st.held[n])));
            }
        }
        out
    }
    /// The things whose roster gives a role on a thing of `unit`: those joined to one by record
    /// edges and edges a chained grant over everything written sets (at any time).
    pub fn roster_reach(&self, st: &State, unit: &Things) -> Things {
        let all = self.full(st, &Set::new()).v.held;
        let ch = self.chained(&all);
        let edges: Vec<Edge> = self.w.records.iter().copied().chain(ch.iter().filter(|&&i| self.grant(i)).filter_map(|&i| self.w.sets(i))).collect();
        let mut back = unit.clone();
        loop {
            let n = back.len();
            back.extend(edges.iter().filter(|e| back.contains(&e.1)).map(|e| e.0).collect::<Vec<_>>());
            if back.len() == n {
                return back;
            }
        }
    }
    /// P9, no roster leaks: every copy an honest node logs under S is on a thing whose roster
    /// gives a role on a thing of S's unit (`roster_reach`), or in the closure of the grants
    /// naming S's thing or (`keys_open`) a thing it reads through, or on such a thing (Role
    /// changes travel: S's own roles, and the rosters of things S's readers read, by design).
    pub fn p9_leak(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        let mut out = vec![];
        for (n, s, logs) in self.honest_logs(rule, st) {
            let unit = &st.units[&s];
            let reach = self.roster_reach(st, unit);
            let held = &st.held[n];
            let takes = self.takes(rule, held);
            let hr: Set = held.iter().copied().filter(|i| takes.as_ref().is_none_or(|t| t.contains(i))).collect();
            let open = self.opened(rule, s, &hr);
            let own: Set = held.iter().copied().filter(|&i| self.holder(i).is_some_and(|hd| open.contains(&hd))).collect();
            let roles = self.closure(rule, &own, held);
            for &c in &logs {
                if !unit.contains(&self.on(c)) && !roles.contains(&c) && !reach.contains(&self.on(c)) && !open.contains(&self.on(c)) {
                    out.push(Fail { prop: "P9-leak", step: st.step, sid: s, id: c, reader: None, full: None });
                }
            }
        }
        out
    }
    /// P10, junk costs nothing: no honest node logs under S an edge-class commit on a thing
    /// outside S's unit that is unchained over everything written (a write by a non-admin, which
    /// no walk applies anywhere).
    pub fn p10_junk(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        let ch = self.chained(&self.full(st, &Set::new()).v.held);
        let mut out = vec![];
        for (_, s, logs) in self.honest_logs(rule, st) {
            for &c in &logs {
                if self.w.edge_class(c) && !st.units[&s].contains(&self.on(c)) && !ch.contains(&c) {
                    out.push(Fail { prop: "P10-junk", step: st.step, sid: s, id: c, reader: None, full: None });
                }
            }
        }
        out
    }
    /// The model's own check: every edge-class commit the node holding everything applies is
    /// chained (spec/permissions.md §4 Chained writes: "Every write the walk applies is chained").
    pub fn p0_applied_chained(&self, st: &State) -> Vec<Fail> {
        let full = self.full(st, &Set::new());
        let ch = self.chained(&full.v.held);
        paths::judge(&self.w, &self.rules, &full.v).applied.difference(&ch).map(|&i| Fail { prop: "P0-unchained-applies", step: st.step, sid: 0, id: i, reader: None, full: None }).collect()
    }
    /// P3: every removal by an honest node that the full closure of a sync ID's bodies holds and
    /// that can move a verdict there (it takes write away and its reach under S is held over
    /// everything written, at any time: notes/evidence-model-findings.md 20) is carried there and
    /// judged required by its reader from its own holdings.
    pub fn p3(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        let all = self.full(st, &Set::new()).v.held;
        let taken: Set = match self.takes(rule, &all) {
            Some(t) => all.iter().copied().filter(|i| t.contains(i)).collect(),
            None => all.clone(),
        };
        let mut out = vec![];
        for &s in &self.sids {
            let closure = self.closure(rule, &self.owed_bodies(st, s), &all);
            let held = &st.entries[&s];
            let req = self.req(rule, s, &st.units, held);
            for &l in &closure {
                let owed = self.removes(l).is_some_and(|(_, t)| self.reach_removal(rule, l, &taken) && self.reach(rule, t, &st.units[&s], &taken).is_some());
                if owed && self.nodes[self.by[l]].honest && !req.contains(&l) {
                    out.push(Fail { prop: "P3", step: st.step, sid: s, id: l, reader: None, full: None });
                }
            }
        }
        out
    }
    /// P4: what a sync ID holds is what its reader requires (copies held are a function of the
    /// commits held: nothing outlives the commits it was needed for); and forgetting each content
    /// body changes no other verdict at the reader and leaves nothing only it needed.
    pub fn p4(&self, rule: &Rule, st: &State, forget_each: bool) -> Vec<Fail> {
        let mut out = vec![];
        for &s in &self.sids {
            let held = &st.entries[&s];
            let req = self.req(rule, s, &st.units, held);
            for &i in held.difference(&req) {
                if self.nodes[self.by[i]].honest {
                    out.push(Fail { prop: "P4-held", step: st.step, sid: s, id: i, reader: None, full: None });
                }
            }
            let lreq = self.req_leaves(rule, s, &st.units, held);
            for l in st.leaves[&s].difference(&lreq) {
                out.push(Fail { prop: "P4-leaf", step: st.step, sid: s, id: l.0, reader: None, full: None });
            }
        }
        if !forget_each {
            return out;
        }
        for &s in &self.sids {
            let before_v = self.reader(rule, st, s, &Set::new());
            // (an opener of a late path entry is a key, not a body anyone forgets)
            let content: Vec<Id> = self.bodies(s, &st.units, &st.entries[&s]).into_iter().filter(|&i| matches!(self.w.commits[i].kind, Kind::Content) && !self.opens.values().any(|&o| o == i)).collect();
            for i in content {
                let mut st2 = st.clone();
                self.forget(rule, &mut st2, i);
                let after_v = self.reader(rule, &st2, s, &Set::new());
                let rest: Set = after_v.v.held.intersection(&self.bodies(s, &st2.units, &before_v.v.held)).copied().collect();
                let (a, b) = (self.verdicts(&before_v, &rest), self.verdicts(&after_v, &rest));
                for j in &rest {
                    if a[j] != b[j] {
                        out.push(Fail { prop: "P4-forget", step: st.step, sid: s, id: *j, reader: Some(b[j]), full: Some(a[j]) });
                    }
                }
                let needed_only_by_i = |c: Id| {
                    let others: Set = self.bodies(s, &st2.units, &st2.entries[&s]);
                    !self.req(rule, s, &st2.units, &others.union(&st2.entries[&s]).copied().collect()).contains(&c)
                };
                for &c in st2.entries[&s].iter() {
                    if !st2.units[&s].contains(&self.on(c)) && needed_only_by_i(c) && self.nodes[self.by[c]].honest {
                        out.push(Fail { prop: "P4-grow", step: st.step, sid: s, id: c, reader: None, full: None });
                    }
                }
                // a leaf left with nothing it is evidence of leaves
                let lreq = self.req_leaves(rule, s, &st2.units, &st2.entries[&s]);
                for l in st2.leaves[&s].difference(&lreq) {
                    out.push(Fail { prop: "P4-leaf-grow", step: st.step, sid: s, id: l.0, reader: None, full: None });
                }
            }
        }
        out
    }
    /// P5, arrival order: for each body and each strict part of its evidence the reader holds,
    /// the reader missing that part judges the body as the node holding everything but that part
    /// does (`local`, a failure), and counts where it judges (not pending) otherwise than once
    /// everything arrived while some missing part is ordered before the body (`provisional`).
    pub fn p5_order(&self, rule: &Rule, st: &State, cap: usize) -> (Vec<Fail>, usize) {
        let mut out = vec![];
        let mut provisional = 0;
        for &s in &self.sids {
            let held = st.entries[&s].clone();
            let bodies = self.bodies(s, &st.units, &held);
            for &i in &bodies {
                let ev: Vec<Id> = self.closure(rule, &Set::from([i]), &held).into_iter().filter(|&j| j != i).take(cap).collect();
                let fin = self.verdicts(&self.reader(rule, st, s, &Set::new()), &Set::from([i]))[&i];
                for mask in 1..(1u32 << ev.len()) {
                    let y: Set = ev.iter().enumerate().filter(|(b, _)| mask >> b & 1 == 1).map(|(_, &j)| j).collect();
                    let r = self.verdicts(&self.reader(rule, st, s, &y), &Set::from([i]))[&i];
                    let f = self.verdicts(&self.full(st, &y), &Set::from([i]))[&i];
                    if r != f {
                        out.push(Fail { prop: "P5-order", step: st.step, sid: s, id: i, reader: Some(r), full: Some(f) });
                    }
                    let early = y.iter().any(|&j| self.w.commits[j].ts <= self.w.commits[i].ts);
                    if r != Verdict::Pending && r != fin && early {
                        provisional += 1;
                    }
                }
            }
        }
        (out, provisional)
    }
    /// P7, a list leaf is evidence: under `Lists::Travels`, for each body and each held leaf that
    /// reads it, the reader holding everything but that leaf judges the body pending, never valid
    /// or invalid.
    pub fn p7_leaf_waits(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        let mut out = vec![];
        if rule.lists == Lists::Whole {
            return out;
        }
        for &s in &self.sids {
            let seen = self.reader(rule, st, s, &Set::new());
            let bodies = self.bodies(s, &st.units, &seen.v.held);
            let held_leaves = seen.lists.clone().unwrap_or_default();
            let ch = Chained::new();
            for &i in &bodies {
                for &l in held_leaves.iter().filter(|&&l| self.reads(seen.keep, l, i, &seen.v.held, &ch)) {
                    let mut short = seen.clone();
                    short.lists.as_mut().unwrap().remove(&l);
                    let r = self.verdicts(&short, &Set::from([i]))[&i];
                    if r != Verdict::Pending {
                        out.push(Fail { prop: "P7-wait", step: st.step, sid: s, id: i, reader: Some(r), full: None });
                    }
                }
            }
        }
        out
    }
    /// What a reader promotes from `seen`: each body it judges valid (a deposit of it promoted, a
    /// cover of it dropping what it covers, shown as settled).
    pub fn promotions(&self, seen: &Seen, bodies: &Set) -> Vec<Id> {
        self.verdicts(seen, bodies).into_iter().filter(|&(_, v)| v == Verdict::Valid).map(|(i, _)| i).collect()
    }
    /// P8, promoting: every promotion a reader of each sync ID takes (`when`) agrees with the
    /// verdict of the node holding everything at that step. `AfterPass` acts on the sync ID's
    /// whole entries; `WhenNothingPends` (the control) also on every arrival order of each body's
    /// evidence (P5's subsets, `cap` parts) where the body does not pend.
    pub fn p8_promotions(&self, rule: &Rule, st: &State, when: PromoteWhen, cap: usize) -> Vec<Fail> {
        let full = self.verdicts(&self.full(st, &Set::new()), &st.written);
        let mut out = vec![];
        let mut check = |s: Sid, promoted: Vec<Id>| {
            for i in promoted {
                if full[&i] != Verdict::Valid {
                    out.push(Fail { prop: "P8-promote", step: st.step, sid: s, id: i, reader: Some(Verdict::Valid), full: Some(full[&i]) });
                }
            }
        };
        for &s in &self.sids {
            let seen = self.reader(rule, st, s, &Set::new());
            let bodies = self.bodies(s, &st.units, &seen.v.held);
            check(s, self.promotions(&seen, &bodies));
            if when == PromoteWhen::AfterPass {
                continue;
            }
            for &i in &bodies {
                let ev: Vec<Id> = self.closure(rule, &Set::from([i]), &seen.v.held).into_iter().filter(|&j| j != i).take(cap).collect();
                for mask in 1..(1u32 << ev.len()) {
                    let y: Set = ev.iter().enumerate().filter(|(b, _)| mask >> b & 1 == 1).map(|(_, &j)| j).collect();
                    check(s, self.promotions(&self.reader(rule, st, s, &y), &Set::from([i])));
                }
            }
        }
        out
    }
}

// ---- Worlds ----

pub mod names {
    use super::Thing;
    /// The mint admin of A, its remover.
    pub const X: Thing = 1;
    /// A member signer of A; the thief once removed.
    pub const K: Thing = 2;
    /// Another member signer of A.
    pub const Q: Thing = 3;
    /// A holder K grants on A (`Shape::grant`).
    pub const Z: Thing = 4;
    /// The mint admin of O, D and R (the organization's side; Risk 4: the raiser).
    pub const Y: Thing = 5;
    /// O's mint admin where O stands apart from Y.
    pub const W: Thing = 6;
    pub const A: Thing = 10;
    pub const O: Thing = 11;
    pub const D: Thing = 12;
    pub const R: Thing = 13;
    /// A dependent of R (no sync ID of its own).
    pub const E: Thing = 14;
    /// A third holder thing (W's), for paths of up to four holder things (`wide`).
    pub const H: Thing = 15;
}

/// The family's shape (`family`): each field one dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// K writes D through [A, O] (O holding write on D) rather than [A].
    pub via_org: bool,
    /// 0: D under its own sync ID only; 1: D in R's unit from the start; 2: D joins R's unit after
    /// K's first write; 3: D leaves R's unit after K's first write; 4: O (on K's path) and D in
    /// R's unit, O leaving after K's first write (as 1 without via_org).
    pub units: u8,
    /// The remover lists K's first write.
    pub listed: bool,
    /// K, stolen, writes D after the removal.
    pub thief: bool,
    /// X re-grants K after the removal.
    pub regrant: bool,
    /// Q's addendum on D lists K's first write.
    pub addendum: bool,
    /// A's role on D (or O's) is read at the removal, raised to write by Y after it (Risk 4);
    /// K's first write is then absent.
    pub raised: bool,
    /// Q syncs D; Q syncs R; Y syncs A (else no honest node syncs both A and Y's things but Q).
    pub q_d: bool,
    pub q_r: bool,
    pub y_a: bool,
    /// O is minted by W, a node syncing O alone, rather than by Y.
    pub org_apart: bool,
    /// K holds admin on A and grants Z write on A after its first write; Z writes D; the removal
    /// does not list the grant, so it falls with Z's write.
    pub grant: bool,
    /// Record edges on K's path (README OPEN 17): 0 grants only; 1 the hop after A a record edge
    /// (A mints O, or, with K writing through [A], A mints D); 2 a mint chain two deep (A mints O,
    /// O mints D: K's path [A, O] or [A] (by descent) climbs records past A). Where the last hop
    /// into D is a record edge, `raised` is X (D's admin by descent) lowering it to read before
    /// K's first write and raising it after the removal: a record edge changed later.
    pub mint: u8,
}

pub const FAMILY: usize = 2 * 5 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 3;

impl Shape {
    pub fn nth(mut i: usize) -> Shape {
        let mut take = |n: usize| {
            let v = i % n;
            i /= n;
            v
        };
        Shape {
            via_org: take(2) == 1,
            units: take(5) as u8,
            listed: take(2) == 1,
            thief: take(2) == 1,
            regrant: take(2) == 1,
            addendum: take(2) == 1,
            raised: take(2) == 1,
            q_d: take(2) == 1,
            q_r: take(2) == 1,
            y_a: take(2) == 1,
            org_apart: take(2) == 1,
            grant: take(2) == 1,
            mint: take(3) as u8,
        }
    }
}

/// The stolen-node story over units. X mints A (the account; K and Q its members), Y mints D, R
/// and O (or W does, or A mints O and A or O mints D: `Shape::mint`); A reaches D directly or
/// through O; K writes D, X removes K, and the shape's other moves. Nodes: X (syncs A), Y (D, R),
/// W (O), Q (A), K (the thief: A, O, D, R), Z; each also syncs what it writes.
pub fn family(sh: Shape) -> World {
    use names::*;
    let o_mint = if sh.mint > 0 { A } else if sh.org_apart { W } else { Y };
    let d_mint = match (sh.mint, sh.via_org) {
        (1, false) => A,
        (2, _) => O,
        _ => Y,
    };
    let pw = paths::World::new(&[(X, A), (o_mint, O), (d_mint, D), (Y, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let x = w.node(true, &[A]);
    let y = w.node(true, &if sh.y_a { vec![D, R, A] } else { vec![D, R] });
    let o = if sh.org_apart { w.node(true, &[O]) } else { y };
    let mut q_syncs = vec![A];
    if sh.q_d {
        q_syncs.push(D);
    }
    if sh.q_r {
        q_syncs.push(R);
    }
    let q = w.node(true, &q_syncs);
    let k = w.node(false, &[A, O, D, R]);
    let path: Vec<Thing> = if sh.via_org { vec![A, O] } else { vec![A] };
    match sh.units {
        1 | 3 => w.member(D, R),
        4 => {
            w.member(D, R);
            if sh.via_org {
                w.member(O, R);
            }
        }
        _ => {}
    }
    let member = if sh.grant { Role::Admin } else { Role::Write };
    w.write(x, |p| p.edge(X, 1, &[], A, K, member, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, member, &[]));
    let on_d = if sh.raised { Role::Read } else { Role::Write };
    let (holder, last) = if sh.via_org || sh.mint == 2 { (O, D) } else { (A, D) };
    if sh.via_org && o_mint != A {
        w.write(o, |p| p.edge(o_mint, 2, &[], O, A, Role::Write, &[]));
    }
    // D's admin: Y, or X by descent where D is minted down A's chain (its stated path the records)
    let (dn, ds) = if d_mint == Y { (y, Y) } else { (x, X) };
    if d_mint == Y {
        w.write(y, |p| p.edge(Y, 2, &[], last, holder, on_d, &[]));
    } else if sh.raised {
        w.write(x, |p| p.edge(X, 2, &[], last, holder, Role::Read, &[]));
    }
    let first = if sh.raised { None } else { Some(w.write(k, |p| p.content(K, 3, &path, D))) };
    match sh.units {
        2 => w.join(D, R),
        3 => w.leave(D, R),
        4 if sh.via_org => w.leave(O, R),
        _ => {}
    }
    let zn = w.node(true, &[]);
    let gz = if sh.grant { Some(w.write(k, |p| p.edge(K, 4, &[], A, Z, Role::Write, &[]))) } else { None };
    if gz.is_some() {
        w.write(zn, |p| p.content(Z, 5, &path, D));
    }
    let listed: Vec<Id> = if sh.listed { first.into_iter().collect() } else { vec![] };
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &listed));
    if sh.raised {
        w.write(dn, |p| p.edge(ds, 7, &[], last, holder, Role::Write, &[]));
    }
    if sh.addendum {
        if let Some(f) = first {
            w.write(q, |p| p.addendum(Q, 7, &path, D, r, &[f]));
        }
    }
    if sh.thief {
        w.write(k, |p| p.content(K, 8, &path, D));
    }
    if sh.regrant {
        w.write(x, |p| p.edge(X, 9, &[], A, K, Role::Write, &[]));
    }
    w
}

/// A random world (sampled searches): the family's cast (X minting A, Y minting D and R, W
/// minting O; members K, Q, Z of A; K the thief), its starting grants at random roles, then `len`
/// moves drawn from: a member's content on D or O along [A] or [A, O] (sometimes backdated), X
/// removing or re-granting a member (a random frontier of what it could have received) or two in
/// one commit, K
/// granting Z, Q writing an addendum against a held removal, Y or W raising or
/// lowering A's or O's edge, retags among the four things, a member's edge write on A or O to any
/// holder (junk where it holds no admin), content along [A, R] (A writing R half the time, R
/// holding nothing on D) or [O, A]; random node sync sets beside each mint admin syncing its
/// things. A third of the worlds have A mint O, and half of those O mint D (README OPEN 17):
/// records on the members' paths in place of the starting grants, changed later by the moves
/// that change A's or O's edge (by X, their admin by descent).
pub fn random(seed: u64, len: usize) -> World {
    use names::*;
    let mut rng = roles_model::Rng::thread(seed, 0);
    let mint = rng.below(6);
    let (o_mint, d_mint) = match mint {
        0 | 1 => (A, if mint == 0 { O } else { Y }),
        _ => (W, Y),
    };
    let pw = paths::World::new(&[(X, A), (o_mint, O), (d_mint, D), (Y, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let things = [A, O, D, R];
    for &(x, s) in &[(D, R), (O, R), (O, D), (D, O)] {
        if rng.below(3) == 0 {
            w.member(x, s);
        }
    }
    // every sync ID has an honest node syncing it: its mint admin's
    let pick = |rng: &mut roles_model::Rng, mine: &[Thing]| -> Vec<Thing> { things.iter().copied().filter(|t| mine.contains(t) || rng.below(3) == 0).collect() };
    let (x, y, wn, q, z) = (w.node(true, &pick(&mut rng, &[A])), w.node(true, &pick(&mut rng, &[D, R])), w.node(true, &pick(&mut rng, &[O])), w.node(true, &pick(&mut rng, &[])), w.node(true, &pick(&mut rng, &[])));
    let k = w.node(false, &[]);
    // a thing's admin by its record chain: the key actor at its top, writing by descent
    let admin = |t: Thing| -> (Thing, usize) {
        match (t, o_mint, d_mint) {
            (O, A, _) | (D, _, O) => (X, x),
            (O, _, _) => (W, wn),
            _ => (Y, y),
        }
    };
    let records = w.w.records.clone();
    let roles = [Role::Read, Role::Write, Role::Admin];
    let up = |rng: &mut roles_model::Rng| roles[1 + rng.below(2)];
    let (rk, rq) = (up(&mut rng), up(&mut rng));
    w.write(x, |p| p.edge(X, 1, &[], A, K, rk, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, rq, &[]));
    for (on, hd) in [(D, A), (O, A), (D, O)] {
        if !records.contains(&(hd, on)) {
            let (a, n) = admin(on);
            w.write(n, |p| p.edge(a, 1, &[], on, hd, Role::Write, &[]));
        }
    }
    if rng.below(2) == 0 {
        // A writes R, which holds nothing on D: [A, R] is a path to D no grant joins
        w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    }
    let mut ts = 2;
    for _ in 0..len {
        ts += rng.below(2) as u32;
        let bts = if rng.below(5) == 0 && ts > 3 { ts - 2 } else { ts };
        let removals: Vec<Id> = (0..w.by.len()).filter(|&j| w.removes(j).is_some_and(|e| e.1 == A)).collect();
        match rng.below(12) {
            0..=2 => {
                let (sg, n) = [(K, k), (Q, q), (Z, z)][rng.below(3)];
                let path: Vec<Thing> = if rng.below(2) == 0 { vec![A] } else { vec![A, O] };
                let on = if path.len() == 1 && rng.below(3) == 0 { O } else { D };
                w.write(n, |p| p.content(sg, bts, &path, on));
            }
            3 | 4 if rng.below(4) == 0 => {
                // X removes or re-grants two members in one commit (finding 9)
                let role = if rng.below(2) == 0 { Role::None } else { up(&mut rng) };
                let (a, b) = [(K, Q), (K, Z), (Q, Z)][rng.below(3)];
                w.write_parts(x, |p| p.commit(X, bts, &[], A, vec![paths::Kind::set(a, role), paths::Kind::set(b, role)]));
            }
            3 | 4 => {
                let m = [K, Q, Z][rng.below(3)];
                let role = if rng.below(2) == 0 { Role::None } else { up(&mut rng) };
                let front: Vec<Id> = (0..w.by.len()).filter(|&j| w.w.hops(j).contains(&(m, A)) && rng.below(2) == 0).collect();
                w.write(x, |p| p.edge(X, bts, &[], A, m, role, if role == Role::None { &front } else { &[] }));
            }
            5 => {
                w.write(k, |p| p.edge(K, bts, &[], A, Z, Role::Write, &[]));
            }
            6 if !removals.is_empty() => {
                let r = removals[rng.below(removals.len())];
                let list: Vec<Id> = (0..w.by.len()).filter(|&j| j != r && rng.below(2) == 0).collect();
                let adds: Vec<Id> = list.iter().copied().filter(|&j| !w.w.edge_class(j) && w.on(j) == D).collect();
                w.write(q, |p| p.addendum(Q, bts, &[A], D, r, &adds));
            }
            7 => {
                let role = [Role::None, Role::Read, Role::Write][rng.below(3)];
                let (on, hd) = [(D, A), (D, O), (O, A)][rng.below(3)];
                let (a, n) = admin(on);
                w.write(n, |p| p.edge(a, bts, &[], on, hd, role, &[]));
            }
            10 => {
                // a member's edge write on A or O, any holder and role: junk where it holds no
                // admin there (finding 11)
                let (sg, n) = [(K, k), (Q, q), (Z, z)][rng.below(3)];
                let on = [A, O][rng.below(2)];
                let h = [K, Q, Z, D, R, O, A][rng.below(7)];
                if h != on {
                    w.write(n, |p| p.edge(sg, bts, &[], on, h, roles[rng.below(3)], &[]));
                }
            }
            11 => {
                // a member's content on D along a path no grant need join: [A, R], or [O, A]
                let (sg, n) = [(K, k), (Q, q), (Z, z)][rng.below(3)];
                let path = if rng.below(2) == 0 { [A, R] } else { [O, A] };
                w.write(n, |p| p.content(sg, bts, &path, D));
            }
            _ => {
                let (xx, ss) = (things[rng.below(4)], things[rng.below(4)]);
                if xx != ss {
                    if rng.below(2) == 0 {
                        w.join(xx, ss);
                    } else {
                        w.leave(xx, ss);
                    }
                }
            }
        }
    }
    w
}

/// What `wide` adds to its base moves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wide {
    /// Content commits in the split form: parts on two things, each with its own path.
    pub split: bool,
    /// A content part whose path entry opens late (`World::opens`): its opener (a content commit
    /// on its thing by the thing's mint admin) written some moves later, or never.
    pub late: bool,
    /// Each of O, H, D, R minted by an earlier one of the five one time in three (README OPEN 17:
    /// record edges anywhere on a route, mint chains up to four deep, a minted thing in a unit, a
    /// record edge changed by churn), its admin the key actor at the top of its record chain,
    /// writing by descent. False: every thing minted by a key actor, the worlds as without it.
    pub mint: bool,
}

/// A random world of paths up to four holder things long (sampled searches): X mints A (members
/// K, Q, Z), W mints O and H, Y mints D and R; the five things ordered A, O, H, D, R, each holding
/// a random role on each later one (a random graph of routes), members sometimes granted directly
/// on another thing (a second route); then `len` moves: a member's content (K's half the time)
/// along a route (`wide_route`: mostly along edges written, else any increasing path; sometimes
/// backdated), K removed or re-granted on any thing it has a route on, X removing
/// or re-granting a member (a random frontier) or two in one commit, an admin's churn on any edge
/// between the things (a removal with a random frontier), junk edge writes by members on any thing
/// to any holder, K granting Z, Q's addenda, direct routes granted and removed, retags
/// among the five, A granted read alone on a thing with the thief writing through that hop
/// (finding 23's read hop); with `opt` split commits and late path entries. Random node sync sets beside
/// each mint admin syncing its things (each other thing one chance in five: honest bridges
/// between two things are rare enough that delivery decides). With `opt.mint` things minted by
/// things.
pub fn wide(seed: u64, len: usize, opt: Wide) -> World {
    use names::*;
    let mut rng = roles_model::Rng::thread(seed, 1);
    let things = [A, O, H, D, R];
    let mut recs = vec![(X, A)];
    for (j, key) in [(1, W), (2, W), (3, Y), (4, Y)] {
        recs.push((if opt.mint && rng.below(3) == 0 { things[rng.below(j)] } else { key }, things[j]));
    }
    let pw = paths::World::new(&recs);
    let mut w = World::new(pw, &things);
    for &(x, s) in &[(D, R), (O, R), (H, D), (O, H), (D, O), (A, H)] {
        if rng.below(4) == 0 {
            w.member(x, s);
        }
    }
    let pick = |rng: &mut roles_model::Rng, mine: &[Thing]| -> Vec<Thing> { things.iter().copied().filter(|t| mine.contains(t) || rng.below(5) == 0).collect() };
    let (x, wn, y, q, z) = (w.node(true, &pick(&mut rng, &[A])), w.node(true, &pick(&mut rng, &[O, H])), w.node(true, &pick(&mut rng, &[D, R])), w.node(true, &pick(&mut rng, &[])), w.node(true, &pick(&mut rng, &[])));
    let k = w.node(false, &[]);
    // the key actor at the top of t's record chain, and its node
    let admin = |t: Thing| {
        let mut top = t;
        while let Some(&(m, _)) = recs.iter().find(|e| e.1 == top) {
            top = m;
        }
        match top {
            X => (X, x),
            W => (W, wn),
            _ => (Y, y),
        }
    };
    let members = [(K, k), (Q, q), (Z, z)];
    let roles = [Role::Read, Role::Write, Role::Admin];
    let up = |rng: &mut roles_model::Rng| roles[1 + rng.below(2)];
    for &(m, _) in &members[..2 + rng.below(2)] {
        let r = up(&mut rng);
        w.write(x, |p| p.edge(X, 1, &[], A, m, r, &[]));
    }
    for i in 0..things.len() {
        for j in i + 1..things.len() {
            if rng.below(2) == 0 && !recs.contains(&(things[i], things[j])) {
                let (a, n) = admin(things[j]);
                let r = [Role::Write, Role::Write, Role::Read, Role::Admin][rng.below(4)];
                w.write(n, |p| p.edge(a, 1, &[], things[j], things[i], r, &[]));
            }
        }
    }
    // second routes: a member granted directly on another thing
    for m in [K, Q, Z] {
        if rng.below(3) == 0 {
            let on = things[1 + rng.below(4)];
            let (a, n) = admin(on);
            w.write(n, |p| p.edge(a, 1, &[], on, m, Role::Write, &[]));
        }
    }
    let mut pending: Vec<(Id, Thing)> = vec![];
    let mut ts = 2;
    for _ in 0..len {
        ts += rng.below(2) as u32;
        let bts = if rng.below(5) == 0 && ts > 3 { ts - 2 } else { ts };
        let removals: Vec<Id> = (0..w.by.len()).filter(|&j| w.removes(j).is_some()).collect();
        match rng.below(15) {
            0..=3 => {
                // the thief half the time
                let (sg, n) = if rng.below(2) == 0 { members[0] } else { members[rng.below(3)] };
                let (path, on) = wide_route(&w, &mut rng, sg);
                w.write(n, |p| p.content(sg, bts, &path, on));
            }
            4 | 5 if rng.below(2) == 0 => {
                // K removed or re-granted on A or on a thing it holds a direct route on
                let on = [A, A, O, H, D, R][rng.below(6)];
                let role = if rng.below(3) == 0 { up(&mut rng) } else { Role::None };
                let front: Vec<Id> = (0..w.by.len()).filter(|&j| w.w.hops(j).contains(&(K, on)) && rng.below(2) == 0).collect();
                let (a, n) = admin(on);
                w.write(n, |p| p.edge(a, bts, &[], on, K, role, if role == Role::None { &front } else { &[] }));
            }
            4 => {
                let m = [K, Q, Z][rng.below(3)];
                let role = if rng.below(2) == 0 { Role::None } else { up(&mut rng) };
                let front: Vec<Id> = (0..w.by.len()).filter(|&j| w.w.hops(j).contains(&(m, A)) && rng.below(2) == 0).collect();
                w.write(x, |p| p.edge(X, bts, &[], A, m, role, if role == Role::None { &front } else { &[] }));
            }
            5 => {
                let role = if rng.below(2) == 0 { Role::None } else { up(&mut rng) };
                let (a, b) = [(K, Q), (K, Z), (Q, Z)][rng.below(3)];
                w.write_parts(x, |p| p.commit(X, bts, &[], A, vec![paths::Kind::set(a, role), paths::Kind::set(b, role)]));
            }
            6 => {
                // churn on an edge between two things, by the target's admin
                let j = 1 + rng.below(things.len() - 1);
                let (hd, on) = (things[rng.below(j)], things[j]);
                let role = [Role::None, Role::Read, Role::Write, Role::Admin][rng.below(4)];
                let front: Vec<Id> = (0..w.by.len()).filter(|&c| w.w.hops(c).contains(&(hd, on)) && rng.below(2) == 0).collect();
                let (a, n) = admin(on);
                w.write(n, |p| p.edge(a, bts, &[], on, hd, role, if role == Role::None { &front } else { &[] }));
            }
            7 => {
                // a member's edge write on any thing to any holder: junk where it holds no admin
                let (sg, n) = members[rng.below(3)];
                let (path, on) = wide_route(&w, &mut rng, sg);
                let hd = [K, Q, Z, A, O, H, D, R][rng.below(8)];
                if hd != on && !path.contains(&hd) {
                    let r = roles[rng.below(3)];
                    w.write(n, |p| p.edge(sg, bts, &path, on, hd, r, &[]));
                }
            }
            8 if !removals.is_empty() => {
                let r = removals[rng.below(removals.len())];
                let list: Vec<Id> = (0..w.by.len()).filter(|&j| j != r && rng.below(2) == 0).collect();
                let t = things[3 + rng.below(2)];
                let adds: Vec<Id> = list.iter().copied().filter(|&j| !w.w.edge_class(j) && w.on(j) == t).collect();
                w.write(q, |p| p.addendum(Q, bts, &[A], t, r, &adds));
            }
            9 => {
                let (sg, n) = members[rng.below(3)];
                let hd = [K, Q, Z][rng.below(3)];
                if hd != sg {
                    let r = up(&mut rng);
                    w.write(n, |p| p.edge(sg, bts, &[], A, hd, r, &[]));
                }
            }
            10 => {
                let (xx, ss) = (things[rng.below(5)], things[rng.below(5)]);
                if xx != ss {
                    if rng.below(2) == 0 {
                        w.join(xx, ss);
                    } else {
                        w.leave(xx, ss);
                    }
                }
            }
            11 if opt.split => {
                let (sg, n) = members[rng.below(3)];
                let ((p1, t1), (p2, t2)) = (wide_route(&w, &mut rng, sg), wide_route(&w, &mut rng, sg));
                if t1 != t2 {
                    let ids = w.write_parts(n, |p| p.split(sg, bts, sg, &[(&p1, t1), (&p2, t2)]));
                    if opt.late && rng.below(2) == 0 {
                        let i = ids[rng.below(2)];
                        w.opens.insert(i, usize::MAX);
                        pending.push((i, w.on(i)));
                    }
                }
            }
            12 => {
                // a direct route: a thing's admin grants (or removes) a member on it
                let m = [K, Q, Z][rng.below(3)];
                let on = things[1 + rng.below(4)];
                let role = if rng.below(3) == 0 { Role::None } else { up(&mut rng) };
                let front: Vec<Id> = (0..w.by.len()).filter(|&c| w.w.hops(c).contains(&(m, on)) && rng.below(2) == 0).collect();
                let (a, n) = admin(on);
                w.write(n, |p| p.edge(a, bts, &[], on, m, role, if role == Role::None { &front } else { &[] }));
            }
            13 if opt.late => {
                let (sg, n) = members[rng.below(3)];
                let (path, on) = wide_route(&w, &mut rng, sg);
                let i = w.write(n, |p| p.content(sg, bts, &path, on));
                w.opens.insert(i, usize::MAX);
                pending.push((i, on));
            }
            14 => {
                // a read hop (finding 23): A granted read on a thing T where nothing gave it write
                // yet, T write on a thing U no honest node syncs together with T or A (an honest
                // bridge would carry the read grant), and the thief writing U through [A, T]:
                // invalid everywhere; the thief logs no grant below write
                let gives_write = |w: &World, e: Edge| recs.contains(&e) || (0..w.by.len()).any(|c| w.w.sets(c) == Some(e) && w.gives_write(c).is_some());
                let bridged = |w: &World, t: Thing, u: Thing| (0..w.nodes.len()).any(|n| w.nodes[n].honest && { let sy = w.syncs(n, &w.units); sy.contains(&u) && (sy.contains(&t) || sy.contains(&A)) }) || w.units[&u].contains(&t) || w.units[&u].contains(&A);
                let pairs: Vec<(Thing, Thing)> = things[1..].iter().flat_map(|&t| things[1..].iter().map(move |&u| (t, u))).filter(|&(t, u)| t != u && !gives_write(&w, (A, t)) && !bridged(&w, t, u)).collect();
                if !pairs.is_empty() {
                    let (t, u) = pairs[rng.below(pairs.len())];
                    let (a, n) = admin(t);
                    w.write(n, |p| p.edge(a, bts, &[], t, A, Role::Read, &[]));
                    if !gives_write(&w, (t, u)) {
                        let (a, n) = admin(u);
                        w.write(n, |p| p.edge(a, bts, &[], u, t, Role::Write, &[]));
                    }
                    w.write(k, |p| p.content(K, bts + 1, &[A, t], u));
                }
            }
            _ => {}
        }
        // a pending path entry opens now and then: its thing's key arrives
        let mut keep = vec![];
        for (i, on) in std::mem::take(&mut pending) {
            if rng.below(3) == 0 {
                let (a, n) = admin(on);
                let o = w.write(n, |p| p.content(a, ts, &[], on));
                w.opens.insert(i, o);
            } else {
                keep.push((i, on));
            }
        }
        pending = keep;
    }
    // one never opening waits for good, at every node alike
    for (i, on) in pending {
        if rng.below(2) == 0 {
            let (a, n) = admin(on);
            let o = w.write(n, |p| p.content(a, ts, &[], on));
            w.opens.insert(i, o);
        }
    }
    w
}

/// A path for `signer` in a `wide` world and the thing written at its end: three times in four a
/// walk from `signer` along edges some edge write set (granted, removed or junk; one to five
/// things), else a random increasing subset of the things before a random target.
fn wide_route(w: &World, rng: &mut roles_model::Rng, signer: Thing) -> (Vec<Thing>, Thing) {
    use names::*;
    let things = [A, O, H, D, R];
    if rng.below(4) != 0 {
        let edges: BTreeSet<Edge> = (0..w.by.len()).filter_map(|i| w.w.sets(i)).chain(w.w.records.iter().copied()).filter(|e| things.contains(&e.1)).collect();
        let mut path: Vec<Thing> = vec![];
        let mut cur = signer;
        loop {
            let next: Vec<Thing> = edges.iter().filter(|e| e.0 == cur && !path.contains(&e.1)).map(|e| e.1).collect();
            if next.is_empty() {
                break;
            }
            cur = next[rng.below(next.len())];
            path.push(cur);
            if path.len() == 5 || rng.below(3) == 0 {
                break;
            }
        }
        if let Some(on) = path.pop() {
            return (path, on);
        }
    }
    let ti = rng.below(things.len());
    let path: Vec<Thing> = things[..ti].iter().copied().filter(|_| rng.below(2) == 0).collect();
    (path, things[ti])
}

// ---- Cost (P6) ----

/// Copies and bodies under D's sync ID after `n` writes by K on D along a path of `k` holder
/// things, `outside` of which lie outside D's unit (the rest in it): each holder thing H_j granted
/// write on the next by X, the last on D. Under the draft (`Rule::design`).
pub fn cost(n: usize, k: usize, outside: usize) -> (usize, usize) {
    let c = cost_with(n, k, outside, 0, 1, Open10::Drafted);
    (c.copies, c.bodies)
}

/// What `cost_with` counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cost {
    /// Copies under D's sync ID (one per (commit, thing): commits write one thing here).
    pub copies: usize,
    pub bodies: usize,
    /// Copies of D's evidence over every sync ID whose unit holds D.
    pub copies_everywhere: usize,
}

/// `cost`, with `churn` more re-grants by X of K's grant on the first holder thing (role churn
/// on a used edge), D in the units of `carried` sync IDs (its own and `carried - 1` others, R_j
/// holding nothing else), under variant `v`.
pub fn cost_with(n: usize, k: usize, outside: usize, churn: usize, carried: usize, v: Open10) -> Cost {
    use names::*;
    assert!(outside <= k && k <= 4 && carried >= 1);
    let hs: Vec<Thing> = (0..k as Thing).map(|j| 20 + j).collect();
    let rs: Vec<Thing> = (1..carried as Thing).map(|j| 40 + j).collect();
    let mut recs: Vec<Edge> = hs.iter().chain(&rs).map(|&h| (X, h)).collect();
    recs.push((X, D));
    let pw = paths::World::new(&recs);
    let mut sids = hs.clone();
    sids.push(D);
    sids.extend(&rs);
    let mut w = World::new(pw, &sids);
    for &h in &hs[outside..] {
        w.member(h, D);
    }
    for &r in &rs {
        w.member(D, r);
    }
    let x = w.node(true, &sids);
    if let Some(&h0) = hs.first() {
        for c in 0..=churn {
            w.write(x, |p| p.edge(X, 1 + c as u32, &[], h0, K, Role::Write, &[]));
        }
    }
    for j in 0..k {
        let next = hs.get(j + 1).copied().unwrap_or(D);
        let h = hs[j];
        w.write(x, |p| p.edge(X, 1, &[], next, h, Role::Write, &[]));
    }
    let t0 = 2 + churn as u32;
    for c in 0..n {
        w.write(x, |p| p.content(if k == 0 { X } else { K }, t0 + c as u32, &hs, D));
    }
    let rule = v.set(&mut w, Rule::design());
    let st = w.run(&rule, |_| {});
    let copies = w.copies(&st, D).len();
    let everywhere = std::iter::once(D).chain(rs.iter().copied()).map(|s| w.copies(&st, s).len()).sum();
    Cost { copies, bodies: st.entries[&D].len() - copies, copies_everywhere: everywhere }
}

// ---- Story worlds (roles-model `paths` story under units) ----

/// How a story world's things are put in units (`story_world`): each a crossing of a path thing
/// or a written thing with a unit, from the start or by a retag after the removal.
pub const STORY_UNITS: usize = 6;

/// roles-model's stolen-node story (`paths::Sim`: invites, finalizes, `until`, covers, purges,
/// addenda by the state-based rule, commits of several edge writes and of several
/// things, self-removals, paths of two hops, a dependent written by descent)
/// as an evidence world: its commits written in the order made, by the node of their signer (the
/// thief's moves and every commit signed by X, whose device the thief holds, by one dishonest
/// node), each node syncing what the story's does, readers trusting the honest removals. Sync IDs
/// A, A2, ORG, T1, T2; D1, minted with T1, is in T1's unit (a dependent, no sync ID). `units`
/// (`0..STORY_UNITS`) crosses things with units: 0 each alone; 1 ORG (on T2's paths) in T2's
/// unit; 2 T1 (and D1) in A's unit (a path thing's unit holding the written thing); 3 ORG joining
/// T2's unit after the removal; 4 ORG in T2's unit, leaving it after the removal; 5 T1 (and D1)
/// in A2's unit, leaving it after the removal.
pub fn story_world(sim: &paths::Sim, units: usize) -> World {
    use paths::{A, A2, D1, ORG, T1, T2, X};
    let mut w = World::new(sim.w.clone(), &[A, A2, ORG, T1, T2]);
    w.member(D1, T1);
    let mut node: BTreeMap<Thing, usize> = BTreeMap::new();
    for (&n, things) in &sim.sync {
        let syncs: Vec<Thing> = things.iter().copied().filter(|t| w.sids.contains(t)).collect();
        node.insert(n, w.node(n != X, &syncs));
    }
    w.trust = sim.removals().into_iter().collect();
    // the retag after the removal (`Sim`: tick 6)
    let retag = |w: &mut World| match units {
        3 => w.join(ORG, T2),
        4 => w.leave(ORG, T2),
        5 => {
            w.leave(T1, A2);
            w.leave(D1, A2);
        }
        _ => {}
    };
    match units {
        1 | 4 => w.member(ORG, T2),
        2 => {
            w.member(T1, A);
            w.member(D1, A);
        }
        5 => {
            w.member(T1, A2);
            w.member(D1, A2);
        }
        _ => {}
    }
    let mut order: Vec<Id> = (0..sim.w.commits.len()).collect();
    order.sort_by_key(|&i| (sim.made[i], i));
    w.by = vec![0; order.len()];
    let mut retagged = false;
    for i in order {
        if !retagged && sim.made[i] > 6 {
            retag(&mut w);
            retagged = true;
        }
        let c = &sim.w.commits[i];
        let signer = if sim.thief.contains_key(&i) { X } else { c.signer };
        let n = *node.entry(signer).or_insert_with(|| {
            w.nodes.push(Node { honest: signer != X, syncs: Things::new() });
            w.nodes.len() - 1
        });
        let mine: Vec<Thing> = c.path.iter().copied().chain([c.on]).filter(|x| w.sids.contains(x)).collect();
        w.nodes[n].syncs.extend(mine);
        w.by[i] = n;
        w.events.push(Ev::Write(i));
    }
    if !retagged {
        retag(&mut w);
    }
    w
}
