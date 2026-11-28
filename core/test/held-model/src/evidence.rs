//! Evidence completeness (notes/evidence-model-findings.md; notes/write-path-design.md §2, §6): a model
//! of what each sync ID carries as evidence for the writes whose bodies it carries, and of whether
//! a reader holding one sync ID alone judges those writes as a node holding everything does.
//! Properties in tests/it/spec_evidence.rs, findings in notes/evidence-model-findings.md.
//!
//! Judging is roles-model `paths` (`Rules::fixed`, the rule A1 builds): a commit states a path,
//! judged along it; a lowering lists a frontier; addenda, re-grants as there. On top:
//! - **Pending** (`pend`, spec/commits.md §4 Unjudgeable): a commit pends at a node while a hop it
//!   rests on (`paths::World::rests`: its key hop, then its path's grants) that is no record hop has
//!   no held grant write ordered before it that does not itself pend, or while a part of its commit
//!   removing a holder resets an entry whose creation (`creation`, named by the reset: the entry in
//!   force in its writer's walk) is not held (spec/permissions.md §2). A pending grant write applies
//!   nothing.
//! - **Sync IDs and units.** Signers have no sync ID; every other thing in `sids` has its own, and
//!   a unit per sync ID: the thing and the members `Ev::Join`/`Ev::Leave` give it. Which things a
//!   unit holds is the closure model's question (`closure::unit`), so here it is an input in time.
//!   A thing outside `sids` (a dependent thing) is carried only in the units holding it.
//! - **Bodies.** A commit's body is under every sync ID whose unit holds the thing it writes
//!   (roles-model commits write one thing: a copy per (commit, thing) is per commit here).
//! - **The required set** of sync ID S over a held set H (`World::req`): the evidence closure
//!   (`paths::evidence`: every held grant write on a seed's key hop, on a grant of its path and on
//!   each grant its commit's grant writes on its thing set, closed under the same for what it adds:
//!   spec/permissions.md §4 Evidence of a commit) of the seeds: the bodies, and the chain stubs'
//!   role entries (spec/sync-set.md §2 Stubs: every holder on a chain by which S's keys open
//!   a thing of S's unit is a stub in it): each grant write on a grant of such a chain, a path of
//!   read grants from S's thing to a thing of the unit (a held write giving read that the node
//!   judges valid over what it holds, at any time, or a record: `World::read_grants`; a grant
//!   giving no more than sync brings the sync-only cut, which this model has no role for;
//!   held-model `box_cut` judges what that holds). What of it lies on things outside the unit is a
//!   copy, the rest bodies. A removal is in it only as evidence of a body (notes/write-path-design.md
//!   §2, D1) or as a chain stub's entry; nothing logs a removal anywhere for its own sake (lazy
//!   delivery), and nothing is sent to a holder for being granted something.
//! - **Delivery** (`Placement`): nodes sync sync IDs (`Node::syncs`, closed as a node closure is:
//!   a node syncing S syncs every sync ID of a thing in S's unit) and hold what those carry and what
//!   they wrote. An honest node logs under each sync ID it syncs what its own view requires there;
//!   an entry no syncing node requires is deleted (a delete-key holder deletes, a holder whose view
//!   requires it logs again: the union). The thief logs its own bodies and the grants they rest on,
//!   never a lowering.
//! - **The reference** (`World::reference`): a reader of S is judged against a node holding
//!   everything written but the grant writes S lacks that no honest node syncing S holds
//!   (`World::undelivered`): lazy delivery brings evidence only where a node holding it holds S.
//!   Where that node's verdict differs from the node holding everything is **the gap**
//!   (`World::gap`, notes/write-path-design.md §2 The gap; issues/removed-key-writes-show-far.md),
//!   counted, never excluded silently.
//! - **Keysets** (`World::rotate`, notes/write-path-design.md §2 D2; notes/a3-spec/README.md Open 8):
//!   a rotation's keyset is a body on its thing carrying the demotions its writer holds, each whole;
//!   with `Rule::keysets` they are in the required set of every sync ID holding the keyset, and a
//!   keyset pends at a node lacking one of them (spec/crypto.md §4, Held keyset).
//! - **Stamping and D4** (`Node::stamps`, `Rule::deposit`): a node logs under a sync ID only where
//!   it can stamp it (a writer; by default every sync ID it syncs). With `Rule::deposit` (D4, off by
//!   default) a node syncing S that cannot stamp it deposits there the copies of the removals S's
//!   required set takes over its holdings (a deposit is an entry readers judge by; it is
//!   recomputed each round, so it leaves with the bodies it judges).
//! - **Readers.** A reader holding one sync ID holds its entries and trusts what the world trusts
//!   that it holds. A lowering's list is in the lowering (notes/write-path-design.md §2, E4): every
//!   copy carries it whole, so whoever holds a lowering reads its whole list (`Lists::Whole`; the
//!   control `Lists::Unit` shows a reader only its unit's things' entries).
//! - **Promoting** (`promotions`, `p8_promotions`): a reader promotes a body it judges valid after a
//!   complete pass of its sync ID or (the control) on any partial arrival. A body judged invalid
//!   is dropped at once (spec/commits.md §5 Invalid): no act waits for it.
//!
//! Left out: records (static, `paths::World::records`), keys and sealing (a keyset is a body that
//! carries demotions, no more), `@` signals, covers, deposits other than D4's and their promotion
//! as a step of its own, multi-thing role commits, how units are computed
//! (an input: `closure` checks the walk).

use roles_model::paths::{self, Grant, Id, Kind, Rules, Set, Thing, Things, View};
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

/// What of a held lowering's list a reader reads (notes/write-path-design.md §2, E4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lists {
    /// The design: the list is in the lowering, so every copy carries it whole and whoever holds
    /// the lowering reads all of it.
    Whole,
    /// Control: a reader reads only the entries for its unit's things (a copy carrying part of
    /// its list; finding 4).
    Unit,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rule {
    pub placement: Placement,
    /// Chain stubs: a grant write on a grant of a chain by which S's keys open a thing of S's
    /// unit is a seed of S (read grants and records at any time: `ROLE_KEEP` read as for good).
    /// False: the control (bodies alone).
    pub chain_stubs: bool,
    /// A grant write in the closure brings every held grant write on each grant its commit's grant
    /// writes on its thing set (spec/permissions.md §4 Evidence of a commit; finding 9: a commit's
    /// grant writes apply together, and a removal waits for the creations its resets name). False:
    /// the control (its commit's other parts on the thing alone).
    pub commit_grants: bool,
    /// Record grants are grants of the read graph (each a mint admin's admin grant on the thing it
    /// minted, at any time: `World::chain_grants`): keys open through them (spec/sync-set.md §2).
    /// False: the control (grants only), which under-reads (record grants open keys as grants do: spec/sync-set.md §2).
    pub records: bool,
    pub lists: Lists,
    /// The carried-demotion seed (notes/a3-spec/README.md Open 8): a held keyset's carried
    /// demotions are in the required set of each sync ID holding it. False: the control.
    pub keysets: bool,
    /// D4, the reader's deposit on sight (notes/write-path-design.md §2): a node syncing S that
    /// cannot stamp it deposits the removal copies S's required set takes over its holdings.
    pub deposit: bool,
}

impl Rule {
    /// The spec's rule (spec/permissions.md §4; notes/a2-spec/README.md Open 2: E1): every held
    /// grant write on a stated path's grants and on the grants its commit sets, lazy delivery, chain
    /// stubs, lists whole.
    pub fn fixed() -> Rule {
        Rule { placement: Placement::Function, chain_stubs: true, commit_grants: true, records: true, lists: Lists::Whole, keysets: true, deposit: false }
    }
    /// The control of chain stubs: a unit carries its bodies' evidence alone.
    pub fn bodies_only() -> Rule {
        Rule { chain_stubs: false, ..Rule::fixed() }
    }
}

/// What a node judges from.
#[derive(Clone, Debug)]
pub struct Seen {
    pub v: View,
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
    /// The sync IDs it can stamp (a writer of their thing; and every thing it writes); None: every
    /// sync ID it syncs.
    pub stamps: Option<Things>,
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
    /// `creation` of every commit (`creations_of`), with the commit and event counts it was
    /// computed at.
    pub creation_memo: std::sync::OnceLock<(usize, usize, Vec<Option<Id>>)>,
    /// Content parts whose path entry opens late (notes/path-form.md, the split form's waiting
    /// paths), each with the commit opening it (a key arriving: a content commit on its thing by
    /// its mint admin): a node holding the part without it knows no path for it, so the part
    /// brings nothing and pends (`World::hidden`). `usize::MAX`: not opened (yet).
    pub opens: BTreeMap<Id, Id>,
    /// Each rotation's keyset (a body on its thing, `World::rotate`) and the demotions it carries.
    pub keysets: BTreeMap<Id, Set>,
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
    /// `Placement::AtLog`: per (sync ID, copy), the commits it was placed for.
    pub placed: BTreeMap<(Sid, Id), Set>,
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
        World { w, rules: Rules::fixed(), sids, units, events: vec![], nodes: vec![], by: vec![], trust: Set::new(), creation_memo: Default::default(), opens: BTreeMap::new(), keysets: BTreeMap::new() }
    }
    pub fn node(&mut self, honest: bool, syncs: &[Thing]) -> usize {
        self.nodes.push(Node { honest, syncs: syncs.iter().copied().collect(), stamps: None });
        self.nodes.len() - 1
    }
    /// Node `n` stamps only `sids` (and what it writes from here on).
    pub fn stamps_only(&mut self, n: usize, sids: &[Thing]) {
        self.nodes[n].stamps = Some(sids.iter().copied().collect());
    }
    /// Node `n` can stamp sync ID `s` (log under it).
    pub fn stamps(&self, n: usize, s: Sid) -> bool {
        self.nodes[n].stamps.as_ref().is_none_or(|t| t.contains(&s))
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
            let on = c.on;
            if let Some(t) = self.nodes[n].stamps.as_mut() {
                t.insert(on);
            }
            self.by.push(n);
            self.events.push(Ev::Write(i));
        }
        ids
    }
    /// A rotation by node `n` (notes/write-path-design.md §2, D2): `f` writes its keyset, a body on
    /// the rotated thing (a content commit standing for the `keys.0` delta), carrying the demotions
    /// `carried` its writer holds (spec/crypto.md §4 Carried demotions), each whole (E4).
    pub fn rotate(&mut self, n: usize, carried: &[Id], f: impl FnOnce(&mut paths::World) -> Id) -> Id {
        let k = self.write(n, f);
        self.keysets.insert(k, carried.iter().copied().collect());
        k
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
            Kind::Grant { holder, .. } => Some(*holder),
            _ => None,
        }
    }
    /// A removal: a grant write giving below write at its own `ts` (none, read, or an `until`
    /// passed), but a finalize. (`paths::World::lowers` counts every write below admin, a fresh
    /// grant of write included.) A demotion from admin to write is not one here.
    pub fn removes(&self, i: Id) -> Option<Grant> {
        match &self.w.commits[i].kind {
            Kind::Grant { holder, role, until, finalize: false, .. } if paths::alive((*role, *until), self.w.commits[i].ts) < Role::Write => Some((*holder, self.on(i))),
            _ => None,
        }
    }
    /// A lowering that takes something away: a grant write below admin at its own `ts`
    /// (`paths::World::lowers`: no finalize), on a record hop or ordered (by key) after a write on
    /// its grant giving more at its own `ts`. What lazy delivery may leave behind (`undelivered`).
    pub fn takes_away(&self, i: Id) -> bool {
        let Some(e) = self.w.lowers(i) else { return false };
        let at = |j: Id| match &self.w.commits[j].kind {
            Kind::Grant { role, until, .. } => paths::alive((*role, *until), self.w.commits[j].ts),
            _ => Role::None,
        };
        self.w.is_record(e) || (0..self.w.commits.len()).any(|j| self.w.sets(j) == Some(e) && self.w.key(j) < self.w.key(i) && at(j) > at(i))
    }
    /// A held grant write giving write or above (any `until`).
    pub fn gives_write(&self, i: Id) -> Option<Grant> {
        match &self.w.commits[i].kind {
            Kind::Grant { holder, role, .. } if *role >= Role::Write => Some((*holder, self.on(i))),
            _ => None,
        }
    }

    // ---- What a sync ID requires ----

    /// The seeds of S's required set over `h`, its unit `unit`: the bodies, and under
    /// `chain_stubs` the grant writes on the grants of a chain from S's thing to a thing of the unit.
    fn seeds(&self, rule: &Rule, s: Sid, unit: &Things, h: &Set, reads: &BTreeSet<Grant>) -> Set {
        let chain = if rule.chain_stubs { self.chain_grants(rule, s, unit, reads) } else { BTreeSet::new() };
        let mut seed: Set = h.iter().copied().filter(|&i| unit.contains(&self.on(i)) || self.holder(i).is_some_and(|hd| chain.contains(&(hd, self.on(i))))).collect();
        if rule.keysets {
            // a held keyset's carried demotions are evidence of it, each whole
            let carried: Vec<Id> = seed.iter().filter_map(|k| self.keysets.get(k)).flatten().copied().filter(|c| h.contains(c)).collect();
            seed.extend(carried);
        }
        seed
    }
    /// S's required set over held set `h` with units `units`: bodies and copies.
    pub fn req(&self, rule: &Rule, s: Sid, units: &BTreeMap<Sid, Things>, h: &Set) -> Set {
        self.req_with(rule, s, units, h, &self.read_grants(h))
    }
    /// `req` with `h`'s read graph grants (`read_grants`) given: judged once per held set, not per
    /// sync ID.
    fn req_with(&self, rule: &Rule, s: Sid, units: &BTreeMap<Sid, Things>, h: &Set, reads: &BTreeSet<Grant>) -> Set {
        self.closure(rule, &self.seeds(rule, s, &units[&s], h, reads), h)
    }
    /// The grants of the chains by which S's keys open a thing of `unit`: read graph grants `reads`
    /// and record grants (`Rule::records`) on a path from S's thing to a thing of the unit, at any
    /// time. A record grant opens as a grant of admin from the mint admin to the thing it minted
    /// (spec/sync-set.md §2 T's keys open: effective role over paths that climb record grants; a
    /// dependent's secrets derive from its mint admin's), standing since the thing's creation,
    /// ordered before every write (spec/crypto.md §4 Key access), and read at any time as grants
    /// are: a record grant removed later still opens (as a grant removed later does).
    fn chain_grants(&self, rule: &Rule, s: Sid, unit: &Things, reads: &BTreeSet<Grant>) -> BTreeSet<Grant> {
        let grants: BTreeSet<Grant> = self.w.records.iter().copied().filter(|_| rule.records).chain(reads.iter().copied()).collect();
        let reach = |from: Things, fwd: bool| {
            let mut seen = from;
            loop {
                let more: Vec<Thing> = grants.iter().filter_map(|&(x, y)| if fwd { (seen.contains(&x) && !seen.contains(&y)).then_some(y) } else { (seen.contains(&y) && !seen.contains(&x)).then_some(x) }).collect();
                if more.is_empty() {
                    return seen;
                }
                seen.extend(more);
            }
        };
        let (from, to) = (reach(Things::from([s]), true), reach(unit.clone(), false));
        grants.into_iter().filter(|(x, y)| from.contains(x) && to.contains(y)).collect()
    }
    /// A grant write giving read or above (any `until`): a link by which keys open, once valid.
    fn gives_read(&self, i: Id) -> Option<Grant> {
        match &self.w.commits[i].kind {
            Kind::Grant { holder, role, .. } if *role >= Role::Read && !self.w.leave(i) => Some((*holder, self.on(i))),
            _ => None,
        }
    }
    /// The read graph's grant grants over held set `h`: each set by a write of `h` giving read that
    /// `h` judges valid (a node's own view, its lists whole), so no invalid or pending write
    /// opens keys or brings a chain stub.
    pub fn read_grants(&self, h: &Set) -> BTreeSet<Grant> {
        self.reads_valid(h).into_iter().filter_map(|i| self.gives_read(i)).collect()
    }
    /// The writes of `h` giving read that `h` judges valid (`read_grants`).
    pub fn reads_valid(&self, h: &Set) -> Set {
        let ids: Set = h.iter().copied().filter(|&i| self.gives_read(i).is_some()).collect();
        if ids.is_empty() {
            return Set::new();
        }
        let trust = self.trust.intersection(h).copied().collect();
        let seen = Seen { v: View { held: h.clone(), leaves: None, trust } };
        self.verdicts(&seen, &ids).into_iter().filter(|(_, v)| *v == Verdict::Valid).map(|(i, _)| i).collect()
    }
    /// Part `i`'s stated path is not known over `h`: its entry opens late (`World::opens`) and
    /// `h` lacks what opens it.
    pub fn hidden(&self, h: &Set, i: Id) -> bool {
        self.opens.get(&i).is_some_and(|o| !h.contains(o))
    }

    // ---- The closure ----

    /// A grant: a grant write setting its grant (no self-removal, no finalize) to a role, `until`
    /// disregarded.
    pub fn grant(&self, i: Id) -> bool {
        matches!(&self.w.commits[i].kind, Kind::Grant { role, finalize: false, .. } if *role > Role::None) && !self.w.leave(i)
    }
    /// Grant write `i` leaves its holder no grant (no role, or `until` 0: a removal, a self-removal,
    /// a finalize): a commit with one applies none of its grant writes on its thing until the
    /// creation of the entry it resets is held; a reset beside a put of a live grant is not waited
    /// for (spec/permissions.md §2 Grant writes; finding 25).
    pub fn ends_grant(&self, i: Id) -> bool {
        matches!(&self.w.commits[i].kind, Kind::Grant { role, until, .. } if *role == Role::None || *until == Some(0))
    }
    /// The creation of the entry grant write `i` resets, as its writer names it (spec/permissions.md
    /// §2 Grant writes): the entry of the write in force on its grant in its writer's walk, the last
    /// applied write on it there, where that write put an entry (a grant); None where none did (a
    /// record grant, a grant already removed: `i` resets an entry of its own, never waited for). The
    /// writer's walk is over everything written before `i`'s commit (it can know no later write).
    pub fn creation(&self, i: Id) -> Option<Id> {
        let at = (self.w.commits.len(), self.events.len());
        let (n, k, memo) = self.creation_memo.get_or_init(|| (at.0, at.1, self.creations_of()));
        if (*n, *k) == at { memo[i] } else { self.creations_of()[i] }
    }
    /// `creation` of every commit, one writer's walk per commit.
    fn creations_of(&self) -> Vec<Option<Id>> {
        let n = self.w.commits.len();
        let mut at = vec![usize::MAX; n];
        for (k, e) in self.events.iter().enumerate() {
            if let Ev::Write(j) = e {
                at[*j] = k;
            }
        }
        let mut walks: BTreeMap<Id, Set> = BTreeMap::new();
        (0..n)
            .map(|i| {
                let e = self.w.sets(i)?;
                let cid = self.w.cid(i);
                let applied = walks.entry(cid).or_insert_with(|| {
                    let held: Set = (0..n).filter(|&j| at[j] < at[cid]).collect();
                    let trust = self.trust.intersection(&held).copied().collect();
                    paths::judge(&self.w, &self.rules, &View { held, leaves: None, trust }).applied
                });
                let last = applied.iter().copied().filter(|&j| self.w.sets(j) == Some(e)).max_by_key(|&j| self.w.key(j))?;
                self.grant(last).then_some(last)
            })
            .collect()
    }
    /// `j` is ordered before `i` as `i`'s verdict reads it: by key for a grant-class `i`, by `ts`
    /// (the start of its `ts`) for content.
    fn before(&self, j: Id, i: Id) -> bool {
        if self.w.grant_class(i) {
            self.w.key(j) < self.w.key(i)
        } else {
            self.w.commits[j].ts < self.w.commits[i].ts
        }
    }
    /// The evidence closure of `seeds` over `avail`: the seeds, the other parts of a member's
    /// commit on its thing, every grant write on a member's key hop and on a grant of its stated
    /// path (E1), and under `commit_grants` on each grant its commit's parts on its thing set:
    /// `paths::evidence`, but for path entries opening late (`hidden`) and the control.
    pub fn closure(&self, rule: &Rule, seeds: &Set, avail: &Set) -> Set {
        if rule.commit_grants && self.opens.is_empty() {
            return paths::evidence(&self.w, seeds, avail);
        }
        let mut grants = BTreeSet::new();
        let mut s = seeds.clone();
        let mut done = Set::new();
        loop {
            for &m in s.difference(&done.clone()) {
                done.insert(m);
                // a part whose path entry has not opened brings nothing of its path
                if !self.hidden(avail, m) {
                    grants.extend(self.w.rests(m).iter().copied());
                }
                if rule.commit_grants && self.w.grant_class(m) {
                    grants.extend(self.w.part_ids(self.w.cid(m)).filter(|&p| self.on(p) == self.on(m)).filter_map(|p| self.w.sets(p)));
                }
            }
            let cids: std::collections::BTreeSet<(Id, Thing)> = s.iter().map(|&i| (self.w.cid(i), self.on(i))).collect();
            let more: Vec<Id> = avail
                .iter()
                .copied()
                .filter(|i| !s.contains(i))
                .filter(|&i| {
                    cids.contains(&(self.w.cid(i), self.on(i)))
                        || match &self.w.commits[i].kind {
                            Kind::Grant { .. } => self.w.sets(i).is_some_and(|e| grants.contains(&e)),
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

    // ---- Delivery ----

    /// The sync IDs node `n` syncs: its own, and the sync ID of every thing in a unit it syncs.
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
    /// What the thief logs under S: its own bodies there and the grants they rest on, read as if
    /// what it withholds were never written: every grant write but its own that gives below write
    /// (`removes`) or takes something away (`takes_away`). Nothing only a withheld write brings is
    /// logged, such as the creation of an entry it resets, or what a withheld read grant rests on.
    fn thief_logs(&self, rule: &Rule, s: Sid, units: &BTreeMap<Sid, Things>, held: &Set, own: &Set) -> Set {
        let mine: Set = own.iter().copied().filter(|&i| units[&s].contains(&self.on(i))).collect();
        let withheld = |i: Id| !own.contains(&i) && (self.takes_away(i) || self.removes(i).is_some());
        // it knows its own paths, opened or not
        let known: Set = held.iter().chain(own.iter().filter_map(|i| self.opens.get(i)).filter(|&&o| o < self.by.len())).copied().filter(|&i| !withheld(i)).collect();
        self.closure(rule, &mine, &known).into_iter().filter(|i| held.contains(i)).collect()
    }
    /// The state before any event.
    pub fn start(&self) -> State {
        let entries = self.sids.iter().map(|&s| (s, Set::new())).collect();
        State { units: self.units.clone(), entries, held: vec![Set::new(); self.nodes.len()], ..State::default() }
    }
    /// Applies event `k`, then lets the nodes log until nothing moves.
    pub fn apply(&self, rule: &Rule, st: &mut State, k: usize) {
        match self.events[k] {
            Ev::Write(i) => {
                st.written.insert(i);
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
        self.settle(rule, st);
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
            st.entries.get_mut(&s).unwrap().remove(&c);
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
        if rule.placement == Placement::AtLog {
            for s in self.sids.clone() {
                self.unplace(st, s, |c| c == i);
            }
        } else {
            for e in st.entries.values_mut() {
                e.remove(&i);
            }
        }
        self.settle(rule, st);
    }
    fn settle(&self, rule: &Rule, st: &mut State) {
        for _ in 0..ROUNDS {
            st.rounds += 1;
            let before = (st.entries.clone(), st.held.clone());
            match rule.placement {
                Placement::Function => self.round_function(rule, st),
                Placement::AtLog => self.round_atlog(st),
            }
            if (st.entries.clone(), st.held.clone()) == before {
                return;
            }
        }
        st.unsettled = true;
    }
    fn round_function(&self, rule: &Rule, st: &mut State) {
        // nothing is kept for its past: an entry stays while a holder's view requires it
        let mut new: BTreeMap<Sid, Set> = self.sids.iter().map(|&s| (s, Set::new())).collect();
        for n in 0..self.nodes.len() {
            let sy = self.syncs(n, &st.units);
            let own = self.own(st, n);
            let mut held: Set = st.held[n].iter().chain(&own).copied().chain(sy.iter().flat_map(|s| st.entries[s].iter().copied())).filter(|i| !st.forgotten.contains(i)).collect();
            // keep only what a synced sync ID requires, and its own writes
            let reads = loop {
                let reads = self.read_grants(&held);
                let keep: Set = sy.iter().flat_map(|&s| self.req_with(rule, s, &st.units, &held, &reads)).chain(own.iter().copied()).filter(|i| held.contains(i)).collect();
                if keep == held {
                    break reads;
                }
                held = keep;
            };
            for &s in &sy {
                let logs = if !self.nodes[n].honest {
                    self.thief_logs(rule, s, &st.units, &held, &own)
                } else if self.stamps(n, s) {
                    self.req_with(rule, s, &st.units, &held, &reads)
                } else if rule.deposit {
                    // D4: the removal copies its view requires there, deposited
                    self.req_with(rule, s, &st.units, &held, &reads).into_iter().filter(|&i| self.takes_away(i) && !st.units[&s].contains(&self.on(i))).collect()
                } else {
                    Set::new()
                };
                new.get_mut(&s).unwrap().extend(logs);
            }
            st.held[n] = held;
        }
        st.entries = new;
    }
    fn round_atlog(&self, st: &mut State) {
        for n in 0..self.nodes.len() {
            let sy = self.syncs(n, &st.units);
            let own = self.own(st, n);
            let honest = self.nodes[n].honest;
            let held: Set = own.iter().copied().chain(sy.iter().flat_map(|s| st.entries[s].iter().copied())).filter(|i| !st.forgotten.contains(i)).collect();
            for &s in &sy {
                let unit = st.units[&s].clone();
                for &c in &held {
                    if !unit.contains(&self.on(c)) || st.entries[&s].contains(&c) || (!honest && !own.contains(&c)) {
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
            st.held[n] = held;
        }
    }

    // ---- Judging ----

    /// `i` pends over `h` (spec/commits.md §4 Unjudgeable): its path entry has not opened, a keyset
    /// lacks a demotion it carries, a held part of its commit on its thing removing a holder resets
    /// an entry whose creation `h` lacks (the model writes a commit's parts as events of their own) (spec/permissions.md §2 Grant writes), or a hop it rests on
    /// (`paths::World::rests`, its key hop first), no record hop, has no held grant write ordered
    /// before it that does not itself pend.
    pub fn pend(&self, h: &Set, i: Id) -> bool {
        self.pend_with(h, i, &mut BTreeMap::new())
    }
    /// `pend`; `memo` what it found of parts over this `h`.
    fn pend_with(&self, h: &Set, i: Id, memo: &mut BTreeMap<Id, bool>) -> bool {
        if let Some(&p) = memo.get(&i) {
            return p;
        }
        let p = self.pends_here(h, i, memo);
        memo.insert(i, p);
        p
    }
    fn pends_here(&self, h: &Set, i: Id, memo: &mut BTreeMap<Id, bool>) -> bool {
        // a keyset is held only with every demotion it carries (spec/crypto.md §4, Held keyset)
        if self.hidden(h, i) || self.keysets.get(&i).is_some_and(|c| !c.is_subset(h)) {
            return true;
        }
        if self.w.grant_class(i) && self.w.part_ids(self.w.cid(i)).any(|p| h.contains(&p) && self.on(p) == self.on(i) && self.ends_grant(p) && self.creation(p).is_some_and(|c| !h.contains(&c))) {
            return true;
        }
        self.w.rests(i).iter().copied().filter(|&e| !self.w.is_record(e)).any(|e| {
            let on_e: Vec<Id> = h.iter().copied().filter(|&j| self.w.sets(j) == Some(e) && self.before(j, i)).collect();
            on_e.iter().all(|&j| self.pend_with(h, j, memo))
        })
    }
    /// The verdict on each of `ids` at a node judging from `s`.
    /// The walk runs over what does not pend: a pending grant write applies nothing (spec/commits.md
    /// §4 Unjudgeable; spec/permissions.md §2: a removal waiting for a creation applies none of its
    /// commit's grant writes).
    pub fn verdicts(&self, s: &Seen, ids: &Set) -> BTreeMap<Id, Verdict> {
        let mut memo = BTreeMap::new();
        let waiting: Set = s.v.held.iter().copied().filter(|&i| self.w.grant_class(i) && self.pend_with(&s.v.held, i, &mut memo)).collect();
        let held: Set = s.v.held.difference(&waiting).copied().collect();
        let trust = s.v.trust.intersection(&held).copied().collect();
        let rd = paths::judge(&self.w, &self.rules, &View { held, leaves: s.v.leaves.clone(), trust });
        ids.iter()
            .map(|&i| {
                let ok = if self.w.grant_class(i) { rd.applied.contains(&i) } else { rd.valid.contains(&i) || rd.copied.contains(&i) };
                let waits = self.pend_with(&s.v.held, i, &mut memo);
                (i, if waits { Verdict::Pending } else if ok { Verdict::Valid } else { Verdict::Invalid })
            })
            .collect()
    }
    /// What a reader holding sync ID `s` alone judges from (its held set minus `without`).
    pub fn reader(&self, rule: &Rule, st: &State, s: Sid, without: &Set) -> Seen {
        let held: Set = st.entries[&s].difference(without).copied().collect();
        self.reader_of(rule, &st.units[&s], held)
    }
    fn reader_of(&self, rule: &Rule, unit: &Things, held: Set) -> Seen {
        let leaves = match rule.lists {
            Lists::Whole => None,
            Lists::Unit => Some(unit.clone()),
        };
        let trust = self.trust.intersection(&held).copied().collect();
        Seen { v: View { held, leaves, trust } }
    }
    /// What the node holding everything written (and not forgotten) judges from.
    pub fn full(&self, st: &State, without: &Set) -> Seen {
        let held: Set = st.written.iter().copied().filter(|i| !st.forgotten.contains(i) && !without.contains(i)).collect();
        let trust = self.trust.intersection(&held).copied().collect();
        Seen { v: View { held, leaves: None, trust } }
    }
    /// The grant writes, written and not forgotten, that S's entries lack and no source of S holds:
    /// what lazy delivery has not brought S (notes/write-path-design.md §2, D1 to D3: evidence
    /// reaches S where a node holding it can log under S; a removal, and alike a grant a thief
    /// withholds that only nodes not syncing S hold, finding 23). A source is an honest node
    /// syncing S that can stamp it, or with `Rule::deposit` (D4) any honest node syncing it.
    pub fn undelivered(&self, rule: &Rule, st: &State, s: Sid) -> Set {
        let sources: Vec<usize> = (0..self.nodes.len()).filter(|&n| self.nodes[n].honest && self.syncs(n, &st.units).contains(&s) && (rule.deposit || self.stamps(n, s))).collect();
        st.written.iter().copied().filter(|&i| !st.forgotten.contains(&i) && self.w.grant_class(i) && !st.entries[&s].contains(&i) && !sources.iter().any(|&n| st.held[n].contains(&i))).collect()
    }
    /// What a reader of S is judged against (without `without`): the node holding everything
    /// written but what lazy delivery has not brought S (`undelivered`).
    pub fn reference(&self, rule: &Rule, st: &State, s: Sid, without: &Set) -> Seen {
        self.full(st, &without.union(&self.undelivered(rule, st, s)).copied().collect())
    }
    /// The gap (notes/write-path-design.md §2, The gap; issues/removed-key-writes-show-far.md):
    /// each body S should carry, honestly written or held, that S's reference judges otherwise
    /// than the node holding everything. Counted, not a failure: a removal no node holding S holds.
    pub fn gap(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        let fv = self.verdicts(&self.full(st, &Set::new()), &st.written);
        let mut out = vec![];
        for &s in &self.sids {
            let un = self.undelivered(rule, st, s);
            if un.is_empty() {
                continue;
            }
            let owed: Set = self.owed_bodies(st, s).into_iter().filter(|&i| self.nodes[self.by[i]].honest || st.entries[&s].contains(&i)).collect();
            for (i, v) in self.verdicts(&self.full(st, &un), &owed) {
                if v != fv[&i] {
                    out.push(Fail { prop: "gap", step: st.step, sid: s, id: i, reader: Some(v), full: Some(fv[&i]) });
                }
            }
        }
        out
    }
    /// What S should carry as bodies: every written commit on its unit's things.
    pub fn owed_bodies(&self, st: &State, s: Sid) -> Set {
        self.bodies(s, &st.units, &self.full(st, &Set::new()).v.held)
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
    /// P1: the reader of each sync ID judges every body it should carry as its reference does
    /// (`reference`: the node holding everything but what lazy delivery has not brought; a body it
    /// lacks is judged absent: `None`). A body under several sync IDs is judged alike under each
    /// only where their references agree (else the gap at one), and there P1 at each implies it:
    /// no check of its own.
    pub fn p1(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        self.p1_trusting(rule, st, &self.trust, "P1")
    }
    /// `p1` (`prop` naming its failures) for readers and references that trust `trust` (each what
    /// of it it holds) in place of the world's: evidence carries no trust, so a reader trusting
    /// otherwise must still hold everything its own walk reads.
    pub fn p1_trusting(&self, rule: &Rule, st: &State, trust: &Set, prop: &'static str) -> Vec<Fail> {
        let trusting = |mut s: Seen| {
            s.v.trust = trust.intersection(&s.v.held).copied().collect();
            s
        };
        let mut out = vec![];
        for &s in &self.sids {
            let owed = self.owed_bodies(st, s);
            let fv = self.verdicts(&trusting(self.reference(rule, st, s, &Set::new())), &owed);
            let v = trusting(self.reader(rule, st, s, &Set::new()));
            let rv = self.verdicts(&v, &owed.intersection(&v.v.held).copied().collect());
            for &i in &owed {
                let r = rv.get(&i).copied();
                if r.is_none() && !self.nodes[self.by[i]].honest {
                    // the thief logs its own writes where it likes
                    continue;
                }
                if r != Some(fv[&i]) {
                    out.push(Fail { prop: if r.is_none() { "P1-carried" } else { prop }, step: st.step, sid: s, id: i, reader: r, full: Some(fv[&i]) });
                }
            }
        }
        out
    }
    /// P11, carried demotions (notes/a3-spec/README.md Open 8): every demotion a keyset S holds
    /// carries is in S's entries and in its
    /// reader's required set (`P11`); a rotator holds what its
    /// keyset carries when it writes it (`P11-held`: the generators' own check).
    pub fn p11_keysets(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        let mut out = vec![];
        if let Some(Ev::Write(k)) = st.step.checked_sub(1).map(|e| self.events[e]) {
            for &c in self.keysets.get(&k).into_iter().flatten() {
                let n = self.by[k];
                if !st.held[n].contains(&c) && self.by[c] != n {
                    out.push(Fail { prop: "P11-held", step: st.step, sid: self.on(k), id: c, reader: None, full: None });
                }
            }
        }
        if !self.keysets.keys().any(|k| st.written.contains(k)) {
            return out;
        }
        for &s in &self.sids {
            let held = &st.entries[&s];
            let req = self.req(rule, s, &st.units, held);
            for c in held.iter().filter_map(|k| self.keysets.get(k)).flatten() {
                if !st.forgotten.contains(c) && !(held.contains(c) && req.contains(c)) {
                    out.push(Fail { prop: "P11", step: st.step, sid: s, id: *c, reader: None, full: None });
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
            }
        }
        out
    }
    /// P5, arrival order: for each body and each strict part of its evidence the reader holds,
    /// the reader missing that part judges the body as its reference without that part does
    /// (`local`, a failure), and counts where it judges (not pending) otherwise than once
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
                    let f = self.verdicts(&self.reference(rule, st, s, &y), &Set::from([i]))[&i];
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
    /// What a reader promotes from `seen`: each body it judges valid (a deposit of it promoted, a
    /// cover of it dropping what it covers, shown as settled).
    pub fn promotions(&self, seen: &Seen, bodies: &Set) -> Vec<Id> {
        self.verdicts(seen, bodies).into_iter().filter(|&(_, v)| v == Verdict::Valid).map(|(i, _)| i).collect()
    }
    /// P8, promoting: every promotion a reader of each sync ID takes (`when`) agrees with the
    /// verdict of its reference at that step. `AfterPass` acts on the sync ID's
    /// whole entries; `WhenNothingPends` (the control) also on every arrival order of each body's
    /// evidence (P5's subsets, `cap` parts) where the body does not pend.
    pub fn p8_promotions(&self, rule: &Rule, st: &State, when: PromoteWhen, cap: usize) -> Vec<Fail> {
        let refs: BTreeMap<Sid, BTreeMap<Id, Verdict>> = self.sids.iter().map(|&s| (s, self.verdicts(&self.reference(rule, st, s, &Set::new()), &st.written))).collect();
        let mut out = vec![];
        let mut check = |s: Sid, promoted: Vec<Id>| {
            for i in promoted {
                if refs[&s][&i] != Verdict::Valid {
                    out.push(Fail { prop: "P8-promote", step: st.step, sid: s, id: i, reader: Some(Verdict::Valid), full: Some(refs[&s][&i]) });
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

// ---- The joint property: acting through chain stubs ----

/// What a joint node holds beside its one sync ID, and logs (`World::joint`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Joint {
    /// The design: the stub of every holder on a path from the signer to a thing of the unit
    /// (the world's paths and those its own reading shows) and the signer's own role entries;
    /// its write logged with what its view requires.
    Paths,
    /// Control of `J-act`: the sync ID alone.
    Unit,
    /// Control of `J-logged`: its write logged with what S's entries alone require of it.
    UnitLog,
    /// Control of `J-act`: of each stub only the writes that remove nothing (`removes`): it acts
    /// along a removed hop.
    Grants,
    /// Control of `J-act`: the stubs of the holders on the world's paths alone: it writes along a
    /// path only its own reading shows (a hop whose grant a removal it lacks undid) without that
    /// path's stubs.
    WorldPaths,
}

impl World {
    /// The things signing a written commit that have no sync ID: what a node acts as.
    pub fn signers(&self, st: &State) -> Things {
        st.written.iter().map(|&i| self.w.commits[i].signer).filter(|a| !self.sids.contains(a)).collect()
    }
    /// The grants a reading gives a role on (records included): the read graph paths run over.
    fn role_grants(&self, rd: &paths::Reading) -> BTreeSet<Grant> {
        rd.roles.iter().filter(|&(_, &r)| r > Role::None).map(|(&e, _)| e).chain(self.w.records.iter().copied()).collect()
    }
    /// The holders on a path of `grants` from `a` to a thing of `unit`.
    pub fn path_holders(grants: &BTreeSet<Grant>, a: Thing, unit: &Things) -> Things {
        let reach = |from: Things, fwd: bool| {
            let mut seen = from;
            loop {
                let more: Vec<Thing> = grants.iter().filter_map(|&(x, y)| if fwd { (seen.contains(&x) && !seen.contains(&y)).then_some(y) } else { (seen.contains(&y) && !seen.contains(&x)).then_some(x) }).collect();
                if more.is_empty() {
                    return seen;
                }
                seen.extend(more);
            }
        };
        let (f, b) = (reach(Things::from([a]), true), reach(unit.clone(), false));
        f.intersection(&b).copied().filter(|&x| x != a).collect()
    }
    /// Holder `h`'s stub at `st`, cut to the grants on it from `from` (the signer and the
    /// holders on its paths): its grant writes on those grants as its own sync ID carries them, with
    /// their evidence there; the signer's (no sync ID in the model: its node's own) every written
    /// grant write on it, with their evidence.
    pub fn stub(&self, rule: &Rule, st: &State, h: Thing, from: &Things) -> Set {
        let (seeds, avail): (Set, Set) = match st.entries.get(&h) {
            Some(e) => (e.iter().copied().filter(|&i| self.on(i) == h && self.holder(i).is_some_and(|g| from.contains(&g))).collect(), e.clone()),
            None => {
                let all = self.full(st, &Set::new()).v.held;
                (all.iter().copied().filter(|&i| self.on(i) == h && self.w.grant_class(i)).collect(), all)
            }
        };
        self.closure(rule, &seeds, &avail)
    }
    /// What a node acting as `a` and syncing `s` holds: S's entries, and under `j` the stubs of
    /// the holders on the paths of `grants` and its own role entries.
    pub fn joint_held(&self, rule: &Rule, st: &State, s: Sid, a: Thing, grants: &BTreeSet<Grant>, j: Joint) -> Set {
        let mut held = st.entries[&s].clone();
        if j != Joint::Unit {
            let holders = Self::path_holders(grants, a, &st.units[&s]);
            let from: Things = holders.iter().copied().chain([a]).collect();
            for h in holders.into_iter().chain([a]) {
                held.extend(self.stub(rule, st, h, &from).into_iter().filter(|&i| j != Joint::Grants || self.removes(i).is_none()));
            }
        }
        held
    }
    /// The simple paths of `grants` from `a` to `t` with at most three hops, as a write states them
    /// (the things between).
    fn candidate_paths(grants: &BTreeSet<Grant>, a: Thing, t: Thing) -> Vec<Vec<Thing>> {
        let mut out = vec![];
        let mut todo = vec![vec![a]];
        while let Some(p) = todo.pop() {
            let at = *p.last().unwrap_or(&a);
            for &(_, y) in grants.range((at, 0)..=(at, Thing::MAX)) {
                if y == t {
                    out.push(p[1..].to_vec());
                } else if !p.contains(&y) && p.len() < 3 {
                    todo.push(p.iter().copied().chain([y]).collect());
                }
            }
        }
        out
    }
    /// The joint property: a node acting as a signer and holding one sync ID plus its paths'
    /// stubs (`joint_held`) judges and acts as the node holding everything.
    /// - `J-judge`: each body S should carry that it holds, it judges as S's reference or as the
    ///   node holding everything (holding a removal S lacks takes it to the latter).
    /// - `J-act`: a content write it would make now on a thing of S's unit, along any path the
    ///   world's roles or its own reading's run (`candidate_paths`), it judges valid iff the node
    ///   holding everything does.
    /// - `J-logged`: one it judges valid, logged under S with what its view requires there
    ///   (`req`), S's reader judges as the node holding everything.
    pub fn joint(&self, rule: &Rule, st: &State, j: Joint) -> Vec<Fail> {
        let full = self.full(st, &Set::new());
        let rd = paths::judge(&self.w, &self.rules, &full.v);
        let grants = self.role_grants(&rd);
        let fv = self.verdicts(&full, &st.written);
        let ts = self.w.commits.iter().map(|c| c.ts).max().unwrap_or(0) + 1;
        let seen = |held: Set| {
            let trust = self.trust.intersection(&held).copied().collect();
            Seen { v: View { held, leaves: None, trust } }
        };
        let mut out = vec![];
        for &s in &self.sids {
            let owed = self.owed_bodies(st, s);
            let refv = self.verdicts(&self.reference(rule, st, s, &Set::new()), &owed);
            for a in self.signers(st) {
                // the paths it would write along: the world's, and those its own reading shows,
                // each holder's stub on any of them held (every path, found by what it holds),
                // until its reading shows no path more
                let mut cand = grants.clone();
                let held = loop {
                    let held = self.joint_held(rule, st, s, a, &cand, j);
                    let more = self.role_grants(&paths::judge(&self.w, &self.rules, &seen(held.clone()).v));
                    if more.is_subset(&cand) || j == Joint::WorldPaths {
                        cand.extend(more);
                        break held;
                    }
                    cand.extend(more);
                };
                for (i, v) in self.verdicts(&seen(held.clone()), &owed.intersection(&held).copied().collect()) {
                    if v != fv[&i] && v != refv[&i] {
                        out.push(Fail { prop: "J-judge", step: st.step, sid: s, id: i, reader: Some(v), full: Some(fv[&i]) });
                    }
                }
                for &t in &st.units[&s] {
                    for path in Self::candidate_paths(&cand, a, t) {
                        let mut w2 = self.clone();
                        let i = w2.write(0, |p| p.content(a, ts, &path, t));
                        let mine: Set = held.iter().copied().chain([i]).collect();
                        let jv = w2.verdicts(&seen(mine.clone()), &Set::from([i]))[&i];
                        let all: Set = full.v.held.iter().copied().chain([i]).collect();
                        let f = w2.verdicts(&seen(all), &Set::from([i]))[&i];
                        if (jv == Verdict::Valid) != (f == Verdict::Valid) {
                            out.push(Fail { prop: "J-act", step: st.step, sid: s, id: i, reader: Some(jv), full: Some(f) });
                        }
                        if jv == Verdict::Valid {
                            let view = if j == Joint::UnitLog { st.entries[&s].iter().copied().chain([i]).collect() } else { mine.clone() };
                            let logged: Set = st.entries[&s].union(&w2.req(rule, s, &st.units, &view)).copied().collect();
                            let r = w2.verdicts(&w2.reader_of(rule, &st.units[&s], logged), &Set::from([i]))[&i];
                            if r != f {
                                out.push(Fail { prop: "J-logged", step: st.step, sid: s, id: i, reader: Some(r), full: Some(f) });
                            }
                        }
                    }
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
    /// Record grants on K's path: 0 grants only; 1 the hop after A a record grant
    /// (A mints O, or, with K writing through [A], A mints D); 2 a mint chain two deep (A mints O,
    /// O mints D: K's path [A, O] or [A] (by descent) climbs records past A). Where the last hop
    /// into D is a record grant, `raised` is X (D's admin by descent) lowering it to read before
    /// K's first write and raising it after the removal: a record grant changed later.
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
    // who can stamp what (a writer of the thing; and whatever it writes): each mint admin its
    // things (X D's and O's where they are minted down A's chain), Q, a member of A, A and D where
    // A writes D (not where A only reads it: `raised`); Y syncing A and Q syncing R only read there
    let mine = |m: Thing| [(D, d_mint), (O, o_mint)].into_iter().filter(move |&(_, by)| by == m).map(|(t, _)| t);
    let xs: Vec<Thing> = [A].into_iter().chain(if d_mint != Y { vec![D] } else { vec![] }).chain(mine(A)).collect();
    w.stamps_only(x, &xs);
    w.stamps_only(y, &[R].into_iter().chain(mine(Y)).collect::<Vec<_>>());
    if sh.org_apart {
        w.stamps_only(o, &mine(W).collect::<Vec<_>>());
    }
    w.stamps_only(q, if sh.raised { &[A] } else { &[A, D] });
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
    w.write(x, |p| p.grant(X, 1, &[], A, K, member, &[]));
    w.write(x, |p| p.grant(X, 1, &[], A, Q, member, &[]));
    let on_d = if sh.raised { Role::Read } else { Role::Write };
    let (holder, last) = if sh.via_org || sh.mint == 2 { (O, D) } else { (A, D) };
    if sh.via_org && o_mint != A {
        w.write(o, |p| p.grant(o_mint, 2, &[], O, A, Role::Write, &[]));
    }
    // D's admin: Y, or X by descent where D is minted down A's chain (its stated path the records)
    let (dn, ds) = if d_mint == Y { (y, Y) } else { (x, X) };
    if d_mint == Y {
        w.write(y, |p| p.grant(Y, 2, &[], last, holder, on_d, &[]));
    } else if sh.raised {
        w.write(x, |p| p.grant(X, 2, &[], last, holder, Role::Read, &[]));
    }
    let first = if sh.raised { None } else { Some(w.write(k, |p| p.content(K, 3, &path, D))) };
    match sh.units {
        2 => w.join(D, R),
        3 => w.leave(D, R),
        4 if sh.via_org => w.leave(O, R),
        _ => {}
    }
    let zn = w.node(true, &[]);
    w.stamps_only(zn, &[]);
    let gz = if sh.grant { Some(w.write(k, |p| p.grant(K, 4, &[], A, Z, Role::Write, &[]))) } else { None };
    if gz.is_some() {
        w.write(zn, |p| p.content(Z, 5, &path, D));
    }
    let listed: Vec<Id> = if sh.listed { first.into_iter().collect() } else { vec![] };
    let r = w.write(x, |p| p.grant(X, 6, &[], A, K, Role::None, &listed));
    if sh.raised {
        w.write(dn, |p| p.grant(ds, 7, &[], last, holder, Role::Write, &[]));
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
        w.write(x, |p| p.grant(X, 9, &[], A, K, Role::Write, &[]));
    }
    w
}

/// A random world (sampled searches): the family's cast (X minting A, Y minting D and R, W
/// minting O; members K, Q, Z of A; K the thief), its starting grants at random roles, then `len`
/// moves drawn from: a member's content on D or O along [A] or [A, O] (sometimes backdated), X
/// removing or re-granting a member (a random frontier of what it could have received) or two in
/// one commit, K
/// granting Z, Q writing an addendum against a held removal, Y or W raising or
/// lowering A's or O's grant, retags among the four things, a member's grant write on A or O to any
/// holder (junk where it holds no admin), content along [A, R] (A writing R half the time, R
/// holding nothing on D) or [O, A]; random node sync sets beside each mint admin syncing its
/// things. A third of the worlds have A mint O, and half of those O mint D (record grants on routes):
/// records on the members' paths in place of the starting grants, changed later by the moves
/// that change A's or O's grant (by X, their admin by descent).
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
    // a thing's admin by its record chain: the node thing at its top, writing by descent
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
    w.write(x, |p| p.grant(X, 1, &[], A, K, rk, &[]));
    w.write(x, |p| p.grant(X, 1, &[], A, Q, rq, &[]));
    for (on, hd) in [(D, A), (O, A), (D, O)] {
        if !records.contains(&(hd, on)) {
            let (a, n) = admin(on);
            w.write(n, |p| p.grant(a, 1, &[], on, hd, Role::Write, &[]));
        }
    }
    if rng.below(2) == 0 {
        // A writes R, which holds nothing on D: [A, R] is a path to D no grant joins
        w.write(y, |p| p.grant(Y, 1, &[], R, A, Role::Write, &[]));
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
                let front: Vec<Id> = (0..w.by.len()).filter(|&j| w.w.rests(j).contains(&(m, A)) && rng.below(2) == 0).collect();
                w.write(x, |p| p.grant(X, bts, &[], A, m, role, if role == Role::None { &front } else { &[] }));
            }
            5 => {
                w.write(k, |p| p.grant(K, bts, &[], A, Z, Role::Write, &[]));
            }
            6 if !removals.is_empty() => {
                let r = removals[rng.below(removals.len())];
                let list: Vec<Id> = (0..w.by.len()).filter(|&j| j != r && rng.below(2) == 0).collect();
                let adds: Vec<Id> = list.iter().copied().filter(|&j| !w.w.grant_class(j) && w.on(j) == D).collect();
                w.write(q, |p| p.addendum(Q, bts, &[A], D, r, &adds));
            }
            7 => {
                let role = [Role::None, Role::Read, Role::Write][rng.below(3)];
                let (on, hd) = [(D, A), (D, O), (O, A)][rng.below(3)];
                let (a, n) = admin(on);
                w.write(n, |p| p.grant(a, bts, &[], on, hd, role, &[]));
            }
            8 => {
                // D's admin rotates D (D2): its keyset carries X's removals on A (A reaches D: the
                // demotions it holds applied), which its node holds where it syncs A
                let (a, n) = admin(D);
                let carried: Vec<Id> = if w.nodes[n].syncs.contains(&A) { (0..w.by.len()).filter(|&j| w.by[j] == x && w.removes(j).is_some_and(|e| e.1 == A) && w.takes_away(j)).collect() } else { vec![] };
                w.rotate(n, &carried, |p| p.content(a, bts, &[], D));
            }
            10 => {
                // a member's grant write on A or O, any holder and role: junk where it holds no
                // admin there (finding 11)
                let (sg, n) = [(K, k), (Q, q), (Z, z)][rng.below(3)];
                let on = [A, O][rng.below(2)];
                let h = [K, Q, Z, D, R, O, A][rng.below(7)];
                if h != on {
                    w.write(n, |p| p.grant(sg, bts, &[], on, h, roles[rng.below(3)], &[]));
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
    /// Each of O, H, D, R minted by an earlier one of the five one time in three (record grants:
    /// record grants anywhere on a route, mint chains up to four deep, a minted thing in a unit, a
    /// record grant changed by churn), its admin the node thing at the top of its record chain,
    /// writing by descent. False: every thing minted by a node thing, the worlds as without it.
    pub mint: bool,
}

/// A random world of paths up to four holder things long (sampled searches): X mints A (members
/// K, Q, Z), W mints O and H, Y mints D and R; the five things ordered A, O, H, D, R, each holding
/// a random role on each later one (a random graph of routes), members sometimes granted directly
/// on another thing (a second route); then `len` moves: a member's content (K's half the time)
/// along a route (`wide_route`: mostly along grants written, else any increasing path; sometimes
/// backdated), K removed or re-granted on any thing it has a route on, X removing
/// or re-granting a member (a random frontier) or two in one commit, an admin's churn on any grant
/// between the things (a removal with a random frontier), junk grant writes by members on any thing
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
    // the node thing at the top of t's record chain, and its node
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
        w.write(x, |p| p.grant(X, 1, &[], A, m, r, &[]));
    }
    for i in 0..things.len() {
        for j in i + 1..things.len() {
            if rng.below(2) == 0 && !recs.contains(&(things[i], things[j])) {
                let (a, n) = admin(things[j]);
                let r = [Role::Write, Role::Write, Role::Read, Role::Admin][rng.below(4)];
                w.write(n, |p| p.grant(a, 1, &[], things[j], things[i], r, &[]));
            }
        }
    }
    // second routes: a member granted directly on another thing
    for m in [K, Q, Z] {
        if rng.below(3) == 0 {
            let on = things[1 + rng.below(4)];
            let (a, n) = admin(on);
            w.write(n, |p| p.grant(a, 1, &[], on, m, Role::Write, &[]));
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
                let front: Vec<Id> = (0..w.by.len()).filter(|&j| w.w.rests(j).contains(&(K, on)) && rng.below(2) == 0).collect();
                let (a, n) = admin(on);
                w.write(n, |p| p.grant(a, bts, &[], on, K, role, if role == Role::None { &front } else { &[] }));
            }
            4 => {
                let m = [K, Q, Z][rng.below(3)];
                let role = if rng.below(2) == 0 { Role::None } else { up(&mut rng) };
                let front: Vec<Id> = (0..w.by.len()).filter(|&j| w.w.rests(j).contains(&(m, A)) && rng.below(2) == 0).collect();
                w.write(x, |p| p.grant(X, bts, &[], A, m, role, if role == Role::None { &front } else { &[] }));
            }
            5 => {
                let role = if rng.below(2) == 0 { Role::None } else { up(&mut rng) };
                let (a, b) = [(K, Q), (K, Z), (Q, Z)][rng.below(3)];
                w.write_parts(x, |p| p.commit(X, bts, &[], A, vec![paths::Kind::set(a, role), paths::Kind::set(b, role)]));
            }
            6 => {
                // churn on a grant between two things, by the target's admin
                let j = 1 + rng.below(things.len() - 1);
                let (hd, on) = (things[rng.below(j)], things[j]);
                let role = [Role::None, Role::Read, Role::Write, Role::Admin][rng.below(4)];
                let front: Vec<Id> = (0..w.by.len()).filter(|&c| w.w.rests(c).contains(&(hd, on)) && rng.below(2) == 0).collect();
                let (a, n) = admin(on);
                w.write(n, |p| p.grant(a, bts, &[], on, hd, role, if role == Role::None { &front } else { &[] }));
            }
            7 => {
                // a member's grant write on any thing to any holder: junk where it holds no admin
                let (sg, n) = members[rng.below(3)];
                let (path, on) = wide_route(&w, &mut rng, sg);
                let hd = [K, Q, Z, A, O, H, D, R][rng.below(8)];
                if hd != on && !path.contains(&hd) {
                    let r = roles[rng.below(3)];
                    w.write(n, |p| p.grant(sg, bts, &path, on, hd, r, &[]));
                }
            }
            8 if !removals.is_empty() => {
                let r = removals[rng.below(removals.len())];
                let list: Vec<Id> = (0..w.by.len()).filter(|&j| j != r && rng.below(2) == 0).collect();
                let t = things[3 + rng.below(2)];
                let adds: Vec<Id> = list.iter().copied().filter(|&j| !w.w.grant_class(j) && w.on(j) == t).collect();
                w.write(q, |p| p.addendum(Q, bts, &[A], t, r, &adds));
            }
            9 => {
                let (sg, n) = members[rng.below(3)];
                let hd = [K, Q, Z][rng.below(3)];
                if hd != sg {
                    let r = up(&mut rng);
                    w.write(n, |p| p.grant(sg, bts, &[], A, hd, r, &[]));
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
                let front: Vec<Id> = (0..w.by.len()).filter(|&c| w.w.rests(c).contains(&(m, on)) && rng.below(2) == 0).collect();
                let (a, n) = admin(on);
                w.write(n, |p| p.grant(a, bts, &[], on, m, role, if role == Role::None { &front } else { &[] }));
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
                let gives_write = |w: &World, e: Grant| recs.contains(&e) || (0..w.by.len()).any(|c| w.w.sets(c) == Some(e) && w.gives_write(c).is_some());
                let bridged = |w: &World, t: Thing, u: Thing| (0..w.nodes.len()).any(|n| w.nodes[n].honest && { let sy = w.syncs(n, &w.units); sy.contains(&u) && (sy.contains(&t) || sy.contains(&A)) }) || w.units[&u].contains(&t) || w.units[&u].contains(&A);
                let pairs: Vec<(Thing, Thing)> = things[1..].iter().flat_map(|&t| things[1..].iter().map(move |&u| (t, u))).filter(|&(t, u)| t != u && !gives_write(&w, (A, t)) && !bridged(&w, t, u)).collect();
                if !pairs.is_empty() {
                    let (t, u) = pairs[rng.below(pairs.len())];
                    let (a, n) = admin(t);
                    w.write(n, |p| p.grant(a, bts, &[], t, A, Role::Read, &[]));
                    if !gives_write(&w, (t, u)) {
                        let (a, n) = admin(u);
                        w.write(n, |p| p.grant(a, bts, &[], u, t, Role::Write, &[]));
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
/// walk from `signer` along grants some grant write set (granted, removed or junk; one to five
/// things), else a random increasing subset of the things before a random target.
fn wide_route(w: &World, rng: &mut roles_model::Rng, signer: Thing) -> (Vec<Thing>, Thing) {
    use names::*;
    let things = [A, O, H, D, R];
    if rng.below(4) != 0 {
        let grants: BTreeSet<Grant> = (0..w.by.len()).filter_map(|i| w.w.sets(i)).chain(w.w.records.iter().copied()).filter(|e| things.contains(&e.1)).collect();
        let mut path: Vec<Thing> = vec![];
        let mut cur = signer;
        loop {
            let next: Vec<Thing> = grants.iter().filter(|e| e.0 == cur && !path.contains(&e.1)).map(|e| e.1).collect();
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
/// write on the next by X, the last on D.
pub fn cost(n: usize, k: usize, outside: usize) -> (usize, usize) {
    let c = cost_with(n, k, outside, 0, 1);
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
/// on a used grant), D in the units of `carried` sync IDs (its own and `carried - 1` others, R_j
/// holding nothing else).
pub fn cost_with(n: usize, k: usize, outside: usize, churn: usize, carried: usize) -> Cost {
    use names::*;
    assert!(outside <= k && k <= 4 && carried >= 1);
    let hs: Vec<Thing> = (0..k as Thing).map(|j| 20 + j).collect();
    let rs: Vec<Thing> = (1..carried as Thing).map(|j| 40 + j).collect();
    let mut recs: Vec<Grant> = hs.iter().chain(&rs).map(|&h| (X, h)).collect();
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
            w.write(x, |p| p.grant(X, 1 + c as u32, &[], h0, K, Role::Write, &[]));
        }
    }
    for j in 0..k {
        let next = hs.get(j + 1).copied().unwrap_or(D);
        let h = hs[j];
        w.write(x, |p| p.grant(X, 1, &[], next, h, Role::Write, &[]));
    }
    let t0 = 2 + churn as u32;
    for c in 0..n {
        w.write(x, |p| p.content(if k == 0 { X } else { K }, t0 + c as u32, &hs, D));
    }
    let st = w.run(&Rule::fixed(), |_| {});
    let copies = w.copies(&st, D).len();
    let everywhere = std::iter::once(D).chain(rs.iter().copied()).map(|s| w.copies(&st, s).len()).sum();
    Cost { copies, bodies: st.entries[&D].len() - copies, copies_everywhere: everywhere }
}

// ---- Story worlds (roles-model `paths` story under units) ----

/// How a story world's things are put in units (`story_world`): each a crossing of a path thing
/// or a written thing with a unit, from the start or by a retag after the removal.
pub const STORY_UNITS: usize = 6;

/// roles-model's stolen-node story (`paths::Sim`: may-grant grants, finalizes, `until`, covers, purges,
/// addenda by the state-based rule, commits of several grant writes and of several
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
            w.nodes.push(Node { honest: signer != X, syncs: Things::new(), stamps: None });
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
