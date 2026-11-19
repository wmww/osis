//! Greenfield model of the sync unit as one independent thing and the dependents it reaches
//! (notes/sync-unit-scope.md, notes/sync-unit-design.md §2-§4, §6), beside `closure`, which models
//! the readable-closure unit the spec states today and which the sync differential reads. Plain
//! data and pure functions; properties in tests/it/spec_unit.rs, readings, counts and findings in
//! notes/closure-model.md (The unit model).
//!
//! Readings (where the notes leave a choice, the simplest):
//! - A unit (`Unit::Reach`) is an independent thing H and the dependents of H (mint-admin chain
//!   first meeting an independent thing at H) reached from H by strongs whose sources are in the
//!   unit. A dependent outside it is in no unit: nobody holds it and its strongs list nothing.
//! - A strong is a dot (its add commit, its target) carrying the home its writer filled
//!   (`Op::Add`); a snapshot (`Op::Cover`) carries on the dots it keeps with their homes.
//! - Handle blobs of S(G) (`View::handles`): each thing outside G's unit a live strong of the
//!   unit targets, and each home such a strong carries. Key blobs of S(K) (`View::keys`): each
//!   independent thing a thing of K's unit holds a direct grant on, naming its sync ID (here the
//!   thing itself) and a first credential (the sync epoch its logger held), which is not judged.
//! - A commit goes under its thing's unit; a role commit also under its holder's unit; a rotation
//!   also under the unit of each holder of a grant on its thing (its boxes).
//! - H's step lists H and every holder of a direct grant on H, steps current. A node holds the sync
//!   secret of each unit it entered and of a dependent of one whose tid it knows (a reader knows the
//!   tids of the units it reads, a node keeping units unread none), and nothing else.
//! - The walk (`walk`), one function for readers and nodes keeping units unread: a unit is entered
//!   when an entered unit lists a handle, an entered unit holds a key blob for that handle, and the
//!   sync ID it names has a step listing a thing whose sync secret the node holds (or the key's
//!   credential is current); read where a unit it reads holds a direct read grant on it.
//! - Stores per unit (`Net`): commit entries and blobs. A writer visiting a store first receives
//!   what it holds of the unit (a complete pass), logs what it holds that the unit carries, then
//!   logs each blob missing and deletes each that is not the unit's (a duplicate: the higher ID).
//! - A fork is commits valid on one side only (`Commit::side`); a blob or entry is the unit's while
//!   either side's view asks for it, and each side's keepers walk by their side's steps.
//!
//! - Promotion (design §5, `Op::Promote`): a view holding a valid promotion of a dependent X counts
//!   X independent, owning sync ID `n + c` (c the promotion's commit; a fork owns several, the
//!   greatest its unit), and X's mint admin holding admin on X by the record edge. The promotion
//!   travels under X's unit and, as a role commit naming the mint admin, under the mint admin's.
//!   `Op::Void` judges a commit invalid where it is held (a removal of its author arriving), so a
//!   voided promotion makes X dependent again. Units, entries, blobs, roots and key blobs' `names`
//!   are sync IDs; things, handles, homes and grants are things (an original independent thing's
//!   sync ID is its own index). A writer syncs the sync IDs its things own by the views it judges
//!   by; a keeper's roots are things, each entered by its sync ID on the keeper's side.
//! - The carrier rule (`Rules::carrier`): a writer deletes an entry its views put under other
//!   units only once each of those units' stores holds it.
//!
//! Left out: validity beyond two fixed sides and voids, keyless grants, public things, caps,
//! tickets other than a root's, sealing, the wire, dropping held commits, a source per node (one
//! store per sync ID).
use crate::closure::{Kind, Role, Set, C, T};
use std::cell::RefCell;
use std::rc::Rc;
use std::collections::{BTreeMap, BTreeSet};

/// A strong as an OR-set element: the commit that added it and its target.
pub type Dot = (C, T);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// A strong to `to` with the home its writer filled (design §2, A strong's home).
    Add { to: T, home: Option<T> },
    /// Removes these dots (strongs added on the same thing).
    Remove(BTreeSet<Dot>),
    /// A snapshot of the thing's strongs: the dots of `covers` it does not keep are gone, and each
    /// kept dot carries on with the home given.
    Cover { covers: BTreeSet<C>, keeps: Vec<(Dot, Option<T>)> },
    /// Sets the role record entry naming this holder on the commit's thing (`None`: removed).
    Role(T, Option<Role>),
    /// A rotation of the thing's sync secret.
    Rotate,
    /// A content delta on the thing; with `also` the same commit writes a second thing (a mixed
    /// commit: one blob under each unit).
    Body { also: Option<T> },
    /// Makes the dependent thing independent with a sync ID of its own (design §5).
    Promote,
    /// Judges commit `C` invalid wherever this is held (on the thing the voided commit is on).
    Void(C),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub on: T,
    pub op: Op,
    /// Valid on this side of a fork only (the other side's admins count it invalid, for good).
    pub side: Option<u8>,
}

/// Which things a unit carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// The design (§6): H and the dependents of H reached from H through things of the unit.
    Reach,
    /// Control: every dependent of H, reached or not.
    All,
    /// Control: also every dependent of H a strong the node holds targets from another unit.
    Held,
}

/// Which targets a unit lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    /// The design (§2): every thing outside the unit a live strong of the unit targets.
    Target,
    /// Control: only those whose independent the unit's thing holds a role on, by any chain.
    Role,
}

/// What a set of commits says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub kinds: Vec<Kind>,
    pub grants: BTreeMap<(T, T), Role>,
    /// Live strongs, each with the homes its live dots carry.
    pub strongs: BTreeMap<(T, T), Set>,
    /// Sync rotations per thing.
    pub epochs: Vec<usize>,
    /// The unit (sync ID) each thing is in, by the view's `Unit` rule.
    pub in_unit: Vec<Option<T>>,
    /// Each thing's mint admin by its record, whatever it counts as now.
    pub mint: Vec<Option<T>>,
    /// The sync IDs each independent thing owns (an original one: its own index; a promoted one:
    /// `n + c` per valid promotion `c` held).
    pub sids: Vec<Set>,
    /// The thing each promotion's sync ID belongs to, for every promotion written.
    pub owner: BTreeMap<T, T>,
    /// A promotion travels under its mint admin's unit too (off: a control).
    pub p_stays: bool,
}

impl View {
    /// The view of `held` (indices into `all`): live dots, role entries last commit wins.
    pub fn of(kinds: &[Kind], all: &[Commit], held: &BTreeSet<C>, unit: Unit) -> View {
        let n = kinds.len();
        let voided: BTreeSet<C> = held.iter().filter_map(|&c| if let Op::Void(x) = all[c].op { Some(x) } else { None }).collect();
        let held: BTreeSet<C> = held.difference(&voided).copied().collect();
        let held = &held;
        let mut removed: BTreeSet<Dot> = BTreeSet::new();
        let mut covered: BTreeSet<C> = BTreeSet::new();
        for &c in held {
            match &all[c].op {
                Op::Remove(r) => removed.extend(r),
                Op::Cover { covers, .. } => covered.extend(covers),
                _ => {}
            }
        }
        let mut v = View {
            kinds: kinds.to_vec(),
            grants: BTreeMap::new(),
            strongs: BTreeMap::new(),
            epochs: vec![0; n],
            in_unit: vec![],
            mint: kinds.iter().map(|k| if let Kind::Dependent(a) = k { Some(*a) } else { None }).collect(),
            sids: (0..n).map(|t| if kinds[t] == Kind::Independent { Set::from([t]) } else { Set::new() }).collect(),
            owner: (0..all.len()).filter(|&c| all[c].op == Op::Promote).map(|c| (n + c, all[c].on)).collect(),
            p_stays: true,
        };
        for &c in held {
            let x = all[c].on;
            if all[c].op == Op::Promote && v.mint[x].is_some() {
                v.kinds[x] = Kind::Independent;
                v.sids[x].insert(n + c);
            }
        }
        let mut live = |on: T, dot: Dot, home: Option<T>| {
            if !removed.contains(&dot) {
                v.strongs.entry((on, dot.1)).or_default().extend(home);
            }
        };
        for &c in held {
            let on = all[c].on;
            match &all[c].op {
                Op::Add { to, home } if !covered.contains(&c) => live(on, (c, *to), *home),
                Op::Cover { keeps, .. } if !covered.contains(&c) => keeps.iter().for_each(|&(d, h)| live(on, d, h)),
                _ => {}
            }
        }
        for &c in held {
            match all[c].op {
                Op::Role(g, Some(r)) => {
                    v.grants.insert((g, all[c].on), r);
                }
                Op::Role(g, None) => {
                    v.grants.remove(&(g, all[c].on));
                }
                Op::Rotate => v.epochs[all[c].on] += 1,
                _ => {}
            }
        }
        // The record edge: a promoted thing's mint admin holds admin on it.
        for x in 0..n {
            if let (Some(a), false) = (v.mint[x], v.sids[x].is_empty()) {
                v.grants.insert((a, x), Role::Admin);
            }
        }
        v.in_unit = v.units_by(unit);
        v
    }
    pub fn all(kinds: &[Kind], all: &[Commit], unit: Unit) -> View {
        View::of(kinds, all, &(0..all.len()).collect(), unit)
    }
    /// An independent thing's sync ID: the greatest it owns (a dependent's: its index, unused).
    pub fn sid(&self, t: T) -> T {
        self.sids[t].last().copied().unwrap_or(t)
    }
    /// The thing a sync ID belongs to.
    pub fn thing(&self, u: T) -> T {
        if u < self.kinds.len() {
            u
        } else {
            self.owner.get(&u).copied().unwrap_or(u)
        }
    }
    /// The units of the view: each independent thing's sync ID.
    pub fn units(&self) -> Set {
        self.independents().into_iter().map(|t| self.sid(t)).collect()
    }
    fn units_by(&self, u: Unit) -> Vec<Option<T>> {
        let n = self.kinds.len();
        let dep = |x: T| self.kinds[x] != Kind::Independent;
        let unit_of = |x: T| self.sid(self.ind(x));
        let mut out: Vec<Option<T>> = (0..n).map(|x| if !dep(x) || u == Unit::All { Some(unit_of(x)) } else { None }).collect();
        if u == Unit::Held {
            for &(a, b) in self.strongs.keys() {
                if dep(b) && self.ind(a) != self.ind(b) {
                    out[b] = Some(unit_of(b));
                }
            }
        }
        loop {
            let mut changed = false;
            for &(a, b) in self.strongs.keys() {
                if out[b].is_none() && out[a] == Some(unit_of(b)) {
                    out[b] = out[a];
                    changed = true;
                }
            }
            if !changed {
                return out;
            }
        }
    }
    /// The independent thing whose unit a dependent `x` belongs to by its mint-admin chain.
    pub fn ind(&self, mut x: T) -> T {
        while let Kind::Dependent(a) = self.kinds[x] {
            x = a;
        }
        x
    }
    pub fn independents(&self) -> Set {
        (0..self.kinds.len()).filter(|&x| self.kinds[x] == Kind::Independent).collect()
    }
    pub fn unit(&self, h: T) -> Set {
        (0..self.kinds.len()).filter(|&x| self.in_unit[x] == Some(h)).collect()
    }
    /// `g`'s role on each independent thing: the best chain of grants, the lowest role along it.
    pub fn roles_from(&self, g: T) -> BTreeMap<T, Role> {
        self.roles_through(g, &|_| true)
    }
    /// The same over chains whose holders (every thing but the last) satisfy `via`.
    pub fn roles_through(&self, g: T, via: &dyn Fn(T) -> bool) -> BTreeMap<T, Role> {
        let mut best = BTreeMap::from([(g, Role::Admin)]);
        loop {
            let mut changed = false;
            for (&(a, b), &r) in &self.grants {
                if let Some(&ra) = best.get(&a).filter(|_| via(a)) {
                    let v = ra.min(r);
                    if best.get(&b).is_none_or(|&o| o < v) {
                        best.insert(b, v);
                        changed = true;
                    }
                }
            }
            if !changed {
                return best;
            }
        }
    }
    /// The things reached from `from` by grants of at least `r`, `from` included.
    pub fn reach_by(&self, from: &Set, r: Role) -> Set {
        let mut out = from.clone();
        loop {
            let n = out.len();
            for (&(a, b), &g) in &self.grants {
                if g >= r && out.contains(&a) {
                    out.insert(b);
                }
            }
            if out.len() == n {
                return out;
            }
        }
    }
    /// The things outside `g`'s unit a live strong from a thing of the unit targets; with
    /// `Member::Role` only those whose independent `g` holds a role on by any chain.
    pub fn targets(&self, g: T, m: Member) -> Set {
        let mut out: Set =
            self.strongs.keys().filter(|&&(a, b)| self.in_unit[a] == Some(g) && self.in_unit[b] != Some(g)).map(|&(_, b)| b).collect();
        if m == Member::Role {
            let roles = self.roles_from(self.thing(g));
            out.retain(|&x| roles.contains_key(&self.ind(x)));
        }
        out
    }
    /// The handle blobs of S(g): each target (`targets`) and, with `homes`, each home a strong to
    /// it carries. No role and no other unit is read (but by `Member::Role`).
    pub fn handles(&self, g: T, m: Member, homes: bool) -> Set {
        let mut out = Set::new();
        for x in self.targets(g, m) {
            out.insert(x);
            if homes {
                for (_, hs) in self.strongs.iter().filter(|(&(a, b), _)| b == x && self.in_unit[a] == Some(g)) {
                    out.extend(hs.iter().filter(|&&h| h != self.thing(g)));
                }
            }
        }
        out
    }
    /// The key blobs of S(k): for each independent thing a thing of `k`'s unit holds a direct grant
    /// on (the role commits naming it travel under S(k)), each sync ID it owns, as (thing, sync ID).
    pub fn keys(&self, k: T) -> BTreeSet<(T, T)> {
        self.grants.keys().filter(|&&(a, _)| self.in_unit[a] == Some(k)).flat_map(|&(_, b)| self.sids[b].iter().map(move |&s| (b, s))).collect()
    }
    /// H's step: H and every holder of a direct grant on H.
    pub fn on_step(&self, w: T, h: T) -> bool {
        w == h || self.grants.contains_key(&(w, h))
    }
    /// The units commit `c` goes under.
    pub fn under(&self, c: &Commit) -> Set {
        let mut out: Set = self.in_unit[c.on].into_iter().collect();
        match c.op {
            Op::Role(w, _) => out.extend(self.in_unit[w]),
            Op::Rotate => out.extend(self.grants.keys().filter(|k| k.1 == c.on).filter_map(|&(w, _)| self.in_unit[w])),
            Op::Body { also: Some(z) } => out.extend(self.in_unit[z]),
            Op::Promote | Op::Void(_) if self.p_stays => out.extend(self.mint[c.on].and_then(|a| self.in_unit[a])),
            _ => {}
        }
        out
    }
}

/// A key blob: found by its target's handle (`of`), it names a sync ID (honest: the target's own)
/// and may carry the target's sync secret at an epoch as a first credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub of: T,
    pub names: T,
    pub cred: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Blob {
    Handle(T),
    Key(Key),
}

/// The honest blobs of S(g) by one view: its handles and its keys (no credential).
pub fn blobs_of(v: &View, g: T, m: Member, homes: bool) -> Vec<Blob> {
    let mut out: Vec<Blob> = v.handles(g, m, homes).into_iter().map(Blob::Handle).collect();
    out.extend(v.keys(g).into_iter().map(|(t, s)| Blob::Key(Key { of: t, names: s, cred: None })));
    out
}

/// The units a node entered: read, kept unread.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entered {
    pub read: Set,
    pub unread: Set,
}

impl Entered {
    pub fn units(&self) -> Set {
        self.read.union(&self.unread).copied().collect()
    }
}

/// How a unit is entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enter {
    /// The design: by the sync secret of a thing on its step, held through a unit entered.
    Steps,
    /// Control: by sync secrets reached through grants at any depth, units on the way unentered.
    Deep,
    /// Control: with no secret.
    Free,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Walk {
    pub enter: Enter,
    /// Control off: the walk stops at a unit kept unread (today's keeper).
    pub follow_unread: bool,
}

impl Walk {
    pub const DESIGN: Walk = Walk { enter: Enter::Steps, follow_unread: true };
}

/// The walk (design §3) of a node reading (`reads`) or keeping unread its `roots`, over the blobs
/// each unit holds (`blobs`), with `steps` the current steps, records and epochs: the least
/// fixpoint of entering the sync ID a key blob of an entered unit names for a handle an entered
/// unit lists, while its step lists a thing whose sync secret the node holds or the key carries a
/// current credential.
pub fn walk(steps: &View, reads: bool, roots: &Set, blobs: &dyn Fn(T) -> Vec<Blob>, w: Walk) -> Entered {
    let start = if reads { Entered { read: roots.clone(), unread: Set::new() } } else { Entered { read: Set::new(), unread: roots.clone() } };
    let deep = steps.reach_by(&roots.iter().map(|&u| steps.thing(u)).collect(), Role::Sync);
    let mut e = start.clone();
    loop {
        let units = e.units();
        let (mut handles, mut keys) = (Set::new(), vec![]);
        for &g in units.iter().filter(|g| w.follow_unread || e.read.contains(g)) {
            for b in blobs(g) {
                match b {
                    Blob::Handle(x) => {
                        handles.insert(x);
                    }
                    Blob::Key(k) => keys.push(k),
                }
            }
        }
        // A thing's sync secret: an entered unit's own, or a dependent's whose tid the node knows
        // (it reads the unit holding it).
        let holds = |h: T| {
            let i = steps.ind(h);
            if h == i {
                return steps.sids[i].iter().any(|s| units.contains(s));
            }
            let u = steps.sid(i);
            e.read.contains(&u) && steps.in_unit[h] == Some(u)
        };
        let mut next = start.clone();
        for k in keys {
            let u = k.names;
            let x = steps.thing(u);
            if !handles.contains(&k.of) || roots.contains(&u) {
                continue;
            }
            let enters = match w.enter {
                Enter::Steps => k.cred == Some(steps.epochs[x]) || (0..steps.kinds.len()).any(|h| steps.on_step(h, x) && holds(h)),
                Enter::Deep => deep.contains(&x),
                Enter::Free => true,
            };
            if !enters {
                continue;
            }
            let read = reads
                && steps.grants.iter().any(|(&(h, t), &r)| t == x && r >= Role::Read && steps.in_unit[h].is_some_and(|y| e.read.contains(&y)));
            if read {
                next.read.insert(u);
            } else {
                next.unread.insert(u);
            }
        }
        next.unread.retain(|u| !next.read.contains(u));
        if next == e {
            return e;
        }
        e = next;
    }
}

// ---- Stores, writers and keepers over time ----

/// When a writer judges a store against what it receives there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    /// The design: after a complete pass (it holds every entry the store has of the unit).
    First,
    /// Control: judges, then receives.
    After,
    /// Control: judges by what peers handed it alone.
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    pub unit: Unit,
    pub member: Member,
    pub pass: Pass,
    /// A blob or entry stands while either side's view asks for it (off, a control: each writer
    /// judges by its own side's view alone).
    pub any_side: bool,
    /// Control off: a key blob logged only by a writer that syncs its target.
    pub keys_by_any: bool,
    /// Of two alike blobs the lower ID stays (off: a control).
    pub lowest_wins: bool,
    /// A writer deletes what is not the unit's (off: a control).
    pub deletes: bool,
    /// The carrier rule (design §5): an entry the writer's views put under other units leaves only
    /// once each of those units' stores holds it (off: a control, it leaves at once).
    pub carrier: bool,
    /// A promotion stays under its mint admin's unit (design §5; off: a control).
    pub p_stays: bool,
}

impl Rules {
    pub const DESIGN: Rules = Rules {
        unit: Unit::Reach,
        member: Member::Target,
        pass: Pass::First,
        any_side: true,
        keys_by_any: true,
        lowest_wins: true,
        deletes: true,
        carrier: true,
        p_stays: true,
    };
}

#[derive(Clone, Debug)]
pub struct Writer {
    pub syncs: Set,
    pub side: u8,
    pub has: BTreeSet<C>,
}

#[derive(Clone, Debug)]
pub struct Keeper {
    /// Things, each entered by its sync ID on the keeper's side.
    pub roots: Set,
    pub side: u8,
    pub reads: bool,
    pub kept: Entered,
    /// The commits it held at its last pass: those of the stores of the units it kept.
    pub holds: BTreeSet<C>,
}

/// What a writer does at one store.
#[derive(Clone, Debug, Default)]
pub struct Acts {
    pub logs: Vec<(T, Blob)>,
    pub dels: Vec<(T, usize)>,
    pub entry_logs: Vec<(T, C)>,
    pub entry_dels: Vec<(T, C)>,
}

/// Writers holding commits and visiting the stores of the units they sync, where commit entries
/// and blobs live (a log adds an entry, a delete removes one, no tombstone); keepers walking the
/// stored blobs.
#[derive(Clone, Debug)]
pub struct Net {
    pub kinds: Vec<Kind>,
    pub commits: Vec<Commit>,
    pub writers: Vec<Writer>,
    pub keepers: Vec<Keeper>,
    /// Commit entries: (unit, commit).
    pub entries: BTreeSet<(T, C)>,
    /// Blobs: (unit, blob ID) -> blob.
    pub store: BTreeMap<(T, usize), Blob>,
    pub next_id: usize,
    pub rules: Rules,
    /// How keepers walk (a control may change it).
    pub walk: Walk,
    /// Store operations and keeper changes; blob operations alone.
    pub churn: usize,
    pub blob_ops: usize,
    /// Single visits after which the store's blobs were not what its own entries give.
    pub off: Vec<String>,
    /// Commits that ever had an entry, and how many times each entry was logged.
    pub ever: BTreeSet<C>,
    pub inserts: BTreeMap<(T, C), usize>,
    /// Moments a commit was carried nowhere though a unit some writer syncs carries it on a side
    /// (after a single visit), or a keeper lost a commit it held that its side's walk still keeps.
    pub lost: Vec<String>,
    /// Whether `lost` is checked (it costs a walk per keeper pass).
    pub watch: bool,
    /// Both sides' views of every commit and of each writer's holdings, by how many there were
    /// (both only grow).
    memo: RefCell<Memo>,
}

#[derive(Clone, Debug, Default)]
struct Memo {
    truth: Option<(usize, Rc<[View; 2]>)>,
    writers: BTreeMap<usize, (usize, Rc<[View; 2]>)>,
}

impl Net {
    /// Writers by (syncs, side), keepers by (roots, side, reads).
    pub fn new(kinds: Vec<Kind>, rules: Rules, writers: &[(Set, u8)], keepers: &[(Set, u8, bool)]) -> Net {
        Net {
            kinds,
            commits: vec![],
            writers: writers.iter().map(|(s, side)| Writer { syncs: s.clone(), side: *side, has: BTreeSet::new() }).collect(),
            keepers: keepers
                .iter()
                .map(|(r, side, reads)| Keeper {
                    roots: r.clone(),
                    side: *side,
                    reads: *reads,
                    kept: if *reads { Entered { read: r.clone(), unread: Set::new() } } else { Entered { read: Set::new(), unread: r.clone() } },
                    holds: BTreeSet::new(),
                })
                .collect(),
            entries: BTreeSet::new(),
            store: BTreeMap::new(),
            next_id: 0,
            rules,
            walk: Walk::DESIGN,
            churn: 0,
            blob_ops: 0,
            off: vec![],
            ever: BTreeSet::new(),
            inserts: BTreeMap::new(),
            lost: vec![],
            watch: false,
            memo: RefCell::default(),
        }
    }
    /// The view one side counts of `held`.
    pub fn side_view(&self, held: &BTreeSet<C>, side: u8) -> View {
        let valid: BTreeSet<C> = held.iter().copied().filter(|&c| self.commits[c].side.is_none_or(|s| s == side)).collect();
        let mut v = View::of(&self.kinds, &self.commits, &valid, self.rules.unit);
        v.p_stays = self.rules.p_stays;
        v
    }
    /// The sync IDs of these things by a view (a thing it counts dependent: none).
    fn sids_of(v: &View, things: &Set) -> Set {
        things.iter().filter(|&&t| v.kinds[t] == Kind::Independent).map(|&t| v.sid(t)).collect()
    }
    /// The units writer `w` syncs: the sync IDs its things own by the views it judges by.
    pub fn units_of(&self, w: usize) -> Set {
        let (vs, r) = self.judging(w);
        vs[r].iter().flat_map(|v| Net::sids_of(v, &self.writers[w].syncs)).collect()
    }
    /// The units keeper `k` roots at, by its side's view of every commit.
    pub fn roots(&self, k: usize) -> Set {
        Net::sids_of(&self.truths()[self.keepers[k].side as usize], &self.keepers[k].roots)
    }
    /// What every commit written says, on one side.
    pub fn truth(&self, side: u8) -> View {
        self.truths()[side as usize].clone()
    }
    /// Both sides' views of every commit written.
    fn truths(&self) -> Rc<[View; 2]> {
        let n = self.commits.len();
        let mut m = self.memo.borrow_mut();
        if m.truth.as_ref().is_none_or(|t| t.0 != n) {
            let all = (0..n).collect();
            m.truth = Some((n, Rc::new([self.side_view(&all, 0), self.side_view(&all, 1)])));
        }
        m.truth.as_ref().unwrap().1.clone()
    }
    /// Both sides' views of what writer `w` holds.
    fn writer_views(&self, w: usize) -> Rc<[View; 2]> {
        let has = &self.writers[w].has;
        let mut m = self.memo.borrow_mut();
        if m.writers.get(&w).is_none_or(|x| x.0 != has.len()) {
            m.writers.insert(w, (has.len(), Rc::new([self.side_view(has, 0), self.side_view(has, 1)])));
        }
        m.writers[&w].1.clone()
    }
    pub fn write(&mut self, c: Commit) -> C {
        self.commits.push(c);
        self.commits.len() - 1
    }
    /// Writer `w` writes `c` and holds it.
    pub fn author(&mut self, w: usize, c: Commit) -> C {
        let c = self.write(c);
        self.writers[w].has.insert(c);
        c
    }
    /// The home writer `w` fills for a strong to `to` (design §2): `to` held as a dependent of
    /// another unit gives that unit's thing; else a home some held delta gives for `to`; else none.
    pub fn home(&self, w: usize, to: T) -> Option<T> {
        let wr = &self.writers[w];
        let vs = self.writer_views(w);
        let v = &vs[wr.side as usize];
        if v.kinds[to] == Kind::Independent {
            return None;
        }
        let h = v.ind(to);
        if wr.syncs.contains(&h) && v.in_unit[to] == Some(v.sid(h)) {
            return Some(h);
        }
        let covered: BTreeSet<C> = wr
            .has
            .iter()
            .filter_map(|&c| if let Op::Cover { covers, .. } = &self.commits[c].op { Some(covers.iter().copied()) } else { None })
            .flatten()
            .collect();
        wr.has.iter().filter(|c| !covered.contains(c)).find_map(|&c| match &self.commits[c].op {
            Op::Add { to: x, home } if *x == to => *home,
            Op::Cover { keeps, .. } => keeps.iter().find(|(d, h)| d.1 == to && h.is_some()).and_then(|x| x.1),
            _ => None,
        })
    }
    /// Hands `c` to writer `w` (a peer exchange) if a unit it syncs carries it on either side.
    pub fn deliver(&mut self, w: usize, c: C) {
        let s = &self.writers[w].syncs;
        if !self.writers[w].has.contains(&c)
            && self.truths().iter().any(|t| !t.under(&self.commits[c]).is_disjoint(&Net::sids_of(t, s)))
        {
            self.writers[w].has.insert(c);
        }
    }
    /// Writer `w` writes `c` and logs it at once under each unit it syncs that its views put it
    /// under (an author logs in the write's transaction, before any pass).
    pub fn author_logs(&mut self, w: usize, c: Commit) -> C {
        let c = self.write(c);
        self.arrive(w, c);
        c
    }
    /// Commit `c` reaches writer `w`, which logs it at once under each unit it syncs that its
    /// views put it under (as its author does in the write's transaction), with no pass first.
    pub fn arrive(&mut self, w: usize, c: C) {
        self.writers[w].has.insert(c);
        let mine = self.units_of(w);
        let (vs, r) = self.judging(w);
        let under: Set = vs[r].iter().flat_map(|v| v.under(&self.commits[c])).filter(|u| mine.contains(u)).collect();
        self.act(Acts { entry_logs: under.into_iter().map(|u| (u, c)).collect(), ..Acts::default() });
    }
    pub fn deliver_all(&mut self) {
        for w in 0..self.writers.len() {
            for c in 0..self.commits.len() {
                self.deliver(w, c);
            }
        }
    }
    /// The views writer `w` judges by: both sides', or with `any_side` off its own.
    fn judging(&self, w: usize) -> (Rc<[View; 2]>, std::ops::Range<usize>) {
        let r = match self.writers[w].side {
            0 if !self.rules.any_side => 0..1,
            1 if !self.rules.any_side => 1..2,
            _ => 0..2,
        };
        (self.writer_views(w), r)
    }
    /// What S(g) is due by these views: its handles and its keys.
    fn due(&self, views: &[View], g: T) -> (Set, BTreeSet<(T, T)>) {
        let mut hs = Set::new();
        let mut ks = BTreeSet::new();
        for v in views {
            hs.extend(v.handles(g, self.rules.member, true));
            ks.extend(v.keys(g));
        }
        (hs, ks)
    }
    pub fn listed(&self, g: T) -> Vec<Blob> {
        self.store.iter().filter(|(&(u, _), _)| u == g).map(|(_, b)| *b).collect()
    }
    pub fn entries_of(&self, g: T) -> BTreeSet<C> {
        self.entries.iter().filter(|e| e.0 == g).map(|e| e.1).collect()
    }
    fn pull(&mut self, w: usize, g: T) {
        let es = self.entries_of(g);
        self.writers[w].has.extend(es);
    }
    /// What writer `w` does at S(g) by what it holds (design §2).
    pub fn look(&self, w: usize, g: T) -> Acts {
        let wr = &self.writers[w];
        let (vs, r) = self.judging(w);
        let views = &vs[r];
        let mut a = Acts::default();
        let under = |c: C| views.iter().any(|v| v.under(&self.commits[c]).contains(&g));
        for &c in &wr.has {
            if under(c) && !self.entries.contains(&(g, c)) {
                a.entry_logs.push((g, c));
            }
        }
        if self.rules.deletes {
            for c in self.entries_of(g) {
                // The carrier rule: where its views put it under other units, it leaves only once
                // each of their stores holds it.
                let elsewhere: Set = views.iter().flat_map(|v| v.under(&self.commits[c])).collect();
                let carried = !self.rules.carrier || elsewhere.iter().all(|&u| self.entries.contains(&(u, c)));
                if wr.has.contains(&c) && !under(c) && carried {
                    a.entry_dels.push((g, c));
                }
            }
        }
        let (hs, ks) = self.due(&views, g);
        let (mut kept_h, mut kept_k) = (Set::new(), BTreeSet::new());
        for (&(u, id), b) in &self.store {
            if u != g {
                continue;
            }
            let (due, first) = match b {
                Blob::Handle(x) => (hs.contains(x), kept_h.insert(*x)),
                Blob::Key(k) => (ks.contains(&(k.of, k.names)), ks.contains(&(k.of, k.names)) && kept_k.insert((k.of, k.names))),
            };
            if (!due && self.rules.deletes) || (due && !first && self.rules.lowest_wins) {
                a.dels.push((g, id));
            }
        }
        for &x in hs.difference(&kept_h) {
            a.logs.push((g, Blob::Handle(x)));
        }
        for &(t, s) in ks.difference(&kept_k) {
            if self.rules.keys_by_any || wr.syncs.contains(&t) {
                let cred = views.iter().map(|v| v.epochs[t]).max();
                a.logs.push((g, Blob::Key(Key { of: t, names: s, cred })));
            }
        }
        a
    }
    pub fn act(&mut self, a: Acts) {
        for (g, b) in a.logs {
            self.store.insert((g, self.next_id), b);
            self.next_id += 1;
            self.churn += 1;
            self.blob_ops += 1;
        }
        for k in a.dels {
            if self.store.remove(&k).is_some() {
                self.churn += 1;
                self.blob_ops += 1;
            }
        }
        for e in a.entry_logs {
            if self.entries.insert(e) {
                self.churn += 1;
                self.ever.insert(e.1);
                *self.inserts.entry(e).or_default() += 1;
            }
        }
        for e in a.entry_dels {
            self.churn += self.entries.remove(&e) as usize;
        }
    }
    /// Where S(g)'s blobs differ from what its own entries give (both sides' views of them): each
    /// due blob once, nothing else.
    pub fn store_off(&self, g: T) -> Option<String> {
        let es = self.entries_of(g);
        let views: Vec<View> = (0..2).map(|s| self.side_view(&es, s)).collect();
        let (hs, ks) = self.due(&views, g);
        let mut want: Vec<Blob> = hs.into_iter().map(Blob::Handle).collect();
        want.extend(ks.into_iter().map(|(t, s)| Blob::Key(Key { of: t, names: s, cred: None })));
        let mut got: Vec<Blob> = self.listed(g).into_iter().map(|b| if let Blob::Key(k) = b { Blob::Key(Key { cred: None, ..k }) } else { b }).collect();
        got.sort();
        (got != want).then(|| format!("S({g}) holds {got:?}, its entries give {want:?}"))
    }
    /// Writer `w` visits S(g): a complete pass (by `Rules::pass`), then it logs and deletes.
    pub fn visit(&mut self, w: usize, g: T) {
        if self.rules.pass == Pass::First {
            self.pull(w, g);
        }
        let a = self.look(w, g);
        self.act(a);
        if self.rules.pass == Pass::After {
            self.pull(w, g);
        }
        if let Some(e) = self.store_off(g) {
            self.off.push(format!("after writer {w}: {e}"));
        }
        self.check_carried(&format!("after writer {w} at S({g})"));
    }
    /// Whether some writer holds `c` and every writer holding it places it under some unit (none
    /// counts it released: a release racing a write is the release rule's, not a move's).
    pub fn placed(&self, c: C) -> bool {
        let holders: Vec<usize> = (0..self.writers.len()).filter(|&w| self.writers[w].has.contains(&c)).collect();
        !holders.is_empty()
            && holders.iter().all(|&w| {
                let (vs, r) = self.judging(w);
                vs[r].iter().any(|v| !v.under(&self.commits[c]).is_empty())
            })
    }
    /// Records each commit that had an entry and has none while it is placed (`placed`).
    pub fn check_carried(&mut self, when: &str) {
        if !self.watch {
            return;
        }
        let held: BTreeSet<C> = self.entries.iter().map(|e| e.1).collect();
        let gone: Vec<C> = self.ever.difference(&held).copied().filter(|&c| self.placed(c)).collect();
        for c in gone {
            self.lost.push(format!("{when}: commit {c} ({:?}) carried by no store", self.commits[c]));
        }
    }
    pub fn visit_all(&mut self, w: usize) {
        for g in self.units_of(w) {
            self.visit(w, g);
        }
    }
    /// Every writer looks at the same stores, then all act.
    pub fn visit_together(&mut self) {
        let mut acts = vec![];
        for w in 0..self.writers.len() {
            for g in self.units_of(w) {
                if self.rules.pass == Pass::First {
                    self.pull(w, g);
                }
                acts.push(self.look(w, g));
            }
        }
        for a in acts {
            self.act(a);
        }
        if self.rules.pass == Pass::After {
            for w in 0..self.writers.len() {
                for g in self.units_of(w) {
                    self.pull(w, g);
                }
            }
        }
        self.check_carried("after a visit together");
    }
    /// Keeper `k` at the stores of what it keeps, by its side's steps: the walk over the stored
    /// blobs; with `count` (a control) a unit stays while a kept unit lists its handle and key.
    pub fn pass(&mut self, k: usize, count: bool) {
        let kp = &self.keepers[k];
        let ts = self.truths();
        let t = &ts[kp.side as usize];
        let roots = self.roots(k);
        let next = if count {
            let mut kept = kp.kept.units();
            loop {
                let mut n = roots.clone();
                n.extend(walk(&t, false, &kept, &|g| self.listed(g), self.walk).units());
                if n == kept {
                    break Entered { unread: kept, ..Entered::default() };
                }
                kept = n;
            }
        } else {
            walk(&t, kp.reads, &roots, &|g| self.listed(g), self.walk)
        };
        let units = next.units();
        let holds: BTreeSet<C> = self.entries.iter().filter(|e| units.contains(&e.0)).map(|e| e.1).collect();
        if self.watch {
            // A commit it held, gone, that a unit its side's walk over the due blobs keeps carries.
            let want = walk(&t, kp.reads, &roots, &|g| self.truth_blobs(g), Walk::DESIGN).units();
            let gone: Vec<C> =
                kp.holds.difference(&holds).copied().filter(|&c| self.placed(c) && !t.under(&self.commits[c]).is_disjoint(&want)).collect();
            for c in gone {
                self.lost.push(format!("keeper {k} of {:?} lost commit {c} ({:?})", self.keepers[k].roots, self.commits[c]));
            }
        }
        self.churn += self.keepers[k].kept.units().symmetric_difference(&units).count();
        self.keepers[k].kept = next;
        self.keepers[k].holds = holds;
    }
    pub fn pass_all(&mut self, count: bool) {
        for k in 0..self.keepers.len() {
            self.pass(k, count);
        }
    }
    /// Every writer visits each unit it syncs in turn, then every keeper passes, until a round
    /// changes nothing: the rounds it took, or `None` within `max`.
    pub fn settle(&mut self, max: usize, count: bool) -> Option<usize> {
        for i in 1..=max {
            let before = self.churn;
            for w in 0..self.writers.len() {
                self.visit_all(w);
            }
            self.pass_all(count);
            if self.churn == before {
                return Some(i);
            }
        }
        None
    }
    /// The design's blobs of S(g) by every commit written: both sides' handles and keys.
    pub fn truth_blobs(&self, g: T) -> Vec<Blob> {
        let views = self.truths();
        let (hs, ks) = self.due(&views[..], g);
        let mut out: Vec<Blob> = hs.into_iter().map(Blob::Handle).collect();
        out.extend(ks.into_iter().map(|(t, s)| Blob::Key(Key { of: t, names: s, cred: None })));
        out
    }
    /// Where the stores and keepers differ from what every commit written says: per unit some
    /// writer syncs, its entries and its blobs (each once); per keeper, its walk over those blobs
    /// with the credentials stored with them (a unit no writer syncs as it is).
    pub fn wrong(&self) -> Vec<String> {
        let views = self.truths();
        let synced_units: Set = self.writers.iter().flat_map(|w| views.iter().flat_map(|v| Net::sids_of(v, &w.syncs))).collect();
        let synced = |g: T| synced_units.contains(&g);
        let mut out = vec![];
        let units: Set = views.iter().flat_map(|v| v.units()).collect();
        for g in units.into_iter().filter(|&g| synced(g)) {
            let want: BTreeSet<C> = (0..self.commits.len()).filter(|&c| views.iter().any(|v| v.under(&self.commits[c]).contains(&g))).collect();
            if self.entries_of(g) != want {
                out.push(format!("S({g}) holds entries {:?}, wants {want:?}", self.entries_of(g)));
            }
            let mut got: Vec<Blob> = self.listed(g).into_iter().map(|b| if let Blob::Key(k) = b { Blob::Key(Key { cred: None, ..k }) } else { b }).collect();
            got.sort();
            if got != self.truth_blobs(g) {
                out.push(format!("S({g}) lists {got:?}, wants {:?}", self.truth_blobs(g)));
            }
        }
        let stored = |g: T| -> Vec<Blob> {
            let creds: BTreeMap<(T, T), Option<usize>> =
                self.listed(g).into_iter().filter_map(|b| if let Blob::Key(k) = b { Some(((k.of, k.names), k.cred)) } else { None }).collect();
            self.truth_blobs(g)
                .into_iter()
                .map(|b| if let Blob::Key(k) = b { Blob::Key(Key { cred: creds.get(&(k.of, k.names)).copied().flatten(), ..k }) } else { b })
                .collect()
        };
        for (i, kp) in self.keepers.iter().enumerate() {
            let blobs = |g: T| if synced(g) { stored(g) } else { self.listed(g) };
            let want = walk(&views[kp.side as usize], kp.reads, &self.roots(i), &blobs, Walk::DESIGN);
            if kp.kept != want {
                out.push(format!("keeper of {:?} keeps {:?}, wants {want:?}", kp.roots, kp.kept));
            }
        }
        out
    }
}
