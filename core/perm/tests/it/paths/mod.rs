//! The walk along stated paths against its oracle, core/test/roles-model `paths` under
//! `Rules::purging` (purge rights by class, copies, own covers;
//! A1 steps 3 and 4: notes/perm-paths.md; spec/permissions.md §1, §2,
//! §5.1, §5.2, §6). For each node's view of a world (what it holds, the frontier leaves it sees,
//! its trust set) both read: every edge-class part's status, every edge's history, the final
//! roles and invites, the trusted writes left void, every delta's validity, the copies valid
//! snapshots show, the purged deltas and copies, what a request could hold, and the dispute set.
//! spec/permissions.md §5.1, §5.2.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod chained;
mod content;
mod counts;
mod dump;
mod hand;
mod hand_content;
mod hand_purge;
mod incremental;
mod purge;
mod shapes;
mod single;

use crate::common::{seeded, sharded};
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts, WallMs};
use osis_perm::paths::{Commit, Content, Delta, DeltaClass, EdgeWrite, List, Names, Part, PartKind, Paths, Stated, Status};
use osis_perm::{Edge, Frontier, WriteId};
use roles_model::paths::{self as m, Honesty, Id, Kind, Reading, Rules, Thing, TinyMode, View, World};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The model's rules: `Rules::purging` (`Rules::fixed` with the draft's purge readings: rights by class and selector, requests
/// reaching copies, own covers standing with their removal).
pub fn rules() -> Rules {
    Rules::purging()
}

pub fn tid(t: Thing) -> Tid {
    let mut b = [0u8; 15];
    b[0] = t;
    Tid::from_bytes(b)
}

/// Thing `n` of a hand-built input (one the walk reads directly, not a model world's).
pub fn t(n: u32) -> Tid {
    let mut b = [0u8; 15];
    b[..4].copy_from_slice(&n.to_be_bytes());
    Tid::from_bytes(b)
}

pub fn cid(n: u64) -> CommitId {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    CommitId(b)
}

/// The commit ID of model commit `i` of `w`.
pub fn model_cid(w: &World, i: Id) -> CommitId {
    cid(w.cid(i) as u64)
}

pub fn ms(n: u64) -> Ts {
    Ts::make(WallMs(n), 0).unwrap()
}

pub fn commit(id: u64, ts: Ts, signer: u32, parts: Vec<Part>) -> Commit {
    Commit { id: cid(id), ts, signer: t(signer), parts }
}

fn role(r: roles_model::Role) -> Option<Role> {
    match r {
        roles_model::Role::None => None,
        roles_model::Role::Read => Some(Role::Read),
        roles_model::Role::Write => Some(Role::Write),
        roles_model::Role::Admin => Some(Role::Admin),
    }
}

pub fn purge_by(r: m::PurgeBy) -> PurgeBy {
    match r {
        m::PurgeBy::Admin => PurgeBy::Admin,
        m::PurgeBy::AuthorOrAdmin => PurgeBy::AuthorOrAdmin,
        m::PurgeBy::Writer => PurgeBy::Writer,
    }
}

/// A delta of the model's content-class kinds: content and purge requests on `doc.0` (a
/// destruction on `created.0`), covers its snapshots (stating each carried commit's own stamp,
/// purge author and purge-by, as an honest snapshot does), addenda on `addenda.0`.
fn delta(w: &World, i: Id) -> Delta {
    let k = &w.commits[i];
    let ids = |s: &m::Set| Frontier::new(s.iter().map(|&j| model_cid(w, j)));
    let (aspect, class) = match &k.kind {
        Kind::Content => ("doc.0", DeltaClass::Plain),
        Kind::Purge { names } => {
            let names = match *names {
                m::Names::Author(a) => Names::Author(tid(a)),
                m::Names::Aspect => Names::Aspect,
                m::Names::Commit(j) => Names::Commit(model_cid(w, j)),
                m::Names::Destroy => Names::Destroy,
            };
            (if names == Names::Destroy { "created.0" } else { "doc.0" }, DeltaClass::Purge { names })
        }
        Kind::Cover { carries } => {
            let stated = carries.iter().map(|&j| (model_cid(w, j), Stated { ts: ms(w.commits[j].ts as u64), purge_author: tid(w.purge_author(j)), purge_by: purge_by(w.commits[j].purge_by) })).collect();
            ("doc.0", DeltaClass::Snapshot { carries: ids(carries), stated, own: k.own })
        }
        Kind::Addendum { removal, list } => ("addenda.0", DeltaClass::Addendum { removal: model_cid(w, *removal), list: ids(list) }),
        _ => unreachable!("content-class kinds only"),
    };
    Delta { aspect: Ak::new(aspect).unwrap(), needs: Role::Write, purge_author: w.chain(i).iter().position(|&t| t == w.purge_author(i)).unwrap() as u32, purge_by: purge_by(k.purge_by), class }
}

/// A world as one node's input: its held parts, commits grouped by the model's commit ID, each
/// part's frontier cut to the leaves the node sees; and the model part each `WriteId` is.
pub struct Input {
    pub records: BTreeMap<Tid, Tid>,
    pub commits: Vec<Commit>,
    pub trust: BTreeSet<WriteId>,
    pub ids: BTreeMap<Id, WriteId>,
}

pub fn input(w: &World, v: &View) -> Input {
    let records = w.records.iter().map(|&(a, t)| (tid(t), tid(a))).collect();
    let mut by: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for &i in &v.held {
        by.entry(w.cid(i)).or_default().push(i);
    }
    let mut ids = BTreeMap::new();
    let mut commits = vec![];
    for (c, parts) in by {
        let first = &w.commits[parts[0]];
        let mut out = vec![];
        for (n, &i) in parts.iter().enumerate() {
            ids.insert(i, WriteId(cid(c as u64), n as u32));
            let k = &w.commits[i];
            let seen = |t: &Thing| v.leaves.as_ref().is_none_or(|l| l.contains(t));
            let kind = match &k.kind {
                Kind::Edge { holder, role: r, until, frontier, may_grant, finalize } => {
                    let value = role(*r).map(|v| Edge { role: v, until: until.map(|u| WallMs(u as u64)), may_grant: *may_grant, retain: false, floor: None });
                    let listed = frontier.iter().filter(|(t, _)| seen(t)).flat_map(|(t, l)| l.iter().map(|&j| (tid(*t), model_cid(w, j))));
                    let frontier = (!finalize).then(|| Arc::new(List::new(listed)));
                    PartKind::Edge(EdgeWrite { holder: tid(*holder), value, frontier })
                }
                _ => PartKind::Delta(delta(w, i)),
            };
            let direct = k.direct.iter().fold(0, |m, &j| m | 1 << j);
            out.push(Part { on: tid(k.on), path: k.path.iter().map(|&t| tid(t)).collect(), direct, kind });
        }
        commits.push(Commit { id: cid(c as u64), ts: ms(first.ts as u64), signer: tid(first.signer), parts: out });
    }
    let trust = v.trust.iter().filter_map(|i| ids.get(i).copied()).collect();
    Input { records, commits, trust, ids }
}

fn model_status(rd: &Reading, i: Id) -> Status {
    if rd.applied.contains(&i) {
        if rd.by_flag.contains(&i) { Status::MayGrant } else { Status::Applied }
    } else if rd.dropped.contains(&i) {
        Status::Dropped
    } else if rd.voided.contains(&i) {
        Status::Void
    } else {
        Status::Unapplied
    }
}

/// Where the walk and the model read `v` of `w` otherwise, the first difference; `disputes`
/// also compares the dispute sets (a walk per candidate on each side).
pub fn diff(w: &World, v: &View, disputes: bool) -> Option<String> {
    let rules = rules();
    let w = &as_known(w, v);
    let rd = m::judge(w, &rules, v);
    let inp = input(w, v);
    let mut p = Paths::evaluate(&inp.records, inp.trust.clone(), &inp.commits);
    compare(w, v, &rules, &rd, &inp, &mut p, disputes)
}

/// `w` as node view `v` can know it (notes/a1-spec/README.md Open 19, (a) as the walk takes it): a
/// cover the view does not hold carries nothing, since what a snapshot carries is known only from
/// the snapshot, while roles-model's `World::names` reads every cover's carries world-wide. Nothing
/// else the model judges reads a commit the view does not hold.
pub fn as_known(w: &World, v: &View) -> World {
    let mut w = w.clone();
    for (i, k) in w.commits.iter_mut().enumerate() {
        if let Kind::Cover { carries } = &mut k.kind
            && !v.held.contains(&i)
        {
            carries.clear();
        }
    }
    w
}

fn compare(w: &World, v: &View, rules: &Rules, rd: &Reading, inp: &Input, p: &mut Paths, disputes: bool) -> Option<String> {
    let back: BTreeMap<WriteId, Id> = inp.ids.iter().map(|(&i, &id)| (id, i)).collect();
    for (&i, id) in &inp.ids {
        if !w.edge_class(i) {
            let (a, b) = (rd.valid.contains(&i), p.content(id));
            if a != matches!(b, Some(Content::Valid(_))) {
                return Some(format!("delta {i}: model valid {a}, walk {b:?}"));
            }
            continue;
        }
        let (a, b) = (model_status(rd, i), p.status(id));
        if Some(a) != b {
            return Some(format!("part {i}: model {a:?}, walk {b:?}"));
        }
    }
    let copied: BTreeSet<CommitId> = rd.copied.iter().map(|&i| model_cid(w, i)).collect();
    if copied != p.copies() {
        return Some(format!("copies: model {copied:?}, walk {:?}", p.copies()));
    }
    let purged: BTreeSet<WriteId> = rd.purged.iter().filter_map(|i| inp.ids.get(i).copied()).collect();
    if purged != p.purged() {
        return Some(format!("purged: model {purged:?}, walk {:?}", p.purged()));
    }
    let copies: BTreeSet<CommitId> = rd.purged.iter().filter(|i| !v.held.contains(i)).map(|&i| model_cid(w, i)).collect();
    if copies != p.purged_copies() {
        return Some(format!("purged copies: model {copies:?}, walk {:?}", p.purged_copies()));
    }
    // what a node that cannot judge acts on: each request's path as could give admin and write
    for (&i, id) in &inp.ids {
        if !matches!(w.commits[i].kind, Kind::Purge { .. }) {
            continue;
        }
        for (r, mr) in [(Role::Admin, roles_model::Role::Admin), (Role::Write, roles_model::Role::Write)] {
            let (a, b) = (m::could_hold(w, &v.held, i, mr), p.could_give(id, r));
            if Some(a) != b {
                return Some(format!("request {i} could give {r:?}: model {a}, walk {b:?}"));
            }
        }
    }
    // histories: the applied writes on each edge, in key order
    let mine: BTreeMap<(Tid, Tid), Vec<Id>> = p
        .histories()
        .into_iter()
        .filter(|(_, h)| !h.is_empty())
        .map(|(e, h)| (e, h.iter().map(|(k, _)| back[&WriteId(k.commit, p_index(p, &inp.commits, k))]).collect()))
        .collect();
    let model: BTreeMap<(Tid, Tid), Vec<Id>> = rd.hist.iter().filter(|(_, h)| !h.is_empty()).map(|(&(a, b), h)| ((tid(a), tid(b)), h.iter().map(|x| x.0 .2).collect())).collect();
    if mine != model {
        return Some(format!("histories: model {model:?}, walk {mine:?}"));
    }
    let finals: BTreeMap<(Tid, Tid), (Option<Role>, Option<Role>)> = rd.roles.iter().map(|(&(a, b), &r)| ((tid(a), tid(b)), (role(r), role(rd.grantable[&(a, b)])))).collect();
    if finals != p.finals() {
        return Some(format!("finals: model {finals:?}, walk {:?}", p.finals()));
    }
    let void: BTreeSet<WriteId> = rd.void.iter().map(|i| inp.ids[i]).collect();
    if void != p.void_trusted() {
        return Some(format!("void trusted: model {void:?}, walk {:?}", p.void_trusted()));
    }
    if disputes {
        let md: BTreeSet<WriteId> = m::disputes(w, rules, v).into_iter().map(|i| inp.ids[&i]).collect();
        let pd = p.disputes();
        if md != pd {
            return Some(format!("disputes: model {md:?}, walk {pd:?}"));
        }
    }
    None
}

/// The input index of the part at key `k` (its `WriteId` index), found by key.
fn p_index(p: &Paths, commits: &[Commit], k: &osis_perm::paths::Key) -> u32 {
    let c = commits.iter().find(|c| c.id == k.commit).unwrap();
    (0..c.parts.len() as u32).find(|&n| p.key(&WriteId(c.id, n)).as_ref() == Some(k)).unwrap()
}

/// The walk of `v` of `w`, with the input it read.
pub fn walk(w: &World, v: &View) -> (Input, Paths) {
    let inp = input(w, v);
    let p = Paths::evaluate(&inp.records, inp.trust.clone(), &inp.commits);
    (inp, p)
}

/// A list naming each of `commits` whole: in the leaf of each of `things` (as A1's single list
/// reads, for hand worlds whose rule is not the leaf's).
pub fn whole(things: &[Tid], commits: impl IntoIterator<Item = CommitId>) -> List {
    let cs: Vec<CommitId> = commits.into_iter().collect();
    List::new(things.iter().flat_map(|&t| cs.iter().map(move |&c| (t, c))))
}

/// The walk's verdict on model delta `i` in `v` of `w`.
pub fn verdict(w: &World, v: &View, i: Id) -> Option<Content> {
    let (inp, p) = walk(w, v);
    p.content(inp.ids.get(&i)?)
}

/// `diff`, panicking with the world's trace.
#[track_caller]
pub fn agree(w: &World, v: &View) {
    if let Some(d) = diff(w, v, true) {
        panic!("{d}\nheld {:?} trust {:?}\n{}", v.held, v.trust, m::tiny_trace(w));
    }
}

/// Every commit held, trusting `trust`.
pub fn all(w: &World, trust: &[Id]) -> View {
    View::all(w).trusting(trust)
}

/// `agree` with every commit held, trusting `trust`.
#[track_caller]
pub fn agree_all(w: &World, trust: &[Id]) {
    agree(w, &all(w, trust));
}

/// A world named for the roles-model test it mirrors (or the walk's own, said so), and the trust
/// sets that test reads it under, every commit held.
pub type Row = (&'static str, fn() -> (World, Vec<Vec<Id>>));

/// Each row's world read alike by the walk and the model under each of its trust sets
/// (`agree_all`); every failing row named.
pub fn rows(rows: &[Row]) {
    let mut fails = Vec::new();
    for (name, world) in rows {
        let (w, trusts) = world();
        for t in &trusts {
            if let Some(d) = diff(&w, &all(&w, t), true) {
                fails.push(format!("{name}, trusting {t:?}: {d}\n{}", m::tiny_trace(&w)));
            }
        }
    }
    assert!(fails.is_empty(), "{}", fails.join("\n\n"));
}

/// The model's A with H (mint), X and B paired by H at 1.
pub fn paired() -> (World, Id, Id) {
    let mut w = m::account();
    let gx = w.edge(m::H, 1, &[], m::A, m::X, roles_model::Role::Admin, &[]);
    let gb = w.edge(m::H, 1, &[], m::A, m::B, roles_model::Role::Admin, &[]);
    (w, gx, gb)
}

/// The model's may-grant world: A2 (K's) shares T1 at write and GU (A2's guests) holds read with
/// the flag, by H through A; K gives X write on A2.
pub fn invited() -> World {
    let mut w = m::account();
    w.push(m::H, 1, &[m::A], m::T1, Kind::set(m::A2, roles_model::Role::Write));
    w.push(m::H, 1, &[m::A], m::T1, Kind::set(m::GU, roles_model::Role::Read).may_grant());
    w.edge(m::K, 1, &[], m::A2, m::X, roles_model::Role::Write, &[]);
    w
}

const MODES: [TinyMode; 9] = [
    TinyMode { flags: false, detached: false, keys: false, honest: Honesty::None },
    TinyMode { flags: true, detached: false, keys: false, honest: Honesty::None },
    TinyMode { flags: false, detached: true, keys: false, honest: Honesty::None },
    TinyMode { flags: false, detached: false, keys: false, honest: Honesty::Lists },
    TinyMode { flags: true, detached: false, keys: false, honest: Honesty::Lists },
    TinyMode { flags: false, detached: true, keys: false, honest: Honesty::Lists },
    TinyMode { flags: false, detached: false, keys: false, honest: Honesty::Writers },
    TinyMode { flags: true, detached: false, keys: false, honest: Honesty::Writers },
    TinyMode { flags: false, detached: true, keys: false, honest: Honesty::Writers },
];

/// Tiny worlds `start..start + n` of every kind; the failures, at most three.
fn tiny_run(start: u64, n: u64, disputes: bool) -> Vec<String> {
    let rules = rules();
    let mut fails = vec![];
    for mode in MODES {
        for i in start..start + n {
            let t = m::tiny_world(i, mode, &rules);
            if let Some(d) = diff(&t.w, &t.v, disputes) {
                fails.push(format!("tiny {mode:?} world {i}: {d}\ntrust {:?}\n{}", t.v.trust, m::tiny_trace(&t.w)));
                if fails.len() >= 3 {
                    return fails;
                }
            }
        }
    }
    fails
}

/// Story worlds `start..start + n`, at every node's view (honest nodes and those trusting
/// nothing); the failures, at most three.
fn story_run(start: u64, n: u64, disputes: bool) -> Vec<String> {
    let mut fails = vec![];
    for i in start..start + n {
        let s = m::random_world(i, &Rules::fixed());
        // Interim (issues/perm-walk-trails-model.md): the walk reads the key hop at A4; until then
        // a world with an edge write on a key hop or a commit signed by a key other than its signer's own
        // (moves 54, 55) is the model's alone
        if (0..s.w.commits.len()).any(|j| s.w.key_write(j) || s.w.commits[j].key != m::own_key(s.w.commits[j].signer)) {
            continue;
        }
        for node in s.honest().into_iter().chain(s.untrusting()) {
            if !s.sync.contains_key(&node) {
                continue;
            }
            let v = s.view(node, &Rules::fixed());
            if let Some(d) = diff(&s.w, &v, disputes) {
                fails.push(format!("story world {i} node {node}: {d}"));
                if fails.len() >= 3 {
                    return fails;
                }
            }
        }
    }
    fails
}

// spec/permissions.md §5.1: the walk reads small worlds of admins, of invites and of a detached
// thing written by marked direct hops as the model does, at every honesty, disputes included.
#[test]
#[ignore = "property"]
fn paths_tiny_agree_plain() {
    let f = tiny_run(0, 150, true);
    assert!(f.is_empty(), "{}", f.join("\n"));
}

// spec/permissions.md §5.1: the walk reads the stolen-node story's worlds at every node as the
// model does (disputes in a few).
#[test]
#[ignore = "property"]
fn paths_story_agree_plain() {
    let f = story_run(0, 6, true);
    assert!(f.is_empty(), "{}", f.join("\n"));
    let f = story_run(6, 30, false);
    assert!(f.is_empty(), "{}", f.join("\n"));
}

// spec/permissions.md §5.1: as above, a sample of tiny worlds (a property).
#[test]
#[ignore]
fn paths_tiny_agree_large() {
    let f: Vec<String> = sharded(160_000, 0x5eed_0a1a, |n, seed| tiny_run(seeded(seed) % (1 << 40), n.div_ceil(MODES.len() as u64), true)).concat();
    assert!(f.is_empty(), "{}", f.join("\n"));
}

// spec/permissions.md §5.1: as above, a sample of story worlds at every node (a property).
#[test]
#[ignore]
fn paths_story_agree_large() {
    let f: Vec<String> = sharded(8_000, 0x5eed_0a1b, |n, seed| story_run(seeded(seed) % (1 << 40), n, true)).concat();
    assert!(f.is_empty(), "{}", f.join("\n"));
}
