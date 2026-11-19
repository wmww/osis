//! The reference-graph differential (notes/test-properties.md): random
//! histories of making, strongs added and removed, grants to accounts and to things (so chains
//! occur), lowering, revoking, rotating, accepting, pairing and faults over a few nodes; at quiet
//! each node holds what held-model `closure` says its node closure is, built from the history
//! alone: it reads a thing exactly when the model reads it, then as the reference (a single
//! engine handed every commit directly: sync's property is perfect delivery to whoever holds
//! the thing), its sync set holds the model's read and stored things and no store entry sits
//! under a history thing's sync ID it does not hold. No needed body is deleted everywhere and no
//! node keeps an entry of a body it judges invalid.
//!
//! A history's writes are `Step`s played through the product's engine flows at one node, which
//! sync then carries. Each commit a step writes is handed to the reference as it is written;
//! what sync itself writes (rotations it makes due, addenda, tickets, account tickets) is handed
//! at the check, from every node. The one excuse (a holder left out of an epoch, spec/permissions.md
//! §3 Left out) is computed from the history's own record of what each node surely received,
//! never from a node under test.

use super::{DiskFault, Loss, Step, World};
use held_model::closure as hc;
use osis_base::{Ak, CommitId, Ref, Role, Tid, Value};
use osis_crypto::{RngCore, SeededRng};
use osis_engine::flows::edges::Demotion;
use osis_engine::local_peer::{Package, Peer};
use osis_engine::sync::Holding;
use osis_engine::{Engine, Ingested, Mutation};
use osis_schema::core_types::{self as ct, Edge};
use std::collections::{BTreeMap, BTreeSet};

/// The role a history grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Gives {
    /// Sync: the holder's nodes keep the thing's sync ID unread.
    Syncs,
    Reads,
    Writes,
}

impl Gives {
    pub fn role(self) -> Role {
        match self {
            Gives::Syncs => Role::Sync,
            Gives::Reads => Role::Read,
            Gives::Writes => Role::Write,
        }
    }

    /// The next role down (shrinking).
    pub fn lesser(self) -> Option<Gives> {
        match self {
            Gives::Writes => Some(Gives::Reads),
            Gives::Reads => Some(Gives::Syncs),
            Gives::Syncs => None,
        }
    }
}

/// Who a grant names: node j's account, or thing k (a chain: thing k's readers hold through it).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Holder {
    Node(usize),
    Thing(usize),
}

/// Printed as a script names it (`Holder::Node(1)`), so a printed step pastes into a test.
impl std::fmt::Debug for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Holder::Node(j) => write!(f, "Holder::Node({j})"),
            Holder::Thing(k) => write!(f, "Holder::Thing({k})"),
        }
    }
}

/// The one aspect a history writes.
pub fn value_ak() -> Ak {
    Ak::new("u:v.0").expect("aspect key")
}

/// A history thing's mint admin: its maker's account root, or thing k (whose keys a dependent
/// thing's derive from).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintAdmin {
    Root(Tid),
    Thing(usize),
}

/// A grant, a change of keys or a value write, for the excuse and lost writes: the node that
/// made it and what that node had surely received then (`Made::know`).
#[derive(Clone, Debug)]
struct Event {
    thing: usize,
    /// The holder's account for a grant to an account; `None` for a rotation or a write.
    granted: Option<Tid>,
    /// The commit of a value write; `None` for a grant or a rotation.
    wrote: Option<CommitId>,
    node: usize,
    known: BTreeSet<usize>,
}

/// What a history made, carried with the world (copied with it).
#[derive(Clone, Default)]
pub struct Made {
    /// Things made (`Step::New`, `Step::NewIn`), by index, with the node that made them.
    pub things: Vec<(Tid, usize)>,
    /// Where each thing was made.
    pub minted_with: Vec<MintAdmin>,
    /// Each thing is independent: a grant or rotation on it applied.
    pub independent: Vec<bool>,
    /// Each value written, with the commit that wrote it (values are unique).
    pub values: BTreeMap<String, CommitId>,
    /// Commits handed to the reference, in the order seen.
    pub handed: Vec<Package>,
    handed_ids: BTreeSet<CommitId>,
    written: u64,
    /// Things whose record edge a removal took (the roster then shows no mint admin either).
    record_gone: BTreeSet<usize>,
    /// (thing, account) pairs given a role directly, with the best role given: their tickets.
    given: BTreeMap<(usize, Tid), Role>,
    /// Grants to accounts and changes of keys, in the order made.
    events: Vec<Event>,
    /// Per node, the events it surely received: its own, and each held by a node it shared a run
    /// with on a clean network (no partition between them, both on, no loss).
    know: Vec<BTreeSet<usize>>,
    /// Per value write (by event), the nodes that surely received it when a node of its writer's
    /// account next took a strong away or lowered a role (a step that may release its thing):
    /// what a release after it could still lose (`lost_writes`).
    froze: BTreeMap<usize, BTreeSet<usize>>,
    /// Hand commits to the reference (`World::differential`); off, a step only writes.
    pub harvest: bool,
    /// Things held by no node at some quiet run (`ran`): gone for everyone, a strong to one
    /// holds nothing from then on (spec/sync-set.md §3 A thing goes when its last reference goes).
    gone: BTreeSet<usize>,
    /// The reference `note_gone` reads, fed what was handed since its last quiet run (made at
    /// the first; a copy of the world copies it).
    quiet: Option<QuietRef>,
}

/// The reference behind a lock (a world is `Send`); cloned, an exact copy sharing nothing, so
/// copies of one world never feed one reference.
struct QuietRef(std::sync::Mutex<Quiet>);

impl Clone for QuietRef {
    fn clone(&self) -> QuietRef {
        let mut q = self.0.lock().unwrap();
        let peer = q.peer.copy().expect("reference copy");
        QuietRef(std::sync::Mutex::new(Quiet { peer, fed: q.fed, waiting: q.waiting.clone() }))
    }
}

/// An incremental reference: the packages handed so far fed, those that did not take yet kept.
struct Quiet {
    peer: Peer,
    fed: usize,
    waiting: Vec<Package>,
}

impl Made {
    fn value(&mut self) -> String {
        self.written += 1;
        format!("v{}", self.written)
    }

    fn event(&mut self, thing: usize, granted: Option<Tid>, node: usize) {
        self.event_of(thing, granted, None, node);
    }

    fn event_of(&mut self, thing: usize, granted: Option<Tid>, wrote: Option<CommitId>, node: usize) {
        let n = self.events.len();
        if self.know.len() <= node {
            self.know.resize(node + 1, BTreeSet::new());
        }
        let known = self.know[node].clone();
        self.events.push(Event { thing, granted, wrote, node, known });
        self.know[node].insert(n);
    }
}

/// After a run: every set of nodes connected on a clean network shares what each surely received.
pub fn ran(w: &mut World) {
    if !w.net.loss.none() || !w.liars.is_empty() {
        return;
    }
    note_gone(w);
    let n = w.len();
    w.history.know.resize(n.max(w.history.know.len()), BTreeSet::new());
    let on: Vec<usize> = (0..n).filter(|i| w.online(*i)).collect();
    let mut seen = BTreeSet::new();
    for &a in &on {
        if !seen.insert(a) {
            continue;
        }
        let mut comp = vec![a];
        let mut k = 0;
        while k < comp.len() {
            let x = comp[k];
            for &y in &on {
                if !w.net.cut_off.contains(&(x.min(y), x.max(y))) && seen.insert(y) {
                    comp.push(y);
                }
            }
            k += 1;
        }
        let all: BTreeSet<usize> = comp.iter().flat_map(|i| w.history.know[*i].clone()).collect();
        for i in comp {
            w.history.know[i] = all.clone();
        }
    }
}

/// At a quiet run with every node on and connected on a clean network, every node holds its
/// node closure: a thing made that no account's model closure holds or carries is held by no
/// node, so it is gone (`Made::gone`). Judged from the history alone (a reference of what was handed).
fn note_gone(w: &mut World) {
    if !w.history.harvest || w.history.things.is_empty() || !w.net.cut_off.is_empty() || (0..w.len()).any(|i| !w.online(i)) {
        return;
    }
    for i in 0..w.len() {
        harvest(w, i);
    }
    let now = w.now();
    let mut qr = w.history.quiet.take().unwrap_or_else(|| QuietRef(std::sync::Mutex::new(Quiet { peer: Peer::new_bare(0x005e_ed0f_5eed, now).expect("reference"), fed: 0, waiting: Vec::new() })));
    let q = qr.0.get_mut().unwrap();
    let new: Vec<Package> = w.history.handed[q.fed..].to_vec();
    q.fed = w.history.handed.len();
    for pk in new {
        let id = pk.id;
        q.waiting.push(pk);
        for i in 0..w.len() {
            q.waiting.extend(w.engine(i).package(&id).ok().flatten());
        }
    }
    let Quiet { peer, waiting, .. } = q;
    loop {
        let before = waiting.len();
        waiting.retain(|pk| peer.receive_with(&pk.bytes, pk.blobs.clone(), &pk.lists).is_err());
        if waiting.len() == before || waiting.is_empty() {
            break;
        }
    }
    peer.clock.set(now);
    let _ = peer.tick();
    let m = Model::of(w, peer);
    // held, or carried unread under a sync ID some node keeps: a later reader fetches it there
    let mut held = hc::Set::new();
    for a in 0..m.accounts.len() {
        held.extend(m.closure(&w.history, a).0.carried);
    }
    for k in 0..w.history.things.len() {
        if !held.contains(&m.thing(k)) {
            w.history.gone.insert(k);
        }
    }
    w.history.quiet = Some(qr);
}

/// Hands the reference every commit node `i` holds that it has not been handed.
pub fn harvest(w: &mut World, i: usize) {
    if !w.history.harvest || !w.online(i) {
        return;
    }
    let e = w.engine(i);
    let ids = e.commit_ids();
    let mut new = Vec::new();
    for id in ids {
        if !w.history.handed_ids.contains(&id) {
            new.extend(w.engine(i).package(&id).ok().flatten());
        }
    }
    for pk in new {
        w.history.handed_ids.insert(pk.id);
        w.history.handed.push(pk);
    }
}

/// Adds (`on`) or removes a strong from `from`'s `holds.0` to `to` in `m`.
fn strong_in(m: &mut Mutation, from: Tid, to: Tid, on: bool) -> osis_engine::Result<()> {
    let v = Value::Strong(to);
    m.op(from, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: if on { osis_crdt::Op::Add(v) } else { osis_crdt::Op::Remove(v) } })?;
    Ok(())
}

fn root_of(e: &Engine) -> osis_engine::Result<Tid> {
    e.account_root().ok_or(osis_engine::Error::Misuse("no account root"))
}

/// Plays one history write; a note of what came of it.
pub fn step(w: &mut World, s: &Step) -> String {
    let i = match s {
        Step::New(i) | Step::NewIn(i, _) | Step::Write(i, _) | Step::Grant(i, ..) | Step::Give(i, ..) | Step::Lower(i, ..) | Step::Remove(i, ..) | Step::Revoke(i, ..) | Step::Rotate(i, _) | Step::Strong(i, ..) | Step::Unstrong(i, ..) | Step::Pair(i) => *i,
        _ => return String::new(),
    };
    if i >= w.len() || !w.online(i) {
        return "skipped: no such node, or off".into();
    }
    if w.node(i).account.is_none() {
        return "skipped: no account".into();
    }
    let r: Result<String, String> = match s {
        Step::New(_) => make(w, i, None),
        Step::NewIn(_, k) => make(w, i, Some(*k)),
        Step::Write(_, k) => {
            let Some(t) = thing(w, *k) else { return "skipped: no such thing".into() };
            let v = w.history.value();
            match w.write(i, |e| {
                let mut m = Mutation::new();
                m.set(t, &value_ak(), &Value::Str(v.clone()))?;
                e.commit(m)
            }) {
                Ok(c) => {
                    w.history.values.extend(c.map(|c| (v.clone(), c)));
                    if let Some(c) = c {
                        w.history.event_of(*k, None, Some(c), i);
                    }
                    Ok(v)
                }
                Err(e) => Err(e.to_string()),
            }
        }
        Step::Grant(_, k, j, g) => {
            // a rule test's shorthand: the role given, then node j accepts
            let r = give(w, i, *k, Holder::Node(*j), *g);
            if r.is_ok() && w.online(*j) {
                let _ = strong(w, *j, None, *k, true);
            }
            r
        }
        Step::Give(_, k, h, g) => give(w, i, *k, *h, *g),
        Step::Lower(_, k, h, g) => demote(w, i, *k, *h, Some(*g)),
        Step::Remove(_, k, j) => demote(w, i, *k, Holder::Node(*j), None),
        Step::Revoke(_, k, h) => demote(w, i, *k, *h, None),
        Step::Rotate(_, k) => {
            let Some(t) = thing(w, *k) else { return "skipped: no such thing".into() };
            let r = w.write(i, |e| e.make_independent_again(&t)).map(|_| String::new()).map_err(|e| e.to_string());
            if r.is_ok() {
                w.history.independent[*k] = true;
                w.history.event(*k, None, i);
            }
            r
        }
        Step::Strong(_, from, k) => strong(w, i, *from, *k, true),
        Step::Unstrong(_, from, k) => strong(w, i, *from, *k, false),
        Step::Pair(_) => {
            let n = w.pair(i);
            w.history.know.resize(n + 1, BTreeSet::new());
            Ok(format!("node {n}"))
        }
        _ => return String::new(),
    };
    if r.is_ok() && matches!(s, Step::Unstrong(..) | Step::Lower(..) | Step::Remove(..) | Step::Revoke(..)) {
        freeze(w, i);
    }
    match r {
        Ok(note) => {
            harvest(w, i);
            note
        }
        Err(e) => format!("refused: {e}"),
    }
}

/// Node `i` may have released a thing: each value write by its account not frozen yet keeps the
/// nodes that surely received it now (`Made::froze`).
fn freeze(w: &mut World, i: usize) {
    let account = w.node(i).account;
    let h = &w.history;
    let due: Vec<usize> = h.events.iter().enumerate().filter(|(n, e)| e.wrote.is_some() && !h.froze.contains_key(n) && w.node(e.node).account == account).map(|(n, _)| n).collect();
    let knew: Vec<(usize, BTreeSet<usize>)> = due.into_iter().map(|n| (n, (0..h.know.len()).filter(|j| h.know[*j].contains(&n)).collect())).collect();
    w.history.froze.extend(knew);
}

fn thing(w: &World, k: usize) -> Option<Tid> {
    w.history.things.get(k).map(|x| x.0)
}

fn holder_tid(w: &World, h: Holder) -> Option<Tid> {
    match h {
        Holder::Node(j) => (j < w.len()).then(|| w.node(j).account).flatten(),
        Holder::Thing(k) => thing(w, k),
    }
}

/// Node `i` mints a thing with its account root (`None`) or thing `k` as admin, held there by a
/// strong in the same commit, a value written.
fn make(w: &mut World, i: usize, mint_admin: Option<usize>) -> Result<String, String> {
    let admin = match mint_admin {
        Some(k) => match thing(w, k) {
            Some(t) => Some(t),
            None => return Ok("skipped: no such thing".into()),
        },
        None => None,
    };
    let v = w.history.value();
    match w.write(i, |e| -> osis_engine::Result<_> {
        let d = root_of(e)?;
        let admin = admin.unwrap_or(d);
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(admin, None));
        m.set(t, &value_ak(), &Value::Str(v.clone()))?;
        strong_in(&mut m, admin, t, true)?;
        Ok((t, d, e.commit(m)?))
    }) {
        Ok((t, d, c)) => {
            let h = &mut w.history;
            h.things.push((t, i));
            h.minted_with.push(mint_admin.map_or(MintAdmin::Root(d), MintAdmin::Thing));
            h.independent.push(false);
            h.values.extend(c.map(|c| (v, c)));
            Ok(format!("thing {}", h.things.len() - 1))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Node `i` gives holder `h` role `g` on thing `k`; nothing accepted.
fn give(w: &mut World, i: usize, k: usize, h: Holder, g: Gives) -> Result<String, String> {
    let (Some(t), Some(holder)) = (thing(w, k), holder_tid(w, h)) else { return Ok("skipped: no such thing or holder".into()) };
    let edge = Edge { role: g.role(), until: None, invite: None, retain: false, floor: None };
    let r = w.write(i, |e| e.grant(&t, &holder, &edge)).map(|_| String::new()).map_err(|e| e.to_string());
    if r.is_ok() || stands(w, i, &t, &holder, Some(g.role())) {
        let account = matches!(h, Holder::Node(_)).then_some(holder);
        let hist = &mut w.history;
        hist.independent[k] = true;
        // a thing granted a role gets secrets of its own first (spec/permissions.md §3)
        if let Holder::Thing(j) = h {
            hist.independent[j] = true;
        }
        if let Some(a) = account {
            let best = hist.given.entry((k, a)).or_insert(g.role());
            *best = (*best).max(g.role());
        }
        hist.event(k, account, i);
    }
    r
}

/// Node `i` lowers holder `h` on thing `k` to `g`, or removes it (`None`).
fn demote(w: &mut World, i: usize, k: usize, h: Holder, g: Option<Gives>) -> Result<String, String> {
    let (Some(t), Some(holder)) = (thing(w, k), holder_tid(w, h)) else { return Ok("skipped: no such thing or holder".into()) };
    let new = g.map(|g| Edge { role: g.role(), until: None, invite: None, retain: false, floor: None });
    let r = w.write(i, |e| e.demote(&t, &Demotion { holder, new, retain: None })).map(|_| String::new()).map_err(|e| e.to_string());
    if r.is_ok() && g.is_none() && matches!(h, Holder::Thing(p) if w.history.minted_with[k] == MintAdmin::Thing(p)) {
        w.history.record_gone.insert(k);
    }
    // a change taking the holder below read rotates the read role
    if (r.is_ok() || stands(w, i, &t, &holder, g.map(Gives::role))) && g.is_none_or(|g| g < Gives::Reads) {
        w.history.event(k, None, i);
    }
    r
}

/// Node `i` adds or removes a strong from its account root (`None`: accepting thing `k` when a
/// ticket for it is held) or from thing `from` to thing `k`.
fn strong(w: &mut World, i: usize, from: Option<usize>, k: usize, on: bool) -> Result<String, String> {
    let Some(t) = thing(w, k) else { return Ok("skipped: no such thing".into()) };
    let from = match from {
        Some(f) => match thing(w, f) {
            Some(x) => Some(x),
            None => return Ok("skipped: no such thing".into()),
        },
        None => None,
    };
    w.write(i, |e| -> osis_engine::Result<_> {
        let from = match from {
            Some(f) => f,
            None => root_of(e)?,
        };
        let mut m = Mutation::new();
        strong_in(&mut m, from, t, on)?;
        e.commit(m)
    })
    .map(|_| String::new())
    .map_err(|e| e.to_string())
}

/// Whether node `i` reads `holder` at `role` on `t` (`None`: no entry): a write refused with
/// its outcome unknown may have applied, and its user reads before repeating it (as the API's
/// `OutcomeUnknown` says).
fn stands(w: &mut World, i: usize, t: &Tid, holder: &Tid, role: Option<Role>) -> bool {
    w.online(i) && w.engine(i).roster(t).get(holder).map(|e| e.role) == role
}

/// What a node reads of a thing: the history's value and the roster's roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reads {
    pub value: Option<Value>,
    pub roles: Vec<(Tid, Role)>,
}

pub fn reads(e: &mut Engine, t: &Tid) -> Reads {
    let value = e.get(t, &value_ak()).ok().flatten();
    let roles = e.roster(t).into_iter().map(|(h, edge)| (h, edge.role)).collect();
    Reads { value, roles }
}

/// A world of `n` nodes, each with an account of its own (`world_of`).
pub fn world(seed: u64, n: usize) -> World {
    world_of(seed, n, n)
}

/// `world(0, 3)` where node 0 makes thing 0 and grants node 1's account sync (it keeps the thing
/// unread) and node 2's `gives`, then runs `runs` times; built once per process (`fixture_with`).
/// The world, the thing and its sync ID.
pub fn three(gives: Gives, runs: usize) -> (World, Tid, osis_base::SyncId) {
    let (w, (t, s)) = super::fixture_with(&format!("three {gives:?} {runs}"), || {
        let mut w = world(0, 3);
        w.cap = 2_000_000;
        let mut steps = vec![Step::New(0), Step::Grant(0, 0, 1, Gives::Syncs), Step::Grant(0, 0, 2, gives)];
        steps.extend(std::iter::repeat_n(Step::Run, runs));
        let _ = super::play(&mut w, &steps, String::new());
        let t = w.history.things[0].0;
        let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
        w.cap = super::RULE_CAP;
        (w, (t, s))
    });
    (w, t, s)
}

/// A world of `accounts` accounts over `nodes` nodes: one node each, each account every other's
/// contact (`introduce`), then a node paired to each account in turn (`World::pair`), quiet,
/// handing its commits to the reference from now on. Nodes find each other only as the product
/// does: whom each dials is `Engine::dial_peers` (contacts' dial lists). Drawn per seed (IDs,
/// keys and tie-breaks); built once per (seed, shape) per process and copied
/// (`osis_base::copying::cached`: a history plays twice, and several tests share seeds). Its
/// setup has its own delivery cap (`RULE_CAP` per node); a test's count starts after it. A random
/// history counts no work: its thread runs the memo effects' debug comparison
/// (`osis_base::memo::check_effects`).
pub fn world_of(seed: u64, accounts: usize, nodes: usize) -> World {
    osis_base::memo::check_effects(true);
    osis_base::copying::cached(
        &format!("history world {seed} {accounts} {nodes}"),
        || {
            let mut w = World::new(seed);
            w.cap = super::RULE_CAP * nodes as u64;
            for _ in 0..accounts {
                w.add_node();
            }
            introduce(&mut w);
            w.run();
            for j in accounts..nodes {
                w.pair(j % accounts.max(1));
            }
            w.run();
            w.cap = super::RULE_CAP;
            w.history.know = vec![BTreeSet::new(); nodes];
            w.history.harvest = true;
            w
        },
        |w: &mut World| w.copy(),
    )
}

/// Every account becomes every other's contact by contact cards (spec/sync-inbox.md §5): each
/// account's first node makes a read link to its profile, a node of every other account redeems
/// it, the join holding the profile from that account's D (a redeem is an accept,
/// spec/sync-set.md §4). Before any history only; nothing is handed by hand.
pub fn introduce(w: &mut World) {
    assert!(w.history.things.is_empty(), "introduce before any history only");
    let n = w.len();
    let mut first: BTreeMap<Tid, usize> = BTreeMap::new();
    for i in 0..n {
        if let Some(a) = w.node(i).account {
            first.entry(a).or_insert(i);
        }
    }
    let ones: Vec<usize> = first.values().copied().collect();
    let cards: BTreeMap<usize, osis_blob::ShareLink> = ones.iter().filter_map(|&i| w.node(i).profile.map(|p| (i, w.make_link(i, p, Role::Read)))).collect();
    let pairs: Vec<(usize, usize)> = ones.iter().flat_map(|&j| ones.iter().map(move |&i| (j, i))).filter(|(j, i)| j != i).collect();
    for &(j, i) in &pairs {
        if let Some(c) = cards.get(&i) {
            w.redeem(j, c);
        }
    }
    w.run();
    for &(j, i) in &pairs {
        if let Some(c) = cards.get(&i) {
            assert_eq!(w.redeem(j, c), osis_sync::types::Waiting::Done, "{j} redeems {i}'s card");
        }
    }
}

/// The reference: a single engine handed every commit any node wrote, again while one
/// applies. Every commit any node holds now is handed too (what sync wrote), each node's copy of
/// it: `harvest` keeps one copy per commit, perhaps a certificate copy (its header and some
/// parts), and the engine joins the parts a later copy carries (spec/commits.md §4).
pub fn reference(w: &mut World, lost: &BTreeSet<CommitId>) -> Peer {
    for i in 0..w.len() {
        harvest(w, i);
    }
    let mut r = Peer::new_bare(0x005e_ed0f_5eed, w.now()).expect("reference");
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    let mut handed = Vec::new();
    for pk in w.history.handed.clone().into_iter().filter(|pk| !lost.contains(&pk.id)) {
        let id = pk.id;
        handed.push(pk);
        for &i in &on {
            handed.extend(w.engine(i).package(&id).ok().flatten());
        }
    }
    for _ in 0..=handed.len() {
        let mut moved = false;
        for pk in &handed {
            moved |= matches!(r.receive_with(&pk.bytes, pk.blobs.clone(), &pk.lists), Ok(x) if !matches!(x, Ingested::Duplicate(_)));
        }
        if !moved {
            break;
        }
    }
    r.clock.set(w.now());
    let _ = r.tick();
    r
}

/// Node `i` reads thing `k` as the reference.
pub fn reads_as(w: &mut World, r: &mut Peer, k: usize, i: usize) {
    let Some((t, _)) = w.history.things.get(k).copied() else { panic!("no thing {k}") };
    let want = reads(&mut r.engine, &t);
    let got = reads(w.engine(i), &t);
    assert_eq!(got, want, "node {i} reads thing {k} unlike the reference");
}

/// The history as held-model sees it at the end, from the history and the reference alone:
/// model things 0..A are the accounts, A..2A their account roots, then the history's things.
pub struct Model {
    accounts: Vec<Tid>,
    world: hc::World,
    edges: hc::Edges,
}

impl Model {
    fn thing(&self, k: usize) -> usize {
        2 * self.accounts.len() + k
    }

    fn account(&self, a: &Tid) -> Option<usize> {
        self.accounts.iter().position(|x| x == a)
    }

    /// The model from the history: kinds (a dependent thing derives from its nearest independent
    /// mint admin), grants (the reference's rosters, each thing's mint admin as admin, each
    /// account admin of its root), strongs (the reference's `holds.0` of every root and thing).
    pub fn of(w: &mut World, r: &mut Peer) -> Model {
        let mut accounts: Vec<Tid> = Vec::new();
        let mut roots: Vec<Tid> = Vec::new();
        for i in 0..w.len() {
            if let Some(a) = w.node(i).account
                && !accounts.contains(&a)
            {
                accounts.push(a);
                roots.push(w.engine(i).account_root().expect("an account root"));
            }
        }
        let na = accounts.len();
        let h = &w.history;
        let things: Vec<Tid> = h.things.iter().map(|x| x.0).collect();
        let index = |t: &Tid| -> Option<usize> {
            accounts.iter().position(|x| x == t).or_else(|| roots.iter().position(|x| x == t).map(|a| na + a)).or_else(|| things.iter().position(|x| x == t).map(|k| 2 * na + k))
        };
        let mint_admin = |k: usize| match h.minted_with[k] {
            MintAdmin::Root(d) => index(&d).expect("a known account root"),
            MintAdmin::Thing(p) => 2 * na + p,
        };
        let mut kinds = vec![hc::Kind::Independent; 2 * na];
        for k in 0..things.len() {
            let mut x = k;
            kinds.push(loop {
                if h.independent[x] {
                    break if x == k { hc::Kind::Independent } else { hc::Kind::Dependent(2 * na + x) };
                }
                match h.minted_with[x] {
                    MintAdmin::Root(d) => break hc::Kind::Dependent(index(&d).expect("a known account root")),
                    MintAdmin::Thing(p) => x = p,
                }
            });
        }
        let mut grants = BTreeMap::new();
        for a in 0..na {
            grants.insert((a, na + a), hc::Role::Admin);
        }
        let mut edges = hc::Edges::new();
        let sources: Vec<Tid> = roots.iter().chain(&things).copied().collect();
        for (k, t) in things.iter().enumerate() {
            // the record edge stands at admin until an edge write lowers it, which the roster then
            // shows, or removes it (`record_gone`)
            let roster = r.engine.roster(t);
            if roster.is_empty() && !h.record_gone.contains(&k) {
                grants.insert((mint_admin(k), 2 * na + k), hc::Role::Admin);
            }
            for (holder, e) in roster {
                if let Some(g) = index(&holder) {
                    let role = match e.role {
                        Role::Sync => hc::Role::Sync,
                        Role::Read => hc::Role::Read,
                        Role::Write => hc::Role::Write,
                        Role::Admin => hc::Role::Admin,
                    };
                    let had = grants.entry((g, 2 * na + k)).or_insert(role);
                    *had = (*had).max(role);
                }
            }
        }
        for s in &sources {
            let from = index(s).expect("a source");
            for x in r.engine.get_typed(s, &ct::HOLDS).ok().flatten().unwrap_or_default() {
                if let Ref::Strong(y) = x
                    && let Some(to) = things.iter().position(|t| *t == y.0)
                {
                    edges.insert((from, 2 * na + to));
                }
            }
        }
        // a gone thing is held by no strong (spec/sync-set.md §3)
        edges.retain(|(_, y)| !h.gone.contains(&(y - 2 * na)));
        // the grants that read nothing (spec/crypto.md §4 Key access), as the reference orders them
        let keyless = r.engine.keyless_grants().iter().filter_map(|(t, g)| Some((index(g)?, index(t)?))).collect();
        Model { accounts, world: hc::World { kinds, grants, keyless }, edges }
    }

    /// Account `a`'s node closure and the keys it reads with: its root entered by keys, and a ticket for each thing given the account directly, open where
    /// its role there at the end (by any chain) is read or above, sync-only where it is sync,
    /// none where it has none (a ticket supplies up to the lower of its role and its holder's,
    /// spec/sync-set.md §2); a ticket gives its keys only where the walk enters its thing (§4).
    fn closure(&self, h: &Made, a: usize) -> (hc::Closure, hc::Set) {
        // the account's grants count on what its node closure reaches by strongs alone (a grant
        // naming it is taken at a strong to its thing, spec/sync-inbox.md §5 Nothing before the
        // strong), so nothing counts through a thing it never accepted, nor through one it keeps
        // unread, whose strongs it cannot read (spec/sync-set.md §2): the least fixpoint
        let na = self.accounts.len();
        let mut reached: hc::Set = hc::targets(&self.edges, na + a).collect();
        loop {
            let c = self.closure_reaching(h, a, &reached);
            let now: hc::Set = c.0.held.iter().filter(|x| !c.0.stored.contains(x)).chain([na + a].iter()).flat_map(|x| hc::targets(&self.edges, *x)).chain(reached.iter().copied()).collect();
            if now == reached {
                return c;
            }
            reached = now;
        }
    }

    /// `closure` with the account's grants counting on `reached` alone.
    fn closure_reaching(&self, h: &Made, a: usize, reached: &hc::Set) -> (hc::Closure, hc::Set) {
        let roles = self.world.roles_from_reached(a, reached);
        let na = self.accounts.len();
        let mut tickets = BTreeMap::from([(na + a, hc::Ticket::Open)]);
        for (&(k, acct), &given) in &h.given {
            if acct != self.accounts[a] {
                continue;
            }
            let given = match given {
                Role::Sync => hc::Role::Sync,
                Role::Read => hc::Role::Read,
                _ => hc::Role::Write,
            };
            match roles.get(&self.thing(k)).map(|r| (*r).min(given)) {
                Some(r) if r >= hc::Role::Read => tickets.insert(self.thing(k), hc::Ticket::Open),
                Some(_) => tickets.insert(self.thing(k), hc::Ticket::SyncOnly),
                None => None,
            };
        }
        let view = hc::NodeView { roots: [na + a].into(), tickets };
        let c = hc::closure(&self.world, &self.edges, &view, hc::Walk::Units);
        let keys = c.keys.clone();
        (c, keys)
    }

    /// Whether account `a` (model index) holds write or above on history thing `k` at the end.
    fn writes(&self, a: usize, k: usize) -> bool {
        self.world.roles_from(a).get(&self.thing(k)).is_some_and(|r| *r >= hc::Role::Write)
    }
}

/// The one excuse (spec/permissions.md §3 Left out): account `a` may fail to read thing `k` at
/// quiet exactly when its last grant on `k` and a change of `k`'s read keys were made each by a
/// node that had not surely received the other (`Made::know`), and no account that change boxed
/// (its maker's, the thing's maker's, and those whose grants its maker had surely received)
/// holds write or above on `k` at the end (every node is on at the check: such a node re-seals).
/// It permits a failure, never requires one.
fn excused(w: &World, m: &Model, a: Tid, k: usize) -> bool {
    let h = &w.history;
    let Some(g) = h.events.iter().rposition(|e| e.thing == k && e.granted == Some(a)) else { return false };
    let account_of = |i: usize| w.node(i).account;
    h.events.iter().enumerate().filter(|(_, e)| e.thing == k && e.granted.is_none() && e.wrote.is_none()).any(|(r, e)| {
        let concurrent = if r > g { !e.known.contains(&g) } else { !h.events[g].known.contains(&r) };
        let mut boxed: BTreeSet<Tid> = [account_of(e.node), account_of(h.things[k].1)].into_iter().flatten().collect();
        boxed.extend(e.known.iter().filter_map(|x| h.events[*x].granted.filter(|_| h.events[*x].thing == k)));
        concurrent && !boxed.iter().any(|b| m.account(b).is_some_and(|b| m.writes(b, k)))
    })
}

/// The value writes a release lost (spec/sync-set.md §3 Nothing of R stays: a node's own writes on
/// a thing it releases not yet held elsewhere go, and a release waits for no peer not connected):
/// node i's write on thing k, after which i's account took a strong away or lowered a role (a step
/// that may release k), that no other node surely received by then (`Made::froze`) whose account's
/// node closure holds k at the end, and that no node holds at the check (i, accepting k again,
/// fetches what others hold). The reference is not handed them. A value write alone: it changes no roster, so the
/// model is the same either way.
fn lost_writes(w: &mut World, m: &Model) -> BTreeSet<CommitId> {
    let holds = |a: Option<Tid>, k: usize| {
        a.and_then(|a| m.account(&a)).is_some_and(|a| {
            let (c, _) = m.closure(&w.history, a);
            c.held.contains(&m.thing(k)) || c.stored.contains(&m.thing(k))
        })
    };
    let mut lost = BTreeSet::new();
    for (n, e) in w.history.events.iter().enumerate() {
        // a write its writer's account may have released since: who had surely received it then
        let (Some(c), Some(knew)) = (e.wrote, w.history.froze.get(&n)) else { continue };
        let shared = knew.iter().any(|&j| j != e.node && j < w.len() && holds(w.node(j).account, e.thing));
        if !shared {
            lost.insert(c);
        }
    }
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    lost.retain(|c| !on.iter().any(|&i| w.engine(i).holds_commit(c)));
    lost
}

/// The compaction snapshots a release lost with the value writes `lost` (`lost_writes`): on the
/// value of a thing a lost write is on, by that write's author, held by no node at the check.
/// A writer's snapshot carries its own writes, so one no node holds goes with them (spec/sync-set.md
/// §3 Nothing of R stays); a later reader holding none of it has nothing to fetch.
fn snapshots_lost(w: &mut World, r: &mut Peer, lost: &BTreeSet<CommitId>) -> BTreeSet<CommitId> {
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    let h = &w.history;
    let by: BTreeSet<(Tid, Tid)> = h.events.iter().filter(|e| e.wrote.is_some_and(|c| lost.contains(&c))).filter_map(|e| Some((h.things[e.thing].0, w.node(e.node).account?))).collect();
    let mut out = BTreeSet::new();
    for (t, author) in by {
        for b in r.engine.body_page(&t, &value_ak(), true, 0, usize::MAX).unwrap_or_default() {
            let snapshot = r.engine.header(&b.id).is_some_and(|h| h.kind.is_compaction() && h.author == author);
            if snapshot && !on.iter().any(|&i| w.engine(i).holds_commit(&b.id)) {
                out.insert(b.id);
            }
        }
    }
    out
}

/// The checks at quiet; a failing one first prints what each node reads against the reference
/// and the model (`at_check`).
pub fn check(w: &mut World) {
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    // a by-hand replay inspecting the world it returns (notes/test-harnesses.md, Env vars)
    if !osis_base::testenv::end_checks() {
        osis_base::testenv::visible(true, "history::check skipped (OSIS_NO_END_CHECKS=1)");
        return;
    }
    let mut r = reference(w, &BTreeSet::new());
    let mut m = Model::of(w, &mut r);
    let mut lost = lost_writes(w, &m);
    if !lost.is_empty() {
        lost.extend(snapshots_lost(w, &mut r, &lost));
        r = reference(w, &lost);
        m = Model::of(w, &mut r);
    }
    let checked = catch_unwind(AssertUnwindSafe(|| {
        closure_clauses(w, &mut r, &m);
        body_clauses(w, &mut r, &m);
        invalid_clauses(w);
    }));
    if let Err(e) = checked {
        if !osis_base::testenv::quiet() {
            eprintln!("{}", at_check(w, &mut r, &m));
        }
        resume_unwind(e)
    }
}

/// Per thing, the value and roster size the reference and each online node read, and what the
/// model says each node does with it; per node, how many of the commits handed to the reference
/// it lacks; the frame census (`Net::census`).
fn at_check(w: &mut World, r: &mut Peer, m: &Model) -> String {
    let brief = |x: &Reads| format!("{} ({} roles)", x.value.as_ref().map_or("none".to_string(), |v| format!("{v:?}")), x.roles.len());
    let mut out = String::from("at the check:");
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    let views: Vec<Option<(hc::Closure, hc::Set)>> = (0..w.len()).map(|i| w.node(i).account.and_then(|a| m.account(&a)).map(|a| m.closure(&w.history, a))).collect();
    for (k, (t, maker)) in w.history.things.clone().iter().enumerate() {
        let x = m.thing(k);
        out.push_str(&format!("\n  thing {k} (made by node {maker}, {:?}): reference {}", m.world.kinds[x], brief(&reads(&mut r.engine, t))));
        for &i in &on {
            let said = views[i].as_ref().map_or("-", |(c, keys)| if c.read.contains(&x) || (c.held.contains(&x) && m.world.opens(keys, x)) { "read" } else if c.stored.contains(&x) || c.held.contains(&x) { "held unread" } else { "not held" });
            out.push_str(&format!("; node {i} {} (model: {said})", brief(&reads(w.engine(i), t))));
        }
    }
    out.push_str(&format!("\n  grants {:?}\n  strongs {:?}", m.world.grants, m.edges));
    let handed = w.history.handed_ids.clone();
    for &i in &on {
        let held: BTreeSet<CommitId> = w.engine(i).commit_ids().into_iter().collect();
        out.push_str(&format!("\n  node {i} lacks {} of {} handed commits", handed.difference(&held).count(), handed.len()));
    }
    out.push_str(&format!("\n  {}", w.net.census().replace('\n', "\n  ")));
    out
}

/// `check`'s closure clauses, per online node of an account and history thing: it reads the
/// thing (a value) exactly when the model reads it, then as the reference; its sync set holds a
/// independent thing read or kept unread exactly as the model does; it keeps no store entry
/// under the sync ID of an independent thing the model has it neither read nor keep unread.
fn closure_clauses(w: &mut World, r: &mut Peer, m: &Model) {
    let things = w.history.things.clone();
    let ids: Vec<Option<osis_base::SyncId>> = things.iter().map(|(t, _)| r.engine.sync_id_of(t).ok().flatten()).collect();
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    for i in on {
        let Some(acct) = w.node(i).account else { continue };
        let a = m.account(&acct).expect("an account");
        let (c, keys) = m.closure(&w.history, a);
        let set = w.engine(i).sync_set().expect("sync set");
        for (k, (t, _)) in things.iter().enumerate() {
            let x = m.thing(k);
            let excused = excused(w, m, acct, k);
            let independent = m.world.independent(x);
            let read = if independent { c.read.contains(&x) } else { c.held.contains(&x) && m.world.opens(&keys, x) };
            let got = reads(w.engine(i), t);
            if !excused {
                if got.value.is_some() != read {
                    panic!("node {i} reads thing {k}: {:?}, the model {}\n{}", got.value, if read { "reads it" } else { "does not" }, why_role(w, i, t));
                }
                if read {
                    let want = reads(&mut r.engine, t);
                    if got != want {
                        panic!("node {i} reads thing {k} unlike the reference\n  left: {got:?}\n right: {want:?}\n{}", why_role(w, i, t));
                    }
                }
            }
            if independent {
                let want = if c.read.contains(&x) { Some(Holding::Read) } else if c.stored.contains(&x) { Some(Holding::Unread) } else { None };
                let held: Vec<Holding> = set.ids.values().filter(|(ts, _)| ts.contains(t)).map(|(_, h)| *h).collect();
                let held = held.iter().copied().max_by_key(|h| matches!(h, Holding::Read));
                // a node keeping a thing unread cannot read its removal: it stops at the step its
                // secrets no longer derive, its entries dropped and its path kept
                // (spec/sync-judgement.md §6 Stops), which the store clause below checks
                let stopped = want.is_none() && held == Some(Holding::Unread);
                if !excused && !stopped && held != want {
                    panic!("node {i}'s sync set holds thing {k} as {held:?}, the model {want:?}\n{}", why_role(w, i, t));
                }
                if let Some(s) = &ids[k]
                    && want.is_none()
                {
                    let n = w.store(i).entries(s).expect("entries").len();
                    assert_eq!(n, 0, "node {i} keeps {n} store entries under thing {k}'s sync ID, which it does not hold");
                }
            }
        }
    }
}

/// Debug builds: node `i`'s role on `t` and its secrets (`World::why_role`), for a role or read
/// clause that fails.
fn why_role(w: &mut World, i: usize, t: &Tid) -> String {
    #[cfg(debug_assertions)]
    {
        format!("why role (node {i}):\n{}", w.why_role(i, t))
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (w, i, t);
        String::new()
    }
}

/// The commits whose bodies the reference holds valid on thing `t`'s value reading `v`: the
/// commit that wrote it and each valid snapshot carrying it (spec/commits.md §5 Covered), so the
/// value survives that commit being forgotten everywhere (Forgetting). Taken from the generated
/// history, never from the nodes under test.
pub fn bodies_reading(r: &mut Peer, t: &Tid, v: &str) -> BTreeSet<CommitId> {
    let page = r.engine.body_page(t, &value_ak(), true, 0, usize::MAX).expect("reference bodies");
    page.into_iter().filter(|b| b.valid && b.value == Some(Value::Str(v.into()))).map(|b| b.id).collect()
}

/// Whether some node holds the body of one of `ids` on thing `t`'s value, reading `v`.
pub fn held_somewhere(w: &mut World, t: &Tid, v: &str, ids: &BTreeSet<CommitId>) -> bool {
    (0..w.len()).any(|i| w.engine(i).body_page(t, &value_ak(), true, 0, usize::MAX).unwrap_or_default().iter().any(|b| ids.contains(&b.id) && b.value == Some(Value::Str(v.into()))))
}

/// `check`'s body clause: some node holds a body the reference reads each thing's value from
/// (a thing nobody holds any more is gone for everyone, spec/sync-set.md §3: no node must), for
/// each thing some account's node closure reads by the model (one read nowhere is held at most
/// as ciphertext kept unread, which shows no value: a later reader fetches it there).
fn body_clauses(w: &mut World, r: &mut Peer, m: &Model) {
    let things = w.history.things.clone();
    let views: Vec<(hc::Closure, hc::Set)> = (0..m.accounts.len()).map(|a| m.closure(&w.history, a)).collect();
    for (k, (t, _)) in things.iter().enumerate() {
        let x = m.thing(k);
        let read = views.iter().any(|(c, keys)| if m.world.independent(x) { c.read.contains(&x) } else { c.held.contains(&x) && m.world.opens(keys, x) });
        if !read || !(0..w.len()).any(|i| w.engine(i).closure_holds(t)) {
            continue;
        }
        if let Some(Value::Str(v)) = reads(&mut r.engine, t).value {
            let ids = bodies_reading(r, t, &v);
            assert!(held_somewhere(w, t, &v, &ids), "thing {k}: every body of its value {v} is deleted everywhere");
        }
    }
}

/// `check`'s invalid clauses (spec/sync-judgement.md §2 Judged invalid, spec/commits.md §5
/// Forgetting): no online node keeps an own-store entry of a body it judges invalid, so none is a
/// refetch source of one and each such commit is forgotten once no source shows an entry.
fn invalid_clauses(w: &mut World) {
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    let things = w.history.things.clone();
    for i in on {
        for s in w.store(i).held_ids().expect("sync IDs") {
            let thing = things.iter().position(|(t, _)| w.engine(i).sync_id_of(t).ok().flatten() == Some(s));
            for e in w.store(i).entries(&s).expect("entries") {
                let Some(c) = w.engine(i).blob_commit(&e.blob) else { continue };
                if w.engine(i).holds_commit(&c) {
                    assert!(!w.engine(i).body_facts(&s, &c).expect("facts").invalid, "node {i} keeps an entry of {c:?}, a body it judges invalid, under {s:?} (history thing {thing:?})");
                }
            }
        }
    }
}

/// The differential's size: nodes, accounts, steps, seeds. Small (the default tests): 3 nodes
/// of 2 accounts, 30 steps, 6 seeds; `OSIS_FULL=1`: 4 nodes of 3 accounts, 60 steps, 100 seeds.
pub fn size() -> (usize, usize, usize, u64) {
    if osis_base::testenv::u64_var("OSIS_FULL") == Some(1) { (4, 3, 60, 100) } else { (3, 2, 30, 6) }
}

/// A random history over `n` nodes of `accounts` accounts (node j's account is j's modulo
/// `accounts`, as `world_of` pairs them) of `len` steps, mostly ones that apply (its player
/// ends it at quiet). `faults`: whether it loses power, partitions, loses
/// messages and fails disks. Accepting is a strong from the grantee's account root, drawn after a
/// grant; declining is drawing none.
pub fn history(seed: u64, n: usize, accounts: usize, len: usize, faults: bool) -> Vec<Step> {
    let mut rng = SeededRng::from_u64(seed ^ 0x6869_7374);
    let mut pick = |m: usize| (rng.next_u64() % m.max(1) as u64) as usize;
    /// A sketch of a thing: its maker's account, whether it is independent, the roles given.
    struct Sketch {
        account: usize,
        independent: bool,
        given: BTreeMap<Holder, Gives>,
    }
    let mut acct: Vec<usize> = (0..n).map(|j| j % accounts.max(1)).collect();
    let mut things: Vec<Sketch> = Vec::new();
    let mut strongs: Vec<(Option<usize>, usize, usize)> = Vec::new();
    let mut off: BTreeSet<usize> = BTreeSet::new();
    let mut out = Vec::new();
    while out.len() < len {
        let roll = pick(100);
        let k = pick(things.len());
        let on: Vec<usize> = (0..acct.len()).filter(|i| !off.contains(i)).collect();
        let node = on[pick(on.len())];
        // the nodes that may write thing k: its maker's account's and each given write
        let writers = |things: &[Sketch], k: usize| -> Vec<usize> {
            let t = &things[k];
            (0..acct.len()).filter(|i| !off.contains(i)).filter(|i| acct[*i] == t.account || t.given.get(&Holder::Node(acct[*i])) == Some(&Gives::Writes)).collect()
        };
        let admins = |things: &[Sketch], k: usize| -> Vec<usize> { (0..acct.len()).filter(|i| !off.contains(i) && acct[*i] == things[k].account).collect() };
        let s = match roll {
            _ if things.is_empty() || (roll < 10 && things.len() < 5) => {
                let ws = if things.is_empty() { Vec::new() } else { writers(&things, k) };
                if !ws.is_empty() && pick(3) == 0 {
                    let i = ws[pick(ws.len())];
                    things.push(Sketch { account: acct[i], independent: false, given: BTreeMap::new() });
                    Step::NewIn(i, k)
                } else {
                    things.push(Sketch { account: acct[node], independent: false, given: BTreeMap::new() });
                    Step::New(node)
                }
            }
            0..=24 => {
                let ws = writers(&things, k);
                // now and then a node that may not write
                let i = if pick(10) == 0 || ws.is_empty() { node } else { ws[pick(ws.len())] };
                Step::Write(i, k)
            }
            25..=42 => {
                let ad = admins(&things, k);
                if ad.is_empty() {
                    Step::Run
                } else {
                    let i = ad[pick(ad.len())];
                    let g = [Gives::Syncs, Gives::Reads, Gives::Writes][pick(3)];
                    let others: Vec<usize> = (0..accounts).filter(|a| *a != things[k].account).collect();
                    let independent: Vec<usize> = (0..things.len()).filter(|x| *x != k && things[*x].independent).collect();
                    let h = if !independent.is_empty() && (others.is_empty() || pick(4) == 0) { Holder::Thing(independent[pick(independent.len())]) } else if others.is_empty() { Holder::Node(i) } else { Holder::Node(others[pick(others.len())]) };
                    things[k].independent = true;
                    things[k].given.insert(h, g);
                    Step::Give(i, k, h, g)
                }
            }
            43..=58 => {
                // accept: a node of a given account holds the thing from its account root
                let given: Vec<usize> = things[k].given.keys().filter_map(|h| if let Holder::Node(a) = h { Some(*a) } else { None }).collect();
                let nodes: Vec<usize> = on.iter().copied().filter(|i| given.contains(&acct[*i])).collect();
                if nodes.is_empty() {
                    Step::Run
                } else {
                    let i = nodes[pick(nodes.len())];
                    strongs.push((None, k, i));
                    Step::Strong(i, None, k)
                }
            }
            59..=64 => {
                // a strong from a thing to any thing, readable or not, or one removed
                if pick(2) == 0 && !strongs.is_empty() {
                    let (from, to, by) = strongs.swap_remove(pick(strongs.len()));
                    let i = match from {
                        Some(f) => writers(&things, f).first().copied().unwrap_or(by),
                        None => on.iter().copied().find(|i| acct[*i] == acct[by]).unwrap_or(by),
                    };
                    Step::Unstrong(i, from, to)
                } else {
                    let f = pick(things.len());
                    let ws = writers(&things, f);
                    if ws.is_empty() || f == k {
                        Step::Run
                    } else {
                        let i = ws[pick(ws.len())];
                        strongs.push((Some(f), k, i));
                        Step::Strong(i, Some(f), k)
                    }
                }
            }
            65..=70 if !things[k].given.is_empty() => {
                let ad = admins(&things, k);
                let held: Vec<Holder> = things[k].given.keys().copied().collect();
                let h = held[pick(held.len())];
                if ad.is_empty() {
                    Step::Run
                } else if pick(2) == 0 && things[k].given[&h] > Gives::Syncs {
                    let g = things[k].given[&h].lesser().unwrap_or(Gives::Syncs);
                    things[k].given.insert(h, g);
                    Step::Lower(ad[pick(ad.len())], k, h, g)
                } else {
                    things[k].given.remove(&h);
                    Step::Revoke(ad[pick(ad.len())], k, h)
                }
            }
            71..=73 if things[k].independent => {
                let ws = writers(&things, k);
                if ws.is_empty() { Step::Run } else { Step::Rotate(ws[pick(ws.len())], k) }
            }
            74 if acct.len() < n + 1 => {
                acct.push(acct[node]);
                Step::Pair(node)
            }
            76..=99 if faults => match pick(7) {
                0 if on.len() > 1 => {
                    off.insert(node);
                    Step::PowerOff(node)
                }
                1 if !off.is_empty() => {
                    let j = off.iter().copied().nth(pick(off.len())).unwrap_or(0);
                    off.remove(&j);
                    Step::PowerOn(j)
                }
                2 if acct.len() > 1 => Step::Partition(node, (node + 1 + pick(acct.len() - 1)) % acct.len()),
                3 => Step::Heal,
                4 => Step::Lossy(Loss { drop: [0, 20, 100][pick(3)], dup: [0, 50][pick(2)], delay: [0, 200][pick(2)], delay_ms: 5_000 }),
                5 => Step::Disk(node, pick(30) as u64, [DiskFault::Fail, DiskFault::Unsynced, DiskFault::Crash][pick(3)]),
                _ => Step::Skew(node, [-90_000i64, 0, 90_000][pick(3)]),
            },
            _ => Step::Run,
        };
        out.push(s);
    }
    out
}
