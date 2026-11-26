//! The reference-graph differential (notes/test-properties.md): random
//! histories of making, strongs added and removed, grants to accounts and to things (so chains
//! occur), lowering, revoking, rotating, pairing, removing a node and faults over a few nodes of
//! fewer accounts; at quiet each node holds what held-model's first entry (`closure::entry`) says
//! its node closure is, built from the history alone: it reads a thing exactly when the model
//! reads it, then as the reference (a twin of a node of its account handed every commit
//! directly: sync's property is perfect delivery to whoever holds the thing), its sync set holds the model's read and stored things and no store entry sits
//! under a history thing's sync ID it does not hold. No needed body is deleted everywhere and no
//! node keeps an entry of a body it judges invalid.
//!
//! A history's writes are `Step`s played through the product's engine flows at one node, which
//! sync then carries. Each commit a step writes is handed to the reference as it is written;
//! what sync itself writes (rotations it makes due, addenda, the fires it sends) is handed
//! at the check, from every node. The one excuse (a holder left out of an epoch, spec/permissions.md
//! §3 Left out) is computed from the history's own record of what each node surely received,
//! never from a node under test.

use super::{DiskFault, Loss, Step, World};
use held_model::closure as hc;
use osis_base::{Ak, CommitId, Ref, Role, Tid, Value};
use osis_crypto::{RngCore, SeededRng};
use osis_engine::flows::Done;
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

/// Who a grant names: node j's account, thing k (thing k's readers hold the role through it),
/// or the public (spec/permissions.md §1: every party reads by it, at most read).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Holder {
    Node(usize),
    Thing(usize),
    Public,
}

/// Printed as a script names it (`Holder::Node(1)`), so a printed step pastes into a test.
impl std::fmt::Debug for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Holder::Node(j) => write!(f, "Holder::Node({j})"),
            Holder::Thing(k) => write!(f, "Holder::Thing({k})"),
            Holder::Public => write!(f, "Holder::Public"),
        }
    }
}

/// The one aspect a history writes.
pub fn value_ak() -> Ak {
    Ak::new("u:v.0").expect("aspect key")
}

/// A history thing's mint admin: its maker's account, or thing k (whose keys a dependent
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
    /// The holder's account for a grant to an account, a lowering included; `None` for any
    /// other.
    granted: Option<Tid>,
    /// The commit of a value write; `None` for a grant or a rotation.
    wrote: Option<CommitId>,
    /// A change of the thing's read keys, for the excuse: a rotation, a removal below read, a
    /// grant to the public or a thing.
    rekeys: bool,
    /// Every commit the write made (the value write's, a grant's or rotation's), each lost when a
    /// release takes it unreceived (`lost_writes`).
    commits: Vec<CommitId>,
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
    /// The commits that made the things (each writes its thing's first value).
    made: BTreeSet<CommitId>,
    written: u64,
    /// Things whose record edge a removal took (the roster then shows no mint admin either).
    record_gone: BTreeSet<usize>,
    /// (thing, holder thing) edges standing that the holder's readers were never offered
    /// (spec/permissions.md §4 Delivering an edge piece): no write of the edge since it last began
    /// was by a node writing the holder (which logs it in the holder's key part), and the holder
    /// did not take `grant@~0` when it was written (`inboxes`). An account is offered every grant:
    /// its inbox enables the signal.
    unoffered: BTreeSet<(usize, Tid)>,
    /// History things made an account's inbox (`Step::Inbox`): their setting takes both inbox
    /// signals from then on.
    inboxes: BTreeSet<usize>,
    /// Grants to accounts and changes of keys, in the order made.
    events: Vec<Event>,
    /// Per node, the events it surely received: its own, and each held by a node it shared a run
    /// with on a clean network (no partition between them, both on, no loss); a value write only
    /// where the node's account's node closure held the write's thing at that run, by the model
    /// of what was handed then (`ran`).
    know: Vec<BTreeSet<usize>>,
    /// Per write (by event), the nodes that surely received it when a node of its writer's
    /// account next took a strong away or lowered a role (a step that may release its thing):
    /// what a release after it could still lose (`lost_writes`).
    froze: BTreeMap<usize, BTreeSet<usize>>,
    /// Hand commits to the reference; off, a step only writes.
    pub harvest: bool,
    /// Things held by no node at some quiet run (`ran`): gone for everyone, a strong to one
    /// holds nothing from then on (spec/sync-set.md §3 A thing goes when its last reference goes).
    gone: BTreeSet<usize>,
    /// The public's pieces logged so far (spec/sync-set.md §2 Public pieces): `(t, x)`, `t`'s sync
    /// ID carrying the public's edge piece on `x`, by the model at each quiet run (`model_now`),
    /// and by each redeem done or pending (the redeeming node reads its account and holds the
    /// public's grant by the link's sync ID as it writes the strong). Logged pieces stay: carriage
    /// outlives its carrier. Where `t` names `x`'s sync ID (`named`) its readers follow `x` by the
    /// public entry and log the piece whenever the public reads `x`, whatever was logged before;
    /// elsewhere, not seen: a node holding `x` by a path of its own only between quiet runs.
    pieces: BTreeSet<(Tid, Tid)>,
    /// `(k, holder)`: an edge of the holder on thing `k` was written and offered to the holder's
    /// readers (`unoffered`), so the holder's key part names `k`'s sync ID for good, the edge
    /// since lowered or removed included (`entry::Net::named`).
    named: BTreeSet<(usize, Tid)>,
    /// The reference `quiet_model` reads, fed what was handed since its last quiet run (made at
    /// the first; a copy of the world copies it).
    quiet: Option<QuietRef>,
    /// Per account, its first node as it stood at the world's setup (`world_of`): the reference's
    /// twins (`Refs`).
    twins: Option<Twins>,
}

/// Per account, a node of it as an exact copy (`Engine::test_copy`), behind a lock (a world is
/// `Send`); cloned, each an exact copy sharing nothing.
struct Twins(std::sync::Mutex<Vec<(Tid, Peer)>>);

impl Clone for Twins {
    fn clone(&self) -> Twins {
        Twins(std::sync::Mutex::new(self.copies()))
    }
}

impl Twins {
    fn copies(&self) -> Vec<(Tid, Peer)> {
        self.0.lock().unwrap().iter_mut().map(|(a, p)| (*a, p.copy().expect("twin copy"))).collect()
    }
}

/// An exact copy of node `i` (`Engine::test_copy`) as a `Peer` on a clock of its own: it never
/// writes into the world (no restart: its disks are not the engine's).
fn twin(w: &mut World, i: usize) -> Peer {
    let clock = std::sync::Arc::new(osis_base::ManualClock::new(w.now()));
    let c: std::sync::Arc<dyn osis_base::Clock> = clock.clone();
    let mut engine = w.engine(i).test_copy(c).expect("twin");
    let events = engine.subscribe();
    let mem = || (osis_store::MemoryBackend::new(), osis_store::MemoryRoot::new());
    let (backend, root) = mem();
    Peer { engine, clock, backend, root, blob_disk: mem(), events, restarts: 0, discarded: Vec::new(), discards: 0, redelivered: 0, pulled_anew: BTreeSet::new(), given: BTreeSet::new(), offers: Default::default(), entries: Default::default() }
}

/// The reference (spec: a node of each account handed every commit directly; sync's property is
/// perfect delivery to whoever holds a thing): per account, its twin (`Made::twins`) handed
/// every commit any node wrote. Each reads what a node of its account reads with nothing
/// missing: a thing enters it only as the account's node closure enters it (spec/sync-set.md
/// §2 First entry), so no one engine could read every account's things.
pub struct Refs(Vec<(Tid, Peer)>);

impl Refs {
    /// Account `a`'s twin.
    pub fn of(&mut self, a: &Tid) -> &mut Peer {
        &mut self.0.iter_mut().find(|(x, _)| x == a).expect("a twin of every account").1
    }

    /// A twin whose node closure holds `t`.
    fn holding(&mut self, t: &Tid) -> Option<&mut Peer> {
        self.0.iter_mut().map(|(_, p)| p).find(|p| p.engine.closure_holds(t))
    }

    fn all(&mut self) -> impl Iterator<Item = &mut Peer> {
        self.0.iter_mut().map(|(_, p)| p)
    }
}

/// The reference behind a lock (a world is `Send`); cloned, an exact copy sharing nothing, so
/// copies of one world never feed one reference.
struct QuietRef(std::sync::Mutex<Quiet>);

impl Clone for QuietRef {
    fn clone(&self) -> QuietRef {
        let mut q = self.0.lock().unwrap();
        let refs = Refs(q.refs.0.iter_mut().map(|(a, p)| (*a, p.copy().expect("reference copy"))).collect());
        QuietRef(std::sync::Mutex::new(Quiet { refs, fed: q.fed, waiting: q.waiting.clone() }))
    }
}

/// An incremental reference: the packages handed so far fed, those that did not take yet kept.
struct Quiet {
    refs: Refs,
    fed: usize,
    waiting: Vec<Package>,
}

impl Made {
    fn value(&mut self) -> String {
        self.written += 1;
        format!("v{}", self.written)
    }

    /// A change of `thing`'s keys or roles by `node`, writing `done`'s commits.
    fn event(&mut self, thing: usize, granted: Option<Tid>, rekeys: bool, done: Done, node: usize) {
        self.push(Event { thing, granted, wrote: None, rekeys, commits: done.commits, node, known: BTreeSet::new() });
    }

    /// A value write of `thing` by `node` in commit `c`.
    fn wrote(&mut self, thing: usize, c: CommitId, node: usize) {
        self.push(Event { thing, granted: None, wrote: Some(c), rekeys: false, commits: vec![c], node, known: BTreeSet::new() });
    }

    fn push(&mut self, mut e: Event) {
        let n = self.events.len();
        if self.know.len() <= e.node {
            self.know.resize(e.node + 1, BTreeSet::new());
        }
        e.known = self.know[e.node].clone();
        self.know[e.node].insert(n);
        self.events.push(e);
    }
}

/// After a run: every set of nodes connected on a clean network shares what each surely received.
/// A node fetches a thing's values only while it syncs the thing, so a value write is shared with
/// the nodes whose account's node closure holds or stores its thing at this run, judged from the
/// history alone (`quiet_model`: a run with every node on and connected; at any other run a value
/// write is surely received by no further node, which can only count a write lost that no node
/// holds at the check, `lost_writes`).
pub fn ran(w: &mut World) {
    if !w.net.loss.none() || !w.liars.is_empty() {
        return;
    }
    let m = quiet_model(w);
    // per node, the history things its account's node closure holds or stores now
    let synced: Vec<BTreeSet<usize>> = (0..w.len())
        .map(|i| {
            let Some((m, a)) = m.as_ref().and_then(|m| Some((m, m.account(&w.node(i).account?)?))) else { return BTreeSet::new() };
            let (c, _) = m.closure(a);
            (0..w.history.things.len()).filter(|k| c.held.contains(&m.thing(*k)) || c.stored.contains(&m.thing(*k))).collect()
        })
        .collect();
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
            let h = &w.history;
            let takes = |n: &usize| h.know[i].contains(n) || h.events[*n].wrote.is_none() || synced[i].contains(&h.events[*n].thing);
            w.history.know[i] = all.iter().copied().filter(takes).collect();
        }
    }
}

/// The model at a quiet run with every node on and connected on a clean network, from the
/// history alone (a reference of what was handed); `None` at any other run. Every node then
/// holds its node closure: a thing made that no account's model closure holds or carries is held
/// by no node, so it is gone (`Made::gone`).
fn quiet_model(w: &mut World) -> Option<Model> {
    if !w.net.cut_off.is_empty() || (0..w.len()).any(|i| !w.online(i)) {
        return None;
    }
    let m = model_now(w)?;
    // held, or carried unread under a sync ID some node keeps: a later reader fetches it there
    let mut held = hc::Set::new();
    for a in 0..m.accounts.len() {
        held.extend(m.closure(a).0.carried);
    }
    for k in 0..w.history.things.len() {
        if !held.contains(&m.thing(k)) {
            w.history.gone.insert(k);
        }
    }
    Some(m)
}

/// The model of what was handed so far (the reference `Made::quiet`, fed what was handed since it
/// was last read), as if every node held it; the public's pieces it logs kept (`Made::pieces`).
/// Read at a quiet run (`quiet_model`).
fn model_now(w: &mut World) -> Option<Model> {
    if !w.history.harvest || w.history.things.is_empty() {
        return None;
    }
    for i in 0..w.len() {
        harvest(w, i);
    }
    let now = w.now();
    let mut qr = w.history.quiet.take().unwrap_or_else(|| QuietRef(std::sync::Mutex::new(Quiet { refs: twins(w), fed: 0, waiting: Vec::new() })));
    let q = qr.0.get_mut().unwrap();
    learn_all(w, &mut q.refs);
    let new: Vec<Package> = w.history.handed[q.fed..].to_vec();
    q.fed = w.history.handed.len();
    for pk in new {
        let id = pk.id;
        q.waiting.push(pk);
        for i in 0..w.len() {
            q.waiting.extend(w.engine(i).package(&id).ok().flatten());
        }
    }
    let Quiet { refs, waiting, .. } = q;
    loop {
        let before = waiting.len();
        // kept while any twin refuses it (one whose account does not hold its thing may never take it)
        waiting.retain(|pk| {
            let refused: Vec<bool> = refs.all().map(|p| p.receive(&pk.bytes, pk.blobs.clone()).is_err()).collect();
            refused.contains(&true)
        });
        if waiting.len() == before || waiting.is_empty() {
            break;
        }
    }
    for p in refs.all() {
        p.clock.set(now);
        let _ = p.tick();
    }
    let m = Model::of(w, refs);
    let pieces = m.pieces_of(w);
    w.history.pieces.extend(pieces);
    w.history.quiet = Some(qr);
    Some(m)
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



/// The node a history write is made by.
fn writer(s: &Step) -> Option<usize> {
    match s {
        Step::New(i) | Step::NewIn(i, _) | Step::Write(i, _) | Step::Grant(i, ..) | Step::Give(i, ..) | Step::Lower(i, ..) | Step::Remove(i, ..) | Step::Revoke(i, ..) | Step::Rotate(i, _) | Step::Strong(i, ..) | Step::Unstrong(i, ..) | Step::Pair(i) | Step::Unpair(i, _) | Step::Redeem(i, _) | Step::Card(i, _) | Step::Inbox(i, _) => Some(*i),
        _ => None,
    }
}

/// Plays one history write; a note of what came of it.
pub fn step(w: &mut World, s: &Step) -> String {
    let Some(i) = writer(s) else { return String::new() };
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
                        w.history.wrote(*k, c, i);
                    }
                    Ok(v)
                }
                Err(e) => Err(e.to_string()),
            }
        }
        Step::Grant(_, k, j, g) => {
            // a rule test's shorthand: the role given, then node j holds the thing from its
            // account
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
            match w.write(i, |e| e.make_independent(&t)) {
                Ok(done) => {
                    w.history.independent[*k] = true;
                    w.history.event(*k, None, true, done, i);
                    Ok(String::new())
                }
                Err(e) => Err(e.to_string()),
            }
        }
        Step::Strong(_, from, k) => strong(w, i, *from, *k, true),
        Step::Unstrong(_, from, k) => strong(w, i, *from, *k, false),
        Step::Pair(_) => {
            let n = w.pair(i);
            w.history.know.resize(n + 1, BTreeSet::new());
            Ok(format!("node {n}"))
        }
        Step::Unpair(_, j) => unpair(w, i, *j),
        Step::Redeem(_, k) => redeem(w, i, *k),
        Step::Card(_, k) => card(w, i, *k),
        Step::Inbox(_, k) => inbox(w, i, *k),
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

/// Node `i` may have released a thing: each write by its account not frozen yet keeps the
/// nodes that surely received it now (`Made::froze`).
fn freeze(w: &mut World, i: usize) {
    let account = w.node(i).account;
    let h = &w.history;
    let due: Vec<usize> = h.events.iter().enumerate().filter(|(n, e)| !e.commits.is_empty() && !h.froze.contains_key(n) && w.node(e.node).account == account).map(|(n, _)| n).collect();
    let knew: Vec<(usize, BTreeSet<usize>)> = due.into_iter().map(|n| (n, (0..h.know.len()).filter(|j| h.know[*j].contains(&n)).collect())).collect();
    w.history.froze.extend(knew);
}

/// Node `i` removes node `j` from its account (`Engine::remove_node`, erasing, as the product's
/// `remove_node`); node `j` acts for no account from then on. Never an account's first node: its
/// copy is the account's twin in the reference (`Refs`). The history removes only a node that
/// wrote nothing (`history`): what a removed node wrote and no other node received goes with its
/// erasing, strongs and grants too; the oracle tracks values, grants and rotations as lost.
fn unpair(w: &mut World, i: usize, j: usize) -> Result<String, String> {
    let a = w.node(i).account.ok_or("no account")?;
    if j >= w.len() || j == i || j < w.history.twins.as_ref().map_or(0, |t| t.0.lock().unwrap().len()) || w.node(j).account != Some(a) {
        return Ok("skipped: not another removable node of the account".into());
    }
    let node = w.nodes[j].node.engine().tid();
    let also: Vec<Tid> = w.node(i).profile.into_iter().collect();
    let r = w.write(i, |e| e.remove_node(&a, &node, false, &also)).map(|_| String::new()).map_err(|e| e.to_string());
    // a removal refused with its outcome unknown may have applied (`stands`)
    if r.is_ok() || (w.online(i) && !w.engine(i).roster(&a).contains_key(&node)) {
        // node j erases what it holds: the account's writes not surely received elsewhere may go
        freeze(w, i);
        w.nodes[j].account = None;
    }
    r
}

fn thing(w: &World, k: usize) -> Option<Tid> {
    w.history.things.get(k).map(|x| x.0)
}

fn holder_tid(w: &World, h: Holder) -> Option<Tid> {
    match h {
        Holder::Node(j) => (j < w.len()).then(|| w.node(j).account).flatten(),
        Holder::Thing(k) => thing(w, k),
        Holder::Public => Some(Tid::PUBLIC),
    }
}

/// Node `i` redeems a public link to thing `k` for its account (spec/sync-set.md §4): the link
/// made at an online node where the public reads `k`, its maker first. It writes the strong once
/// the public's grant is held here, else gives up after its follow time (`Node::redeem`).
fn redeem(w: &mut World, i: usize, k: usize) -> Result<String, String> {
    let Some(t) = thing(w, k) else { return Ok("skipped: no such thing".into()) };
    let maker = w.history.things[k].1;
    let at = std::iter::once(maker).chain(0..w.len()).find(|&m| m < w.len() && w.online(m) && w.engine(m).public_reads(&t));
    let Some(link) = at.and_then(|m| w.public_link(m, t)) else { return Ok("skipped: the public reads it at no online node".into()) };
    let done = w.redeem_any(i, &link);
    // done, or following the link until it writes the strong
    if matches!(done, osis_sync::types::Waiting::Done | osis_sync::types::Waiting::Pending)
        && let Some(a) = w.node(i).account
    {
        let x = independent_of(w, k);
        w.history.pieces.insert((a, w.history.things[x].0));
    }
    Ok(format!("{done:?}"))
}

/// The history thing whose secrets thing `k`'s derive from (`Model::of`'s kinds): `k` where it is
/// independent, else up its mint admins to the nearest independent one, or the last thing on the
/// way made with an account as admin (its secrets derive from the account's: no history thing).
fn independent_of(w: &World, k: usize) -> usize {
    let h = &w.history;
    let mut x = k;
    while !h.independent[x]
        && let MintAdmin::Thing(p) = h.minted_with[x]
    {
        x = p;
    }
    x
}

/// Node `i` writes its account's card on thing `k` (spec/sync-inbox.md §1 Card: valid only where
/// node `i` writes `k` along a path through the account, refused otherwise).
fn card(w: &mut World, i: usize, k: usize) -> Result<String, String> {
    let Some(t) = thing(w, k) else { return Ok("skipped: no such thing".into()) };
    let a = w.node(i).account.ok_or("no account")?;
    w.write(i, |e| e.write_card(t, a))
    .map(|wrote| if wrote { String::new() } else { "nothing to carry".into() })
    .map_err(|e| e.to_string())
}

/// Node `i` moves its account's inbox to thing `k` (made independent first where it is not, as a
/// fire goes under the inbox's own sync ID sealed to its keys, spec/sync-inbox.md §2; then its
/// setting taking both inbox signals) or back to the one the account was made with (`None`): the
/// account's `keys.0` names it, an admin's write (spec/sync-inbox.md §1), refused at a node that
/// is no admin of the account.
fn inbox(w: &mut World, i: usize, k: Option<usize>) -> Result<String, String> {
    let a = w.node(i).account.ok_or("no account")?;
    let to = match k {
        Some(k) => match thing(w, k) {
            Some(t) => Some(t),
            None => return Ok("skipped: no such thing".into()),
        },
        None => None,
    };
    let made = w.node(i).inbox.ok_or("no inbox")?;
    if let (Some(k), Some(t)) = (k, to)
        && !w.history.independent[k]
    {
        let done = w.write(i, |e| e.make_independent(&t)).map_err(|e| e.to_string())?;
        w.history.independent[k] = true;
        w.history.event(k, None, true, done, i);
    }
    let r = w.write(i, |e| -> osis_engine::Result<()> {
        let to = match to {
            Some(t) => {
                let mut setting: ct::RetentionSetting = e.get_typed(&t, &ct::RETENTION)?.unwrap_or_default();
                setting.take_inbox_signals();
                let mut m = Mutation::new();
                m.set(t, &ct::RETENTION, &setting)?;
                e.commit(m)?;
                t
            }
            None => made,
        };
        e.set_inbox(a, Some(to))
    });
    // the setting's commit stands even where the move was refused
    if let Some(k) = k
        && w.online(i)
        && let Some(t) = thing(w, k)
        && w.engine(i).get_typed(&t, &ct::RETENTION).ok().flatten().is_some_and(|s: ct::RetentionSetting| s.enables(&Ak::new("grant@~0").expect("an external signal")))
    {
        w.history.inboxes.insert(k);
    }
    r.map(|_| String::new()).map_err(|e| e.to_string())
}

/// Node `i` mints a thing with its account (`None`) or thing `k` as admin, held there by a
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
    let d = w.node(i).account.ok_or("no account")?;
    match w.write(i, |e| -> osis_engine::Result<_> {
        // minted with the account, held from it, or from the thing it is minted with
        let mut m = Mutation::new();
        let t = m.create(e.thing_record(admin.unwrap_or(d), None));
        m.set(t, &value_ak(), &Value::Str(v.clone()))?;
        strong_in(&mut m, admin.unwrap_or(d), t, true)?;
        Ok((t, d, e.commit(m)?))
    }) {
        Ok((t, d, c)) => {
            let h = &mut w.history;
            h.things.push((t, i));
            h.minted_with.push(mint_admin.map_or(MintAdmin::Root(d), MintAdmin::Thing));
            h.independent.push(false);
            h.values.extend(c.map(|c| (v, c)));
            if let Some(c) = c {
                h.made.insert(c);
                h.wrote(h.things.len() - 1, c, i);
            }
            Ok(format!("thing {}", h.things.len() - 1))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Notes a write of holder `h`'s edge on thing `k` by node `i`, whose role on the holder was
/// `on_holder` and which read the edge as standing or not (`stood`) before it: by a writer of the
/// holder it reaches the holder's readers; from outside it stays as it was, unoffered where it
/// begins the edge.
fn note_offered(w: &mut World, k: usize, h: Holder, holder: Tid, on_holder: Option<Role>, stood: bool) {
    if matches!(h, Holder::Node(_) | Holder::Public) {
        return;
    }
    // a holder taking `grant@~0` is offered a grant from outside at itself (spec/sync-inbox.md §5)
    if on_holder >= Some(Role::Write) || matches!(h, Holder::Thing(j) if w.history.inboxes.contains(&j)) {
        w.history.unoffered.remove(&(k, holder));
    } else if !stood {
        w.history.unoffered.insert((k, holder));
    }
}

/// Node `i`'s role on `holder` and whether it reads `holder`'s edge on `t`, before a write of it.
fn before_edge(w: &mut World, i: usize, t: &Tid, holder: &Tid) -> (Option<Role>, bool) {
    if !w.online(i) {
        return (None, false);
    }
    (w.engine(i).role_on(holder), w.engine(i).roster(t).contains_key(holder))
}

/// Node `i` gives holder `h` role `g` on thing `k`.
fn give(w: &mut World, i: usize, k: usize, h: Holder, g: Gives) -> Result<String, String> {
    let (Some(t), Some(holder)) = (thing(w, k), holder_tid(w, h)) else { return Ok("skipped: no such thing or holder".into()) };
    let edge = Edge { role: g.role(), until: None, may_grant: false, retain: false, floor: None };
    let (on_holder, stood) = before_edge(w, i, &t, &holder);
    let r = w.write(i, |e| e.grant(&t, &holder, &edge)).map_err(|e| e.to_string());
    if r.is_ok() || stands(w, i, &t, &holder, Some(g.role())) {
        note_offered(w, k, h, holder, on_holder, stood);
        let account = matches!(h, Holder::Node(_)).then_some(holder);
        let hist = &mut w.history;
        hist.independent[k] = true;
        // a thing granted a role becomes independent first (spec/permissions.md §3)
        if let Holder::Thing(j) = h {
            hist.independent[j] = true;
        }
        // a refused grant that stands made its commits unseen: none to lose
        let done = r.as_ref().cloned().unwrap_or_default();
        hist.event(k, account, account.is_none(), done, i);
        if h != Holder::Public {
            hist.named.insert((k, holder));
        }
    }
    r.map(|_| String::new())
}

/// Node `i` lowers holder `h` on thing `k` to `g`, or removes it (`None`).
fn demote(w: &mut World, i: usize, k: usize, h: Holder, g: Option<Gives>) -> Result<String, String> {
    let (Some(t), Some(holder)) = (thing(w, k), holder_tid(w, h)) else { return Ok("skipped: no such thing or holder".into()) };
    let new = g.map(|g| Edge { role: g.role(), until: None, may_grant: false, retain: false, floor: None });
    let (on_holder, stood) = before_edge(w, i, &t, &holder);
    let r = w.write(i, |e| e.demote(&t, &Demotion { holder, new, retain: None })).map_err(|e| e.to_string());
    let applied = r.is_ok() || stands(w, i, &t, &holder, g.map(Gives::role));
    if g.is_some() && stood && applied {
        note_offered(w, k, h, holder, on_holder, stood);
    }
    if r.is_ok() && g.is_none() && matches!(h, Holder::Thing(p) if w.history.minted_with[k] == MintAdmin::Thing(p)) {
        w.history.record_gone.insert(k);
    }
    // a change taking the holder below read rotates the read role; either way its commits may go
    // with a release (`lost_writes`)
    if applied {
        let rekeys = g.is_none_or(|g| g < Gives::Reads);
        // a lowering the holder still reads after is a grant to it (the excuse's last grant)
        let account = matches!(h, Holder::Node(_)).then_some(holder).filter(|_| !rekeys);
        let done = r.as_ref().cloned().unwrap_or_default();
        w.history.event(k, account, rekeys, done, i);
    }
    r.map(|_| String::new())
}

/// Node `i` adds or removes a strong from its account (`None`) or from thing `from` to
/// thing `k`.
fn strong(w: &mut World, i: usize, from: Option<usize>, k: usize, on: bool) -> Result<String, String> {
    let Some(t) = thing(w, k) else { return Ok("skipped: no such thing".into()) };
    let from = match from {
        Some(f) => match thing(w, f) {
            Some(x) => Some(x),
            None => return Ok("skipped: no such thing".into()),
        },
        None => None,
    };
    let account = w.node(i).account.ok_or("no account")?;
    w.write(i, |e| -> osis_engine::Result<_> {
        let from = from.unwrap_or(account);
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

/// `world_of(0, 3, 3)` where node 0 makes thing 0 and grants node 1's account sync (it keeps the thing
/// unread) and node 2's `gives`, then runs `runs` times; built once per process (`fixture_with`).
/// The world, the thing and its sync ID.
pub fn three(gives: Gives, runs: usize) -> (World, Tid, osis_base::SyncId) {
    let (w, (t, s)) = super::fixture_with(&format!("three {gives:?} {runs}"), || {
        let mut w = world_of(0, 3, 3);
        let mut steps = vec![Step::New(0), Step::Grant(0, 0, 1, Gives::Syncs), Step::Grant(0, 0, 2, gives)];
        steps.extend(std::iter::repeat_n(Step::Run, runs));
        let _ = super::play(&mut w, &steps, String::new());
        let t = w.history.things[0].0;
        let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
        (w, (t, s))
    });
    (w, t, s)
}

/// `three(Gives::Reads, 1)` with `n` things, each kept unread by node 1 and read by node 2, quiet,
/// each pair reconnected once since (those past the first made on the world of one, after its
/// reconnects); built once per process per `n` (`fixture`). The first reconnect after first contact
/// proves other actors than the record names (the cards' link keys), so it tests every credential
/// again (spec/sync-opens.md §3): an idle reconnect comes after it.
pub fn shared(n: usize) -> World {
    super::fixture(&format!("shared {n}"), || {
        let mut w = if n == 1 { three(Gives::Reads, 1).0 } else { shared(1) };
        let mut steps: Vec<Step> = (w.history.things.len()..n).flat_map(|k| [Step::New(0), Step::Grant(0, k, 1, Gives::Syncs), Step::Grant(0, k, 2, Gives::Reads)]).collect();
        if n > 1 {
            steps.push(Step::Run);
        }
        steps.extend([Step::Cut(0, 1), Step::Run, Step::Cut(0, 2), Step::Run]);
        let _ = super::play(&mut w, &steps, String::new());
        w
    })
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
            let firsts: Vec<(Tid, usize)> = (0..accounts.min(nodes)).filter_map(|i| Some((w.node(i).account?, i))).collect();
            let twins = firsts.into_iter().map(|(a, i)| (a, twin(&mut w, i))).collect();
            w.history.twins = Some(Twins(std::sync::Mutex::new(twins)));
            w.history.know = vec![BTreeSet::new(); nodes];
            w.history.harvest = true;
            w
        },
        |w: &mut World| w.copy(),
    )
}

/// Every account becomes every other's contact by contact cards (spec/sync-inbox.md §5): each
/// account's first node makes a public link to its profile (public from its making), a node of
/// every other account redeems it, holding the profile from that account (a redeem writes the
/// strong, spec/sync-set.md §4). Before any history only; nothing is handed by hand.
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
    let cards: BTreeMap<usize, osis_blob::Link> = ones.iter().filter_map(|&i| w.public_link(i, w.node(i).profile?).map(|l| (i, l))).collect();
    let pairs: Vec<(usize, usize)> = ones.iter().flat_map(|&j| ones.iter().map(move |&i| (j, i))).filter(|(j, i)| j != i).collect();
    for &(j, i) in &pairs {
        if let Some(c) = cards.get(&i) {
            w.redeem_any(j, c);
        }
    }
    w.run();
    for &(j, i) in &pairs {
        if let Some(c) = cards.get(&i) {
            assert_eq!(w.redeem_any(j, c), osis_sync::types::Waiting::Done, "{j} redeems {i}'s card");
        }
    }
}

/// The reference (`Refs`): each twin handed every commit any node wrote, again while one
/// applies. Every commit any node holds now is handed too (what sync wrote), each node's copy of
/// it: `harvest` keeps one copy per commit, perhaps a certificate copy (its header and some
/// parts), and the engine joins the parts a later copy carries (spec/commits.md §4). Each twin
/// learns every read secret any node holds of a history thing or account (as a link key gives
/// one, `Engine::learn_secret`), so a box left out of a node's reach (the excuse) does not hide
/// a value from the reference. It is handed no commit in `lost`.
pub fn reference(w: &mut World, lost: &BTreeSet<CommitId>) -> Refs {
    for i in 0..w.len() {
        harvest(w, i);
    }
    let mut refs = twins(w);
    learn_all(w, &mut refs);
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    let mut handed = Vec::new();
    for pk in w.history.handed.clone().into_iter().filter(|pk| !lost.contains(&pk.id)) {
        let id = pk.id;
        handed.push(pk);
        for &i in &on {
            handed.extend(w.engine(i).package(&id).ok().flatten());
        }
    }
    let now = w.now();
    for r in refs.all() {
        // again while a round applies anything or moves what pends (a commit kept pending is
        // handed again each round and comes back pending: that alone moves nothing)
        for _ in 0..=handed.len() {
            let was = r.engine.pending();
            let mut applied = false;
            for pk in &handed {
                applied |= matches!(r.receive(&pk.bytes, pk.blobs.clone()), Ok(Ingested::Applied(_)));
            }
            if !applied && r.engine.pending() == was {
                break;
            }
        }
        r.clock.set(now);
        let _ = r.tick();
    }
    refs
}

/// Fresh copies of the world's twins (`Made::twins`).
fn twins(w: &World) -> Refs {
    Refs(w.history.twins.as_ref().expect("a history world's twins").copies())
}

/// Each twin learns every read secret of a history thing or account that a node holds and it
/// does not (taken as from the public's entry box: whatever the twin's own departures).
fn learn_all(w: &mut World, refs: &mut Refs) {
    let mut all: Vec<Tid> = w.history.things.iter().map(|x| x.0).collect();
    all.extend((0..w.len()).filter_map(|i| w.node(i).account));
    for t in &all {
        for i in 0..w.len() {
            let Some(es) = w.engine(i).epochs(t) else { continue };
            for (e, s) in es.role(Role::Read).held() {
                for r in refs.all() {
                    let _ = r.engine.learn_secret(t, Role::Read, e, s.secret().clone(), &Tid::PUBLIC);
                }
            }
        }
    }
}

/// Node `i` reads thing `k` as its account's twin.
pub fn reads_as(w: &mut World, refs: &mut Refs, k: usize, i: usize) {
    let Some((t, _)) = w.history.things.get(k).copied() else { panic!("no thing {k}") };
    let a = w.node(i).account.expect("an account");
    let want = reads(&mut refs.of(&a).engine, &t);
    let got = reads(w.engine(i), &t);
    assert_eq!(got, want, "node {i} reads thing {k} unlike the reference");
}

/// The history as held-model sees it at the end, from the history and the reference alone:
/// model things 0..A are the accounts, then the history's things. A node of an account acts for
/// it at admin (its node thing paired so), so its node closure is the account's: held-model's
/// node with the account its own thing and its root (the account's strongs are its `holds.0`).
pub struct Model {
    accounts: Vec<Tid>,
    world: hc::World,
    edges: hc::Edges,
    /// The grants (holder, target) whose holder's readers were never offered them (`Made::unoffered`).
    unoffered: BTreeSet<(usize, usize)>,
    /// What the accounts' node closures log under the sync IDs they read: bridges and stubs (`entry::Net::logged`).
    logged: hc::Edges,
    /// The public's pieces under the sync IDs they read (`entry::Net::pieces`): those logged before
    /// in the history (`Made::pieces`) and what the closures log now.
    pieces: hc::Edges,
    /// The sync IDs each holder's key part names (`Made::named`, and each thing's mint admin by
    /// its record edge; `entry::Net::named`).
    named: hc::Edges,
}

impl Model {
    fn thing(&self, k: usize) -> usize {
        self.accounts.len() + k
    }

    fn account(&self, a: &Tid) -> Option<usize> {
        self.accounts.iter().position(|x| x == a)
    }

    /// The model from the history: kinds (a dependent thing derives from its nearest independent
    /// mint admin), grants (the rosters as a twin holding each thing reads them, each thing's mint
    /// admin as admin), strongs (the `holds.0` of every account and thing as a twin reads it).
    pub fn of(w: &mut World, refs: &mut Refs) -> Model {
        let mut accounts: Vec<Tid> = Vec::new();
        for (a, _) in &refs.0 {
            if !accounts.contains(a) {
                accounts.push(*a);
            }
        }
        let na = accounts.len();
        let h = &w.history;
        let things: Vec<Tid> = h.things.iter().map(|x| x.0).collect();
        let index = |t: &Tid| -> Option<usize> { accounts.iter().position(|x| x == t).or_else(|| things.iter().position(|x| x == t).map(|k| na + k)) };
        let mint_admin = |k: usize| match h.minted_with[k] {
            MintAdmin::Root(d) => index(&d).expect("a known account"),
            MintAdmin::Thing(p) => na + p,
        };
        let mut kinds = vec![hc::Kind::Independent; na];
        for k in 0..things.len() {
            let mut x = k;
            kinds.push(loop {
                if h.independent[x] {
                    break if x == k { hc::Kind::Independent } else { hc::Kind::Dependent(na + x) };
                }
                match h.minted_with[x] {
                    MintAdmin::Root(d) => break hc::Kind::Dependent(index(&d).expect("a known account")),
                    MintAdmin::Thing(p) => x = p,
                }
            });
        }
        let mut grants = BTreeMap::new();
        let mut unoffered = BTreeSet::new();
        let mut public = hc::Set::new();
        let mut public_sync = hc::Set::new();
        let mut edges = hc::Edges::new();
        for (k, t) in things.iter().enumerate() {
            // the record edge stands at admin until an edge write lowers it, which the roster then
            // shows, or removes it (`record_gone`)
            let roster = refs.holding(t).map(|r| r.engine.roster(t)).unwrap_or_default();
            if roster.is_empty() && !h.record_gone.contains(&k) {
                grants.insert((mint_admin(k), na + k), hc::Role::Admin);
            }
            for (holder, e) in roster {
                // the public reads by its own grant on the thing (spec/permissions.md §1)
                if holder == Tid::PUBLIC {
                    match e.role >= Role::Read {
                        true => drop(public.insert(na + k)),
                        false => drop(public_sync.insert(na + k)),
                    }
                    continue;
                }
                if let Some(g) = index(&holder) {
                    if h.unoffered.contains(&(k, holder)) {
                        unoffered.insert((g, na + k));
                    }
                    let role = match e.role {
                        Role::Sync => hc::Role::Sync,
                        Role::Read => hc::Role::Read,
                        Role::Write => hc::Role::Write,
                        Role::Admin => hc::Role::Admin,
                    };
                    let had = grants.entry((g, na + k)).or_insert(role);
                    *had = (*had).max(role);
                }
            }
        }
        for s in accounts.iter().chain(&things) {
            let from = index(s).expect("a source");
            let held = refs.all().find_map(|r| r.engine.get_typed(s, &ct::HOLDS).ok().flatten()).unwrap_or_default();
            for x in held {
                if let Ref::Strong(y) = x
                    && let Some(to) = things.iter().position(|t| *t == y.0)
                {
                    edges.insert((from, na + to));
                }
            }
        }
        // a gone thing is held by no strong (spec/sync-set.md §3)
        edges.retain(|(_, y)| !h.gone.contains(&(y - na)));
        // the grants that read nothing (spec/crypto.md §4 Key access), as the twins order them
        let mut keyless = BTreeSet::new();
        for r in refs.all() {
            keyless.extend(r.engine.keyless_grants().iter().filter_map(|(t, g)| Some((index(g)?, index(t)?))));
        }
        let pieces = h.pieces.iter().filter_map(|(t, x)| Some((index(t)?, index(x)?))).collect();
        let mut named: hc::Edges = h.named.iter().filter(|(k, g)| !h.unoffered.contains(&(*k, *g))).filter_map(|(k, g)| Some((index(g)?, na + k))).collect();
        named.extend((0..things.len()).map(|k| (mint_admin(k), na + k)));
        let mut m = Model { accounts, world: hc::World { kinds, grants, keyless, public, public_sync }, edges, unoffered, logged: hc::Edges::new(), pieces, named };
        // what the closures log, to their least fixpoint over the accounts (`entry::Net::held_all`)
        loop {
            let (mut more, mut pieces) = (m.logged.clone(), m.pieces.clone());
            for a in 0..m.accounts.len() {
                let (net, held) = m.entry(a);
                more.extend(net.logs(held_model::closure::entry::Rule::SPEC, &held));
                pieces.extend(net.logs_pieces(held_model::closure::entry::Rule::SPEC, &held));
            }
            if more == m.logged && pieces == m.pieces {
                return m;
            }
            (m.logged, m.pieces) = (more, pieces);
        }
    }

    /// The public's pieces logged (`pieces`) as the history's tids, for `Made::pieces`.
    fn pieces_of(&self, w: &World) -> Vec<(Tid, Tid)> {
        let na = self.accounts.len();
        let tid = |x: usize| if x < na { Some(self.accounts[x]) } else { w.history.things.get(x - na).map(|t| t.0) };
        self.pieces.iter().filter_map(|&(t, x)| Some((tid(t)?, tid(x)?))).collect()
    }

    /// Account `a`'s node closure and the keys it reads with (spec/sync-set.md §2): held-model's
    /// first entry (`closure::entry`, `Rule::SPEC`) for a node of the account, its node thing N
    /// (model thing `n + 2a`, `n` the accounts and history things) holding admin on the account by
    /// its record edge and its node root (`n + 2a + 1`) holding strongs to N and the account. A
    /// grant is its target's data: one its holder's readers were never offered (`unoffered`)
    /// counts once the node reads the target by another way, and opens nothing before (no node of
    /// the holder's learns the target's sync ID or box by it). The least such closure, as
    /// `hc::Closure` (`carried`: what its read units and the units of what it keeps unread carry;
    /// `for_keys`: holders held for keys alone) and the keys of what it reads, with what
    /// every account's closure logs (`Model::logged`, spec/sync-set.md §2 Carriers).
    fn closure(&self, a: usize) -> (hc::Closure, hc::Set) {
        use held_model::closure::entry;
        let (net, held) = self.entry(a);
        let e = net.edges(entry::Rule::SPEC);
        let keys = net.ring(entry::Rule::SPEC, &held.s.read);
        let mut carried = held.held.clone();
        for &t in &held.s.kept {
            carried.extend(net.unit(entry::Rule::SPEC, t, &e));
        }
        let for_keys = held.s.keyparts.iter().copied().filter(|x| !held.s.read.contains(x) && !held.s.kept.contains(x)).collect();
        let c = hc::Closure { read: held.s.read, stored: held.s.kept, held: held.held, carried, keys: keys.clone(), synced: hc::Set::new(), for_keys, follows: held.follows };
        (c, keys)
    }

    /// Account `a`'s first-entry world (`closure`) with what is logged, and what its node holds.
    fn entry(&self, a: usize) -> (held_model::closure::entry::Net, held_model::closure::entry::Held) {
        use held_model::closure::entry;
        let n = self.world.kinds.len();
        let mut known = hc::Set::new();
        loop {
            let mut w = self.world.clone();
            w.grants.retain(|e, _| !self.unoffered.contains(e) || known.contains(&e.1));
            let mut strongs = self.edges.clone();
            let mut nodes = Vec::new();
            for b in 0..self.accounts.len() {
                let (thing, root) = (n + 2 * b, n + 2 * b + 1);
                w.kinds.extend([hc::Kind::Independent, hc::Kind::Dependent(thing)]);
                w.grants.insert((thing, b), hc::Role::Admin);
                strongs.extend([(root, thing), (root, b)]);
                nodes.push(entry::Node { thing, root, offers: hc::Set::new() });
            }
            let records = (0..self.accounts.len()).map(|b| (n + 2 * b, b)).collect();
            let net = entry::Net { w, records, strongs, nodes, logged: self.logged.clone(), pieces: self.pieces.clone(), named: self.named.clone() };
            let held = net.held_alone(a, entry::Rule::SPEC);
            if held.s.read.is_subset(&known) {
                return (net, held);
            }
            known.extend(held.s.read.iter().copied());
        }
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
/// A grant or change whose commits a release lost all of (`lost_writes`) was never made. It
/// permits a failure, never requires one.
fn excused(w: &World, m: &Model, lost: &BTreeSet<CommitId>, a: Tid, k: usize) -> bool {
    let h = &w.history;
    // a refused grant that stands made no commits of its own: it stands
    let made = |e: &Event| e.commits.is_empty() || !e.commits.iter().all(|c| lost.contains(c));
    let Some(g) = h.events.iter().rposition(|e| e.thing == k && e.granted == Some(a) && made(e)) else { return false };
    let account_of = |i: usize| w.node(i).account;
    h.events.iter().enumerate().filter(|(_, e)| e.thing == k && e.rekeys && made(e)).any(|(r, e)| {
        let concurrent = if r > g { !e.known.contains(&g) } else { !h.events[g].known.contains(&r) };
        let mut boxed: BTreeSet<Tid> = [account_of(e.node), account_of(h.things[k].1)].into_iter().flatten().collect();
        boxed.extend(e.known.iter().filter_map(|x| h.events[*x].granted.filter(|_| h.events[*x].thing == k)));
        concurrent && !boxed.iter().any(|b| m.account(b).is_some_and(|b| m.writes(b, k)))
    })
}

/// The writes a release lost (spec/sync-set.md §3 Nothing of R stays: a node's own writes on a
/// thing it releases not yet held elsewhere go, and a release waits for no peer not connected):
/// each commit of node i's write on thing k (a value, a grant, a lowering, a rotation), after
/// which i's account took a strong away, lowered a role or removed a node (a step that may
/// release k: a removed node erases), that no other node surely received by then (`Made::froze`)
/// whose account's node closure holds k at the end, and that no node holds at the check (its
/// value part, for a value write: i, holding k again, fetches what others hold). A thing's making
/// is such a write: released before another node received it, its value is gone. The reference
/// and the model are built without the lost commits (a lost grant changes the roster, and a
/// later commit on it stands without it where a node took it as a piece); a lost making the
/// reference is handed whole, for the thing's record, and its value is read as none
/// (`closure_clauses`).
fn lost_writes(w: &mut World, m: &Model) -> BTreeSet<CommitId> {
    let holds = |a: Option<Tid>, k: usize| {
        a.and_then(|a| m.account(&a)).is_some_and(|a| {
            let (c, _) = m.closure(a);
            c.held.contains(&m.thing(k)) || c.stored.contains(&m.thing(k))
        })
    };
    let mut lost = BTreeSet::new();
    for (n, e) in w.history.events.iter().enumerate() {
        // a write its writer's account may have released since: who had surely received it then
        let Some(knew) = w.history.froze.get(&n) else { continue };
        let shared = knew.iter().any(|&j| j != e.node && j < w.len() && holds(w.node(j).account, e.thing));
        if !shared {
            lost.extend(e.commits.iter().map(|c| (*c, e.wrote.is_some())));
        }
    }
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    lost.retain(|(c, value)| !on.iter().any(|&i| if *value { holds_value(w, i, c) } else { w.engine(i).holds_commit(c) }));
    lost.into_iter().map(|(c, _)| c).collect()
}

/// Whether node `i` holds a value part (`value_ak`) of commit `c`.
fn holds_value(w: &mut World, i: usize, c: &CommitId) -> bool {
    let Some(h) = w.engine(i).header(c) else { return false };
    let missing = w.engine(i).commit_parts_missing().remove(c).unwrap_or_default();
    h.aspects.iter().enumerate().any(|(ai, a)| a.ak == value_ak() && !missing.contains(&ai))
}

/// The compaction snapshots a release lost with the value writes `lost` (`lost_writes`): on the
/// value of a thing a lost write is on, by that write's author, held by no node at the check.
/// A writer's snapshot carries its own writes, so one no node holds goes with them (spec/sync-set.md
/// §3 Nothing of R stays); a later reader holding none of it has nothing to fetch.
fn snapshots_lost(w: &mut World, refs: &mut Refs, lost: &BTreeSet<CommitId>) -> BTreeSet<CommitId> {
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    let h = &w.history;
    let by: BTreeSet<(Tid, Tid)> = h.events.iter().filter(|e| e.wrote.is_some_and(|c| lost.contains(&c))).filter_map(|e| Some((h.things[e.thing].0, w.node(e.node).account?))).collect();
    let mut out = BTreeSet::new();
    for (t, author) in by {
        for r in refs.all() {
            for b in r.engine.body_page(&t, &value_ak(), true, 0, usize::MAX).unwrap_or_default() {
                let snapshot = r.engine.header(&b.id).is_some_and(|h| h.kind.is_compaction() && h.signer == author);
                if snapshot {
                    out.insert(b.id);
                }
            }
        }
    }
    out.retain(|c| !on.iter().any(|&i| w.engine(i).holds_commit(c)));
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
    let unmade: BTreeSet<CommitId> = lost.intersection(&w.history.made).copied().collect();
    lost.retain(|c| !unmade.contains(c));
    if !lost.is_empty() {
        lost.extend(snapshots_lost(w, &mut r, &lost));
        r = reference(w, &lost);
        m = Model::of(w, &mut r);
    }
    let checked = catch_unwind(AssertUnwindSafe(|| {
        // the values of the lost makings (`lost_writes`): gone, the reference's as none
        let gone: BTreeSet<String> = w.history.values.iter().filter(|(_, c)| unmade.contains(*c)).map(|(v, _)| v.clone()).collect();
        closure_clauses(w, &mut r, &m, &gone, &lost);
        card_clauses(w, &mut r, &m);
        body_clauses(w, &mut r, &m, &gone);
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
fn at_check(w: &mut World, refs: &mut Refs, m: &Model) -> String {
    let brief = |x: &Reads| format!("{} ({} roles)", x.value.as_ref().map_or("none".to_string(), |v| format!("{v:?}")), x.roles.len());
    let mut out = String::from("at the check:");
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    let views: Vec<Option<(hc::Closure, hc::Set)>> = (0..w.len()).map(|i| w.node(i).account.and_then(|a| m.account(&a)).map(|a| m.closure(a))).collect();
    for (k, (t, maker)) in w.history.things.clone().iter().enumerate() {
        let x = m.thing(k);
        out.push_str(&format!("\n  thing {k} (made by node {maker}, {:?}): reference", m.world.kinds[x]));
        for (a, r) in refs.0.iter_mut() {
            out.push_str(&format!(" {} {}", m.account(a).map_or("-".into(), |a| format!("a{a}")), brief(&reads(&mut r.engine, t))));
        }
        for &i in &on {
            let said = views[i].as_ref().map_or("-", |(c, keys)| if c.read.contains(&x) || (c.held.contains(&x) && m.world.opens(keys, x)) { "read" } else if c.stored.contains(&x) || c.held.contains(&x) { "held unread" } else { "not held" });
            out.push_str(&format!("; node {i} {} (model: {said})", brief(&reads(w.engine(i), t))));
        }
    }
    out.push_str(&format!("\n  grants {:?}\n  strongs {:?}\n  public {:?}, its pieces {:?}", m.world.grants, m.edges, m.world.public, m.pieces));
    let handed = w.history.handed_ids.clone();
    for &i in &on {
        let held: BTreeSet<CommitId> = w.engine(i).commit_ids().into_iter().collect();
        out.push_str(&format!("\n  node {i} lacks {} of {} handed commits", handed.difference(&held).count(), handed.len()));
    }
    out.push_str(&format!("\n  {}", w.net.census().replace('\n', "\n  ")));
    out
}

/// `check`'s closure clauses, per online node of an account and history thing: it reads a
/// value of the thing only where the model reads it, and there reads as the reference (no value
/// where the thing's making was lost and no later value stands, `lost_writes`); its sync set holds a
/// independent thing read, for keys or kept unread exactly as the model does; it keeps no store entry
/// under the sync ID of an independent thing the model has it neither read nor keep unread; its
/// store of one it keeps unread stands at the head an online reader records.
fn closure_clauses(w: &mut World, refs: &mut Refs, m: &Model, gone: &BTreeSet<String>, lost: &BTreeSet<CommitId>) {
    let things = w.history.things.clone();
    let ids: Vec<Option<osis_base::SyncId>> = things.iter().map(|(t, _)| refs.all().find_map(|r| r.engine.sync_id_of(t).ok().flatten())).collect();
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    for i in on {
        let Some(acct) = w.node(i).account else {
            // a node removed from its account (`Step::Unpair`) holds nothing of the history
            for (k, (t, _)) in things.iter().enumerate() {
                let got = reads(w.engine(i), t);
                assert!(got.value.is_none(), "node {i}, removed from its account, reads thing {k}: {:?}\n{}", got.value, why_role(w, i, t));
                if let Some(s) = &ids[k] {
                    let n = w.store(i).entries(s).expect("entries").len();
                    assert!(n == 0, "node {i}, removed from its account, keeps {n} store entries under thing {k}'s sync ID");
                }
            }
            continue;
        };
        let a = m.account(&acct).expect("an account");
        let (c, keys) = m.closure(a);
        let set = w.engine(i).sync_set().expect("sync set");
        for (k, (t, _)) in things.iter().enumerate() {
            let x = m.thing(k);
            let excused = excused(w, m, lost, acct, k);
            let independent = m.world.independent(x);
            let read = if independent { c.read.contains(&x) } else { c.held.contains(&x) && m.world.opens(&keys, x) };
            let got = reads(w.engine(i), t);
            if !excused {
                if got.value.is_some() && !read {
                    panic!("node {i} reads thing {k}: {:?}, the model does not\n{}", got.value, why_role(w, i, t));
                }
                if read {
                    let mut want = reads(&mut refs.of(&acct).engine, t);
                    want.value = want.value.filter(|v| !matches!(v, Value::Str(x) if gone.contains(x)));
                    if got != want {
                        panic!("node {i} reads thing {k} unlike the reference\n  left: {got:?}\n right: {want:?}\n{}", why_role(w, i, t));
                    }
                }
            }
            if independent {
                let want = if c.read.contains(&x) || c.follows.contains(&x) { Some(Holding::Read) } else if c.for_keys.contains(&x) { Some(Holding::Keys) } else if c.stored.contains(&x) { Some(Holding::Unread) } else { None };
                let held: Vec<Holding> = set.ids.values().filter(|(ts, _)| ts.contains(t)).map(|(_, h)| *h).collect();
                let held = held.iter().copied().max_by_key(|h| matches!(h, Holding::Read));
                // a node keeping a thing unread cannot read its removal: it stops at the step its
                // secrets no longer derive, its entries dropped and its path kept
                // (spec/sync-judgement.md §6 Stops), which the store clause below checks
                let stopped = want.is_none() && held == Some(Holding::Unread);
                if !excused && !stopped && held != want {
                    panic!("node {i}'s sync set holds thing {k} as {held:?}, the model {want:?}\n{}", why_role(w, i, t));
                }
                // a node keeping it unread stands where its readers do: moved along their recorded
                // path to its head, or to a recorded sibling as deep (siblings stand: spec/sync-ids.md
                // §6 Steps, Register), it takes what they log. Not a node that lied in its own log:
                // its readers never saw it hold the rotation commits a step needs, so none
                // registers the step there (spec/sync-ids.md §6 Steps; spec/sync.md §4, a peer's
                // word changes only what that peer holds)
                let hides_log = w.lied_log.contains(&i);
                if let Some(s) = &ids[k]
                    && !excused
                    && !hides_log
                    && want == Some(Holding::Unread)
                    && let Some((depth, recorded)) = recorded_steps(w, t, s)
                {
                    let path = w.store(i).path(s).expect("path").map(|p| p.steps.iter().map(|(st, _)| st.id()).collect::<Vec<_>>()).unwrap_or_default();
                    if path.len() != depth || !path.last().is_some_and(|h| recorded.contains(h)) {
                        panic!("node {i} keeps thing {k} unread at step {:?} ({} deep), its readers' head is {depth} deep\n{}", path.last(), path.len(), why_role(w, i, t));
                    }
                }
                if let Some(s) = &ids[k]
                    && want.is_none()
                {
                    let n = w.store(i).entries(s).expect("entries").len();
                    if n != 0 {
                        panic!("node {i} keeps {n} store entries under thing {k}'s sync ID, which it does not hold\n{}", why_role(w, i, t));
                    }
                }
            }
        }
    }
}

/// The length of the path an online node reading `t` records for its sync ID `s`, with every
/// step its `sync.0` records, when one does.
fn recorded_steps(w: &mut World, t: &Tid, s: &osis_base::SyncId) -> Option<(usize, BTreeSet<osis_blob::StepId>)> {
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    for i in on {
        let reads = w.engine(i).sync_set().expect("sync set").ids.get(s).is_some_and(|(_, h)| *h == Holding::Read);
        if reads && let Some(o) = w.engine(i).sync_ids(t).expect("sync ids").iter().find(|o| o.id == *s && !o.hint) {
            return Some((o.path.steps.len(), o.tree.keys().copied().collect()));
        }
    }
    None
}

/// `check`'s card clause (spec/sync-inbox.md §1 Card): each online node of an account takes every
/// account's inbox as its account's reference does (handed every commit: the accounts' `keys.0`
/// and the cards alike), so an inbox move spreads to every card read and no keys refresh undoes it.
fn card_clauses(w: &mut World, refs: &mut Refs, m: &Model) {
    let on: Vec<usize> = (0..w.len()).filter(|i| w.online(*i)).collect();
    for i in on {
        let Some(acct) = w.node(i).account else { continue };
        for b in &m.accounts {
            let got = w.engine(i).inbox_of(b).expect("inbox");
            let want = refs.of(&acct).engine.inbox_of(b).expect("reference inbox");
            assert_eq!(got, want, "node {i} takes account {b}'s inbox unlike the reference");
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

/// `check`'s body clause: some node holds a body the reference reads each thing's value from,
/// but a lost making's (`gone`)
/// (a thing nobody holds any more is gone for everyone, spec/sync-set.md §3: no node must), for
/// each thing some account's node closure reads by the model (one read nowhere is held at most
/// as ciphertext kept unread, which shows no value: a later reader fetches it there).
fn body_clauses(w: &mut World, refs: &mut Refs, m: &Model, gone: &BTreeSet<String>) {
    let things = w.history.things.clone();
    let views: Vec<(hc::Closure, hc::Set)> = (0..m.accounts.len()).map(|a| m.closure(a)).collect();
    for (k, (t, _)) in things.iter().enumerate() {
        let x = m.thing(k);
        let reader = views.iter().position(|(c, keys)| if m.world.independent(x) { c.read.contains(&x) } else { c.held.contains(&x) && m.world.opens(keys, x) });
        let Some(reader) = reader.filter(|_| (0..w.len()).any(|i| w.engine(i).closure_holds(t))) else { continue };
        let r = refs.of(&m.accounts[reader]);
        if let Some(Value::Str(v)) = reads(&mut r.engine, t).value.filter(|v| !matches!(v, Value::Str(x) if gone.contains(x))) {
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
                let Some(c) = w.engine(i).blob_body(&s, &e.blob).expect("body") else { continue };
                if w.engine(i).holds_commit(&c.commit) {
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
/// messages and fails disks. A grantee holds what it is granted by a strong from its
/// account, drawn after a grant, or never.
pub fn history(seed: u64, n: usize, accounts: usize, len: usize, faults: bool) -> Vec<Step> {
    let mut rng = SeededRng::from_u64(seed ^ 0x6869_7374);
    let mut pick = |m: usize| (rng.next_u64() % m.max(1) as u64) as usize;
    /// A sketch of a thing: its maker's account, whether it is independent, the roles given.
    struct Sketch {
        account: usize,
        /// Minted with its maker's account (`New`), held from it for good.
        root: bool,
        independent: bool,
        given: BTreeMap<Holder, Gives>,
    }
    let mut acct: Vec<usize> = (0..n).map(|j| j % accounts.max(1)).collect();
    let mut things: Vec<Sketch> = Vec::new();
    let mut strongs: Vec<(Option<usize>, usize, usize)> = Vec::new();
    let mut off: BTreeSet<usize> = BTreeSet::new();
    // nodes removed from their accounts (`Step::Unpair`), and the one set aside to be (on half the
    // seeds, the last of the setup's paired nodes): they write nothing (`unpair`)
    let mut gone: BTreeSet<usize> = BTreeSet::new();
    let mut doomed = (n > accounts && pick(2) == 0).then_some(n - 1);
    gone.extend(doomed);
    let mut out = Vec::new();
    while out.len() < len {
        let roll = pick(100);
        let k = pick(things.len());
        let on: Vec<usize> = (0..acct.len()).filter(|i| !off.contains(i) && !gone.contains(i)).collect();
        let node = on[pick(on.len())];
        // the nodes that may write thing k: its maker's account's and each given write
        let writers = |things: &[Sketch], k: usize| -> Vec<usize> {
            let t = &things[k];
            (0..acct.len()).filter(|i| !off.contains(i) && !gone.contains(i)).filter(|i| acct[*i] == t.account || t.given.get(&Holder::Node(acct[*i])) == Some(&Gives::Writes)).collect()
        };
        let admins = |things: &[Sketch], k: usize| -> Vec<usize> { (0..acct.len()).filter(|i| !off.contains(i) && !gone.contains(i) && acct[*i] == things[k].account).collect() };
        let s = match roll {
            _ if things.is_empty() || (roll < 10 && things.len() < 5) => {
                let ws = if things.is_empty() { Vec::new() } else { writers(&things, k) };
                if !ws.is_empty() && pick(3) == 0 {
                    let i = ws[pick(ws.len())];
                    things.push(Sketch { account: acct[i], root: false, independent: false, given: BTreeMap::new() });
                    Step::NewIn(i, k)
                } else {
                    things.push(Sketch { account: acct[node], root: true, independent: false, given: BTreeMap::new() });
                    Step::New(node)
                }
            }
            0..=24 => {
                let ws = writers(&things, k);
                // now and then a node that may not write
                let i = if pick(10) == 0 || ws.is_empty() { node } else { ws[pick(ws.len())] };
                // now and then its account's card on the thing in place of a value
                if pick(8) == 0 { Step::Card(i, k) } else { Step::Write(i, k) }
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
                    let h = if pick(6) == 0 {
                        Holder::Public
                    } else if !independent.is_empty() && (others.is_empty() || pick(4) == 0) {
                        Holder::Thing(independent[pick(independent.len())])
                    } else if others.is_empty() {
                        Holder::Node(i)
                    } else {
                        Holder::Node(others[pick(others.len())])
                    };
                    // the public at most read (spec/permissions.md §2)
                    let g = if h == Holder::Public { g.min(Gives::Reads) } else { g };
                    things[k].independent = true;
                    things[k].given.insert(h, g);
                    Step::Give(i, k, h, g)
                }
            }
            43..=58 if things[k].given.get(&Holder::Public) == Some(&Gives::Reads) && pick(3) == 0 => {
                // any node redeems a public link to it for its account
                strongs.push((None, k, node));
                Step::Redeem(node, k)
            }
            43..=58 => {
                // a node of a given account holds the thing from its account
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
            75..=79 => {
                // the node set aside, by a node of its account
                let by: Vec<usize> = on.iter().copied().filter(|i| doomed.is_some_and(|j| acct[*i] == acct[j])).collect();
                match doomed {
                    Some(j) if !by.is_empty() => {
                        doomed = None;
                        Step::Unpair(by[pick(by.len())], j)
                    }
                    // an account's inbox moved to a thing its node made from it, or back
                    _ if things[k].root && things[k].account == acct[node] && pick(2) == 0 => Step::Inbox(node, Some(k)),
                    _ if pick(3) == 0 => Step::Inbox(node, None),
                    _ => Step::Run,
                }
            }
            80..=99 if faults => match pick(7) {
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
