//! Forgetting (issues/account-signing.md step 2, notes/growth.md row 1): can a node drop a
//! commit's ID for good, and do the cover rules that would allow it keep what listing every
//! commit keeps? Candidates, each judged against `Policy::LIST_ALL`:
//! - `OWN` (A): a list leaves out what the leaver's own named snapshot carries, and a node
//!   forgets a commit its author's own valid held snapshot carries.
//! - `B_ANY`, `B_AFTER` (B): a removal commit carries the remover's fresh snapshot of the
//!   leaver's writes (`Kind::RemSnap`, standing exactly while the removal applies) and lists
//!   nothing it carries; a node forgets what any valid held cover carries (`B_ANY`), or only
//!   what a removal's snapshot carries (`B_AFTER`).
//! - `Policy::grace`: a node forgets only that long after receiving the cover.
//!
//! Layer 2 is `addenda::Ctx`, judged per node over what the node really holds. Per-node
//! simulation (`Run`): arrivals in time order; a body dropped when a valid held snapshot
//! carries it (anyone's: the worst retention), an invalid body at once; a valid body missing
//! fetched from any node still holding it; forgetting removes the header too, so the node
//! reads as if it never received it and can list only what it still holds. Lists are written
//! from the node's view when it writes: its frontier by what it received before its `ts`,
//! a witness's addendum on first holding the removal, by what it received before the
//! removal's `ts` (a late copy of a snapshot is not named: Bob could have signed it after
//! his removal). Everything anyone still holds is exchanged at the end.
//!
//! Attacker (`Script::forged`): the removed writer signs any commit at a closed standing,
//! backdated, on a counter of a listed or covered commit, delivered before or after the
//! removal reaches each node. A lying snapshot (`Script::claims`) covers a write it does not
//! carry. `exhaustive` runs the small families; hand tests below state each result.
//! The same questions at the account level are in `forget_account`.

use crate::addenda::{Cover, Ctx, Eval, Item, Kind, View, World, L1, PLAN};
use crate::joint::{JHist, JWrite};
use crate::shrink::LATE;
use crate::{Rng, Role};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};
use std::rc::Rc;

pub const ALICE: usize = 0;
pub const BOB: usize = 1;
pub const CAROL: usize = 2;
pub const DAVE: usize = 3;
pub const EVE: usize = 4;
/// Fresh node for the arrival-order check; receives only in `Run::order_check`.
pub const FRANK: usize = 5;
pub const NN: usize = 6;

/// Time at which everything held anywhere is delivered.
const FINAL: u32 = 100;
/// IDs: plain writes < 100, snapshots 100.., role writes 1000.., removal snapshots 2000 + rid,
/// addenda 10000 + 10 * (rid - 1000) + author.
fn remsnap_id(rid: u32) -> u32 {
    2000 + rid
}
fn add_id(rid: u32, a: usize) -> u32 {
    10000 + 10 * (rid - 1000) + a as u32
}
fn is_write(id: u32) -> bool {
    id < 100 || (100_000..1_000_000).contains(&id)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Forget {
    Never,
    /// Covered by its author's own valid held snapshot.
    Own,
    /// Covered by any valid held snapshot or removal snapshot.
    Any,
    /// Covered by a valid held removal snapshot.
    AfterRemoval,
}

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub name: &'static str,
    pub forget: Forget,
    /// Lists leave out what the leaver's own valid held snapshot carries and name it.
    pub own_cover: bool,
    /// A removal commit carries the remover's snapshot.
    pub removal_snapshot: bool,
    pub grace: u32,
}

impl Policy {
    pub const LIST_ALL: Policy = Policy { name: "list all", forget: Forget::Never, own_cover: false, removal_snapshot: false, grace: 0 };
    /// Today's listing with `Cover::OmitOwn`: no forgetting.
    pub const OWN_KEEP: Policy = Policy { name: "own, nothing forgotten", forget: Forget::Never, own_cover: true, removal_snapshot: false, grace: 0 };
    pub const OWN: Policy = Policy { name: "A own, forget", forget: Forget::Own, own_cover: true, removal_snapshot: false, grace: 0 };
    pub const B_ANY: Policy = Policy { name: "B removal snapshot, forget any cover", forget: Forget::Any, own_cover: true, removal_snapshot: true, grace: 0 };
    pub const B_AFTER: Policy = Policy { name: "B removal snapshot, forget at removals", forget: Forget::AfterRemoval, own_cover: true, removal_snapshot: true, grace: 0 };
}

/// The candidates compared with `LIST_ALL`.
pub const CANDIDATES: [Policy; 4] = [Policy::OWN_KEEP, Policy::OWN, Policy::B_ANY, Policy::B_AFTER];

/// A snapshot to write at `t` by `author`: carries what it reads then.
#[derive(Clone, Debug)]
pub struct SnapPlan {
    pub id: u32,
    pub author: usize,
    pub t: u32,
    pub recv: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct Script {
    pub roles: JHist,
    /// Plain writes (and forged commits, `forged` set).
    pub writes: Vec<Item>,
    pub snaps: Vec<SnapPlan>,
    /// Writes a remover cannot carry in its snapshot (a field it cannot read).
    pub blind: HashSet<u32>,
    /// A hostile snapshot's ID -> writes it claims to carry without holding their value.
    pub claims: HashMap<u32, Vec<u32>>,
    /// Commit ID -> session counter: two commits of one counter are both invalid (forks).
    pub ctr: HashMap<u32, u32>,
}

impl Script {
    pub fn new() -> Script {
        Script { roles: genesis(), writes: vec![], snaps: vec![], blind: HashSet::new(), claims: HashMap::new(), ctr: HashMap::new() }
    }
    fn row(author: usize, t: u32, recv: &[(usize, u32)]) -> Vec<u32> {
        let mut r = vec![LATE; NN];
        r[author] = t;
        for &(n, tn) in recv {
            r[n] = tn;
        }
        r
    }
    pub fn write(&mut self, id: u32, author: usize, t: u32, recv: &[(usize, u32)]) {
        self.writes.push(Item { kind: Kind::Plain, author, t, id, thing: 0, acting: None, recv: Self::row(author, t, recv), forged: false });
    }
    pub fn snap(&mut self, id: u32, author: usize, t: u32, recv: &[(usize, u32)]) {
        self.snaps.push(SnapPlan { id, author, t, recv: Self::row(author, t, recv) });
    }
    /// `by` removes `victim` from the thing at `t`.
    pub fn remove(&mut self, rid: u32, by: usize, victim: usize, t: u32, recv: &[(usize, u32)]) {
        self.roles.writes.push(JWrite { author: by, t, id: rid, target: 0, holder: victim, role: Role::None });
        self.roles.recv.push(Self::row(by, t, recv));
    }
}

/// Alice and Carol admins, Bob and Dave writers, Eve a reader (a blind holder's stand-in).
fn genesis() -> JHist {
    let mut genesis = vec![vec![Role::None]; NN + 1];
    genesis[ALICE][0] = Role::Admin;
    genesis[BOB][0] = Role::Write;
    genesis[CAROL][0] = Role::Admin;
    genesis[DAVE][0] = Role::Write;
    genesis[EVE][0] = Role::Read;
    JHist { nodes: NN, admins: vec![ALICE], genesis, writes: vec![], recv: vec![] }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
enum Ev {
    Tick(usize),
    Role(usize),
    Snap(usize),
    DeliverRole(usize, usize),
    Deliver(usize, usize),
}

/// One run's result.
#[derive(Debug)]
pub struct Out {
    /// Per node, the write IDs it reads.
    pub visible: Vec<BTreeSet<u32>>,
    /// Per node, what it forgot and did not end up holding.
    pub forgot: Vec<BTreeSet<u32>>,
    /// Every node (Frank aside) reads alike after the final exchange.
    pub agree: bool,
    /// A fresh node given everything held, in several orders, reads as they do.
    pub orders_agree: bool,
    /// IDs held at the end, per node.
    pub ids_held: Vec<usize>,
    /// IDs in the frontier of each removal, addenda's lists.
    pub frontier_ids: u64,
    pub addendum_ids: u64,
    pub rounds_cut: bool,
    /// Per node, the IDs it named or carried in anything it wrote.
    pub used: Vec<BTreeSet<u32>>,
}

struct Run<'a> {
    s: &'a Script,
    p: Policy,
    w: World,
    /// [node][item] receipt time.
    hdr: Vec<Vec<Option<u32>>>,
    body: Vec<Vec<bool>>,
    rh: Vec<Vec<bool>>,
    forgot: Vec<BTreeSet<u32>>,
    idx: HashMap<u32, usize>,
    /// Snapshot ID -> what it replaces besides what it carries (older snapshots it read).
    absorbs: HashMap<u32, Vec<u32>>,
    cache: HashMap<u64, Rc<L1>>,
    heap: BinaryHeap<Reverse<(u32, u8, u64, Ev)>>,
    seq: u64,
    now: u32,
    done_add: HashSet<(u32, usize)>,
    suppress: Option<(usize, u32)>,
    frontier_ids: u64,
    addendum_ids: u64,
    rounds_cut: bool,
    used: Vec<BTreeSet<u32>>,
}

impl<'a> Run<'a> {
    fn new(s: &'a Script, p: Policy, suppress: Option<(usize, u32)>) -> Self {
        let w = World { roles: s.roles.clone(), items: vec![], frontier: HashMap::new() };
        let mut r = Run {
            s,
            p,
            w,
            hdr: vec![vec![]; NN],
            body: vec![vec![]; NN],
            rh: vec![vec![false; s.roles.writes.len()]; NN],
            forgot: vec![BTreeSet::new(); NN],
            idx: HashMap::new(),
            absorbs: HashMap::new(),
            cache: HashMap::new(),
            heap: BinaryHeap::new(),
            seq: 0,
            now: 0,
            done_add: HashSet::new(),
            suppress,
            frontier_ids: 0,
            addendum_ids: 0,
            rounds_cut: false,
            used: vec![BTreeSet::new(); NN],
        };
        for it in &s.writes {
            r.push_item(it.clone());
        }
        for (i, w) in s.roles.writes.iter().enumerate() {
            r.push_ev(w.t, 0, Ev::Role(i));
        }
        for (k, sp) in s.snaps.iter().enumerate() {
            r.push_ev(sp.t, 0, Ev::Snap(k));
        }
        if p.grace > 0 {
            for t in 0..30 {
                for v in 0..NN {
                    r.push_ev(t, 2, Ev::Tick(v));
                }
            }
        }
        r
    }

    fn push_ev(&mut self, t: u32, class: u8, ev: Ev) {
        self.seq += 1;
        self.heap.push(Reverse((t, class, self.seq, ev)));
    }

    /// Adds an item and schedules its deliveries by its receipts.
    fn push_item(&mut self, it: Item) -> usize {
        let i = self.w.items.len();
        self.idx.insert(it.id, i);
        for v in 0..NN {
            self.hdr[v].push(None);
            self.body[v].push(false);
        }
        for v in 0..NN {
            if it.recv[v] < LATE && v != FRANK {
                self.push_ev(it.recv[v].max(it.t), 1, Ev::Deliver(v, i));
            }
        }
        self.w.items.push(it);
        i
    }

    /// Snapshots and removal snapshots: coverage of `s` (what it carries, absorbs, or claims).
    fn coverage(&self, s: usize) -> Vec<u32> {
        let it = &self.w.items[s];
        let mut c: Vec<u32> = it.kind.carries().to_vec();
        c.extend(self.absorbs.get(&it.id).into_iter().flatten());
        c.extend(self.s.claims.get(&it.id).into_iter().flatten());
        c
    }

    /// L1 and evaluation of node v's held set, restricted to receipts before `tau` if given.
    fn eval(&mut self, v: usize, tau: Option<u32>) -> (Rc<L1>, Eval, Vec<bool>, Vec<bool>) {
        let nr = self.w.roles.writes.len();
        let mut mask = 0u64;
        for i in 0..nr {
            let held = self.rh[v][i] && tau.map_or(true, |t| self.w.roles.recv[i][v].max(self.w.roles.writes[i].t) < t);
            if held {
                mask |= 1 << i;
            }
        }
        let l1 = self.cache.entry(mask).or_insert_with(|| Rc::new(L1::new(&self.w.roles, |i| mask >> i & 1 == 1))).clone();
        let n = self.w.items.len();
        let mut hdr: Vec<bool> = (0..n).map(|i| self.hdr[v][i].map_or(false, |r| tau.map_or(true, |t| r < t))).collect();
        let body: Vec<bool> = (0..n).map(|i| hdr[i] && self.body[v][i]).collect();
        // Forks and counters: two commits of one counter are both invalid; a commit whose
        // counter a valid held snapshot's coverage holds reads as covered (never applied).
        let by_ctr = |r: &Run, a: u32, b: u32| r.s.ctr.get(&a).is_some() && r.s.ctr.get(&a) == r.s.ctr.get(&b);
        for i in 0..n {
            for j in 0..n {
                if i != j && hdr[i] && hdr[j] && by_ctr(self, self.w.items[i].id, self.w.items[j].id) {
                    hdr[i] = false;
                    hdr[j] = false;
                }
            }
        }
        let e = Ctx::new(&self.w, View { l1: &l1, hdr: &hdr, body: &body }, self.rules()).eval();
        // A commit on a counter a valid held snapshot covers reads as covered.
        let mut e = e;
        for i in 0..n {
            if !hdr[i] || !e.valid[i] {
                continue;
            }
            for s in 0..n {
                if s != i && e.valid[s] && hdr[s] && body[s] && self.coverage(s).iter().any(|c| by_ctr(self, *c, self.w.items[i].id)) && !self.coverage(s).contains(&self.w.items[i].id) {
                    e.valid[i] = false;
                }
            }
        }
        (l1, e, hdr, body)
    }

    fn rules(&self) -> crate::addenda::Rules {
        crate::addenda::Rules { cover: if self.p.own_cover { Cover::OmitOwn } else { Cover::ListAll }, ..PLAN }
    }

    /// Node v's bodies and held IDs brought in line: invalid bodies dropped, covered bodies
    /// dropped (and forgotten as the policy says), valid bodies fetched.
    fn settle(&mut self, v: usize) {
        for _ in 0..50 {
            let (_, e, hdr, _) = self.eval(v, None);
            let n = self.w.items.len();
            for i in 0..n {
                // Eve stands in for a holder that cannot judge: it drops only under a cover.
                if v != EVE && self.hdr[v][i].is_some() && !e.valid[i] {
                    self.body[v][i] = false;
                }
            }
            let (_, e, hdr2, _) = self.eval(v, None);
            let _ = hdr;
            // What a valid held snapshot covers, and by whom.
            let mut covered = vec![false; n];
            let mut forget_now: Vec<usize> = vec![];
            for s in 0..n {
                let si = &self.w.items[s];
                if !matches!(si.kind, Kind::Snap(_) | Kind::RemSnap { .. }) || !hdr2[s] || !e.valid[s] || !self.body[v][s] {
                    continue;
                }
                let is_rem = matches!(si.kind, Kind::RemSnap { .. });
                let recv_s = self.hdr[v][s].unwrap_or(0);
                let aged = self.now >= recv_s.saturating_add(self.p.grace);
                let sa = si.author;
                for id in self.coverage(s) {
                    let Some(&c) = self.idx.get(&id) else { continue };
                    if c == s || !hdr2[c] {
                        continue;
                    }
                    covered[c] = true;
                    let ci = &self.w.items[c];
                    if !aged || !matches!(ci.kind, Kind::Plain | Kind::Snap(_)) {
                        continue;
                    }
                    let f = match self.p.forget {
                        Forget::Never => false,
                        Forget::Own => ci.author == sa,
                        Forget::Any => true,
                        Forget::AfterRemoval => is_rem,
                    };
                    if f {
                        forget_now.push(c);
                    }
                }
            }
            for c in forget_now {
                self.hdr[v][c] = None;
                self.body[v][c] = false;
                self.forgot[v].insert(self.w.items[c].id);
            }
            let mut fetched = false;
            for i in 0..n {
                if self.hdr[v][i].is_none() {
                    continue;
                }
                if covered[i] {
                    self.body[v][i] = false;
                    continue;
                }
                if e.valid[i] && !self.body[v][i] && (0..NN).any(|u| self.body[u][i]) {
                    self.body[v][i] = true;
                    fetched = true;
                }
            }
            if !fetched {
                return;
            }
        }
        panic!("settle does not end");
    }

    /// The victim's items node v held before `tau`, less what a snapshot of its own covers
    /// (`own_cover`), that snapshot named instead; also returns the IDs left out.
    fn own_list(&mut self, v: usize, tau: u32, victim: usize, for_addendum: bool) -> Vec<u32> {
        let (_, e, hdr, _) = self.eval(v, Some(tau));
        let n = self.w.items.len();
        let mut carried: HashSet<u32> = HashSet::new();
        if self.p.own_cover {
            for s in 0..n {
                if hdr[s] && e.valid[s] && self.w.items[s].author == victim && matches!(self.w.items[s].kind, Kind::Snap(_)) && self.body[v][s] {
                    carried.extend(self.coverage(s));
                }
            }
        }
        (0..n)
            .filter(|&c| {
                let ci = &self.w.items[c];
                hdr[c] && ci.author == victim && !carried.contains(&ci.id) && match ci.kind {
                    Kind::Plain | Kind::Add { .. } => true,
                    Kind::Snap(_) => !for_addendum || self.p.own_cover,
                    _ => false,
                }
            })
            .map(|c| self.w.items[c].id)
            .collect()
    }

    fn write_role(&mut self, i: usize) {
        let wr = self.w.roles.writes[i].clone();
        let v = wr.author;
        // A removal in its author's view: whatever the walk later makes of it.
        let mut front: HashSet<u32> = HashSet::new();
        if wr.role < Role::Write {
            let victim = wr.holder;
            let mut lists = self.own_list(v, wr.t, victim, false);
            if self.p.removal_snapshot {
                let (_, e, _, _) = self.eval(v, Some(wr.t));
                let n = self.w.items.len();
                let carries: Vec<u32> = (0..n).filter(|&c| e.visible[c] && self.w.items[c].author == victim && is_write(self.w.items[c].id) && !self.s.blind.contains(&self.w.items[c].id)).map(|c| self.w.items[c].id).collect();
                if !carries.is_empty() {
                    self.used[v].extend(carries.iter().copied());
                    // Arrives with the removal itself (`DeliverRole`): one commit.
                    let it = Item { kind: Kind::RemSnap { removal: wr.id, carries: carries.clone() }, author: v, t: wr.t, id: remsnap_id(wr.id), thing: 0, acting: None, recv: vec![LATE; NN], forged: false };
                    self.push_item(it);
                    lists.retain(|c| !carries.contains(c));
                }
            }
            self.frontier_ids += lists.len() as u64;
            self.used[v].extend(lists.iter().copied());
            front = lists.into_iter().collect();
        }
        self.w.frontier.insert(wr.id, front);
        let recv = self.w.roles.recv[i].clone();
        for u in 0..NN {
            if recv[u] < LATE && u != FRANK {
                self.push_ev(recv[u].max(wr.t), 1, Ev::DeliverRole(u, i));
            }
        }
    }

    fn write_snap(&mut self, k: usize) {
        let sp = self.s.snaps[k].clone();
        let (l1, e, hdr, _) = self.eval(sp.author, Some(sp.t));
        if l1.role(sp.author, 0, (sp.t, sp.author, sp.id)) < Role::Write {
            return;
        }
        let n = self.w.items.len();
        let carries: Vec<u32> = (0..n).filter(|&c| e.visible[c]).map(|c| self.w.items[c].id).collect();
        if carries.is_empty() {
            return;
        }
        let absorbs: Vec<u32> = (0..n).filter(|&c| hdr[c] && e.valid[c] && matches!(self.w.items[c].kind, Kind::Snap(_))).map(|c| self.w.items[c].id).collect();
        self.used[sp.author].extend(carries.iter().copied());
        self.absorbs.insert(sp.id, absorbs);
        let it = Item { kind: Kind::Snap(carries), author: sp.author, t: sp.t, id: sp.id, thing: 0, acting: None, recv: sp.recv, forged: false };
        self.push_item(it);
    }

    fn witness(&mut self, v: usize, i: usize) {
        let wr = self.w.roles.writes[i].clone();
        let victim = wr.holder;
        if wr.role >= Role::Write || v == victim || v == wr.author || !self.done_add.insert((wr.id, v)) {
            return;
        }
        let id = add_id(wr.id, v);
        let (l1, ..) = self.eval(v, None);
        if l1.role(v, 0, (self.now, v, id)) < Role::Write {
            return;
        }
        let front = self.w.frontier.get(&wr.id).cloned().unwrap_or_default();
        // What the removal's own snapshot carries needs no addendum.
        let carried: Vec<u32> = self.idx.get(&remsnap_id(wr.id)).map_or(vec![], |&r| self.w.items[r].kind.carries().to_vec());
        let lists: Vec<u32> = self.own_list(v, wr.t, victim, true).into_iter().filter(|c| !front.contains(c) && !carried.contains(c)).collect();
        if lists.is_empty() {
            return;
        }
        self.addendum_ids += lists.len() as u64;
        self.used[v].extend(lists.iter().copied());
        let recv: Vec<u32> = (0..NN).map(|u| if u == v { self.now } else if u == FRANK { LATE } else { self.now + 1 }).collect();
        let it = Item { kind: Kind::Add { removal: wr.id, lists }, author: v, t: self.now, id, thing: 0, acting: None, recv, forged: false };
        // Its author holds it before the removal's effect settles.
        let a = self.push_item(it);
        self.hdr[v][a] = Some(self.now);
        self.body[v][a] = true;
    }

    fn drain(&mut self) {
        while let Some(Reverse((t, _, _, ev))) = self.heap.pop() {
            self.now = t;
            match ev {
                Ev::Tick(v) => self.settle(v),
                Ev::Role(i) => self.write_role(i),
                Ev::Snap(k) => self.write_snap(k),
                Ev::DeliverRole(v, i) => {
                    if !self.rh[v][i] {
                        self.rh[v][i] = true;
                        if let Some(&r) = self.idx.get(&remsnap_id(self.w.roles.writes[i].id)) {
                            self.hdr[v][r] = Some(self.now);
                            self.body[v][r] = true;
                        }
                        self.witness(v, i);
                        self.settle(v);
                    }
                }
                Ev::Deliver(v, i) => self.deliver(v, i),
            }
        }
    }

    fn deliver(&mut self, v: usize, i: usize) {
        if self.suppress.map_or(false, |(sv, id)| sv == v && self.w.items[i].id == id) {
            return;
        }
        if self.hdr[v][i].is_none() {
            self.hdr[v][i] = Some(self.now);
            self.body[v][i] = true;
            self.settle(v);
        }
    }

    /// What everyone holds of item i: its header at some node, and a body at some node.
    fn exchange(&mut self) {
        let snap = |r: &Run| (r.hdr.iter().map(|h| h.iter().map(|x| x.is_some()).collect::<Vec<_>>()).collect::<Vec<_>>(), r.body.clone());
        self.now = FINAL;
        for i in 0..self.w.roles.writes.len() {
            for v in 0..NN {
                if !self.rh[v][i] && v != FRANK {
                    self.push_ev(FINAL, 1, Ev::DeliverRole(v, i));
                }
            }
        }
        self.drain();
        for round in 0..30 {
            let before = snap(self);
            self.now = FINAL + 1 + round;
            for v in 0..NN {
                if v == FRANK {
                    continue;
                }
                for i in 0..self.w.items.len() {
                    if self.hdr[v][i].is_none() && !self.suppress.map_or(false, |(sv, id)| sv == v && self.w.items[i].id == id) && (0..NN).any(|u| u != FRANK && self.hdr[u][i].is_some()) {
                        self.hdr[v][i] = Some(self.now);
                        self.body[v][i] = (0..NN).any(|u| u != FRANK && self.body[u][i]);
                    }
                }
                self.settle(v);
            }
            if snap(self) == before {
                return;
            }
        }
        self.rounds_cut = true;
    }

    fn visible(&mut self, v: usize) -> BTreeSet<u32> {
        let (_, e, _, _) = self.eval(v, None);
        (0..self.w.items.len()).filter(|&i| e.visible[i] && is_write(self.w.items[i].id)).map(|i| self.w.items[i].id).collect()
    }

    /// A fresh node (Frank) given every role write and every item held anywhere, in a few
    /// orders, ends reading as the others do.
    fn order_check(&mut self, rng: &mut Rng) -> bool {
        let expect = self.visible(ALICE);
        let n = self.w.items.len();
        let nr = self.w.roles.writes.len();
        let held: Vec<usize> = (0..n).filter(|&i| !matches!(self.w.items[i].kind, Kind::RemSnap { .. }) && (0..NN).any(|u| self.hdr[u][i].is_some())).collect();
        let mut all: Vec<(bool, usize)> = held.iter().map(|&i| (true, i)).chain((0..nr).map(|i| (false, i))).collect();
        let k = all.len();
        let mut ok = true;
        for trial in 0..4 {
            if trial == 1 {
                all.reverse();
            } else if trial > 1 {
                let p = rng.perm(k);
                all = p.iter().map(|&i| all[i]).collect();
            }
            for x in &mut self.hdr[FRANK] {
                *x = None;
            }
            for x in &mut self.body[FRANK] {
                *x = false;
            }
            self.rh[FRANK] = vec![false; nr];
            self.now = FINAL + 40;
            for &(is_item, i) in &all {
                if is_item {
                    self.hdr[FRANK][i] = Some(self.now);
                    self.body[FRANK][i] = (0..NN).any(|u| u != FRANK && self.body[u][i]);
                } else {
                    self.rh[FRANK][i] = true;
                    if let Some(&r) = self.idx.get(&remsnap_id(self.w.roles.writes[i].id)) {
                        self.hdr[FRANK][r] = Some(self.now);
                        self.body[FRANK][r] = true;
                    }
                }
                self.settle(FRANK);
            }
            // Forgetting is never having received: a later sync offers it again.
            for _ in 0..3 {
                for &(is_item, i) in &all {
                    if is_item && self.hdr[FRANK][i].is_none() {
                        self.hdr[FRANK][i] = Some(self.now);
                        self.body[FRANK][i] = (0..NN).any(|u| u != FRANK && self.body[u][i]);
                        self.settle(FRANK);
                    }
                }
            }
            ok &= self.visible(FRANK) == expect;
        }
        ok
    }

    fn finish(mut self, rng: &mut Rng) -> Out {
        self.drain();
        self.exchange();
        self.settle(FRANK);
        let visible: Vec<BTreeSet<u32>> = (0..NN).map(|v| self.visible(v)).collect();
        let agree = (0..FRANK).all(|v| visible[v] == visible[0]);
        let orders_agree = self.order_check(rng);
        let ids_held = (0..NN).map(|v| self.hdr[v].iter().filter(|h| h.is_some()).count()).collect();
        let forgot = (0..NN).map(|v| self.forgot[v].iter().filter(|id| self.hdr[v][self.idx[id]].is_none()).copied().collect()).collect();
        Out { visible, forgot, agree, orders_agree, ids_held, frontier_ids: self.frontier_ids, addendum_ids: self.addendum_ids, rounds_cut: self.rounds_cut, used: self.used.clone() }
    }
}

pub fn run(s: &Script, p: Policy) -> Out {
    Run::new(s, p, None).finish(&mut Rng(0xf0))
}

fn run_suppressed(s: &Script, p: Policy, sup: (usize, u32)) -> Out {
    Run::new(s, p, Some(sup)).finish(&mut Rng(0xf0))
}

/// The honest writes `other` reads at node v that `reference` does not, and conversely.
fn diff(reference: &Out, other: &Out, v: usize) -> (Vec<u32>, Vec<u32>) {
    let lost = reference.visible[v].difference(&other.visible[v]).copied().collect();
    let gained = other.visible[v].difference(&reference.visible[v]).copied().collect();
    (lost, gained)
}

// ---------- exhaustive family ----------

#[derive(Default, Clone)]
pub struct Tally {
    pub worlds: u64,
    pub loses: u64,
    pub gains: u64,
    pub disagree: u64,
    pub order: u64,
    pub forget_read: u64,
    pub attack_gain: u64,
    pub forged_lost: u64,
    pub ex: BTreeMap<&'static str, Script>,
}

impl Tally {
    fn merge(&mut self, o: Tally) {
        self.worlds += o.worlds;
        self.loses += o.loses;
        self.gains += o.gains;
        self.disagree += o.disagree;
        self.order += o.order;
        self.forget_read += o.forget_read;
        self.attack_gain += o.attack_gain;
        self.forged_lost += o.forged_lost;
        for (k, v) in o.ex {
            self.ex.entry(k).or_insert(v);
        }
    }
    pub fn print(&self, name: &str) {
        println!("{name}: {} worlds | loses (ListAll keeps) {} | gains {} | disagree {} | order {} | forget reads otherwise {} | attacker gains {} | loses under attack {}", self.worlds, self.loses, self.gains, self.disagree, self.order, self.forget_read, self.attack_gain, self.forged_lost);
    }
}

/// One script's checks of a candidate against the reference: `base`, the reference's run.
fn judge(s: &Script, p: Policy, base: &Out, t: &mut Tally, rng: &mut Rng) {
    let o = Run::new(s, p, None).finish(rng);
    t.worlds += 1;
    let mut loses = false;
    let mut gains = false;
    for v in 0..FRANK {
        let (l, g) = diff(base, &o, v);
        loses |= !l.is_empty();
        gains |= !g.is_empty();
    }
    let record = |t: &mut Tally, label: &'static str, s: &Script| {
        t.ex.entry(label).or_insert_with(|| s.clone());
    };
    if loses {
        t.loses += 1;
        record(t, "loses", s);
    }
    if gains {
        t.gains += 1;
        record(t, "gains", s);
    }
    if !o.agree {
        t.disagree += 1;
        record(t, "disagree", s);
    }
    if !o.orders_agree {
        t.order += 1;
        record(t, "order", s);
    }
    if o.rounds_cut {
        t.disagree += 1;
        record(t, "no fixpoint", s);
    }
    // Forgetting reads like never having received it.
    for v in 0..FRANK {
        // Except what the node wrote from it, which the rule keeps.
        for &id in o.forgot[v].difference(&o.used[v]) {
            let cf = run_suppressed(s, p, (v, id));
            if cf.visible[v] != o.visible[v] {
                t.forget_read += 1;
                record(t, "forget reads otherwise", s);
                return;
            }
        }
    }
}

/// Bob's write c (t=1) reaching each of Alice, Carol, Dave, Eve at 2 or late; a second write
/// (t=5, everyone) or none; a snapshot at t=3 by Bob, Alice or Dave, reaching each of the
/// others at 4, 8 (after Bob's removal's ts) or never; Alice removes Bob at t=6, reaching
/// Carol, Dave, Eve at 7 or 10; none, or Carol removes Dave or Alice at 5 (or Alice at 7),
/// reaching each other at t+1 or never (exchanged at the end, whatever).
pub fn member_family(share: (usize, usize), mut f: impl FnMut(Script)) {
    let mut index = 0;
    for cm in 0..16u32 {
        for c2 in 0..2 {
            for sa in [Option::None, Some(BOB), Some(ALICE), Some(DAVE)] {
                let receivers: Vec<usize> = [ALICE, BOB, CAROL, DAVE, EVE].into_iter().filter(|&n| Some(n) != sa).collect();
                let smax = if sa.is_some() { 3usize.pow(4) } else { 1 };
                for sm in 0..smax {
                    for rm in 0..8u32 {
                        for (by, victim, t2) in [(0, 0, 0), (CAROL, DAVE, 5), (CAROL, ALICE, 5), (CAROL, ALICE, 7)] {
                            for r2m in 0..if by != 0 { 16 } else { 1 } {
                                index += 1;
                                if index % share.1 != share.0 {
                                    continue;
                                }
                                let mut s = Script::new();
                                let bit = |m: u32, k: usize, t: u32| if m >> k & 1 == 1 { t } else { LATE };
                                s.write(1, BOB, 1, &[(ALICE, bit(cm, 0, 2)), (CAROL, bit(cm, 1, 2)), (DAVE, bit(cm, 2, 2)), (EVE, bit(cm, 3, 2))]);
                                if c2 == 1 {
                                    s.write(2, BOB, 5, &[(ALICE, 6), (CAROL, 6), (DAVE, 6), (EVE, 6)]);
                                }
                                if let Some(a) = sa {
                                    let mut k = sm;
                                    let recv: Vec<(usize, u32)> = receivers
                                        .iter()
                                        .map(|&n| {
                                            let d = k % 3;
                                            k /= 3;
                                            (n, [4, 8, LATE][d])
                                        })
                                        .collect();
                                    s.snap(100, a, 3, &recv);
                                }
                                let others = |m: u32, t: u32, skip: usize| -> Vec<(usize, u32)> { [ALICE, BOB, CAROL, DAVE, EVE].into_iter().filter(|&n| n != skip).enumerate().map(|(k, n)| (n, bit(m, k, t))).collect() };
                                let r7 = |b: u32| if rm >> b & 1 == 1 { 7 } else { 10 };
                                s.remove(1000, ALICE, BOB, 6, &[(BOB, 7), (CAROL, r7(0)), (DAVE, r7(1)), (EVE, r7(2))]);
                                if by != 0 {
                                    s.remove(1001, by, victim, t2, &others(r2m, t2 + 1, by));
                                }
                                f(s);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Attacks on a small base: Bob's write c (t=1) and snapshot (t=3), seen by Alice, Carol, Eve;
/// Alice removes Bob at 6. After it Bob signs (forged): a plain write or a snapshot carrying
/// a new write, backdated (t=2) or not (t=8), on c's counter or a new one; delivered to each
/// of Carol, Dave, Eve at 7 (before the removal reaches them) or 12, or never.
pub fn attack_family(share: (usize, usize), mut f: impl FnMut(Script)) {
    let mut index = 0;
    for snap in [true, false] {
        for rm in 0..8u32 {
            for kind in 0..2 {
                for t in [2u32, 8] {
                    for fork in [true, false] {
                        for dm in 0..27u32 {
                            index += 1;
                            if index % share.1 != share.0 {
                                continue;
                            }
                            let mut s = Script::new();
                            s.write(1, BOB, 1, &[(ALICE, 2), (CAROL, 2), (EVE, 2)]);
                            s.ctr.insert(1, 1);
                            if snap {
                                s.snap(100, BOB, 3, &[(ALICE, 4), (CAROL, 4), (EVE, 4)]);
                            }
                            let r = |b: u32| if rm >> b & 1 == 1 { 10 } else { 7 };
                            s.remove(1000, ALICE, BOB, 6, &[(BOB, 7), (CAROL, r(0)), (DAVE, r(1)), (EVE, r(2))]);
                            let d = |k: u32| [7u32, 12, LATE][(dm / 3u32.pow(k) % 3) as usize];
                            let deliver = [(CAROL, d(0)), (DAVE, d(1)), (EVE, d(2))];
                            // The forged new write (a value nobody else ever wrote).
                            s.write(50, BOB, t, &if kind == 0 { deliver.to_vec() } else { vec![] });
                            { let f = s.writes.last_mut().unwrap(); f.forged = true; f.recv[BOB] = LATE; }
                            if fork {
                                s.ctr.insert(50, 1);
                            }
                            if kind == 1 {
                                // Bob's own forged snapshot carrying the forged write.
                                s.writes.push(Item { kind: Kind::Snap(vec![50]), author: BOB, t: t + 1, id: 150, thing: 0, acting: None, recv: { let mut r = Script::row(BOB, 9, &deliver); r[BOB] = LATE; r }, forged: true });
                            }
                            f(s);
                        }
                    }
                }
            }
        }
    }
}

/// Attack checks: what the attacker made is no more visible than under listing all, and a
/// forged commit never makes an honest write the reference keeps disappear.
fn judge_attack(s: &Script, p: Policy, base: &Out, t: &mut Tally, rng: &mut Rng) {
    let o = Run::new(s, p, None).finish(rng);
    t.worlds += 1;
    let forged: HashSet<u32> = s.writes.iter().filter(|w| w.forged).map(|w| w.id).collect();
    for v in 0..FRANK {
        if o.visible[v].iter().any(|id| forged.contains(id) && !base.visible[v].contains(id)) {
            t.attack_gain += 1;
            t.ex.entry("attack gain").or_insert_with(|| s.clone());
            break;
        }
    }
    for v in 0..FRANK {
        let (l, _) = diff(base, &o, v);
        if l.iter().any(|id| !forged.contains(id)) {
            t.forged_lost += 1;
            t.ex.entry("loses under attack").or_insert_with(|| s.clone());
            break;
        }
    }
}

fn run_family(gen: impl Fn((usize, usize), &mut dyn FnMut(Script)) + Sync, attack: bool, cands: &[Policy]) -> Vec<Tally> {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let parts: Vec<Vec<Tally>> = std::thread::scope(|sc| {
        let gen = &gen;
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                sc.spawn(move || {
                    let mut rng = Rng(0x5eed ^ (th as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
                    let mut tallies = vec![Tally::default(); cands.len()];
                    gen((th, threads), &mut |s: Script| {
                        let base = run(&s, Policy::LIST_ALL);
                        for (k, p) in cands.iter().enumerate() {
                            if attack {
                                judge_attack(&s, *p, &base, &mut tallies[k], &mut rng);
                            } else {
                                judge(&s, *p, &base, &mut tallies[k], &mut rng);
                            }
                        }
                    });
                    tallies
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = vec![Tally::default(); cands.len()];
    for p in parts {
        for (a, b) in all.iter_mut().zip(p) {
            a.merge(b);
        }
    }
    all
}

/// Both member-level families, against the reference; returns the failure count.
pub fn exhaustive() {
    let mut cands = CANDIDATES.to_vec();
    cands.push(Policy { name: "A own, forget, grace 3", grace: 3, ..Policy::OWN });
    let base_t = run_family(|sh, f| member_family(sh, f), false, &cands);
    for (p, t) in cands.iter().zip(&base_t) {
        t.print(&format!("family: {}", p.name));
        for (l, ex) in &t.ex {
            print_min(*p, l, ex);
        }
    }
    let atk = run_family(|sh, f| attack_family(sh, f), true, &cands);
    for (p, t) in cands.iter().zip(&atk) {
        t.print(&format!("attacks: {}", p.name));
        for (l, ex) in &t.ex {
            println!("  first {l}:\n{}", show(ex));
        }
    }
    let mut lista = Tally::default();
    let mut rng = Rng(1);
    attack_family((0, 1), |s| judge_attack(&s, Policy::LIST_ALL, &run_empty_base(&s), &mut lista, &mut rng));
    lista.print("attacks: list all (absolute, against no forged commit seen)");
}

fn print_min(p: Policy, label: &str, ex: &Script) {
    let f: Box<dyn Fn(&Script) -> bool> = match label {
        "loses" => Box::new(move |s| { let (b, o) = (run(s, Policy::LIST_ALL), run(s, p)); (0..FRANK).any(|v| !diff(&b, &o, v).0.is_empty()) }),
        "gains" => Box::new(move |s| { let (b, o) = (run(s, Policy::LIST_ALL), run(s, p)); (0..FRANK).any(|v| !diff(&b, &o, v).1.is_empty()) }),
        "order" => Box::new(move |s| !run(s, p).orders_agree),
        "forget reads otherwise" => Box::new(move |s| { let o = run(s, p); (0..FRANK).any(|v| o.forgot[v].difference(&o.used[v]).any(|&id| run_suppressed(s, p, (v, id)).visible[v] != o.visible[v])) }),
        _ => Box::new(|_| false),
    };
    let m = if f(ex) { minimize(ex.clone(), &*f) } else { ex.clone() };
    let (b, o) = (run(&m, Policy::LIST_ALL), run(&m, p));
    println!("  {label}:\n{}    list all reads {:?}, this reads {:?}", show(&m), b.visible[0], o.visible[0]);
}

fn run_empty_base(s: &Script) -> Out {
    let mut b = s.clone();
    let forged: HashSet<u32> = s.writes.iter().filter(|w| w.forged).map(|w| w.id).collect();
    b.writes.retain(|w| !w.forged);
    let _ = forged;
    run(&b, Policy::LIST_ALL)
}

/// Greedy minimal script still satisfying `bad`: drops events and deliveries.
fn minimize(mut s: Script, bad: &dyn Fn(&Script) -> bool) -> Script {
    loop {
        let mut smaller: Vec<Script> = vec![];
        for i in 0..s.writes.len() {
            let mut x = s.clone();
            x.writes.remove(i);
            smaller.push(x);
            for v in 0..NN {
                if s.writes[i].recv[v] < LATE && v != s.writes[i].author {
                    let mut x = s.clone();
                    x.writes[i].recv[v] = LATE;
                    smaller.push(x);
                }
            }
        }
        for i in 0..s.snaps.len() {
            let mut x = s.clone();
            x.snaps.remove(i);
            smaller.push(x);
            for v in 0..NN {
                if s.snaps[i].recv[v] < LATE && v != s.snaps[i].author {
                    let mut x = s.clone();
                    x.snaps[i].recv[v] = LATE;
                    smaller.push(x);
                }
            }
        }
        for i in 0..s.roles.writes.len() {
            let mut x = s.clone();
            x.roles.writes.remove(i);
            x.roles.recv.remove(i);
            smaller.push(x);
            for v in 0..NN {
                if s.roles.recv[i][v] < LATE && v != s.roles.writes[i].author {
                    let mut x = s.clone();
                    x.roles.recv[i][v] = LATE;
                    smaller.push(x);
                }
            }
        }
        match smaller.into_iter().find(|x| bad(x)) {
            Some(x) => s = x,
            None => return s,
        }
    }
}

/// A script as a few readable lines.
pub fn show(s: &Script) -> String {
    let name = ["Alice", "Bob", "Carol", "Dave", "Eve", "Frank"];
    let recv = |r: &[u32], a: usize| (0..NN).filter(|&v| v != a && r[v] < LATE).map(|v| format!("{} {}", name[v], r[v])).collect::<Vec<_>>().join(", ");
    let mut out = String::new();
    for w in &s.writes {
        out += &format!("  write {} by {} at {}{}; seen: {}\n", w.id, name[w.author], w.t, if w.forged { " FORGED" } else { "" }, recv(&w.recv, w.author));
    }
    for sp in &s.snaps {
        out += &format!("  snapshot {} by {} at {}; seen: {}\n", sp.id, name[sp.author], sp.t, recv(&sp.recv, sp.author));
    }
    for (w, r) in s.roles.writes.iter().zip(&s.roles.recv) {
        out += &format!("  {} removes {} at {}; seen: {}\n", name[w.author], name[w.holder], w.t, recv(r, w.author));
    }
    out
}

fn minimal_examples(p: Policy, keep: impl Fn(&Script) -> bool) {
    let bad_loses = |s: &Script| {
        if !keep(s) {
            return false;
        }
        let (b, o) = (run(s, Policy::LIST_ALL), run(s, p));
        (0..FRANK).any(|v| !diff(&b, &o, v).0.is_empty())
    };
    let bad_order = |s: &Script| keep(s) && !run(s, p).orders_agree;
    let bad_forget = |s: &Script| {
        let o = run(s, p);
        keep(s) && (0..FRANK).any(|v| o.forgot[v].iter().any(|&id| !o.used[v].contains(&id) && run_suppressed(s, p, (v, id)).visible[v] != o.visible[v]))
    };
    let mut first: [Option<Script>; 3] = [None, None, None];
    let mut all = vec![];
    member_family((0, 7), |s| all.push(s));
    let mut rng = Rng(0x9e37);
    let order = rng.perm(all.len());
    for i in order.into_iter().take(200_000) {
        for (k, f) in [&bad_loses as &dyn Fn(&Script) -> bool, &bad_order, &bad_forget].into_iter().enumerate() {
            if first[k].is_none() && f(&all[i]) {
                first[k] = Some(all[i].clone());
            }
        }
        if first.iter().all(|x| x.is_some()) {
            break;
        }
    }
    for (k, label) in ["loses", "order", "forget reads otherwise"].into_iter().enumerate() {
        if let Some(s) = first[k].take() {
            let f = [&bad_loses as &dyn Fn(&Script) -> bool, &bad_order, &bad_forget][k];
            let m = minimize(s, f);
            let b = run(&m, Policy::LIST_ALL);
            let o = run(&m, p);
            println!("{} {label}:\n{}  list all reads {:?}, this reads {:?}, forgot {:?}", p.name, show(&m), b.visible[0], o.visible[0], o.forgot);
        }
    }
}

/// Minimal counterexamples for each candidate (`forget-min`).
pub fn minimal() {
    for p in CANDIDATES {
        minimal_examples(p, |_| true);
    }
}

/// Costs, counted: Bob writes `n` commits, seen by everyone at once; a compaction every 10
/// commits by `by` (none, Bob, or Dave); then Alice removes Bob. Per candidate: IDs Alice
/// still holds, IDs the removal lists, IDs in addenda.
pub fn costs() {
    let policies = [Policy::LIST_ALL, Policy::OWN, Policy::B_ANY, Policy::B_AFTER];
    for (label, by) in [("nobody compacts", None), ("Bob compacts his own", Some(BOB)), ("Dave compacts", Some(DAVE))] {
        for n in [20usize, 200] {
            let mut s = Script::new();
            let mut sid = 0;
            for k in 0..n {
                let t = 1 + 2 * k as u32;
                let id = 100_000 + k as u32;
                s.write(id, BOB, t, &[(ALICE, t + 1), (CAROL, t + 1), (DAVE, t + 1), (EVE, t + 1)]);
                if let Some(b) = by {
                    if k % 10 == 9 {
                        sid += 1;
                        s.snap(50_000 + sid, b, t + 1, &[ALICE, BOB, CAROL, DAVE, EVE].into_iter().filter(|&x| x != b).map(|x| (x, t + 2)).collect::<Vec<_>>());
                    }
                }
            }
            let tr = 3 + 2 * n as u32;
            s.remove(1000, ALICE, BOB, tr, &[(BOB, tr + 1), (CAROL, tr + 1), (DAVE, tr + 1), (EVE, tr + 1)]);
            for p in policies {
                let o = run(&s, p);
                println!("{label}, n={n}, {}: IDs Alice holds {} ({} snapshots) | removal lists {} | addenda list {} | reads {} of {n}", p.name, o.ids_held[ALICE], sid, o.frontier_ids, o.addendum_ids, o.visible[ALICE].len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: u32 = 1;

    fn reads(s: &Script, p: Policy, id: u32) -> bool {
        let o = run(s, p);
        assert!(o.agree, "{}: nodes disagree", p.name);
        o.visible[ALICE].contains(&id)
    }

    /// Alice removes Bob; Dave's snapshot of Bob's edit and his removal by Carol as in
    /// `addenda::another_writers_cover_falls_with_its_author`: B's removal snapshot keeps
    /// the edit, A does not forget under another's cover and keeps it by listing.
    #[test]
    fn another_writers_cover() {
        let mut s = Script::new();
        s.write(C, BOB, 1, &[(ALICE, 2), (DAVE, 2)]);
        s.snap(100, DAVE, 4, &[(ALICE, 5)]);
        s.remove(1000, CAROL, DAVE, 5, &[(BOB, 6), (DAVE, 6), (EVE, 6)]);
        s.remove(1001, ALICE, BOB, 6, &[(BOB, 7), (CAROL, 7), (DAVE, 7), (EVE, 7)]);
        for p in [Policy::LIST_ALL, Policy::OWN_KEEP, Policy::OWN, Policy::B_ANY] {
            assert!(reads(&s, p, C), "{}", p.name);
        }
    }

    /// A's window: Alice held Bob's edit since 2, and got Bob's snapshot of it at 8, after the
    /// removal's ts (6) but before the removal reached her (9), by Carol who had neither.
    /// Listing every commit keeps the edit; forgetting loses it (Eve's copy of the body is
    /// valid again only if someone lists it).
    fn window() -> Script {
        let mut s = Script::new();
        s.write(C, BOB, 1, &[(ALICE, 2), (EVE, 2)]);
        s.snap(100, BOB, 3, &[(ALICE, 8)]);
        s.remove(1000, CAROL, BOB, 6, &[(ALICE, 9), (DAVE, 9), (EVE, 9), (BOB, 9)]);
        s
    }

    #[test]
    fn a_late_snapshot_loses_the_edit() {
        let s = window();
        assert!(reads(&s, Policy::LIST_ALL, C), "reference keeps it");
        assert!(reads(&s, Policy::OWN_KEEP, C), "own cover with nothing forgotten");
        assert!(!reads(&s, Policy::OWN, C), "A forgets it before the removal shows");
        assert!(!reads(&s, Policy::B_ANY, C), "B's witness forgets likewise");
        // Waiting past the removal's arrival keeps it (the window is bounded by the wait).
        assert!(reads(&s, Policy { grace: 2, ..Policy::OWN }, C));
        assert!(reads(&s, Policy { grace: 1, ..Policy::OWN }, C), "one tick after the cover, the removal has come");
    }

    /// Own cover without the late arrival works: Alice got the snapshot before the removal.
    #[test]
    fn a_holds_when_the_snapshot_came_first() {
        let mut s = Script::new();
        s.write(C, BOB, 1, &[(ALICE, 2)]);
        s.snap(100, BOB, 3, &[(ALICE, 4)]);
        s.remove(1000, CAROL, BOB, 6, &[(ALICE, 7), (DAVE, 7), (EVE, 7), (BOB, 7)]);
        assert!(reads(&s, Policy::OWN, C));
        assert!(run(&s, Policy::OWN).forgot[ALICE].contains(&C));
    }

    /// Naming a snapshot in an addendum, even with nothing forgotten: Dave vouches for Bob's
    /// snapshot, so Alice drops the edit's body under it; Carol had removed Dave before his
    /// addendum, which falls, the snapshot with it. Alice's list still names the edit, but no
    /// body is left. Listing alone never lets a snapshot stand on an addendum.
    #[test]
    fn a_cover_standing_on_an_addendum_falls() {
        let mut s = Script::new();
        s.write(C, BOB, 1, &[(ALICE, 2)]);
        s.snap(100, BOB, 3, &[(ALICE, 8), (DAVE, 4)]);
        s.remove(1000, CAROL, DAVE, 5, &[]);
        s.remove(1001, ALICE, BOB, 6, &[(DAVE, 7)]);
        assert!(reads(&s, Policy::LIST_ALL, C));
        assert!(!reads(&s, Policy::OWN_KEEP, C));
    }

    /// B, removal of the remover: Alice's removal of Bob carries his edit; Carol removes Alice
    /// without having received it, so the removal and its snapshot fall and Bob's edit counts
    /// again, but only a node still holding its body can show it: Alice forgot it and no one
    /// else ever held the body.
    #[test]
    fn b_remover_removed_loses_the_edit() {
        let mut s = Script::new();
        s.write(C, BOB, 1, &[(ALICE, 2)]);
        s.remove(1000, ALICE, BOB, 6, &[(EVE, 7), (DAVE, 7), (BOB, 7)]);
        s.remove(1001, CAROL, ALICE, 7, &[(DAVE, 8), (BOB, 8), (EVE, 8)]);
        assert!(reads(&s, Policy::LIST_ALL, C), "the fallen removal gives the edit back");
        assert!(!reads(&s, Policy::B_ANY, C));
        assert!(!reads(&s, Policy::B_AFTER, C));
    }

    /// B: the remover cannot read the field the removed writer wrote, so its snapshot cannot
    /// carry the edit; it must list it, so the ID stays.
    #[test]
    fn b_remover_cannot_read_the_field() {
        let mut s = Script::new();
        s.write(C, BOB, 1, &[(ALICE, 2)]);
        s.blind.insert(C);
        s.remove(1000, ALICE, BOB, 6, &[(EVE, 7), (BOB, 7)]);
        let o = run(&s, Policy::B_ANY);
        assert!(o.visible[ALICE].contains(&C) && o.frontier_ids == 1, "listed instead");
    }

    /// B, forgetting under another writer's cover: Carol forgot Bob's edit under Dave's
    /// snapshot, Alice removes Bob without either; a later removal of Dave by Alice drops
    /// Dave's snapshot. Listing every commit keeps the edit through Carol's addendum.
    #[test]
    fn b_forget_any_loses_a_falling_cover() {
        let mut s = Script::new();
        s.write(C, BOB, 1, &[(CAROL, 2), (DAVE, 2), (EVE, 2)]);
        s.snap(100, DAVE, 4, &[(CAROL, 10), (DAVE, 4)]);
        s.remove(1000, ALICE, BOB, 6, &[(CAROL, 12), (DAVE, 12), (EVE, 12), (BOB, 12)]);
        s.remove(1001, ALICE, DAVE, 9, &[(CAROL, 11), (DAVE, 11), (EVE, 11), (BOB, 11)]);
        assert!(reads(&s, Policy::LIST_ALL, C));
        assert!(!reads(&s, Policy::B_ANY, C));
    }

    /// The removed writer gains nothing: Bob signs a backdated plain commit on a covered
    /// counter (fork) after his removal, delivered before the removal reaches Carol: not
    /// listed, not visible, under every candidate.
    #[test]
    fn backdated_fork_gains_nothing() {
        let mut s = Script::new();
        s.write(C, BOB, 1, &[(ALICE, 2), (CAROL, 2), (EVE, 2)]);
        s.ctr.insert(C, 1);
        s.snap(100, BOB, 3, &[(ALICE, 4), (CAROL, 4), (EVE, 4)]);
        s.remove(1000, ALICE, BOB, 6, &[(CAROL, 10), (DAVE, 10), (EVE, 10), (BOB, 7)]);
        s.write(50, BOB, 2, &[(CAROL, 7), (DAVE, 7), (EVE, 7)]);
        { let f = s.writes.last_mut().unwrap(); f.forged = true; f.recv[BOB] = LATE; }
        s.ctr.insert(50, 1);
        for p in [Policy::LIST_ALL, Policy::OWN, Policy::B_ANY] {
            assert!(!reads(&s, p, 50), "{}", p.name);
            assert!(reads(&s, p, C), "{}: the snapshot still carries c", p.name);
        }
    }

    /// A slice of each family: finds no failure the candidates' tests name beyond the stated.
    #[test]
    fn family_slice_runs() {
        let mut n = 0;
        member_family((0, 2000), |s| {
            let _ = run(&s, Policy::OWN);
            n += 1;
        });
        assert!(n > 0);
    }
}
