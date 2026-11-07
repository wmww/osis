//! Addenda (spec/permissions.md §5.2, Addenda; notes/permissions.md Revocation): layer 2 over the
//! joint role timeline (`joint`, unchanged) with several content authors. A removal R of X
//! (an explicit demotion below write, §5.2) lists what its author had received; a writer W
//! that received X's plain content before R's `ts` and R did not list it publishes an
//! **addendum**: a plain write of W on the thing, naming R and listing those commit IDs.
//! Every writer publishes for everything it saw that R did not list, with no coordination.
//!
//! A part (a commit's delta on a thing, or its acting check on its header actor, §5.2 Acting)
//! by X on thing m is valid iff X is re-granted there (§5.2), or held write at its key and no
//! demotion of X below write on m follows, or else the frontier of any such demotion lists it
//! (whatever the order: a frontier is what its demoter had received), or a counting addendum A
//! names such a demotion D ordered after it and lists it. A counts iff (plan rules 1-5):
//! - A is valid (rule 5: an ordinary write of its author, audited by its author's removals);
//! - A's key is after D's and the listed commit's before D's (rule 2);
//! - A's author holds write on m at A's key (rules 1 and 3: readers and blind hosts hold no
//!   write; a commit's acting check is its part on its header actor, vouched for there by a
//!   writer of that actor, as the removal's frontier lists it there);
//! - the listed commit is plain content, no compaction snapshot (rule 4; `Kind::Special` stands for role-class,
//!   admin-only and purge writes; role commits are not items at all).
//!
//! Validity is the least fixpoint of that rule seeded by the writes valid without addenda
//! (`Ctx::fixpoint`). A valid compaction snapshot (`Kind::Snap`) keeps what it carries
//! visible (§5.2), and is itself a plain write of its author.
//!
//! Variants: `Rerem` (on a re-removal, do earlier removals' addenda or frontiers still count)
//! and `Rules::omit_covered` (removals and addenda leave out commits a snapshot their author
//! holds valid carries, today's "covered commits" rule, vs listing them).
//!
//! Bodies (`Sim`): every node drops an invalid body at once and fetches a valid one it lacks
//! from any node holding it; a body nobody holds stays lost. An addendum's list is its body.
//!
//! Search: `roles-model -- N addenda` (random) and `addenda-exh` (exhaustive small family).
//! Results: notes/permissions.md, Role timeline (Addenda model).

use crate::joint::{self, JHist};
use crate::shrink::LATE;
use crate::{Rng, Role};
use std::collections::{HashMap, HashSet};

/// Timeline key: (ts, author node, commit ID), shared by role writes and items.
pub type Key = (u32, usize, u32);

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Plain,
    /// Role-class, admin-only or purge write: judged like content, never listable (rule 4).
    Special,
    /// Compaction snapshot carrying these content items (IDs) of its thing.
    Snap(Vec<u32>),
    /// Addendum naming a removal (role write ID) and listing commit IDs.
    Add { removal: u32, lists: Vec<u32> },
}

#[derive(Clone, Debug)]
pub struct Item {
    pub kind: Kind,
    pub author: usize,
    pub t: u32,
    pub id: u32,
    pub thing: usize,
    /// Header actor when it acts for another actor (§5.2 Acting).
    pub acting: Option<usize>,
    /// [node] receipt time; `LATE` never.
    pub recv: Vec<u32>,
    /// Written by the attacker (`World::forge`).
    pub forged: bool,
}

impl Item {
    pub fn key(&self) -> Key {
        (self.t, self.author, self.id)
    }
    /// Plain content commits and addenda (rule 4): no role-class, admin-only or purge write,
    /// no compaction snapshot (spec/permissions.md §5.2, Addenda).
    fn listable(&self) -> bool {
        matches!(self.kind, Kind::Plain | Kind::Add { .. })
    }
    fn content(&self) -> bool {
        matches!(self.kind, Kind::Plain | Kind::Special)
    }
    fn parts(&self) -> impl Iterator<Item = usize> {
        std::iter::once(self.thing).chain(self.acting)
    }
    /// Node v holds it before time `tau` on v's clock: an author's clock running ahead stamps
    /// it after its receipt.
    fn held(&self, v: usize, tau: u32) -> bool {
        self.recv[v] < LATE && self.recv[v] < tau
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rerem {
    /// Only the newest removal's frontier and addenda count.
    Newest,
    /// Addenda naming any later removal count; frontiers the newest only.
    AnyAddenda,
    /// Every removal's frontier counts, whatever the order (§5.2), and addenda naming any later
    /// removal.
    Any,
    /// As `Any`, but a frontier counts only for writes ordered before its removal.
    Later,
}

#[derive(Clone, Copy, Debug)]
pub struct Rules {
    pub rerem: Rerem,
    pub omit_covered: bool,
    /// A listed commit (frontier or addendum) counts only if its author held write at its key.
    pub held_only: bool,
    /// Bodies (`Sim`): a node keeps what an addendum it holds lists, and its own addenda,
    /// however it judges them.
    pub keep_listed: bool,
}

/// The plan as decided for the model.
pub const PLAN: Rules = Rules { rerem: Rerem::Any, omit_covered: false, held_only: false, keep_listed: false };

#[derive(Clone)]
pub struct World {
    pub roles: JHist,
    pub items: Vec<Item>,
    /// Role write ID -> the item IDs its author had received before its `ts`.
    pub frontier: HashMap<u32, HashSet<u32>>,
}

/// An explicit demotion below write (`JHist::steps`).
#[derive(Clone, Debug)]
pub struct Dem {
    pub rid: u32,
    pub key: Key,
    pub author: usize,
    pub victim: usize,
    pub thing: usize,
}

/// The role timeline as layer 2 reads it.
pub struct L1 {
    keys: Vec<Key>,
    states: Vec<Vec<Vec<Role>>>,
    pub dems: Vec<Dem>,
}

impl L1 {
    /// The settled joint walk over the role writes `keep` selects.
    pub fn new(h: &JHist, keep: impl Fn(usize) -> bool) -> L1 {
        let idx: Vec<usize> = (0..h.writes.len()).filter(|&i| keep(i)).collect();
        let sub = JHist { nodes: h.nodes, admins: h.admins.clone(), genesis: h.genesis.clone(), writes: idx.iter().map(|&i| h.writes[i].clone()).collect(), recv: idx.iter().map(|&i| h.recv[i].clone()).collect() };
        let s = sub.steps();
        let wkey = |i: usize| (sub.writes[i].t, sub.writes[i].author, sub.writes[i].id);
        let mut l = L1 { keys: vec![], states: vec![s.genesis], dems: vec![] };
        for (i, r) in s.after {
            l.keys.push(wkey(i));
            l.states.push(r);
        }
        l.dems = s.demotions.iter().map(|&(i, x, n)| Dem { rid: sub.writes[i].id, key: wkey(i), author: sub.writes[i].author, victim: x, thing: n }).collect();
        l
    }
    fn at(&self, key: Key) -> usize {
        self.keys.partition_point(|k| *k < key)
    }
    pub fn role(&self, n: usize, x: usize, key: Key) -> Role {
        self.states[self.at(key)][n][x]
    }
    /// §5.2 re-grant: write in the final state, and the key at or after the first point n
    /// ever held write on x.
    fn regrant(&self, n: usize, x: usize, key: Key) -> bool {
        self.states.last().map_or(false, |s| s[n][x] >= Role::Write) && self.states.iter().position(|s| s[n][x] >= Role::Write).map_or(false, |p| p <= self.at(key))
    }
}

/// One node's held set: headers and bodies (by item index) and its role timeline.
pub struct View<'a> {
    pub l1: &'a L1,
    pub hdr: &'a [bool],
    pub body: &'a [bool],
}

#[derive(Clone, Debug, PartialEq)]
pub struct Eval {
    pub valid: Vec<bool>,
    /// Content items whose writes show: valid with the body held, or carried by a valid held
    /// snapshot.
    pub visible: Vec<bool>,
    /// Iterations of the fixpoint, the last one changing nothing.
    pub rounds: usize,
}

/// One evaluation's inputs.
pub struct Ctx<'a> {
    w: &'a World,
    v: View<'a>,
    rules: Rules,
    /// (removal, thing) -> held addenda with bodies: (item, listed IDs).
    adds: HashMap<(u32, usize), Vec<(usize, HashSet<u32>)>>,
}

impl<'a> Ctx<'a> {
    pub fn new(w: &'a World, v: View<'a>, rules: Rules) -> Self {
        let mut adds: HashMap<(u32, usize), Vec<(usize, HashSet<u32>)>> = HashMap::new();
        for (i, it) in w.items.iter().enumerate() {
            if let Kind::Add { removal, lists } = &it.kind {
                if v.hdr[i] && v.body[i] {
                    adds.entry((*removal, it.thing)).or_default().push((i, lists.iter().copied().collect()));
                }
            }
        }
        Ctx { w, v, rules, adds }
    }

    /// Addendum `a` vouches for item `c`'s part on thing m against demotion d (rules 2 and 3;
    /// rule 4 and A's own validity are checked by the caller).
    fn vouches(&self, a: usize, c: usize, m: usize, d: &Dem) -> bool {
        let (ad, l1) = (&self.w.items[a], self.v.l1);
        let k = ad.key();
        k > d.key && self.w.items[c].key() < d.key && l1.role(ad.author, m, k) >= Role::Write
    }

    /// Whether item c's part on thing m is valid, given which items are valid (`valid`).
    pub fn part_ok(&self, c: usize, m: usize, valid: &[bool]) -> bool {
        let it = &self.w.items[c];
        let (x, key, l1) = (it.author, it.key(), self.v.l1);
        if l1.regrant(x, m, key) {
            return true;
        }
        let dems: Vec<&Dem> = l1.dems.iter().filter(|d| d.victim == x && d.thing == m).collect();
        let held = l1.role(x, m, key) >= Role::Write;
        if held && !dems.iter().any(|d| d.key > key) {
            return true;
        }
        if self.rules.held_only && !held {
            return false;
        }
        let Some(newest) = dems.iter().copied().max_by_key(|d| d.key) else { return false };
        let lists = |d: &Dem| self.w.frontier.get(&d.rid).map_or(false, |f| f.contains(&it.id));
        // a frontier is what its demoter had received: it saves what it lists whatever the order
        let saving: Vec<&Dem> = match self.rules.rerem {
            Rerem::Any => dems.clone(),
            Rerem::Later => dems.iter().copied().filter(|d| d.key > key).collect(),
            _ => vec![newest],
        };
        if saving.iter().any(|d| lists(d)) {
            return true;
        }
        let cands: Vec<&Dem> = match self.rules.rerem {
            Rerem::Newest => vec![newest],
            _ => dems.iter().copied().filter(|d| d.key > key).collect(),
        };
        if !it.listable() {
            return false;
        }
        cands.iter().any(|d| self.adds.get(&(d.rid, m)).map_or(false, |v| v.iter().any(|(a, l)| valid[*a] && l.contains(&it.id) && self.vouches(*a, c, m, d))))
    }

    fn step(&self, valid: &[bool]) -> Vec<bool> {
        (0..self.w.items.len()).map(|c| self.v.hdr[c] && self.w.items[c].parts().all(|m| self.part_ok(c, m, valid))).collect()
    }

    /// The least fixpoint from the writes valid without addenda (`from_top`: the greatest,
    /// from everything held, for comparison only).
    pub fn fixpoint(&self, from_top: bool) -> (Vec<bool>, usize) {
        let mut valid: Vec<bool> = if from_top { self.v.hdr.to_vec() } else { vec![false; self.w.items.len()] };
        let mut rounds = 0;
        loop {
            rounds += 1;
            let next = self.step(&valid);
            if next == valid {
                return (valid, rounds);
            }
            valid = next;
        }
    }

    pub fn eval(&self) -> Eval {
        let (valid, rounds) = self.fixpoint(false);
        let w = self.w;
        let held = |i: usize| self.v.hdr[i] && self.v.body[i] && valid[i];
        let visible = (0..w.items.len())
            .map(|c| {
                let it = &w.items[c];
                it.content() && (held(c) || w.items.iter().enumerate().any(|(s, si)| matches!(&si.kind, Kind::Snap(cs) if si.thing == it.thing && cs.contains(&it.id)) && held(s)))
            })
            .collect();
        Eval { valid, visible, rounds }
    }
}

impl World {
    fn nodes(&self) -> usize {
        self.roles.nodes
    }
    fn actors(&self) -> usize {
        self.roles.admins.len()
    }

    /// Everything held, every body: the reference result.
    pub fn ideal(&self, rules: Rules) -> Eval {
        let l1 = L1::new(&self.roles, |_| true);
        let all = vec![true; self.items.len()];
        Ctx::new(self, View { l1: &l1, hdr: &all, body: &all }, rules).eval()
    }

    /// Items valid without any addendum, everything held.
    pub fn ideal_base(&self) -> Vec<bool> {
        let l1 = L1::new(&self.roles, |_| true);
        let all = vec![true; self.items.len()];
        let ctx = Ctx::new(self, View { l1: &l1, hdr: &all, body: &all }, PLAN);
        ctx.step(&vec![false; self.items.len()])
    }

    /// Node v's view before time `tau`, every body it received held.
    fn view_at(&self, v: usize, tau: u32, rules: Rules) -> (L1, Eval) {
        let r = &self.roles;
        let l1 = L1::new(r, |i| r.recv[i][v] < LATE && r.recv[i][v].max(r.writes[i].t) < tau);
        let hdr: Vec<bool> = self.items.iter().map(|it| it.held(v, tau)).collect();
        let e = Ctx::new(self, View { l1: &l1, hdr: &hdr, body: &hdr }, rules).eval();
        (l1, e)
    }

    /// Items a snapshot node v holds valid before `tau` carries.
    fn covered_at(&self, v: usize, tau: u32, rules: Rules) -> HashSet<u32> {
        let (_, e) = self.view_at(v, tau, rules);
        let mut out = HashSet::new();
        for (s, it) in self.items.iter().enumerate() {
            if let Kind::Snap(cs) = &it.kind {
                if e.valid[s] {
                    out.extend(cs.iter().copied());
                }
            }
        }
        out
    }

    /// Honest frontiers, snapshots and addenda, written in time order, each from its author's
    /// view at the time. Every random draw is made whatever the rules decide, so worlds
    /// generated from one seed under different rules share their base.
    /// `add_recv`: receipts of addenda (author, t), else random.
    fn derive(&mut self, rng: &mut Rng, rules: Rules, snaps: &[(usize, u32, usize)], ids: &mut HashSet<u32>, add_recv: Option<&dyn Fn(usize, u32) -> Vec<u32>>) {
        let g = L1::new(&self.roles, |_| true);
        let nn = self.nodes();
        enum Trig {
            Front(usize),
            Snap(usize, u32, usize),
            Add(usize, usize),
        }
        let mut trig: Vec<(u32, u8, usize, Trig)> = vec![];
        for (i, w) in self.roles.writes.iter().enumerate() {
            trig.push((w.t, 0, i, Trig::Front(i)));
        }
        for (k, &(s, ts, m)) in snaps.iter().enumerate() {
            trig.push((ts, 1, k, Trig::Snap(s, ts, m)));
        }
        for (k, d) in g.dems.iter().enumerate() {
            let ri = self.roles.writes.iter().position(|w| w.id == d.rid).unwrap();
            for w in (0..nn).filter(|&w| w != d.victim && w != d.author && self.roles.recv[ri][w] < LATE) {
                trig.push((self.roles.recv[ri][w].max(d.key.0) + 1, 2, k * nn + w, Trig::Add(k, w)));
            }
        }
        trig.sort_by_key(|t| (t.0, t.1, t.2));
        for (time, _, _, tr) in trig {
            match tr {
                Trig::Front(i) => {
                    let wr = &self.roles.writes[i];
                    let covered = if rules.omit_covered { self.covered_at(wr.author, wr.t, rules) } else { HashSet::new() };
                    let f = self.items.iter().filter(|it| it.held(wr.author, wr.t) && !covered.contains(&it.id)).map(|it| it.id).collect();
                    self.frontier.insert(wr.id, f);
                }
                Trig::Snap(s, ts, m) => {
                    let id = fresh(rng, ids);
                    let recv = recv_row(rng, nn, s, ts, false);
                    let (l1, e) = self.view_at(s, ts, rules);
                    if l1.role(s, m, (ts, s, id)) < Role::Write {
                        continue;
                    }
                    let carries: Vec<u32> = self.items.iter().enumerate().filter(|(c, it)| it.content() && it.thing == m && e.visible[*c]).map(|(_, it)| it.id).collect();
                    if !carries.is_empty() {
                        self.items.push(Item { kind: Kind::Snap(carries), author: s, t: ts, id, thing: m, acting: None, recv, forged: false });
                    }
                }
                Trig::Add(k, w) => {
                    let d = &g.dems[k];
                    let id = fresh(rng, ids);
                    let mut recv = recv_row(rng, nn, w, time, false);
                    if let Some(f) = add_recv {
                        recv = f(w, time);
                    }
                    let key = (time, w, id);
                    if g.role(w, d.thing, key) < Role::Write {
                        continue;
                    }
                    let covered = if rules.omit_covered { self.covered_at(w, d.key.0, rules) } else { HashSet::new() };
                    let front = &self.frontier[&d.rid];
                    let lists: Vec<u32> = self
                        .items
                        .iter()
                        .filter(|c| c.author == d.victim && c.listable() && c.parts().any(|m| m == d.thing) && c.held(w, d.key.0) && !front.contains(&c.id) && !covered.contains(&c.id))
                        .map(|c| c.id)
                        .collect();
                    if !lists.is_empty() {
                        self.items.push(Item { kind: Kind::Add { removal: d.rid, lists }, author: w, t: time, id, thing: d.thing, acting: None, recv, forged: false });
                    }
                }
            }
        }
    }

    /// An attacker (`att`, one or two nodes, any roles) forges up to three addenda: any
    /// removal, thing, `ts` (backdated included), any list (role-class, later and acting
    /// commits, other addenda, role write IDs), any receipts. Frontiers list them as received.
    pub fn forge(&self, rng: &mut Rng, att: &[usize]) -> World {
        let mut w = self.clone();
        let mut ids: HashSet<u32> = self.roles.writes.iter().map(|x| x.id).chain(self.items.iter().map(|x| x.id)).collect();
        let pool: Vec<u32> = ids.iter().copied().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        let rids: Vec<u32> = self.roles.writes.iter().map(|x| x.id).collect();
        if rids.is_empty() {
            return w;
        }
        for _ in 0..1 + rng.below(3) {
            let author = att[rng.below(att.len())];
            let t = rng.below(12) as u32;
            let id = fresh(rng, &mut ids);
            let lists = pool.iter().copied().filter(|_| rng.below(2) == 0).collect();
            let recv = recv_row(rng, self.nodes(), author, t, true);
            let it = Item { kind: Kind::Add { removal: rids[rng.below(rids.len())], lists }, author, t, id, thing: rng.below(self.actors()), acting: None, recv, forged: true };
            for wr in &self.roles.writes {
                if it.held(wr.author, wr.t) {
                    w.frontier.get_mut(&wr.id).unwrap().insert(it.id);
                }
            }
            w.items.push(it);
        }
        w
    }

    /// The world with items and role writes in another input order.
    pub fn permuted(&self, rng: &mut Rng) -> World {
        let pi = rng.perm(self.items.len());
        let pr = rng.perm(self.roles.writes.len());
        let mut roles = self.roles.clone();
        roles.writes = pr.iter().map(|&i| self.roles.writes[i].clone()).collect();
        roles.recv = pr.iter().map(|&i| self.roles.recv[i].clone()).collect();
        World { roles, items: pi.iter().map(|&i| self.items[i].clone()).collect(), frontier: self.frontier.clone() }
    }

    /// IDs of the items set in `bits`.
    pub fn ids(&self, bits: &[bool]) -> Vec<u32> {
        let mut v: Vec<u32> = self.items.iter().zip(bits).filter(|(_, &b)| b).map(|(it, _)| it.id).collect();
        v.sort();
        v
    }

    /// The world without item i (lists naming it keep the ID).
    pub fn without(&self, i: usize) -> World {
        World { items: crate::shrink::without(&self.items, i), ..self.clone() }
    }
}

fn fresh(rng: &mut Rng, ids: &mut HashSet<u32>) -> u32 {
    loop {
        let id = rng.next() as u32;
        if ids.insert(id) {
            return id;
        }
    }
}

/// Receipts: the author at `t`; others a third never, else near `t`: up to 2 earlier (skewed
/// clocks) when `early`, else up to 3 later.
fn recv_row(rng: &mut Rng, nn: usize, author: usize, t: u32, early: bool) -> Vec<u32> {
    (0..nn)
        .map(|v| {
            let r = if rng.below(3) == 0 { LATE } else if early { (t as i64 + rng.below(6) as i64 - 2).max(0) as u32 } else { t + rng.below(4) as u32 };
            if v == author { t } else { r }
        })
        .collect()
}

/// A random world: a `joint` role history (its things are actors), 1-6 content commits (two
/// thirds by a node some removal demotes, on that thing, before it; a sixth acting for
/// another actor, an eighth special), up to two snapshots, and the honest addenda.
pub fn random_world(rng: &mut Rng, rules: Rules) -> World {
    let roles = joint::random_hist(rng);
    let (nn, na) = (roles.nodes, roles.admins.len());
    let mut ids: HashSet<u32> = roles.writes.iter().map(|w| w.id).collect();
    let mut items = vec![];
    // Two thirds of the content by a removed writer on the thing, before its removal.
    let dems = L1::new(&roles, |_| true).dems;
    for _ in 0..1 + rng.below(6) {
        let (mut author, mut t, mut thing) = (rng.below(nn), 1 + rng.below(9) as u32, rng.below(na));
        if !dems.is_empty() && rng.below(3) != 0 {
            let d = &dems[rng.below(dems.len())];
            (author, thing, t) = (d.victim, d.thing, 1 + rng.below(d.key.0.max(2) as usize - 1) as u32);
        }
        let acting = (rng.below(6) == 0).then(|| (thing + 1 + rng.below(na - 1)) % na);
        let kind = if rng.below(8) == 0 { Kind::Special } else { Kind::Plain };
        let id = fresh(rng, &mut ids);
        let recv = recv_row(rng, nn, author, t, true);
        items.push(Item { kind, author, t, id, thing, acting, recv, forged: false });
    }
    let snaps: Vec<(usize, u32, usize)> = (0..rng.below(3)).map(|_| (rng.below(nn), 2 + rng.below(9) as u32, rng.below(na))).collect();
    let mut w = World { roles, items, frontier: HashMap::new() };
    w.derive(rng, rules, &snaps, &mut ids, None);
    w
}

// ---------- bodies ----------

/// Every node drops invalid bodies at once and fetches valid ones it lacks from any holder;
/// after the deliveries everyone exchanges every header. `order`: per-node delivery orders
/// (item or role write), else by receipt time.
pub struct Sim {
    /// Every node's final valid and visible IDs agree.
    pub agree: bool,
    pub valid: Vec<bool>,
    pub visible: Vec<bool>,
}

impl World {
    pub fn simulate(&self, rules: Rules, shuffle: Option<&mut Rng>) -> Sim {
        let (nn, n, nr) = (self.nodes(), self.items.len(), self.roles.writes.len());
        let mut hdr = vec![vec![false; n]; nn];
        let mut body = vec![vec![false; n]; nn];
        let mut rh = vec![vec![false; nr]; nn];
        // (time, node, is item, index)
        // (time, node, is item, index). A witness writes its addendum on receipt of the
        // removal, while it still holds what it lists: its own addendum arrives with the
        // removal, just before it.
        let held_role = |v: usize, rid: u32| (0..nr).find(|&i| self.roles.writes[i].id == rid && self.roles.recv[i][v] < LATE);
        let own_add = |v: usize, it: &Item| match &it.kind {
            Kind::Add { removal, .. } if it.author == v && !it.forged => held_role(v, *removal),
            _ => Option::None,
        };
        let mut ev: Vec<(u32, usize, bool, usize)> = vec![];
        for v in 0..nn {
            for (i, w) in self.roles.writes.iter().enumerate() {
                if self.roles.recv[i][v] < LATE {
                    ev.push((self.roles.recv[i][v].max(w.t), v, false, i));
                }
            }
            for (i, it) in self.items.iter().enumerate() {
                if it.recv[v] < LATE && own_add(v, it).is_none() {
                    ev.push((it.recv[v].max(it.t), v, true, i));
                }
            }
        }
        ev.sort();
        if let Some(rng) = shuffle {
            let p = rng.perm(ev.len());
            ev = p.into_iter().map(|i| ev[i]).collect();
        }
        for v in 0..nn {
            for (i, it) in self.items.iter().enumerate() {
                if let Some(r) = own_add(v, it) {
                    let at = ev.iter().position(|e| *e == (e.0, v, false, r)).unwrap();
                    let time = ev[at].0;
                    ev.insert(at, (time, v, true, i));
                }
            }
        }
        let settle = |v: usize, hdr: &Vec<Vec<bool>>, body: &mut Vec<Vec<bool>>, rh: &Vec<Vec<bool>>| -> (bool, Eval) {
            let l1 = L1::new(&self.roles, |i| rh[v][i]);
            let mut changed = false;
            loop {
                let e = Ctx::new(self, View { l1: &l1, hdr: &hdr[v], body: &body[v] }, rules).eval();
                let mut fetched = false;
                for i in 0..n {
                    if hdr[v][i] && e.valid[i] && !body[v][i] && (0..nn).any(|u| body[u][i]) {
                        body[v][i] = true;
                        fetched = true;
                    }
                }
                // `keep_listed`: what a held addendum lists, and one's own addenda, stay.
                let listed: HashSet<u32> = if rules.keep_listed {
                    (0..n).filter(|&a| hdr[v][a] && body[v][a]).filter_map(|a| if let Kind::Add { lists, .. } = &self.items[a].kind { Some(lists.iter().copied()) } else { Option::None }).flatten().collect()
                } else {
                    HashSet::new()
                };
                let keep = |i: usize| rules.keep_listed && (listed.contains(&self.items[i].id) || self.items[i].author == v && matches!(self.items[i].kind, Kind::Add { .. }));
                for i in 0..n {
                    if hdr[v][i] && !e.valid[i] && body[v][i] && !keep(i) {
                        body[v][i] = false;
                        changed = true;
                    }
                }
                changed |= fetched;
                if !fetched {
                    return (changed, e);
                }
            }
        };
        for (_, v, is_item, i) in ev {
            if is_item {
                hdr[v][i] = true;
                body[v][i] = true;
            } else {
                rh[v][i] = true;
            }
            settle(v, &hdr, &mut body, &rh);
        }
        for v in 0..nn {
            hdr[v].fill(true);
            rh[v].fill(true);
        }
        let mut evs = vec![];
        loop {
            let mut changed = false;
            evs.clear();
            for v in 0..nn {
                let (c, e) = settle(v, &hdr, &mut body, &rh);
                changed |= c;
                evs.push(e);
            }
            if !changed {
                break;
            }
        }
        let agree = evs.iter().all(|e| e.valid == evs[0].valid && e.visible == evs[0].visible);
        Sim { agree, valid: evs[0].valid.clone(), visible: evs[0].visible.clone() }
    }
}

// ---------- trace ----------

impl std::fmt::Display for World {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.roles)?;
        let l1 = L1::new(&self.roles, |_| true);
        for d in &l1.dems {
            writeln!(f, "  demotion: id {} by n{} at {:?} takes n{} below write on A{}", d.rid, d.author, d.key, d.victim, d.thing)?;
        }
        let mut o: Vec<usize> = (0..self.items.len()).collect();
        o.sort_by_key(|&i| self.items[i].key());
        for i in o {
            let it = &self.items[i];
            let what = match &it.kind {
                Kind::Plain => "plain".to_string(),
                Kind::Special => "special".to_string(),
                Kind::Snap(c) => format!("snapshot carrying {c:?}"),
                Kind::Add { removal, lists } => format!("addendum to {removal} listing {lists:?}"),
            };
            let acting = it.acting.map_or(String::new(), |h| format!(" acting A{h}"));
            let forged = if it.forged { " FORGED" } else { "" };
            writeln!(f, "  item {i}: t={} n{} (id {}) on A{}{acting}: {what}{forged} | {}", it.t, it.author, it.id, it.thing, crate::fmt_recv(&it.recv, it.author))?;
        }
        let mut fr: Vec<_> = self.frontier.iter().filter(|(_, s)| !s.is_empty()).collect();
        fr.sort_by_key(|(k, _)| **k);
        for (rid, s) in fr {
            let mut s: Vec<_> = s.iter().collect();
            s.sort();
            writeln!(f, "  frontier of {rid}: {s:?}")?;
        }
        Ok(())
    }
}

impl crate::shrink::Shrink for World {
    fn smaller(&self) -> Vec<World> {
        let mut out: Vec<World> = (0..self.items.len()).map(|i| self.without(i)).collect();
        for i in 0..self.roles.writes.len() {
            let mut w = self.clone();
            w.roles.writes.remove(i);
            w.roles.recv.remove(i);
            out.push(w);
        }
        out
    }
}

// ---------- search ----------

/// Per removal (a demotion of one victim on one thing) in the honest world.
#[derive(Default, Clone, Debug)]
pub struct Cost {
    pub removals: u64,
    /// The victim's items there the removal lists.
    pub frontier: u64,
    pub addenda: u64,
    pub max_addenda: u64,
    /// IDs listed by addenda, and of those listed by more than one addendum (extra copies).
    pub listed: u64,
    pub dup: u64,
    pub max_listed: u64,
    /// The victim's items there valid only thanks to addenda.
    pub rescued: u64,
}

impl Cost {
    fn add(&mut self, w: &World, rules: Rules) {
        let l1 = L1::new(&w.roles, |_| true);
        let all = vec![true; w.items.len()];
        let ctx = Ctx::new(w, View { l1: &l1, hdr: &all, body: &all }, rules);
        let (valid, _) = ctx.fixpoint(false);
        let base = ctx.step(&vec![false; w.items.len()]);
        for d in &l1.dems {
            self.removals += 1;
            let mine: Vec<usize> = (0..w.items.len()).filter(|&c| w.items[c].author == d.victim && !w.items[c].forged && w.items[c].parts().any(|m| m == d.thing)).collect();
            self.frontier += mine.iter().filter(|&&c| w.frontier[&d.rid].contains(&w.items[c].id)).count() as u64;
            let mut count: HashMap<u32, u64> = HashMap::new();
            let mut n = 0;
            for it in &w.items {
                if let Kind::Add { removal, lists } = &it.kind {
                    if *removal == d.rid && it.thing == d.thing && !it.forged {
                        n += 1;
                        for id in lists {
                            *count.entry(*id).or_default() += 1;
                        }
                    }
                }
            }
            let listed: u64 = count.values().sum();
            self.addenda += n;
            self.max_addenda = self.max_addenda.max(n);
            self.listed += listed;
            self.max_listed = self.max_listed.max(listed);
            self.dup += listed - count.len() as u64;
            self.rescued += mine.iter().filter(|&&c| valid[c] && !base[c]).count() as u64;
        }
    }
    fn print(&self, label: &str) {
        let r = self.removals.max(1) as f64;
        println!(
            "  cost {label}: {} removals | per removal: frontier {:.2} IDs, addenda {:.2} (max {}), listed {:.2} IDs (max {}), duplicate copies {:.2}, rescued {:.3}",
            self.removals,
            self.frontier as f64 / r,
            self.addenda as f64 / r,
            self.max_addenda,
            self.listed as f64 / r,
            self.max_listed,
            self.dup as f64 / r,
            self.rescued as f64 / r
        );
    }
}

/// Counters and first counterexamples of `check`.
#[derive(Default)]
pub struct Stats {
    pub worlds: u64,
    pub with_addenda: u64,
    pub rescued_worlds: u64,
    pub max_rounds: usize,
    /// Failures (each must stay 0).
    pub order_dep: u64,
    pub nonmonotone: u64,
    pub disagree: u64,
    pub sim_gains: u64,
    pub attack_gain: u64,
    pub variant_order: u64,
    /// Measured.
    pub gfp_differs: u64,
    pub sim_lost: u64,
    pub sim_lost_ids: u64,
    /// Of those, writes valid only through addenda (the rest are valid without them).
    pub sim_lost_addenda: u64,
    /// `Rules::held_only`: worlds reading otherwise, and addenda-only writes lost.
    pub held_only_differs: u64,
    pub held_only_lost_addenda: u64,
    /// `Rules::keep_listed`: writes lost, and of those valid only through addenda.
    pub keep_listed_lost: u64,
    pub keep_listed_lost_addenda: u64,
    pub both_lost_addenda: u64,
    pub shuffle_differs: u64,
    pub newest_vs_any_addenda: u64,
    pub newest_vs_any: u64,
    pub later_vs_any: u64,
    pub omit_loses: u64,
    pub omit_gains: u64,
    pub cost: Cost,
    pub cost_omit: Cost,
    pub ex: Vec<(&'static str, World)>,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.worlds += o.worlds;
        self.with_addenda += o.with_addenda;
        self.rescued_worlds += o.rescued_worlds;
        self.max_rounds = self.max_rounds.max(o.max_rounds);
        self.order_dep += o.order_dep;
        self.nonmonotone += o.nonmonotone;
        self.disagree += o.disagree;
        self.sim_gains += o.sim_gains;
        self.attack_gain += o.attack_gain;
        self.variant_order += o.variant_order;
        self.gfp_differs += o.gfp_differs;
        self.sim_lost += o.sim_lost;
        self.sim_lost_ids += o.sim_lost_ids;
        self.sim_lost_addenda += o.sim_lost_addenda;
        self.held_only_differs += o.held_only_differs;
        self.held_only_lost_addenda += o.held_only_lost_addenda;
        self.keep_listed_lost += o.keep_listed_lost;
        self.keep_listed_lost_addenda += o.keep_listed_lost_addenda;
        self.both_lost_addenda += o.both_lost_addenda;
        self.shuffle_differs += o.shuffle_differs;
        self.newest_vs_any_addenda += o.newest_vs_any_addenda;
        self.newest_vs_any += o.newest_vs_any;
        self.later_vs_any += o.later_vs_any;
        self.omit_loses += o.omit_loses;
        self.omit_gains += o.omit_gains;
        for (a, b) in [(&mut self.cost, o.cost), (&mut self.cost_omit, o.cost_omit)] {
            a.removals += b.removals;
            a.frontier += b.frontier;
            a.addenda += b.addenda;
            a.max_addenda = a.max_addenda.max(b.max_addenda);
            a.listed += b.listed;
            a.dup += b.dup;
            a.max_listed = a.max_listed.max(b.max_listed);
            a.rescued += b.rescued;
        }
        for (l, w) in o.ex {
            if !self.ex.iter().any(|(m, _)| *m == l) {
                self.ex.push((l, w));
            }
        }
    }

    pub fn failures(&self) -> u64 {
        self.order_dep + self.nonmonotone + self.disagree + self.sim_gains + self.attack_gain + self.variant_order
    }

    pub fn print(&self) {
        println!(
            "addenda: {} worlds ({} with addenda, {} with a write rescued) | max fixpoint rounds {} | FAIL order-dependent {}, non-monotone {}, nodes disagreeing {}, bodies gaining over ideal {}, attack gains {}, variants not nested {}",
            self.worlds, self.with_addenda, self.rescued_worlds, self.max_rounds, self.order_dep, self.nonmonotone, self.disagree, self.sim_gains, self.attack_gain, self.variant_order
        );
        println!(
            "  measured: greatest fixpoint differs {} | drop-at-once loses visible writes in {} worlds ({} writes, {} valid only through addenda), shuffled arrival changes the result {} | re-removal: any-addenda differs from newest {}, any (frontiers too) {}; frontiers only for earlier writes differs {} | omitting covered commits: loses visible writes {}, gains {}",
            self.gfp_differs, self.sim_lost, self.sim_lost_ids, self.sim_lost_addenda, self.shuffle_differs, self.newest_vs_any_addenda, self.newest_vs_any, self.later_vs_any, self.omit_loses, self.omit_gains
        );
        println!("  held-only listing: reads otherwise in {} worlds, addenda-only writes lost {}", self.held_only_differs, self.held_only_lost_addenda);
        println!("  keeping what held addenda list: writes lost {} ({} valid only through addenda); with held-only too: addenda-only writes lost {}", self.keep_listed_lost, self.keep_listed_lost_addenda, self.both_lost_addenda);
        self.cost.print("listing every commit");
        self.cost_omit.print("omitting covered commits");
        for (label, w) in &self.ex {
            let shrinkable = !matches!(*label, "attack gain" | "order dependence" | "bodies gain" | "variants not nested" | "omit loses (omit world)");
            let fails = |x: &World| fails_check(label, x);
            let w = if shrinkable && fails(w) { crate::shrink::shrink(w.clone(), fails) } else { w.clone() };
            println!("  {label} example:\n{w}");
        }
    }
}

fn subset(a: &[bool], b: &[bool]) -> bool {
    a.iter().zip(b).all(|(x, y)| !*x || *y)
}

/// Whether `w` still fails the named check (for shrinking).
fn fails_check(label: &str, w: &World) -> bool {
    match label {
        "non-monotone" => nonmonotone(w, PLAN),
        "nodes disagree" => !w.simulate(PLAN, None).agree,
        "body loss" | "body loss (rescued by addenda)" => {
            let s = w.simulate(PLAN, None);
            s.visible != w.ideal(PLAN).visible
        }
        "held-only addenda loss" => {
            let ho = Rules { held_only: true, ..PLAN };
            let (eh, sh, base) = (w.ideal(ho), w.simulate(ho, None), w.ideal_base());
            (0..w.items.len()).any(|c| eh.visible[c] && !sh.visible[c] && !base[c])
        }
        "keep-listed addenda loss" => {
            let (e, sk, base) = (w.ideal(PLAN), w.simulate(Rules { keep_listed: true, ..PLAN }, None), w.ideal_base());
            (0..w.items.len()).any(|c| e.visible[c] && !sk.visible[c] && !base[c])
        }
        "both addenda loss" => {
            let both = Rules { keep_listed: true, held_only: true, ..PLAN };
            let (e, sb, base) = (w.ideal(both), w.simulate(both, None), w.ideal_base());
            (0..w.items.len()).any(|c| e.visible[c] && !sb.visible[c] && !base[c])
        }
        "re-removal variants differ" => w.ideal(Rules { rerem: Rerem::Newest, ..PLAN }).valid != w.ideal(Rules { rerem: Rerem::AnyAddenda, ..PLAN }).valid,
        "gfp differs" => {
            let l1 = L1::new(&w.roles, |_| true);
            let all = vec![true; w.items.len()];
            let c = Ctx::new(w, View { l1: &l1, hdr: &all, body: &all }, PLAN);
            c.fixpoint(false).0 != c.fixpoint(true).0
        }
        _ => true,
    }
}

/// Removing one honest addendum turns some write valid (or visible).
fn nonmonotone(w: &World, rules: Rules) -> bool {
    let e = w.ideal(rules);
    (0..w.items.len()).filter(|&a| matches!(w.items[a].kind, Kind::Add { .. })).any(|a| {
        let wa = w.without(a);
        let ea = wa.ideal(rules);
        let (v, va) = (w.ids(&e.valid), wa.ids(&ea.valid));
        let (s, sa) = (w.ids(&e.visible), wa.ids(&ea.visible));
        va.iter().any(|id| !v.contains(id)) || sa.iter().any(|id| !s.contains(id))
    })
}

/// Attack: every part the forged addenda turn valid is a plain write's part on a thing m
/// where a valid forged addendum on m has its author holding write at its key: nothing beyond
/// the attacker's own write power on that thing (a part attributed to an actor is vouched for
/// on the actor by a writer of it, as a frontier lists it).
fn attack_gains(w: &World, f: &World, rules: Rules) -> bool {
    let l1 = L1::new(&w.roles, |_| true);
    let (a0, a1) = (vec![true; w.items.len()], vec![true; f.items.len()]);
    let c0 = Ctx::new(w, View { l1: &l1, hdr: &a0, body: &a0 }, rules);
    let c1 = Ctx::new(f, View { l1: &l1, hdr: &a1, body: &a1 }, rules);
    let (v0, _) = c0.fixpoint(false);
    let (v1, _) = c1.fixpoint(false);
    (0..w.items.len()).any(|c| {
        let it = &w.items[c];
        it.parts().any(|m| {
            if !c1.part_ok(c, m, &v1) || c0.part_ok(c, m, &v0) {
                return false;
            }
            if !it.listable() {
                return true;
            }
            !(w.items.len()..f.items.len()).any(|a| {
                let ad = &f.items[a];
                let k = ad.key();
                v1[a] && ad.thing == m && l1.role(ad.author, m, k) >= Role::Write
            })
        })
    })
}

/// Every check on one world; `seed` regenerates it under the omit rule for the comparison.
pub fn check(w: &World, omit: Option<&World>, st: &mut Stats, rng: &mut Rng) {
    st.worlds += 1;
    let e = w.ideal(PLAN);
    st.max_rounds = st.max_rounds.max(e.rounds);
    st.with_addenda += w.items.iter().any(|it| matches!(it.kind, Kind::Add { .. })) as u64;
    let before = st.cost.rescued;
    st.cost.add(w, PLAN);
    st.rescued_worlds += (st.cost.rescued > before) as u64;
    let fail = |st: &mut Stats, label: &'static str, bad: bool, ex: &World| {
        if bad && !st.ex.iter().any(|(l, _)| *l == label) {
            st.ex.push((label, ex.clone()));
        }
        bad
    };
    // One result for every input order.
    let p = w.permuted(rng);
    let ep = p.ideal(PLAN);
    if fail(st, "order dependence", p.ids(&ep.valid) != w.ids(&e.valid) || p.ids(&ep.visible) != w.ids(&e.visible), w) {
        st.order_dep += 1;
    }
    if fail(st, "non-monotone", nonmonotone(w, PLAN), w) {
        st.nonmonotone += 1;
    }
    {
        let l1 = L1::new(&w.roles, |_| true);
        let all = vec![true; w.items.len()];
        let c = Ctx::new(w, View { l1: &l1, hdr: &all, body: &all }, PLAN);
        if fail(st, "gfp differs", c.fixpoint(true).0 != e.valid, w) {
            st.gfp_differs += 1;
        }
    }
    // Bodies dropped and refetched.
    let s = w.simulate(PLAN, None);
    if fail(st, "nodes disagree", !s.agree, w) {
        st.disagree += 1;
    }
    if fail(st, "bodies gain", !subset(&s.visible, &e.visible) || !subset(&s.valid, &e.valid), w) {
        st.sim_gains += 1;
    }
    if s.visible != e.visible {
        let base = w.ideal_base();
        let lost: Vec<usize> = (0..w.items.len()).filter(|&c| e.visible[c] && !s.visible[c]).collect();
        st.sim_lost += 1;
        st.sim_lost_ids += lost.len() as u64;
        let by_addenda = lost.iter().filter(|&&c| !base[c]).count() as u64;
        st.sim_lost_addenda += by_addenda;
        if by_addenda > 0 {
            fail(st, "body loss (rescued by addenda)", true, w);
        } else {
            fail(st, "body loss", true, w);
        }
    }
    {
        let ho = Rules { held_only: true, ..PLAN };
        let (eh, sh) = (w.ideal(ho), w.simulate(ho, None));
        st.held_only_differs += (eh.visible != e.visible) as u64;
        let base = w.ideal_base();
        let n = (0..w.items.len()).filter(|&c| eh.visible[c] && !sh.visible[c] && !base[c]).count() as u64;
        st.held_only_lost_addenda += n;
        fail(st, "held-only addenda loss", n > 0, w);
    }
    {
        let kl = Rules { keep_listed: true, ..PLAN };
        let sk = w.simulate(kl, None);
        let base = w.ideal_base();
        let n = (0..w.items.len()).filter(|&c| e.visible[c] && !sk.visible[c] && !base[c]).count() as u64;
        st.keep_listed_lost_addenda += n;
        st.keep_listed_lost += (0..w.items.len()).filter(|&c| e.visible[c] && !sk.visible[c]).count() as u64;
        fail(st, "keep-listed addenda loss", n > 0, w);
        let both = Rules { keep_listed: true, held_only: true, ..PLAN };
        let (eb, sb) = (w.ideal(both), w.simulate(both, None));
        let n = (0..w.items.len()).filter(|&c| eb.visible[c] && !sb.visible[c] && !base[c]).count() as u64;
        st.both_lost_addenda += n;
        fail(st, "both addenda loss", n > 0, w);
    }
    let s2 = w.simulate(PLAN, Some(rng));
    st.shuffle_differs += (s2.visible != s.visible) as u64;
    // Re-removal variants.
    let en = w.ideal(Rules { rerem: Rerem::Newest, ..PLAN });
    let ea = w.ideal(Rules { rerem: Rerem::AnyAddenda, ..PLAN });
    st.newest_vs_any_addenda += (ea.valid != en.valid) as u64;
    fail(st, "re-removal variants differ", ea.valid != en.valid, w);
    st.newest_vs_any += (e.valid != en.valid) as u64;
    let el = w.ideal(Rules { rerem: Rerem::Later, ..PLAN });
    st.later_vs_any += (e.valid != el.valid) as u64;
    if fail(st, "variants not nested", !subset(&en.valid, &ea.valid) || !subset(&ea.valid, &e.valid) || !subset(&el.valid, &e.valid), w) {
        st.variant_order += 1;
    }
    // Attacks, under every variant.
    let nn = w.roles.nodes;
    let att: Vec<usize> = if rng.below(2) == 0 { vec![rng.below(nn)] } else { vec![rng.below(nn), rng.below(nn)] };
    let f = w.forge(rng, &att);
    for rerem in [Rerem::Newest, Rerem::AnyAddenda, Rerem::Any, Rerem::Later] {
        let rules = Rules { rerem, ..PLAN };
        if fail(st, "attack gain", attack_gains(w, &f, rules), &f) {
            st.attack_gain += 1;
            break;
        }
    }
    if let Some(o) = omit {
        let om = Rules { omit_covered: true, ..PLAN };
        st.cost_omit.add(o, om);
        let eo = o.ideal(om);
        let (vi, vo) = (w.ids(&e.visible), o.ids(&eo.visible));
        st.omit_loses += vi.iter().any(|id| !vo.contains(id)) as u64;
        fail(st, "omit loses (omit world)", vi.iter().any(|id| !vo.contains(id)), o);
        st.omit_gains += vo.iter().any(|id| !vi.contains(id)) as u64;
    }
}

pub fn random(samples: u64, seed: u64) -> Stats {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    let stats: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut rng = Rng(seed ^ (th + 1).wrapping_mul(0x9E3779B97F4A7C15));
                    let mut st = Stats::default();
                    for _ in 0..samples / threads {
                        let s0 = rng.next();
                        let w = random_world(&mut Rng(s0), PLAN);
                        let o = random_world(&mut Rng(s0), Rules { omit_covered: true, ..PLAN });
                        check(&w, Some(&o), &mut st, &mut rng);
                    }
                    st
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for s in stats {
        all.merge(s);
    }
    all
}

// ---------- cost sweep ----------

/// Cost at sizes the random worlds do not reach: one thing, Alice (first admin) removes Bob
/// at t=10; `writers` other writers; Bob's `m` commits before it, each received by each node
/// with probability 1/2 (Alice's frontier and each writer's receipts). Prints, per removal,
/// frontier IDs, addenda, listed IDs and duplicate copies (listed more than once, or by
/// more addenda than one), averaged over `samples`.
pub fn cost_sweep(samples: u64) {
    for writers in [1usize, 3, 10, 30] {
        for m in [1usize, 10, 100] {
            let nn = writers + 2;
            let mut rng = Rng(0xc057 ^ (writers * 1000 + m) as u64);
            let mut c = Cost::default();
            for _ in 0..samples {
                let mut genesis = vec![vec![Role::Write]; nn + 1];
                genesis[0][0] = Role::Admin;
                genesis[nn][0] = Role::None;
                let roles = JHist { nodes: nn, admins: vec![0], genesis, writes: vec![joint::JWrite { author: 0, t: 10, id: 1, target: 0, holder: 1, role: Role::None }], recv: vec![(0..nn).map(|v| if v == 0 { 10 } else { 11 }).collect()] };
                let items = (0..m).map(|k| Item { kind: Kind::Plain, author: 1, t: 1 + (k % 8) as u32, id: 10 + k as u32, thing: 0, acting: Option::None, recv: (0..nn).map(|v| if v == 1 { 1 + (k % 8) as u32 } else if rng.below(2) == 0 { LATE } else { 9 }).collect(), forged: false }).collect();
                let mut w = World { roles, items, frontier: HashMap::new() };
                let mut ids: HashSet<u32> = (0..1000).collect();
                w.derive(&mut rng, PLAN, &[], &mut ids, Option::None);
                c.add(&w, PLAN);
            }
            let r = c.removals.max(1) as f64;
            println!("  writers {writers:>2}, Bob's commits {m:>3}: frontier {:>6.1} IDs | addenda {:>5.1} | listed {:>7.1} IDs, of which duplicate copies {:>7.1} | rescued {:>6.1}", c.frontier as f64 / r, c.addenda as f64 / r, c.listed as f64 / r, c.dup as f64 / r, c.rescued as f64 / r);
        }
    }
}

// ---------- exhaustive ----------

/// The small family, every combination: thing A0 (first admin n0 = Alice), n1 Bob and n2
/// Carol writers, n3 Dave a writer or a reader. Up to three role writes by Alice at t=3, 6,
/// 9, each one of: remove Bob, remove Carol, remove Dave, re-grant Bob write; each received
/// by Carol and Dave at t+1 or never. Bob writes at t=1 or 4 and at 7 (or not), each
/// received by Alice, Carol, Dave at t+1 or never. Addenda: honest, received by everyone at
/// their t+1 or (a switch) never by Alice.
pub fn exhaustive_worlds(share: (usize, usize), mut f: impl FnMut(World)) {
    use Role::{Admin, None, Read, Write};
    let nn = 4;
    let menu: [(usize, Role); 4] = [(1, None), (2, None), (3, None), (1, Write)];
    let mut index = 0usize;
    for dave in [Read, Write] {
        for script in 0..5usize.pow(3) {
            for rmask in 0..(1u32 << 6) {
                let mut genesis = vec![vec![None]; nn + 1];
                genesis[0][0] = Admin;
                genesis[1][0] = Write;
                genesis[2][0] = Write;
                genesis[3][0] = dave;
                let mut roles = JHist { nodes: nn, admins: vec![0], genesis, writes: vec![], recv: vec![] };
                let mut s = script;
                let mut used = 0;
                for (slot, t) in [3u32, 6, 9].into_iter().enumerate() {
                    let pick = s % 5;
                    s /= 5;
                    if pick == 0 {
                        continue;
                    }
                    let (holder, role) = menu[pick - 1];
                    let bits = rmask >> (2 * slot);
                    let r = |b: u32| if bits >> b & 1 == 1 { LATE } else { t + 1 };
                    roles.writes.push(joint::JWrite { author: 0, t, id: 1000 + slot as u32, target: 0, holder, role });
                    roles.recv.push(vec![t, t + 1, r(0), r(1)]);
                    used |= 3 << (2 * slot);
                }
                if rmask & !used != 0 {
                    continue;
                }
                for bob in 0..(2 * 8 * 9) {
                    for alice_sees in [true, false] {
                        index += 1;
                        if index % share.1 != share.0 {
                            continue;
                        }
                        let (t1, rest) = ([1u32, 4][bob % 2], bob / 2);
                        let (r1, second) = (rest % 8, rest / 8);
                        let row = |t: u32, m: usize| -> Vec<u32> { vec![if m & 1 == 1 { t + 1 } else { LATE }, t, if m & 2 == 2 { t + 1 } else { LATE }, if m & 4 == 4 { t + 1 } else { LATE }] };
                        let mut items = vec![Item { kind: Kind::Plain, author: 1, t: t1, id: 1, thing: 0, acting: Option::None, recv: row(t1, r1), forged: false }];
                        if second > 0 {
                            items.push(Item { kind: Kind::Plain, author: 1, t: 7, id: 2, thing: 0, acting: Option::None, recv: row(7, second - 1), forged: false });
                        }
                        let mut w = World { roles: roles.clone(), items, frontier: HashMap::new() };
                        let mut ids: HashSet<u32> = (0..2000).collect();
                        let add_recv = |a: usize, t: u32| -> Vec<u32> { (0..nn).map(|v| if v == a { t } else if v == 0 && !alice_sees { LATE } else { t + 1 }).collect() };
                        w.derive(&mut Rng(1), PLAN, &[], &mut ids, Some(&add_recv));
                        f(w);
                    }
                }
            }
        }
    }
}

pub fn exhaustive() -> Stats {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let stats: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut rng = Rng(0x5eed ^ (th as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
                    let mut st = Stats::default();
                    exhaustive_worlds((th, threads), |w| check(&w, None, &mut st, &mut rng));
                    st
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for s in stats {
        all.merge(s);
    }
    all
}

// ---------- scenarios ----------

#[cfg(test)]
mod tests {
    use super::*;
    use Role::{Admin, None, Read, Write};

    /// Nodes: n0 Alice (first admin of A0 and A1), n1 Bob, n2 Carol, n3 Dave (writers on A0),
    /// n4 Eve (reader). A1: Dave writes there, nobody else.
    const NN: usize = 5;
    const ALICE: usize = 0;
    const BOB: usize = 1;
    const CAROL: usize = 2;
    const DAVE: usize = 3;
    const EVE: usize = 4;

    struct B {
        w: World,
        next: u32,
    }

    impl B {
        fn new() -> B {
            let mut genesis = vec![vec![None; 2]; NN + 2];
            genesis[ALICE] = vec![Admin, Admin];
            genesis[BOB][0] = Write;
            genesis[CAROL][0] = Write;
            genesis[DAVE] = vec![Write, Write];
            genesis[EVE][0] = Read;
            let roles = JHist { nodes: NN, admins: vec![ALICE, ALICE], genesis, writes: vec![], recv: vec![] };
            B { w: World { roles, items: vec![], frontier: HashMap::new() }, next: 100 }
        }
        fn row(author: usize, t: u32, recv: &[(usize, u32)]) -> Vec<u32> {
            let mut r = vec![LATE; NN];
            r[author] = t;
            for &(n, tn) in recv {
                r[n] = tn;
            }
            r
        }
        /// Alice sets `holder`'s role on A0 at t, everyone receiving it at t+1.
        fn set(&mut self, holder: usize, role: Role, t: u32) -> u32 {
            self.next += 1;
            self.w.roles.writes.push(joint::JWrite { author: ALICE, t, id: self.next, target: 0, holder, role });
            self.w.roles.recv.push(vec![t + 1; NN].into_iter().enumerate().map(|(n, r)| if n == ALICE { t } else { r }).collect());
            self.next
        }
        fn item(&mut self, kind: Kind, author: usize, t: u32, recv: &[(usize, u32)]) -> u32 {
            self.next += 1;
            self.w.items.push(Item { kind, author, t, id: self.next, thing: 0, acting: Option::None, recv: Self::row(author, t, recv), forged: false });
            self.next
        }
        fn write(&mut self, author: usize, t: u32, recv: &[(usize, u32)]) -> u32 {
            self.item(Kind::Plain, author, t, recv)
        }
        /// Honest frontiers and addenda; addenda reach everyone at t+1 but `unseen` nodes.
        fn derive(mut self, unseen: &[usize]) -> World {
            let mut ids: HashSet<u32> = (0..1000).collect();
            let add_recv = |a: usize, t: u32| -> Vec<u32> { (0..NN).map(|v| if v == a { t } else if unseen.contains(&v) { LATE } else { t + 1 }).collect() };
            self.w.derive(&mut Rng(7), PLAN, &[], &mut ids, Some(&add_recv));
            self.w
        }
    }

    fn valid(w: &World, id: u32) -> bool {
        let e = w.ideal(PLAN);
        let i = w.items.iter().position(|it| it.id == id).unwrap();
        let s = w.simulate(PLAN, Option::None);
        assert!(s.agree);
        assert_eq!(s.visible[i], e.visible[i], "bodies dropped and refetched read like the ideal");
        e.valid[i]
    }

    fn addenda(w: &World) -> Vec<&Item> {
        w.items.iter().filter(|it| matches!(it.kind, Kind::Add { .. })).collect()
    }

    /// Alice removes Bob without having synced: his edits return iff a writer (Carol) received
    /// them before the removal; a reader's receipt (Eve) counts for nothing.
    #[test]
    fn unsynced_removal_witnessed_by_carol() {
        for carol_saw in [true, false] {
            let mut b = B::new();
            let e1 = b.write(BOB, 2, &[(EVE, 3), (CAROL, 3)].into_iter().filter(|&(n, _)| carol_saw || n != CAROL).collect::<Vec<_>>());
            let e2 = b.write(BOB, 3, if carol_saw { &[(CAROL, 4)] } else { &[] });
            b.set(BOB, None, 5);
            let w = b.derive(&[]);
            assert_eq!(addenda(&w).len(), carol_saw as usize);
            assert_eq!((valid(&w, e1), valid(&w, e2)), (carol_saw, carol_saw), "carol saw {carol_saw}");
        }
    }

    /// Carol and Dave both saw Bob's edit and both vouch (no coordination). Dave's later
    /// removal by Alice, who never received his addendum, voids Dave's; Carol's still
    /// covers. Without Carol's, the edit falls with Dave's addendum unless a writer that
    /// received Dave's addendum in time (Carol) vouches for it in turn.
    #[test]
    fn coverage_falls_and_recovers() {
        let mut b = B::new();
        let e = b.write(BOB, 2, &[(CAROL, 3), (DAVE, 3)]);
        b.set(BOB, None, 5);
        b.set(DAVE, None, 9);
        let w = b.derive(&[ALICE]);
        // Carol's and Dave's to Bob's removal, Carol's to Dave's (listing Dave's addendum).
        assert_eq!(addenda(&w).len(), 3);
        assert!(valid(&w, e));
        // Carol's addendum to Bob's removal withdrawn: the edit now rests on Dave's, which
        // Carol's addendum to Dave's removal restores.
        let carols: Vec<usize> = (0..w.items.len()).filter(|&i| w.items[i].author == CAROL).collect();
        assert_eq!(carols.len(), 2);
        let to_bob = carols.iter().copied().find(|&i| matches!(&w.items[i].kind, Kind::Add { lists, .. } if lists.contains(&e))).unwrap();
        let w2 = w.without(to_bob);
        assert!(valid(&w2, e));
        let w3 = w2.without(w2.items.iter().position(|it| it.author == CAROL).unwrap());
        assert!(!valid(&w3, e));
    }

    /// An edit no writer saw stays invalid; re-grant restores everything, the gap included.
    #[test]
    fn unseen_stays_lost_regrant_restores() {
        let mut b = B::new();
        let e1 = b.write(BOB, 2, &[(EVE, 3)]);
        b.set(BOB, None, 5);
        let e2 = b.write(BOB, 6, &[(CAROL, 7)]);
        let w = b.derive(&[]);
        assert!(addenda(&w).is_empty());
        assert!(!valid(&w, e1) && !valid(&w, e2));
        let mut b = B { w: w.clone(), next: 500 };
        b.set(BOB, Write, 12);
        let w = b.w;
        assert!(w.ideal(PLAN).valid.iter().all(|v| *v));
    }

    fn forged(w: &World, author: usize, t: u32, removal: u32, lists: Vec<u32>) -> World {
        let mut w = w.clone();
        w.items.push(Item { kind: Kind::Add { removal, lists }, author, t, id: 900 + w.items.len() as u32, thing: 0, acting: Option::None, recv: B::row(author, t, &[]), forged: true });
        w
    }

    /// Readers, removed writers (backdated or not, alone or vouching for each other) and
    /// addenda listing special or later commits, or a role commit, gain nothing; a writer's
    /// addendum does, while its author keeps write, whatever receipt time it claims.
    #[test]
    fn attacks() {
        let mut b = B::new();
        let e = b.write(BOB, 2, &[]);
        let sp = b.item(Kind::Special, BOB, 3, &[]);
        let rb = b.set(BOB, None, 5);
        let late = b.write(BOB, 6, &[]);
        let ed = b.write(DAVE, 4, &[]);
        let rd = b.set(DAVE, None, 7);
        let w = b.derive(&[]);
        assert!(addenda(&w).is_empty());
        let base = w.ideal(PLAN).valid;
        let same = |f: &World| f.ideal(PLAN).valid[..w.items.len()] == base[..];
        assert!(same(&forged(&w, EVE, 6, rb, vec![e])), "reader");
        assert!(same(&forged(&w, CAROL, 6, rb, vec![sp, rb])), "special commit and a role commit");
        assert!(same(&forged(&w, CAROL, 6, rb, vec![late])), "commit after the removal");
        assert!(same(&forged(&w, BOB, 4, rb, vec![e])), "backdated before its own removal");
        assert!(same(&forged(&w, BOB, 6, rb, vec![e])), "removed writer");
        let mutual = forged(&forged(&w, BOB, 8, rd, vec![ed]), DAVE, 8, rb, vec![e]);
        assert!(same(&mutual), "two removed writers vouching for each other");
        // Dave vouching for Bob between the two removals: Dave's own write power then, which
        // falls with Dave's addendum when Alice's removal of Dave does not list it.
        let dave_between = forged(&w, DAVE, 6, rb, vec![e]);
        assert!(same(&dave_between));
        // Carol, a writer throughout, may claim any receipt time: her own write power.
        let carol = forged(&w, CAROL, 6, rb, vec![e]);
        let v = carol.ideal(PLAN).valid;
        assert!(v[w.items.iter().position(|it| it.id == e).unwrap()]);
    }

    /// Acting (rule 3): Bob's commit on A0 acting for A1, Bob removed from both: its part on A0
    /// needs a witness on A0 and its acting check one on A1 (Dave writes on both; Carol only on
    /// A0, so hers alone leaves it invalid).
    #[test]
    fn acting_needs_a_witness_on_the_actor() {
        for witness in [CAROL, DAVE] {
            let mut b = B::new();
            b.w.roles.genesis[BOB][1] = Write;
            let e = b.write(BOB, 2, &[(witness, 3)]);
            b.w.items[0].acting = Some(1);
            b.set(BOB, None, 5);
            b.next += 1;
            b.w.roles.writes.push(joint::JWrite { author: ALICE, t: 5, id: b.next, target: 1, holder: BOB, role: None });
            b.w.roles.recv.push(vec![5, 6, 6, 6, 6]);
            let w = b.derive(&[]);
            let honest = addenda(&w).len();
            assert_eq!(honest, if witness == DAVE { 2 } else { 1 }, "an honest witness answers on each thing it writes on");
            assert_eq!(valid(&w, e), witness == DAVE, "witness n{witness}: the acting check needs a witness on A1");
        }
    }

    /// The joint walk's replay (`steps`) ends in the walk's own roles.
    #[test]
    fn steps_follow_the_walk() {
        let mut rng = Rng(11);
        for _ in 0..2000 {
            let h = joint::random_hist(&mut rng);
            let s = h.steps();
            assert_eq!(s.after.last().map_or(&s.genesis, |a| &a.1), &joint::walk(&h).roles);
        }
    }

    /// The random search finds no failure (counters in `Stats::failures`).
    #[test]
    fn random_search_holds() {
        let st = random(1600, 0xadd);
        assert!(st.with_addenda > 0);
        assert_eq!(st.failures(), 0);
    }
}
