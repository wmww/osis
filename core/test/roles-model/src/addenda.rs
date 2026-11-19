//! Addenda (spec/permissions.md §5.2, Addenda; notes/addenda.md): layer 2 over the
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
//! - A's author holds write on m at A's key (rules 1 and 3: readers and nodes keeping it unread hold no
//!   write; a commit's acting check is its part on its header actor, vouched for there by a
//!   writer of that actor, as the removal's frontier lists it there);
//! - the listed commit is plain content, no compaction snapshot (rule 4; `Kind::Special` stands for role-class,
//!   admin-only and purge writes; role commits are not items at all).
//!
//! Validity is the least fixpoint of that rule seeded by the writes valid without addenda
//! (`Ctx::fixpoint`). A valid compaction snapshot (`Kind::Snap`) keeps what it carries
//! visible (§5.2), and is itself a plain write of its author.
//!
//! S3 brief 3 (`Gaps`, off by default): admin-only content (`Kind::AdminOnly`, judged with admin
//! against demotions below admin) listable by a witness holding admin; a witness lacking the role
//! as it applies the removal writes when it first holds it after. Checks `check_gaps`, search
//! `addenda-gaps` (README.md, Addenda gaps).
//!
//! On a re-removal every removal's frontier counts, whatever the order, and addenda naming any
//! later removal. Variant: `Cover` (which covered commits a removal's frontier and addenda leave
//! out, against listing every commit).
//!
//! Bodies (`Sim`): every node drops an invalid body at once and fetches a valid one it lacks
//! from any node holding it; a body nobody holds stays lost. An addendum's list is its body.
//!
//! Search: `roles-model -- N addenda` (random) and `addenda-exh` (exhaustive small family).
//! Results: notes/addenda.md, Addenda model.

use crate::joint::{self, JHist};
use crate::shrink::LATE;
use crate::{Rng, Role};
use std::collections::{HashMap, HashSet};

/// Timeline key: (ts, author node, commit ID), shared by role writes and items.
pub type Key = (u32, usize, u32);

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Plain,
    /// A delta on an admin-only aspect that is not role-class (a setting, §5.2): judged with
    /// admin in place of write, against demotions below admin; listable by addenda only under
    /// `Gaps::admin_only`.
    AdminOnly,
    /// Role-class, admin-only or purge write: judged like content, never listable (rule 4).
    Special,
    /// Compaction snapshot carrying these content items (IDs) of its thing.
    Snap(Vec<u32>),
    /// Addendum naming a removal (role write ID) and listing commit IDs.
    Add { removal: u32, lists: Vec<u32> },
    /// `forget`, candidate B: the remover's snapshot its removal names, carrying these content
    /// items; it stands while that removal (role write ID) applies, else as its author's write.
    RemSnap { removal: u32, carries: Vec<u32> },
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

impl Kind {
    /// The content items a snapshot carries (none for other kinds).
    pub fn carries(&self) -> &[u32] {
        match self {
            Kind::Snap(cs) | Kind::RemSnap { carries: cs, .. } => cs,
            _ => &[],
        }
    }
}

impl Item {
    pub fn key(&self) -> Key {
        (self.t, self.author, self.id)
    }
    /// Where layer 2 judges it (spec/permissions.md §5.2, Position): before every role write at
    /// its `ts`, at or after every one before it. No role write's key is below it at its `ts`, so
    /// "a role write after it" reads `>=` and "before it" `<`.
    pub fn pos(&self) -> Key {
        (self.t, 0, 0)
    }
    /// Plain content commits and addenda (rule 4): no role-class, admin-only or purge write;
    /// a compaction snapshot only where the cover rule lets addenda name one
    /// (spec/permissions.md §5.2, Addenda); admin-only content under `Gaps::admin_only`.
    fn listable(&self, rules: Cover, gaps: Gaps) -> bool {
        matches!(self.kind, Kind::Plain | Kind::Add { .. }) || matches!(self.kind, Kind::Snap(_)) && rules != Cover::ListAll || self.kind == Kind::AdminOnly && gaps.admin_only
    }
    fn content(&self) -> bool {
        matches!(self.kind, Kind::Plain | Kind::Special | Kind::AdminOnly)
    }
    /// The role its writes need.
    pub fn level(&self) -> Role {
        if self.kind == Kind::AdminOnly {
            Role::Admin
        } else {
            Role::Write
        }
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

/// Which of the leaver's commits a lister (a demoter's frontier, a witness's addendum) leaves
/// out as covered by a snapshot it holds valid, the commits listed otherwise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cover {
    /// Every commit received, covered or not.
    ListAll,
    /// Leaves out a commit a snapshot by another writer covers; one covered only by the
    /// leaver's own snapshot is left out when the list saves that snapshot (lists it; an
    /// addendum only one ordered before the removal), as addenda may list snapshots.
    OmitOthers,
    /// Leaves out only a commit the leaver's own snapshot covers, where the list saves that
    /// snapshot (as above); another writer's cover saves nothing.
    OmitOwn,
}

/// The plan as decided for the model.
pub const PLAN: Cover = Cover::ListAll;

/// S3 brief 3's rules (notes/redesign-plan.md S3; notes/account-membership-design.md §4,
/// Addenda reach admin-only content and Writing). Both off is today's rule (osis-perm's
/// differential compares against that).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gaps {
    /// An addendum by a witness holding admin at its key vouches for the leaver's admin-only
    /// content that is not role-class, against a demotion below admin.
    pub admin_only: bool,
    /// A witness lacking the role when it applies the removal writes its addendum when it first
    /// holds it after (re-granted); else it writes none.
    pub rewrite: bool,
}

pub const GAPS: Gaps = Gaps { admin_only: true, rewrite: true };

/// The cover rules compared with listing every commit (`check`).
pub const COVERS: [(&str, Cover); 2] = [("omit others' covers", Cover::OmitOthers), ("omit own covers", Cover::OmitOwn)];

#[derive(Clone)]
pub struct World {
    pub roles: JHist,
    pub items: Vec<Item>,
    /// Role write ID -> the item IDs its author had received before its `ts`.
    pub frontier: HashMap<u32, HashSet<u32>>,
    pub gaps: Gaps,
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
    /// Explicit demotions below admin.
    pub dems_admin: Vec<Dem>,
}

impl L1 {
    /// The settled joint walk over the role writes `keep` selects.
    pub fn new(h: &JHist, keep: impl Fn(usize) -> bool) -> L1 {
        let idx: Vec<usize> = (0..h.writes.len()).filter(|&i| keep(i)).collect();
        let sub = JHist { nodes: h.nodes, admins: h.admins.clone(), genesis: h.genesis.clone(), writes: idx.iter().map(|&i| h.writes[i].clone()).collect(), recv: idx.iter().map(|&i| h.recv[i].clone()).collect() };
        let s = sub.steps();
        let wkey = |i: usize| (sub.writes[i].t, sub.writes[i].author, sub.writes[i].id);
        let mut l = L1 { keys: vec![], states: vec![s.genesis], dems: vec![], dems_admin: vec![] };
        for (i, r) in s.after {
            l.keys.push(wkey(i));
            l.states.push(r);
        }
        let dem = |&(i, x, n): &(usize, usize, usize)| Dem { rid: sub.writes[i].id, key: wkey(i), author: sub.writes[i].author, victim: x, thing: n };
        l.dems = s.demotions.iter().map(dem).collect();
        l.dems_admin = s.demotions_admin.iter().map(dem).collect();
        l
    }
    /// The explicit demotions below `level`.
    pub fn dems_below(&self, level: Role) -> &[Dem] {
        if level == Role::Admin {
            &self.dems_admin
        } else {
            &self.dems
        }
    }
    /// The first key at or after `key` where x holds `level` on n, if any.
    fn first_held(&self, n: usize, x: usize, key: Key, level: Role) -> Option<Key> {
        let at = self.at(key);
        if self.states[at][n][x] >= level {
            return Some(key);
        }
        (at..self.keys.len()).find(|&i| self.states[i + 1][n][x] >= level).map(|i| self.keys[i])
    }
    fn at(&self, key: Key) -> usize {
        self.keys.partition_point(|k| *k < key)
    }
    /// The role write with this ID is applied in the settled walk.
    pub fn applied(&self, rid: u32) -> bool {
        self.keys.iter().any(|k| k.2 == rid)
    }
    pub fn role(&self, n: usize, x: usize, key: Key) -> Role {
        self.states[self.at(key)][n][x]
    }
    /// §5.2 re-grant: `level` in the final state, and the key at or after the first point n
    /// ever held it on x.
    fn regrant(&self, n: usize, x: usize, key: Key, level: Role) -> bool {
        self.states.last().map_or(false, |s| s[n][x] >= level) && self.states.iter().position(|s| s[n][x] >= level).map_or(false, |p| p <= self.at(key))
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
    rules: Cover,
    /// (removal, thing) -> held addenda with bodies: (item, listed IDs).
    adds: HashMap<(u32, usize), Vec<(usize, HashSet<u32>)>>,
}

impl<'a> Ctx<'a> {
    pub fn new(w: &'a World, v: View<'a>, rules: Cover) -> Self {
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
        let k = ad.pos();
        d.key < k && self.w.items[c].pos() <= d.key && l1.role(ad.author, m, k) >= self.w.items[c].level()
    }

    /// Whether item c's part on thing m is valid, given which items are valid (`valid`).
    pub fn part_ok(&self, c: usize, m: usize, valid: &[bool]) -> bool {
        let it = &self.w.items[c];
        let (x, key, l1) = (it.author, it.pos(), self.v.l1);
        // the demoter's own cover its removal names (spec/permissions.md §5.1, Own cover):
        // made while its author held write, ordered no later than the removal, it stands while
        // that removal applies as a demotion on its thing; else it is judged as its author's
        // snapshot
        if let Kind::RemSnap { removal, .. } = &it.kind {
            if l1.role(x, m, key) >= Role::Write && l1.dems.iter().any(|d| d.rid == *removal && d.thing == m && d.author == x && key <= d.key) {
                return true;
            }
        }
        let level = it.level();
        if l1.regrant(x, m, key, level) {
            return true;
        }
        let dems: Vec<&Dem> = l1.dems_below(level).iter().filter(|d| d.victim == x && d.thing == m).collect();
        let held = l1.role(x, m, key) >= level;
        if held && !dems.iter().any(|d| d.key >= key) {
            return true;
        }
        // a frontier is what its demoter had received: it saves what it lists whatever the order
        if dems.iter().any(|d| self.w.frontier.get(&d.rid).map_or(false, |f| f.contains(&it.id))) {
            return true;
        }
        if !it.listable(self.rules, self.w.gaps) {
            return false;
        }
        dems.iter().filter(|d| d.key >= key).any(|d| self.adds.get(&(d.rid, m)).map_or(false, |v| v.iter().any(|(a, l)| valid[*a] && l.contains(&it.id) && self.vouches(*a, c, m, d))))
    }

    fn step(&self, valid: &[bool]) -> Vec<bool> {
        (0..self.w.items.len()).map(|c| self.v.hdr[c] && self.w.items[c].parts().all(|m| self.part_ok(c, m, valid))).collect()
    }

    /// The least fixpoint from the writes valid without addenda.
    pub fn fixpoint(&self) -> (Vec<bool>, usize) {
        let mut valid = vec![false; self.w.items.len()];
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
        let (valid, rounds) = self.fixpoint();
        let w = self.w;
        let held = |i: usize| self.v.hdr[i] && self.v.body[i] && valid[i];
        let visible = (0..w.items.len())
            .map(|c| {
                let it = &w.items[c];
                it.content() && (held(c) || w.items.iter().enumerate().any(|(s, si)| si.thing == it.thing && si.kind.carries().contains(&it.id) && held(s)))
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
    pub fn ideal(&self, rules: Cover) -> Eval {
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
    fn view_at(&self, v: usize, tau: u32, rules: Cover) -> (L1, Eval) {
        let r = &self.roles;
        let l1 = L1::new(r, |i| r.recv[i][v] < LATE && r.recv[i][v].max(r.writes[i].t) < tau);
        let hdr: Vec<bool> = self.items.iter().map(|it| it.held(v, tau)).collect();
        let e = Ctx::new(self, View { l1: &l1, hdr: &hdr, body: &hdr }, rules).eval();
        (l1, e)
    }

    /// The commits a list by node v before `tau` leaves out (`Cover`): those a snapshot v holds
    /// valid carries, by another writer than the commit's author (`OmitOthers`) or by the
    /// author itself where `saves` says the list saves that snapshot.
    fn omitted(&self, v: usize, tau: u32, rules: Cover, saves: impl Fn(&Item) -> bool) -> HashSet<u32> {
        let mut out = HashSet::new();
        if rules == Cover::ListAll {
            return out;
        }
        let (_, e) = self.view_at(v, tau, rules);
        for (s, it) in self.items.iter().enumerate() {
            let Kind::Snap(cs) = &it.kind else { continue };
            if !e.valid[s] || !it.held(v, tau) {
                continue;
            }
            for c in self.items.iter().filter(|c| cs.contains(&c.id)) {
                let own = c.author == it.author;
                if own && saves(it) || !own && rules == Cover::OmitOthers {
                    out.insert(c.id);
                }
            }
        }
        out
    }

    /// Honest frontiers, snapshots and addenda, written in time order, each from its author's
    /// view at the time. Every random draw is made whatever the rules decide, so worlds
    /// generated from one seed under different rules share their base.
    /// `add_recv`: receipts of addenda (author, t), else random.
    fn derive(&mut self, rng: &mut Rng, rules: Cover, snaps: &[(usize, u32, usize)], ids: &mut HashSet<u32>, add_recv: Option<&dyn Fn(usize, u32) -> Vec<u32>>) {
        let g = L1::new(&self.roles, |_| true);
        let nn = self.nodes();
        enum Trig {
            Front(usize),
            Snap(usize, u32, usize),
            Add(usize, usize, Role),
        }
        let mut trig: Vec<(u32, u8, usize, Trig)> = vec![];
        for (i, w) in self.roles.writes.iter().enumerate() {
            trig.push((w.t, 0, i, Trig::Front(i)));
        }
        for (k, &(s, ts, m)) in snaps.iter().enumerate() {
            trig.push((ts, 1, k, Trig::Snap(s, ts, m)));
        }
        let levels: &[Role] = if self.gaps.admin_only { &[Role::Write, Role::Admin] } else { &[Role::Write] };
        for (li, &level) in levels.iter().enumerate() {
            for (k, d) in g.dems_below(level).iter().enumerate() {
                let ri = self.roles.writes.iter().position(|w| w.id == d.rid).unwrap();
                for w in (0..nn).filter(|&w| w != d.victim && w != d.author && self.roles.recv[ri][w] < LATE) {
                    trig.push((self.roles.recv[ri][w].max(d.key.0) + 1, 2 + li as u8, k * nn + w, Trig::Add(k, w, level)));
                }
            }
        }
        trig.sort_by_key(|t| (t.0, t.1, t.2));
        for (time, _, _, tr) in trig {
            match tr {
                Trig::Front(i) => {
                    let wr = &self.roles.writes[i];
                    // a frontier lists every held snapshot: it saves the leaver's own
                    let covered = self.omitted(wr.author, wr.t, rules, |_| true);
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
                Trig::Add(k, w, level) => {
                    let d = &g.dems_below(level)[k];
                    let id = fresh(rng, ids);
                    let mut recv = recv_row(rng, nn, w, time, false);
                    // lacking the role as it applies the removal, a witness writes when it first
                    // holds it after (`Gaps::rewrite`), else never
                    let time = match g.first_held(w, d.thing, (time, 0, 0), level) {
                        Some(k2) if k2 == (time, 0, 0) => time,
                        Some(k2) if self.gaps.rewrite => {
                            let t2 = k2.0 + 1;
                            recv.iter_mut().filter(|r| **r < LATE).for_each(|r| *r += t2 - time);
                            t2
                        }
                        _ => continue,
                    };
                    if let Some(f) = add_recv {
                        recv = f(w, time);
                    }
                    let front = &self.frontier[&d.rid];
                    // an addendum saves the leaver's snapshot the frontier lists, or one it lists
                    // itself ordered before the removal
                    let covered = self.omitted(w, d.key.0, rules, |s| front.contains(&s.id) || s.author == d.victim && s.thing == d.thing && s.pos() <= d.key);
                    let lists: Vec<u32> = self
                        .items
                        .iter()
                        .filter(|c| c.author == d.victim && c.level() == level && c.listable(rules, self.gaps) && c.parts().any(|m| m == d.thing) && c.held(w, d.key.0) && !front.contains(&c.id) && !covered.contains(&c.id))
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
        World { roles, items: pi.iter().map(|&i| self.items[i].clone()).collect(), frontier: self.frontier.clone(), gaps: self.gaps }
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
pub fn random_world(rng: &mut Rng, rules: Cover) -> World {
    random_world_with(rng, rules, Gaps::default(), false)
}

/// `random_world` under `gaps`; with `admin_items` a third of the plain content is admin-only
/// instead (acting for nobody).
pub fn random_world_with(rng: &mut Rng, rules: Cover, gaps: Gaps, admin_items: bool) -> World {
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
        let mut acting = (rng.below(6) == 0).then(|| (thing + 1 + rng.below(na - 1)) % na);
        let mut kind = if rng.below(8) == 0 { Kind::Special } else { Kind::Plain };
        if admin_items && kind == Kind::Plain && rng.below(3) == 0 {
            (kind, acting) = (Kind::AdminOnly, Option::None);
        }
        let id = fresh(rng, &mut ids);
        let recv = recv_row(rng, nn, author, t, true);
        items.push(Item { kind, author, t, id, thing, acting, recv, forged: false });
    }
    let snaps: Vec<(usize, u32, usize)> = (0..rng.below(3)).map(|_| (rng.below(nn), 2 + rng.below(9) as u32, rng.below(na))).collect();
    let mut w = World { roles, items, frontier: HashMap::new(), gaps };
    w.derive(rng, rules, &snaps, &mut ids, None);
    // half the removals name their demoter's own cover of the thing, written at the removal's
    // `ts` from its view (spec/permissions.md §5.1, Own cover)
    for d in L1::new(&w.roles, |_| true).dems {
        if rng.below(2) != 0 || w.items.iter().any(|it| matches!(it.kind, Kind::RemSnap { removal, .. } if removal == d.rid)) {
            continue;
        }
        let (_, e) = w.view_at(d.author, d.key.0, rules);
        let carries: Vec<u32> = w.items.iter().enumerate().filter(|(c, it)| it.content() && it.thing == d.thing && e.visible[*c]).map(|(_, it)| it.id).collect();
        let id = fresh(rng, &mut ids);
        let recv = recv_row(rng, nn, d.author, d.key.0, false);
        w.items.push(Item { kind: Kind::RemSnap { removal: d.rid, carries }, author: d.author, t: d.key.0, id, thing: d.thing, acting: None, recv, forged: false });
        w.frontier.entry(d.rid).or_default().insert(id);
    }
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
    pub fn simulate(&self, rules: Cover, shuffle: Option<&mut Rng>) -> Sim {
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
                for i in 0..n {
                    if hdr[v][i] && !e.valid[i] && body[v][i] {
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
                Kind::AdminOnly => "admin-only".to_string(),
                Kind::Snap(c) => format!("snapshot carrying {c:?}"),
                Kind::Add { removal, lists } => format!("addendum to {removal} listing {lists:?}"),
                Kind::RemSnap { removal, carries } => format!("snapshot in removal {removal} carrying {carries:?}"),
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
    fn add(&mut self, w: &World, rules: Cover) {
        let l1 = L1::new(&w.roles, |_| true);
        let all = vec![true; w.items.len()];
        let ctx = Ctx::new(w, View { l1: &l1, hdr: &all, body: &all }, rules);
        let (valid, _) = ctx.fixpoint();
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

/// One cover rule (`COVERS`) against listing every commit, on the world generated from the
/// same seed under it.
#[derive(Default)]
pub struct CoverStats {
    /// Worlds where a write visible when listing everything is not (each must stay 0).
    pub loses: u64,
    /// Worlds where more is visible.
    pub gains: u64,
    /// Forged addenda gaining beyond the forger's write power, or an honest addendum's removal
    /// making more valid, under the variant (each must stay 0).
    pub attack_gain: u64,
    pub nonmonotone: u64,
    pub cost: Cost,
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
    /// Measured.
    pub sim_lost: u64,
    pub sim_lost_ids: u64,
    /// Of those, writes valid only through addenda (the rest are valid without them).
    pub sim_lost_addenda: u64,
    pub shuffle_differs: u64,
    pub cost: Cost,
    /// Per `COVERS` variant, against listing every commit.
    pub covers: [CoverStats; 2],
    pub ex: Vec<(&'static str, World)>,
}

impl crate::Tally for Stats {
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
        self.sim_lost += o.sim_lost;
        self.sim_lost_ids += o.sim_lost_ids;
        self.sim_lost_addenda += o.sim_lost_addenda;
        self.shuffle_differs += o.shuffle_differs;
        let [c0, c1] = o.covers;
        let mut costs = vec![(&mut self.cost, o.cost)];
        for (a, b) in self.covers.iter_mut().zip([c0, c1]) {
            a.loses += b.loses;
            a.gains += b.gains;
            a.attack_gain += b.attack_gain;
            a.nonmonotone += b.nonmonotone;
            costs.push((&mut a.cost, b.cost));
        }
        for (a, b) in costs {
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
}

impl Stats {

    pub fn failures(&self) -> u64 {
        self.order_dep + self.nonmonotone + self.disagree + self.sim_gains + self.attack_gain
    }

    /// Failures of cover variant `k` (`COVERS`).
    pub fn cover_failures(&self, k: usize) -> u64 {
        let c = &self.covers[k];
        c.loses + c.attack_gain + c.nonmonotone
    }

    pub fn print(&self) {
        println!(
            "addenda: {} worlds ({} with addenda, {} with a write rescued) | max fixpoint rounds {} | FAIL order-dependent {}, non-monotone {}, nodes disagreeing {}, bodies gaining over ideal {}, attack gains {}",
            self.worlds, self.with_addenda, self.rescued_worlds, self.max_rounds, self.order_dep, self.nonmonotone, self.disagree, self.sim_gains, self.attack_gain
        );
        println!(
            "  measured: drop-at-once loses visible writes in {} worlds ({} writes, {} valid only through addenda), shuffled arrival changes the result {}",
            self.sim_lost, self.sim_lost_ids, self.sim_lost_addenda, self.shuffle_differs
        );
        for ((name, _), c) in COVERS.iter().zip(&self.covers) {
            println!("  {name}: FAIL loses visible writes in {} worlds, attack gains {}, non-monotone {} | gains in {} worlds", c.loses, c.attack_gain, c.nonmonotone, c.gains);
        }
        self.cost.print("listing every commit");
        for ((name, _), c) in COVERS.iter().zip(&self.covers) {
            c.cost.print(name);
        }
        for (label, w) in &self.ex {
            let shrinkable = !matches!(*label, "attack gain" | "order dependence" | "bodies gain") && !label.starts_with("cover");
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
        _ => true,
    }
}

/// Removing one honest addendum turns some write valid (or visible).
fn nonmonotone(w: &World, rules: Cover) -> bool {
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
/// where a valid forged addendum on m has its author holding write (admin for admin-only
/// content) at its key: nothing beyond
/// the attacker's own write power on that thing (a part attributed to an actor is vouched for
/// on the actor by a writer of it, as a frontier lists it).
fn attack_gains(w: &World, f: &World, rules: Cover) -> bool {
    let l1 = L1::new(&w.roles, |_| true);
    let (a0, a1) = (vec![true; w.items.len()], vec![true; f.items.len()]);
    let c0 = Ctx::new(w, View { l1: &l1, hdr: &a0, body: &a0 }, rules);
    let c1 = Ctx::new(f, View { l1: &l1, hdr: &a1, body: &a1 }, rules);
    let (v0, _) = c0.fixpoint();
    let (v1, _) = c1.fixpoint();
    (0..w.items.len()).any(|c| {
        let it = &w.items[c];
        it.parts().any(|m| {
            if !c1.part_ok(c, m, &v1) || c0.part_ok(c, m, &v0) {
                return false;
            }
            if !it.listable(rules, w.gaps) {
                return true;
            }
            !(w.items.len()..f.items.len()).any(|a| {
                let ad = &f.items[a];
                let k = ad.pos();
                v1[a] && ad.thing == m && l1.role(ad.author, m, k) >= it.level()
            })
        })
    })
}

/// Every check on one world; `covers`: the same world generated under each `COVERS` rule.
pub fn check(w: &World, covers: Option<&[World; 2]>, st: &mut Stats, rng: &mut Rng) {
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
    let s2 = w.simulate(PLAN, Some(rng));
    st.shuffle_differs += (s2.visible != s.visible) as u64;
    // Attacks.
    let nn = w.roles.nodes;
    let att: Vec<usize> = if rng.below(2) == 0 { vec![rng.below(nn)] } else { vec![rng.below(nn), rng.below(nn)] };
    let f = w.forge(rng, &att);
    if fail(st, "attack gain", attack_gains(w, &f, PLAN), &f) {
        st.attack_gain += 1;
    }
    for (k, o) in covers.into_iter().flatten().enumerate() {
        let rules = COVERS[k].1;
        st.covers[k].cost.add(o, rules);
        let eo = o.ideal(rules);
        let (vi, vo) = (w.ids(&e.visible), o.ids(&eo.visible));
        let loses = vi.iter().any(|id| !vo.contains(id));
        st.covers[k].loses += loses as u64;
        fail(st, ["cover loses: omit others' covers", "cover loses: omit own covers"][k], loses, o);
        st.covers[k].gains += vo.iter().any(|id| !vi.contains(id)) as u64;
        let nm = nonmonotone(o, rules);
        st.covers[k].nonmonotone += nm as u64;
        fail(st, ["cover non-monotone: omit others' covers", "cover non-monotone: omit own covers"][k], nm, o);
        let f = o.forge(rng, &att);
        let ag = attack_gains(o, &f, rules);
        st.covers[k].attack_gain += ag as u64;
        fail(st, ["cover attack gain: omit others' covers", "cover attack gain: omit own covers"][k], ag, &f);
    }
}

pub fn random(samples: u64, seed: u64) -> Stats {
    crate::each_world(seed, 0..samples, |rng, st| {
        let s0 = rng.next();
        let w = random_world(&mut Rng(s0), PLAN);
        let o = COVERS.map(|(_, cover)| random_world(&mut Rng(s0), cover));
        check(&w, Some(&o), st, rng);
    })
}

// ---------- exhaustive ----------

/// The small family, every combination: thing A0 (mint admin n0 = Alice), n1 Bob and n2
/// Carol writers, n3 Dave a writer or a reader. Up to three role writes by Alice at t=3, 6,
/// 9, each one of: remove Bob, remove Carol, remove Dave, re-grant Bob write; each received
/// by Carol and Dave at t+1 or never. Bob writes at t=1 or 4 and at 7 (or not), each
/// received by Alice, Carol, Dave at t+1 or never. Addenda: honest, received by everyone at
/// their t+1 or (a switch) never by Alice.
///
/// With `gaps` (S3 brief 3's family): Bob is an admin, the menu's "remove Carol" is "grant Carol
/// admin" and "re-grant Bob write" demotes Bob to write, Bob's first write is admin-only content,
/// and the addenda follow `gaps`.
pub fn exhaustive_worlds(share: (usize, usize), gaps: Option<Gaps>, mut f: impl FnMut(World)) {
    use Role::{Admin, None, Read, Write};
    let nn = 4;
    let menu: [(usize, Role); 4] = if gaps.is_some() { [(1, None), (2, Admin), (3, None), (1, Write)] } else { [(1, None), (2, None), (3, None), (1, Write)] };
    let mut index = 0usize;
    for dave in [Read, Write] {
        for script in 0..5usize.pow(3) {
            for rmask in 0..(1u32 << 6) {
                let mut genesis = vec![vec![None]; nn + 1];
                genesis[0][0] = Admin;
                genesis[1][0] = if gaps.is_some() { Admin } else { Write };
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
                        let kind = if gaps.is_some() { Kind::AdminOnly } else { Kind::Plain };
                        let mut items = vec![Item { kind, author: 1, t: t1, id: 1, thing: 0, acting: Option::None, recv: row(t1, r1), forged: false }];
                        if second > 0 {
                            items.push(Item { kind: Kind::Plain, author: 1, t: 7, id: 2, thing: 0, acting: Option::None, recv: row(7, second - 1), forged: false });
                        }
                        let mut w = World { roles: roles.clone(), items, frontier: HashMap::new(), gaps: gaps.unwrap_or_default() };
                        let mut ids: HashSet<u32> = (0..2000).collect();
                        let add_recv = |a: usize, t: u32| -> Vec<u32> { (0..nn).map(|v| if v == a { t } else if v == 0 && !alice_sees { LATE } else { t + 1 }).collect() };
                        w.derive(&mut Rng(0), PLAN, &[], &mut ids, Some(&add_recv));
                        f(w);
                    }
                }
            }
        }
    }
}

/// The cover family, every combination, each world under every rule (`[PLAN, COVERS..]`):
/// thing A0, n0 Alice and n2 Carol admins, n1 Bob and n3 Dave writers. Bob writes c at t=1
/// or 3, received by each other node at t+1 or never. A snapshot carrying c at t=4 by any
/// node that received it, received by each other node at 5 or never. Alice removes Bob at 6,
/// received by each other node at 7 or never; then none, or the snapshot's author removed
/// by Carol at 5 or 7 or by Alice at 8 (not by itself), received by each other node at t+1 or
/// never. Addenda reach everyone at their t+1.
pub fn cover_worlds(share: (usize, usize), mut f: impl FnMut([World; 3])) {
    use Role::{Admin, None, Write};
    let nn = 4;
    let mut index = 0usize;
    let row = |author: usize, t: u32, at: u32, mask: usize| -> Vec<u32> {
        let mut k = 0;
        (0..nn)
            .map(|v| {
                if v == author {
                    return t;
                }
                k += 1;
                if mask >> (k - 1) & 1 == 1 { at } else { LATE }
            })
            .collect()
    };
    for t1 in [1u32, 3] {
        for cm in 0..8 {
            for sa in 0..nn {
                for sm in 0..8 {
                    for rm in 0..8 {
                        for (second, t2) in [(Option::None, 0u32), (Some(2usize), 5), (Some(2), 7), (Some(0), 8)] {
                            if second == Some(sa) {
                                continue;
                            }
                            for r2m in 0..if second.is_some() { 8 } else { 1 } {
                                index += 1;
                                if index % share.1 != share.0 {
                                    continue;
                                }
                                let c = Item { kind: Kind::Plain, author: 1, t: t1, id: 1, thing: 0, acting: Option::None, recv: row(1, t1, t1 + 1, cm), forged: false };
                                if !c.held(sa, 4) && sa != 1 {
                                    continue;
                                }
                                let snap = Item { kind: Kind::Snap(vec![1]), author: sa, t: 4, id: 2, thing: 0, acting: Option::None, recv: row(sa, 4, 5, sm), forged: false };
                                let mut genesis = vec![vec![None]; nn + 1];
                                genesis[0][0] = Admin;
                                genesis[1][0] = Write;
                                genesis[2][0] = Admin;
                                genesis[3][0] = Write;
                                let mut roles = JHist { nodes: nn, admins: vec![0], genesis, writes: vec![], recv: vec![] };
                                roles.writes.push(joint::JWrite { author: 0, t: 6, id: 1000, target: 0, holder: 1, role: None });
                                roles.recv.push(row(0, 6, 7, rm));
                                if let Some(by) = second {
                                    roles.writes.push(joint::JWrite { author: by, t: t2, id: 1001, target: 0, holder: sa, role: None });
                                    roles.recv.push(row(by, t2, t2 + 1, r2m));
                                }
                                let add_recv = |a: usize, t: u32| -> Vec<u32> { (0..nn).map(|v| if v == a { t } else { t + 1 }).collect() };
                                let make = |rules: Cover| {
                                    let mut w = World { roles: roles.clone(), items: vec![c.clone(), snap.clone()], frontier: HashMap::new(), gaps: Gaps::default() };
                                    w.derive(&mut Rng(0), rules, &[], &mut (0..2000).collect(), Some(&add_recv));
                                    w
                                };
                                f([make(PLAN), make(COVERS[0].1), make(COVERS[1].1)]);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Both exhaustive families: `cover_worlds` (with `covers_only`, alone) and `exhaustive_worlds`.
pub fn exhaustive(covers_only: bool) -> Stats {
    crate::on_every_core(|th, threads, st| {
        let mut rng = Rng::thread(0x5eed, th);
        cover_worlds((th, threads), |[w, o, p]| check(&w, Some(&[o, p]), st, &mut rng));
        if !covers_only {
            exhaustive_worlds((th, threads), Option::None, |w| check(&w, None, st, &mut rng));
        }
    })
}

// ---------- S3 brief 3 (`Gaps`) ----------

/// Content of a removed writer that a remaining witness received is reached: a non-forged plain
/// or admin-only commit of X on m (acting for nobody), ordered no later than an explicit
/// demotion D of X below the role it needs, that a node other than X and D's author received
/// before D's `ts`, which received D and holds that role on m in the final state, is valid.
/// Returns (wanted, not reached).
pub fn reached(w: &World) -> (u64, u64) {
    let (wanted, lost, _) = reached_items(w);
    (wanted, lost)
}

/// `reached` with the wanted items' indices.
fn reached_items(w: &World) -> (u64, u64, Vec<usize>) {
    let l1 = L1::new(&w.roles, |_| true);
    let e = w.ideal(PLAN);
    let (mut wanted, mut lost, mut items) = (0, 0, vec![]);
    for (c, it) in w.items.iter().enumerate() {
        if it.forged || it.acting.is_some() || !matches!(it.kind, Kind::Plain | Kind::AdminOnly) {
            continue;
        }
        let level = it.level();
        let want = l1.dems_below(level).iter().filter(|d| d.victim == it.author && d.thing == it.thing && it.pos() <= d.key).any(|d| {
            let ri = w.roles.writes.iter().position(|x| x.id == d.rid).unwrap();
            (0..w.nodes()).any(|v| v != it.author && v != d.author && w.roles.recv[ri][v] < LATE && it.held(v, d.key.0) && l1.states.last().map_or(false, |s| s[v][it.thing] >= level))
        });
        if want {
            wanted += 1;
            lost += !e.valid[c] as u64;
            items.push(c);
        }
    }
    (wanted, lost, items)
}

#[derive(Default)]
pub struct GapStats {
    pub worlds: u64,
    pub admin_items: u64,
    pub wanted: u64,
    pub lost: u64,
    pub order_dep: u64,
    pub nonmonotone: u64,
    pub attack_gain: u64,
    /// Measured (random worlds): wanted items valid but not visible with bodies dropped at once.
    pub sim_lost: u64,
    pub ex: Vec<(&'static str, World)>,
}

impl crate::Tally for GapStats {
    fn merge(&mut self, o: GapStats) {
        self.worlds += o.worlds;
        self.admin_items += o.admin_items;
        self.wanted += o.wanted;
        self.lost += o.lost;
        self.order_dep += o.order_dep;
        self.nonmonotone += o.nonmonotone;
        self.attack_gain += o.attack_gain;
        self.sim_lost += o.sim_lost;
        for (l, w) in o.ex {
            if !self.ex.iter().any(|(m, _)| *m == l) {
                self.ex.push((l, w));
            }
        }
    }
}

impl GapStats {
    pub fn failures(&self) -> u64 {
        self.lost + self.order_dep + self.nonmonotone + self.attack_gain
    }
    pub fn print(&self, name: &str) {
        println!(
            "{name}: {} worlds ({} admin-only items) | reached {} wanted, FAIL {} | FAIL order-dependent {}, non-monotone {}, attack gains {} | measured: wanted and lost with bodies dropped at once {}",
            self.worlds, self.admin_items, self.wanted, self.lost, self.order_dep, self.nonmonotone, self.attack_gain, self.sim_lost
        );
        for (label, w) in &self.ex {
            // not shrunk: dropping items drops the honest addenda with them
            println!("  {label} example:\n{w}");
        }
    }
}

/// The checks of `Gaps` on one world: reached, one result for every input order, monotone,
/// forged addenda gaining nothing beyond their author's power.
pub fn check_gaps(w: &World, sim: bool, st: &mut GapStats, rng: &mut Rng) {
    st.worlds += 1;
    st.admin_items += w.items.iter().filter(|it| it.kind == Kind::AdminOnly).count() as u64;
    let note = |st: &mut GapStats, label: &'static str, bad: bool, x: &World| {
        if bad && !st.ex.iter().any(|(l, _)| *l == label) {
            st.ex.push((label, x.clone()));
        }
        bad as u64
    };
    let (wanted, lost, items) = reached_items(w);
    st.wanted += wanted;
    st.lost += lost;
    if sim && !items.is_empty() {
        let v = w.simulate(PLAN, Option::None).visible;
        st.sim_lost += items.iter().filter(|&&c| !v[c]).count() as u64;
    }
    note(st, "not reached", lost > 0, w);
    let e = w.ideal(PLAN);
    let p = w.permuted(rng);
    let ep = p.ideal(PLAN);
    st.order_dep += note(st, "order dependence", p.ids(&ep.valid) != w.ids(&e.valid), w);
    st.nonmonotone += note(st, "non-monotone", nonmonotone(w, PLAN), w);
    let nn = w.roles.nodes;
    let att = [rng.below(nn)];
    let f = w.forge(rng, &att);
    st.attack_gain += note(st, "attack gain", attack_gains(w, &f, PLAN), &f);
}

/// Search driver: `addenda-gaps[-exh][-no-admin|-no-rewrite]` (random worlds with admin-only
/// content, or the gaps family). Failures found.
pub fn run_gaps(samples: u64, mode: &str) -> u64 {
    let exh = mode.starts_with("addenda-gaps-exh");
    let gaps = match mode.trim_start_matches("addenda-gaps").trim_start_matches("-exh") {
        "-no-admin" => Gaps { admin_only: false, ..GAPS },
        "-no-rewrite" => Gaps { rewrite: false, ..GAPS },
        _ => GAPS,
    };
    let st = if exh {
        crate::on_every_core(|th, threads, st: &mut GapStats| {
            let mut rng = Rng::thread(0x5eed, th);
            exhaustive_worlds((th, threads), Some(gaps), |w| check_gaps(&w, false, st, &mut rng));
        })
    } else {
        crate::each_world(0x5eed, 0..samples, |rng, st: &mut GapStats| {
            let s0 = rng.next();
            let w = random_world_with(&mut Rng(s0), PLAN, gaps, true);
            check_gaps(&w, true, st, rng);
        })
    };
    st.print(mode);
    st.failures()
}

// ---------- scenarios ----------

#[cfg(test)]
mod tests {
    use super::*;
    use Role::{Admin, None, Read, Write};

    /// Nodes: n0 Alice (mint admin of A0 and A1), n1 Bob, n2 Carol, n3 Dave (writers on A0),
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
            B { w: World { roles, items: vec![], frontier: HashMap::new(), gaps: Gaps::default() }, next: 100 }
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
        fn derive(self, unseen: &[usize]) -> World {
            self.derive_by(PLAN, unseen)
        }
        fn derive_by(mut self, rules: Cover, unseen: &[usize]) -> World {
            let mut ids: HashSet<u32> = (0..1000).collect();
            let add_recv = |a: usize, t: u32| -> Vec<u32> { (0..NN).map(|v| if v == a { t } else if unseen.contains(&v) { LATE } else { t + 1 }).collect() };
            self.w.derive(&mut Rng(0), rules, &[], &mut ids, Some(&add_recv));
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

    /// Admin Bob changes a setting (admin-only, not role-class); only admin Carol received it;
    /// Alice removes Bob. Carol's addendum reaches it (S3 brief 3); today's rule loses it.
    #[test]
    fn a_setting_only_an_admin_witness_received_is_reached() {
        let world = |gaps: Gaps| {
            let mut b = B::new();
            b.w.gaps = gaps;
            b.w.roles.genesis[BOB][0] = Admin;
            b.w.roles.genesis[CAROL][0] = Admin;
            let s = b.item(Kind::AdminOnly, BOB, 1, &[(CAROL, 2)]);
            b.set(BOB, None, 3);
            (b.derive(&[]), s)
        };
        let (w, s) = world(GAPS);
        assert!(valid(&w, s));
        assert_eq!(reached(&w), (1, 0));
        let (w, s) = world(Gaps { admin_only: false, ..GAPS });
        assert!(!valid(&w, s));
        assert_eq!(reached(&w), (1, 1));
    }

    /// Carol only writes when she applies Bob's removal; Alice grants her admin after it: her
    /// addendum written then reaches Bob's setting. Writing only on applying the removal loses it.
    /// With bodies dropped at once (`simulate`) it is lost all the same: invalid from the removal
    /// to Carol's grant, every node dropped its body, and nobody holds one to fetch.
    #[test]
    fn a_witness_granted_admin_after_the_removal_reaches_the_setting() {
        let world = |gaps: Gaps| {
            let mut b = B::new();
            b.w.gaps = gaps;
            b.w.roles.genesis[BOB][0] = Admin;
            let s = b.item(Kind::AdminOnly, BOB, 1, &[(CAROL, 2)]);
            b.set(BOB, None, 3);
            b.set(CAROL, Admin, 6);
            (b.derive(&[]), s)
        };
        let (w, s) = world(GAPS);
        let i = w.items.iter().position(|it| it.id == s).unwrap();
        assert!(w.ideal(PLAN).valid[i]);
        assert!(!w.simulate(PLAN, Option::None).visible[i]);
        assert!(addenda(&w).iter().any(|a| a.author == CAROL && a.t == 7));
        let (w, s) = world(Gaps { rewrite: false, ..GAPS });
        assert!(!w.ideal(PLAN).valid[w.items.iter().position(|it| it.id == s).unwrap()]);
    }

    /// A writer forging an addendum for an admin-only commit gains nothing.
    #[test]
    fn a_writers_addendum_vouches_for_no_setting() {
        let mut b = B::new();
        b.w.gaps = GAPS;
        b.w.roles.genesis[BOB][0] = Admin;
        let s = b.item(Kind::AdminOnly, BOB, 1, &[(CAROL, 2)]);
        let r = b.set(BOB, None, 3);
        let w = b.derive(&[]);
        assert!(addenda(&w).is_empty());
        let f = forged(&w, CAROL, 5, r, vec![s]);
        assert!(!f.ideal(PLAN).valid[f.items.iter().position(|it| it.id == s).unwrap()]);
    }

    #[test]
    fn gaps_random_and_family_sample_hold_and_controls_fail() {
        let mut st = GapStats::default();
        let mut rng = Rng(7);
        for _ in 0..300 {
            let s0 = rng.next();
            check_gaps(&random_world_with(&mut Rng(s0), PLAN, GAPS, true), true, &mut st, &mut rng);
        }
        exhaustive_worlds((0, 997), Some(GAPS), |w| check_gaps(&w, false, &mut st, &mut rng));
        assert_eq!(st.failures(), 0);
        assert!(st.wanted > 0);
        for gaps in [Gaps { admin_only: false, ..GAPS }, Gaps { rewrite: false, ..GAPS }] {
            let mut st = GapStats::default();
            exhaustive_worlds((0, 997), Some(gaps), |w| check_gaps(&w, false, &mut st, &mut rng));
            assert!(st.lost > 0, "{gaps:?}");
        }
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

    fn visible(w: &World, rules: Cover, id: u32) -> bool {
        w.ideal(rules).visible[w.items.iter().position(|it| it.id == id).unwrap()]
    }

    /// A cover by another writer falls with that writer's own removal, which the leaver's
    /// remover may not know of: Dave's snapshot carries Bob's edit, Alice holds both and removes
    /// Bob, Carol (an admin too) has removed Dave without receiving the snapshot. Leaving the
    /// edit out of Bob's frontier loses it; listing it, or leaving out only what Bob's own
    /// snapshot covers, keeps it.
    #[test]
    fn another_writers_cover_falls_with_its_author() {
        let make = |rules: Cover| {
            let mut b = B::new();
            b.w.roles.genesis[CAROL][0] = Admin;
            let e = b.write(BOB, 1, &[(ALICE, 2), (DAVE, 2)]);
            b.item(Kind::Snap(vec![e]), DAVE, 4, &[(ALICE, 5)]);
            b.next += 1;
            b.w.roles.writes.push(joint::JWrite { author: CAROL, t: 5, id: b.next, target: 0, holder: DAVE, role: None });
            b.w.roles.recv.push(B::row(CAROL, 5, &[(BOB, 6), (DAVE, 6), (EVE, 6)]));
            b.set(BOB, None, 6);
            (b.derive_by(rules, &[]), e)
        };
        for (cover, keeps) in [(Cover::ListAll, true), (Cover::OmitOthers, false), (Cover::OmitOwn, true)] {
            let rules = cover;
            let (w, e) = make(rules);
            assert_eq!(visible(&w, rules, e), keeps, "{cover:?}");
        }
    }

    /// A cover by the leaver's own snapshot falls only with the removal, which saves it by
    /// naming it: Alice received neither Bob's edit nor his snapshot of it; Carol received both
    /// and her addendum names the snapshot alone, which keeps the edit visible.
    #[test]
    fn leavers_own_cover_is_named() {
        let rules = Cover::OmitOwn;
        let mut b = B::new();
        let e = b.write(BOB, 1, &[(CAROL, 2)]);
        let s = b.item(Kind::Snap(vec![e]), BOB, 4, &[(CAROL, 5)]);
        b.set(BOB, None, 6);
        let w = b.derive_by(rules, &[]);
        let lists: Vec<&Vec<u32>> = w.items.iter().filter_map(|it| if let Kind::Add { lists, .. } = &it.kind { Some(lists) } else { Option::None }).collect();
        assert_eq!(lists, [&vec![s]]);
        assert!(visible(&w, rules, e));
        assert!(!w.ideal(rules).valid[0], "the edit itself is not listed");
    }

    /// Leaving out only what the leaver's own named snapshot covers loses no visible write
    /// against listing every commit, over a slice of the cover family (whole: `addenda-covers`).
    #[test]
    fn own_covers_lose_nothing() {
        let mut st = Stats::default();
        let mut rng = Rng(0);
        cover_worlds((0, 64), |[w, o, p]| check(&w, Some(&[o, p]), &mut st, &mut rng));
        assert!(st.covers[0].loses > 0, "the family reaches another writer's falling cover");
        assert_eq!(st.cover_failures(1), 0);
        assert_eq!(st.failures(), 0);
    }

    /// The joint walk's replay (`steps`) ends in the walk's own roles.
    #[test]
    fn steps_follow_the_walk() {
        let mut rng = Rng(0);
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
