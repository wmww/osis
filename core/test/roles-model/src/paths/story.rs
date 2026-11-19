//! The stolen-node story over the path rule: parties, ticks, the thief's moves, honest writing
//! (the state-based rule) and the properties.

use super::*;

pub const H: Thing = 1;
pub const B: Thing = 2;
pub const X: Thing = 3;
pub const N5: Thing = 4;
pub const K: Thing = 5;
pub const Z: Thing = 6;
pub const N6: Thing = 7;
/// The mint admin of A in `Setup::mint` worlds, who leaves A.
pub const M: Thing = 8;
pub const A: Thing = 10;
pub const A2: Thing = 11;
pub const ORG: Thing = 12;
pub const T1: Thing = 13;
pub const T2: Thing = 14;
/// A dependent of T1 (minted with it, in T1's unit): written by descent.
pub const D1: Thing = 15;
/// Readers outside A (nodes, not signers): holding only T1 and D1, only T2 (part of the evidence).
pub const RD: Thing = 20;
pub const RD2: Thing = 21;

const SETTLE: u32 = 11;
const AFTER: u32 = 12;
/// The last tick honest nodes write answers at.
const END: u32 = 15;
/// The tick of H's removal of X.
const REMOVAL: u32 = 6;
/// When `Setup::mint` names B, B's admin grant ends here, after the story.
const B_UNTIL: u32 = 20;

/// Account A (minted by H's key), the collaborator's account A2 (K's), ORG and T1 minted with A,
/// T2 minted with ORG: a path to T2 has two hops above the signer's; D1 minted with T1, a
/// dependent in T1's unit.
pub fn account() -> World {
    minted_by(H)
}

/// As `account`, A minted by `mint`.
pub fn minted_by(mint: Thing) -> World {
    World::new(&[(mint, A), (K, A2), (A, ORG), (ORG, T2), (A, T1), (T1, D1)])
}

/// One world of the family (`Sim::build`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Setup {
    /// The remover syncs T1, T2.
    pub h_t1: bool,
    pub h_t2: bool,
    /// B is offline from tick 4 to the settle.
    pub b_offline: bool,
    /// A2's role on T1 is granted by X (else by B).
    pub sharer_x: bool,
    /// 0: no N5; 1: X paired N5 and H received the grant before its removal; 2: H did not.
    pub n5: u8,
    /// X's role write before the theft. 0: none; 1: demotes B to write on A; 2: removes A2 from
    /// T1 (when B shared it); 3: grants A2 admin on T2.
    pub x_role: u8,
    /// H received it before its removal.
    pub x_role_seen: bool,
    /// 0: X holds nothing on A2; 1: write on A2; 2: write, and K removes it as H does; 3: admin
    /// on A2, and A2 admin on T1 (X administers T1 through A2 for good).
    pub x_a2: u8,
    /// B sides with X's removal of H until its user switches at `AFTER`.
    pub b_side_x: bool,
    /// At `AFTER` H grants N5 again and B grants A2 write on T1 again.
    pub regrant: bool,
    /// 0: H mints A. 1: M mints A, pairs H at 0, writes T1 at 1, leaves A at 2 naming H as the
    /// remaining admin, writes T1 again at 3. 2: as 1, naming B, whose admin grant is timed.
    pub mint: u8,
    /// The thief removes H at the theft, honestly stamped, and every node receives it at once:
    /// H's removal of X lists it.
    pub x_first: bool,
}

/// One move of the thief after the removal: `kind` indexes `MOVES`, stamped `ts`, made at `made`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Move {
    pub kind: usize,
    pub ts: u32,
    pub made: u32,
}

pub const MOVES: usize = 23;

/// What a world is built from: its setup, the thief's moves, and the receipts generator.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    pub setup: Setup,
    pub moves: Vec<Move>,
    pub rng: u64,
}

#[derive(Clone, Debug)]
pub struct Sim {
    pub w: World,
    pub spec: Spec,
    pub setup: Setup,
    pub made: Vec<u32>,
    /// When each node received each commit (absent: not before the final reading).
    pub recv: Vec<BTreeMap<Thing, u32>>,
    pub sync: BTreeMap<Thing, Things>,
    /// H's removal of X; K's of X from A2; X's removal of H that B sides with; X's removal of H
    /// at the theft.
    pub r: Id,
    pub r2: Option<Id>,
    pub rx: Option<Id>,
    pub xfirst: Option<Id>,
    pub gs: Id,
    pub g5: Option<Id>,
    pub xrole: Option<Id>,
    /// Removals and the further units they are logged under.
    pub logged: BTreeMap<Id, Things>,
}

fn role_path(n: Thing, on: Thing) -> Option<Vec<Thing>> {
    match (n, on) {
        (H | B | X | N5 | Z | M, A) | (K, A2) => Some(vec![]),
        (K, T1) => Some(vec![A2]),
        // A reaches D1 by descent; A2 holds on T1, D1's mint
        (K, D1) => Some(vec![A2, T1]),
        (H | B | X | N5 | Z | M, D1) => Some(vec![A]),
        (H | B | X | N5 | Z | M, T1 | ORG) => Some(vec![A]),
        (H | B | X | N5 | Z, T2) => Some(vec![A, ORG]),
        _ => None,
    }
}

/// An answer owed: against removal `r`, on thing `on` by `path`, a vouch (`edge`) or an
/// addendum, listing what the node had received by `r`'s `ts` that `r` does not list.
type Owed = (Id, Thing, Vec<Thing>, bool, Set);

impl Sim {
    fn put(&mut self, c: (Thing, u32, &[Thing], Thing, Kind), made: u32, rng: &mut Rng, hostile: bool) -> Id {
        let (signer, ts, path, on, kind) = c;
        let i = self.w.push(signer, ts, path, on, kind);
        self.made.push(made);
        let mut units = Things::from([on]);
        units.extend(self.logged.get(&i).into_iter().flatten());
        let mut recv = BTreeMap::new();
        for (&n, syncs) in &self.sync {
            if !syncs.iter().any(|u| units.contains(u)) {
                continue;
            }
            let t = if n == signer || n == X {
                made
            } else if (self.setup.b_offline && n == B && made >= 4) || (hostile && rng.below(2) == 0) {
                SETTLE.max(made)
            } else {
                made + rng.below(2) as u32
            };
            recv.insert(n, t);
        }
        self.recv.push(recv);
        i
    }
    pub fn got(&self, i: Id, n: Thing, by: u32) -> bool {
        self.recv[i].get(&n).is_some_and(|t| *t <= by)
    }
    /// The story. Ticks 0-4: A's nodes are paired, T1 is shared, X's role write, content.
    /// 5: X is stolen and writes. 6: H removes X (K too where X holds on A2). 7-10: the thief's
    /// moves and honest content. 11: the settle, every node receives everything in the units it
    /// syncs. 12: re-grants, B's switch. From 7 to `END` each honest node writes its answers
    /// by the state-based rule (`answers`).
    pub fn build(setup: &Setup, rules: &Rules, moves: &[Move], rng: &mut Rng) -> Sim {
        let s = *setup;
        let spec = Spec { setup: s, moves: moves.to_vec(), rng: rng.0 };
        let mut sync: BTreeMap<Thing, Things> = BTreeMap::new();
        let mut hs = Things::from([A, ORG]);
        if s.h_t1 {
            hs.extend([T1, D1]);
        }
        if s.h_t2 {
            hs.insert(T2);
        }
        sync.insert(H, hs);
        sync.insert(B, Things::from([A, ORG, T1, D1, T2]));
        sync.insert(X, Things::from([A, A2, ORG, T1, D1, T2]));
        if s.n5 > 0 {
            sync.insert(N5, Things::from([A, ORG, T1, D1, T2]));
        }
        sync.insert(K, Things::from([A2, T1, D1]));
        sync.insert(RD, Things::from([T1, D1]));
        sync.insert(RD2, Things::from([T2]));
        let w = if s.mint > 0 { minted_by(M) } else { account() };
        let mut m = Sim { w, spec, setup: s, made: vec![], recv: vec![], sync, r: 0, r2: None, rx: None, xfirst: None, gs: 0, g5: None, xrole: None, logged: BTreeMap::new() };
        let grant = Kind::set;
        if s.mint > 0 {
            m.put((M, 0, &[], A, grant(H, Role::Admin)), 0, rng, false);
        }
        m.put((H, 1, &[], A, grant(X, Role::Admin)), 1, rng, false);
        let until = (s.mint == 2).then_some(B_UNTIL);
        m.put((H, 1, &[], A, match until { Some(u) => grant(B, Role::Admin).until(u), None => grant(B, Role::Admin) }), 1, rng, false);
        let a2 = if s.x_a2 == 3 { Role::Admin } else { Role::Write };
        if s.x_a2 > 0 {
            m.put((K, 1, &[], A2, grant(X, a2)), 1, rng, false);
        }
        if s.mint > 0 {
            m.put((M, 1, &[A], T1, Kind::Content), 1, rng, false);
            let f = m.w.cut(&m.w.through((M, A), |_| true));
            let relies = if s.mint == 1 { H } else { B };
            m.put((M, 2, &[], A, grant(M, Role::None).listing(f).relying(relies)), 2, rng, false);
            m.put((M, 3, &[A], T1, Kind::Content), 3, rng, false);
        }
        let sharer = if s.sharer_x { X } else { B };
        m.gs = m.put((sharer, 2, &[A], T1, grant(A2, a2)), 2, rng, false);
        if s.n5 > 0 {
            let g = m.put((X, 2, &[], A, grant(N5, Role::Admin)), 2, rng, false);
            m.recv[g].insert(H, if s.n5 == 1 { 2 } else { SETTLE });
            m.g5 = Some(g);
        }
        let x_role = if s.x_role == 2 && s.sharer_x { 0 } else { s.x_role };
        if x_role > 0 {
            let (path, on, holder, role): (&[Thing], _, _, _) = match x_role {
                1 => (&[], A, B, Role::Write),
                2 => (&[A], T1, A2, Role::None),
                _ => (&[A, ORG], T2, A2, Role::Admin),
            };
            let f = m.w.cut(&m.w.through((holder, on), |_| true));
            let g = m.put((X, 3, path, on, grant(holder, role).listing(f)), 3, rng, false);
            if m.sync[&H].contains(&on) {
                m.recv[g].insert(H, if s.x_role_seen { 3 } else { SETTLE });
            }
            m.xrole = Some(g);
        }
        for tick in [3, 4, 5, 8, 9] {
            let writers: &[Thing] = if tick < 5 { &[H, B, X, K, N5] } else if tick == 5 { &[X] } else { &[H, B, K, N5] };
            for &n in writers {
                for on in [T1, T2, D1] {
                    if m.sync.get(&n).is_some_and(|u| u.contains(&on)) && rng.below(2) == 0 {
                        if let Some(p) = role_path(n, on) {
                            m.put((n, tick, &p, on, Kind::Content), tick, rng, false);
                        }
                    }
                }
            }
            if tick == 5 {
                if s.x_first {
                    let f = m.w.cut(&m.w.through((H, A), |_| true));
                    let i = m.put((X, 5, &[], A, grant(H, Role::None).listing(f)), 5, rng, false);
                    m.recv[i].values_mut().for_each(|t| *t = 5);
                    m.xfirst = Some(i);
                }
                m.remove(rng);
            }
        }
        for mv in moves {
            m.thief(mv, rng);
        }
        if s.b_side_x {
            let f = m.w.cut(&m.w.through((H, A), |i| i != m.r));
            m.rx = Some(m.put((X, 5, &[], A, grant(H, Role::None).listing(f)), 7, rng, false));
        }
        // the settle: whatever exists reaches every node syncing its unit
        for i in 0..m.w.commits.len() {
            let on = m.w.commits[i].on;
            let mut units = Things::from([on]);
            units.extend(m.logged.get(&i).into_iter().flatten());
            for (&n, syncs) in &m.sync {
                if syncs.iter().any(|u| units.contains(u)) {
                    let t = m.recv[i].entry(n).or_insert(SETTLE);
                    *t = (*t).min(SETTLE.max(m.made[i]));
                }
            }
        }
        if s.regrant {
            if s.n5 > 0 {
                m.put((H, AFTER, &[], A, grant(N5, Role::Admin)), AFTER, rng, false);
            }
            m.put((B, AFTER, &[A], T1, grant(A2, Role::Write)), AFTER, rng, false);
        }
        m.answers(rules, rng);
        m
    }
    /// The removals at tick 6, each listing what its author had received through the edge.
    fn remove(&mut self, rng: &mut Rng) {
        let f = self.w.cut(&self.w.through((X, A), |i| self.got(i, H, REMOVAL - 1)));
        let i = self.w.commits.len();
        self.logged.insert(i, Things::from([ORG, T1, T2]));
        self.r = self.put((H, REMOVAL, &[], A, Kind::set(X, Role::None).listing(f)), REMOVAL, rng, false);
        if self.setup.x_a2 == 2 {
            let f = self.w.cut(&self.w.through((X, A2), |i| self.got(i, K, REMOVAL - 1)));
            let i = self.w.commits.len();
            self.logged.insert(i, Things::from([T1]));
            self.r2 = Some(self.put((K, REMOVAL, &[], A2, Kind::set(X, Role::None).listing(f)), REMOVAL, rng, false));
        }
    }
    /// Per removal, thing and kind (addendum for plain content on T1 and T2, vouch for role
    /// writes): the commits through the removed edge node `n` had received by the removal's
    /// `ts` that the removal does not list.
    fn owed(&self, n: Thing, rules: &Rules) -> Vec<Owed> {
        let mut out = vec![];
        for r in [Some(self.r), self.r2].into_iter().flatten() {
            let h = self.w.sets(r).unwrap();
            for on in [A, ORG, T1, D1, T2] {
                let Some(path) = role_path(n, on) else { continue };
                if !self.sync[&n].contains(&on) {
                    continue;
                }
                for edge in [false, true] {
                    if (edge && rules.vouch == Vouch::Off) || (!edge && ![T1, T2, D1].contains(&on)) {
                        continue;
                    }
                    let list: Set = (0..self.w.commits.len())
                        .filter(|&i| i != r && self.w.commits[i].on == on && self.w.edge_class(i) == edge && self.w.hops(i).contains(&h) && self.got(i, n, REMOVAL) && self.made[i] <= REMOVAL && !self.w.in_frontier(r, i))
                        .collect();
                    if !list.is_empty() {
                        out.push((r, on, path.clone(), edge, list));
                    }
                }
            }
        }
        out
    }
    /// Honest writing, the state-based rule (vouches README, `Rules::state`): at every tick, a
    /// node whose own current walk applies a removal it holds writes, per thing, an addendum (a
    /// vouch) listing what it owes there whenever its path gives it write (admin, in the walk
    /// with no vouch counting) and some owed commit is named by no addendum (counting vouch) of
    /// its own. So it writes at receipt, again once it holds the right after a re-grant or a
    /// switch of side, and again whenever its earlier one stops counting.
    fn answers(&mut self, rules: &Rules, rng: &mut Rng) {
        let mut seen: BTreeMap<Thing, (Set, Set)> = BTreeMap::new();
        let mut done: BTreeSet<(Thing, Id, Thing, bool)> = BTreeSet::new();
        for t in REMOVAL + 1..=END {
            for n in [H, B, N5, K] {
                if !self.sync.contains_key(&n) {
                    continue;
                }
                let owed: Vec<Owed> = self.owed(n, rules).into_iter().filter(|o| self.got(o.0, n, t) && (rules.rewrite || !done.contains(&(n, o.0, o.1, o.3)))).collect();
                if owed.is_empty() {
                    continue;
                }
                let v = self.view_at(n, Some(t), rules);
                let key = (v.held.clone(), v.trust.clone());
                if seen.get(&n) == Some(&key) {
                    continue;
                }
                seen.insert(n, key);
                let rd = judge(&self.w, rules, &v);
                for (r, on, path, edge, list) in owed {
                    if !rd.applied.contains(&r) {
                        continue;
                    }
                    done.insert((n, r, on, edge));
                    let (state, need) = if edge { (&rd.first, Role::Admin) } else { (&rd.state, Role::Write) };
                    let mut all = vec![n];
                    all.extend(&path);
                    all.push(on);
                    if !all.windows(2).flat_map(|p| self.w.joins(p[0], p[1])).all(|e| state.get(&e).is_some_and(|&v| alive(v, t) >= need)) {
                        continue;
                    }
                    let mine = if edge { &rd.counting } else { &rd.vouching };
                    let covered = |c: &Id| {
                        mine.iter().any(|&a| {
                            self.w.commits[a].signer == n && matches!(&self.w.commits[a].kind, Kind::Addendum { removal, list } | Kind::Vouch { removal, list } if *removal == r && list.contains(c))
                        })
                    };
                    if list.iter().all(covered) {
                        continue;
                    }
                    let kind = if edge { Kind::Vouch { removal: r, list } } else { Kind::Addendum { removal: r, list } };
                    self.put((n, t, &path, on, kind), t, rng, false);
                }
            }
        }
    }
    /// One move of the thief: any `ts`, any path, as X or as the made-up key Z.
    fn thief(&mut self, mv: &Move, rng: &mut Rng) {
        let grant = Kind::set;
        let mine = |m: &Sim, on: Thing, edge: bool| -> Set { (0..m.w.commits.len()).filter(|&i| m.w.commits[i].signer == X && m.w.commits[i].on == on && m.w.edge_class(i) == edge && m.w.hops(i).contains(&(X, A))).collect() };
        if mv.kind == 19 {
            // a grant through the cut path, backdated, and X's own vouch for it along A2
            self.put((X, mv.ts.min(5), &[A], T1, grant(Z, Role::Write)), mv.made, rng, true);
            let list = mine(self, T1, true);
            self.put((X, mv.ts.max(REMOVAL + 1), &[A2], T1, Kind::Vouch { removal: self.r, list }), mv.made, rng, true);
            return;
        }
        let c: (Thing, &[Thing], Thing, Kind) = match mv.kind {
            0 | 18 => (X, &[A], T1, Kind::Content),
            19 => unreachable!(),
            1 => (X, &[A, ORG], T2, Kind::Content),
            2 => (X, &[A2], T1, Kind::Content),
            3 => (X, &[ORG], T1, Kind::Content),
            4 => (X, &[], A, grant(Z, Role::Admin)),
            5 => (X, &[A], T1, grant(Z, Role::Write)),
            6 => (X, &[A, ORG], T2, grant(Z, Role::Admin)),
            7 => (Z, &[A], T1, Kind::Content),
            8 => (Z, &[], T1, Kind::Content),
            9 => (Z, &[], T2, Kind::Content),
            10 => (Z, &[], A, grant(H, Role::None)),
            11 => (X, &[], A, grant(H, Role::None)),
            12 => (X, &[], A, grant(B, Role::None)),
            13 => (X, &[A2], T1, Kind::Addendum { removal: self.r, list: mine(self, T1, false) }),
            14 => (X, &[], A, Kind::Vouch { removal: self.r, list: mine(self, A, true) }),
            15 => (Z, &[], A, grant(X, Role::Admin)),
            16 => (Z, &[], A, Kind::Vouch { removal: self.r, list: mine(self, A, true) }),
            17 => (X, &[], A, grant(N5, Role::None)),
            // by descent through the cut path
            20 => (X, &[A], D1, Kind::Content),
            // X leaves A by itself (a self-removal, its path ending at itself)
            21 => (X, &[], A, grant(X, Role::None).relying(H)),
            // X makes A leave T1, its path ending at A, marked adminless
            22 => {
                let mut k = grant(A, Role::None);
                if let Kind::Edge { adminless, .. } = &mut k {
                    *adminless = true;
                }
                (X, &[A], T1, k)
            }
            _ => unreachable!("move {}", mv.kind),
        };
        let ts = if mv.kind == 18 { 20 } else { mv.ts };
        self.put((c.0, ts, c.1, c.2, c.3), mv.made, rng, true);
    }
    /// What a node holds by `t` (None: at the final reading): its units' commits, the removals
    /// logged there, and their evidence among the commits made by then.
    pub fn held_at(&self, n: Thing, t: Option<u32>) -> Set {
        let avail: Set = (0..self.w.commits.len()).filter(|&i| t.is_none_or(|t| self.made[i] <= t)).collect();
        let unit: Set = avail.iter().copied().filter(|&i| self.recv[i].get(&n).is_some_and(|r| t.is_none_or(|t| *r <= t))).collect();
        evidence(&self.w, &unit, &avail)
    }
    pub fn held(&self, n: Thing) -> Set {
        self.held_at(n, None)
    }
    /// The node's view by `t`: leaves for the things it syncs, and with `Rules::evidence_leaves`
    /// for every thing a held edge write is on; it trusts the removals of X, B rather X's
    /// removal of H until its switch.
    pub fn view_at(&self, n: Thing, t: Option<u32>, rules: &Rules) -> View {
        let held = self.held_at(n, t);
        let mut leaves = self.sync[&n].clone();
        if rules.evidence_leaves {
            leaves.extend(held.iter().filter(|&&i| self.w.edge_class(i)).map(|&i| self.w.commits[i].on));
        }
        let trust = if self.setup.b_side_x && n == B && t.is_some_and(|t| t < AFTER) { self.rx.into_iter().collect() } else { [Some(self.r), self.r2].into_iter().flatten().collect() };
        View { held, leaves: Some(leaves), trust }
    }
    pub fn view(&self, n: Thing, rules: &Rules) -> View {
        self.view_at(n, None, rules)
    }
    pub fn honest(&self) -> Vec<Thing> {
        [H, B, N5, K, RD, RD2].into_iter().filter(|n| self.sync.contains_key(n)).collect()
    }
    fn hostile(&self, i: Id) -> bool {
        self.w.commits[i].signer == Z || (self.w.commits[i].signer == X && self.made[i] > REMOVAL)
    }
    /// A lowering of an edge a removal of X's own path stands on.
    fn lowers_remover(&self, i: Id) -> bool {
        self.w.lowers(i).is_some_and(|e| [Some(self.r), self.r2].into_iter().flatten().any(|r| self.w.hops(r).contains(&e)))
    }
}

/// Failures by property, the first failing world of each, and what is counted.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub worlds: u64,
    pub fails: BTreeMap<&'static str, u64>,
    pub first: BTreeMap<&'static str, (String, Spec)>,
    /// Checks made of each kind (a dead check shows as 0).
    pub checked: BTreeMap<&'static str, u64>,
}

impl crate::Tally for Stats {
    fn merge(&mut self, o: Stats) {
        self.worlds += o.worlds;
        for (k, n) in o.fails {
            *self.fails.entry(k).or_default() += n;
        }
        for (k, n) in o.checked {
            *self.checked.entry(k).or_default() += n;
        }
        for (k, s) in o.first {
            self.first.entry(k).or_insert(s);
        }
    }
}

impl Stats {
    pub fn failures(&self) -> u64 {
        self.fails.values().sum()
    }
    /// Prints the counts and, per failing property, its first world shrunk under `rules`.
    pub fn print(&self, name: &str, rules: &Rules) {
        println!("{name}: {} worlds, checks {:?}, failing checks {:?}", self.worlds, self.checked, self.fails);
        for (k, (what, spec)) in &self.first {
            let small = shrink(spec, rules, k);
            let mut st = Stats::default();
            let m = Sim::build(&small.setup, rules, &small.moves, &mut Rng(small.rng));
            check(&m, rules, &mut st);
            let what = st.first.get(k).map_or(what.clone(), |x| x.0.clone());
            println!("FAIL {k} (shrunk): {what}\n{:?} moves {:?}\n{}", small.setup, small.moves, trace(&m));
        }
    }
    fn fail(&mut self, prop: &'static str, m: &Sim, what: String) {
        *self.fails.entry(prop).or_default() += 1;
        self.first.entry(prop).or_insert_with(|| (what, m.spec.clone()));
    }
    fn count(&mut self, k: &'static str) {
        *self.checked.entry(k).or_default() += 1;
    }
}

/// The setups one step smaller than `s`: one field moved toward its default.
fn smaller_setups(s: &Setup) -> Vec<Setup> {
    let mut out = vec![];
    let mut try_ = |f: &dyn Fn(&mut Setup)| {
        let mut t = *s;
        f(&mut t);
        if t != *s {
            out.push(t);
        }
    };
    try_(&|t| t.h_t1 = false);
    try_(&|t| t.h_t2 = false);
    try_(&|t| t.b_offline = false);
    try_(&|t| t.sharer_x = false);
    try_(&|t| t.x_role_seen = false);
    try_(&|t| t.b_side_x = false);
    try_(&|t| t.regrant = false);
    try_(&|t| t.x_first = false);
    try_(&|t| t.n5 = 0);
    try_(&|t| t.n5 = t.n5.saturating_sub(1));
    try_(&|t| t.x_role = 0);
    try_(&|t| t.x_a2 = 0);
    try_(&|t| t.x_a2 = t.x_a2.saturating_sub(1));
    try_(&|t| t.mint = 0);
    try_(&|t| t.mint = t.mint.saturating_sub(1));
    out
}

/// The smallest spec reachable from `spec` by single steps (a move dropped, a setup field
/// toward its default) that still fails `prop` under `rules`, the world rebuilt under them.
pub fn shrink(spec: &Spec, rules: &Rules, prop: &str) -> Spec {
    let fails = |s: &Spec| {
        let mut st = Stats::default();
        check(&Sim::build(&s.setup, rules, &s.moves, &mut Rng(s.rng)), rules, &mut st);
        st.fails.contains_key(prop)
    };
    let mut cur = spec.clone();
    'step: loop {
        let mut next: Vec<Spec> = (0..cur.moves.len()).map(|k| Spec { moves: crate::shrink::without(&cur.moves, k), ..cur.clone() }).collect();
        next.extend(smaller_setups(&cur.setup).into_iter().map(|setup| Spec { setup, ..cur.clone() }));
        for c in next {
            if fails(&c) {
                cur = c;
                continue 'step;
            }
        }
        return cur;
    }
}

pub fn trace(m: &Sim) -> String {
    let name = |t: &Thing| ["?", "H", "B", "X", "N5", "K", "Z", "N6", "M", "?", "A", "A2", "ORG", "T1", "T2", "D1"].get(*t as usize).copied().unwrap_or("?");
    let mut s = String::new();
    for (i, c) in m.w.commits.iter().enumerate() {
        let path: Vec<&str> = c.path.iter().map(name).collect();
        let kind = match &c.kind {
            Kind::Content => "content".to_string(),
            Kind::Edge { holder, role, until, frontier, relies, adminless } => {
                let mut k = format!("{} := {role:?}", name(holder));
                if let Some(u) = until {
                    k += &format!(" until {u}");
                }
                if let Some(n) = relies {
                    k += &format!(" relying on {}", name(n));
                }
                if *adminless {
                    k += " adminless";
                }
                k + &format!(" frontier {:?}", frontier.values().flatten().collect::<Vec<_>>())
            }
            Kind::Addendum { removal, list } => format!("addendum against {removal} {list:?}"),
            Kind::Vouch { removal, list } => format!("vouch against {removal} {list:?}"),
        };
        let recv: Vec<String> = m.recv[i].iter().filter(|(n, _)| **n != X && **n != c.signer).map(|(n, t)| format!("{}@{t}", if *n == RD { "RD" } else if *n == RD2 { "RD2" } else { name(n) })).collect();
        s += &format!("  {i}: {} ts {} made {} [{}] on {}: {kind}; recv {}\n", name(&c.signer), c.ts, m.made[i], path.join(","), name(&c.on), recv.join(" "));
    }
    s
}

/// The properties, at every honest node's final reading. The oracle is the wanted behaviour
/// (issues/actors-one-mechanism.md: a removed node's role writes are kept on the same terms as
/// its content), computed from the story, never from a reading.
pub fn check(m: &Sim, rules: &Rules, st: &mut Stats) {
    st.worlds += 1;
    let (w, s) = (&m.w, &m.setup);
    let nodes = m.honest();
    let rds: BTreeMap<Thing, (View, Reading)> = nodes
        .iter()
        .map(|&n| {
            let v = m.view(n, rules);
            let rd = judge(w, rules, &v);
            (n, (v, rd))
        })
        .collect();
    let in_r = |i: Id| w.in_frontier(m.r, i);
    let regrant_n5 = s.regrant && s.n5 > 0;
    // who may vouch: A's admins by a chain not through X, once they hold the right
    let mut admins = vec![H];
    if !(s.x_role == 1 && m.xrole.is_some_and(in_r)) {
        admins.push(B);
    }
    if m.g5.is_some_and(in_r) || regrant_n5 {
        admins.push(N5);
    }
    let saved = |g: Id| in_r(g) || admins.iter().any(|&n| m.sync.get(&n).is_some_and(|u| u.contains(&w.commits[g].on)) && m.got(g, n, REMOVAL));
    let x_removed_a2 = s.x_role == 2 && m.xrole.is_some();
    // B grants again only while it is an admin: X's demotion of it may stand
    let b_admin = !(s.x_role == 1 && m.xrole.is_some_and(saved));
    let stands = |n: Thing| match n {
        H | B => true,
        N5 => m.g5.is_some_and(saved) || regrant_n5,
        K => !x_removed_a2 && (!s.sharer_x || saved(m.gs) || (s.regrant && b_admin)),
        _ => false,
    };
    // whose addendum vouches: a writer holding write at its addendum's key, which a node
    // re-granted writes after its new grant
    let wrote = |n: Thing| match n {
        H | B => true,
        N5 => m.g5.is_some_and(saved) || regrant_n5,
        K => !x_removed_a2 && (!s.sharer_x || saved(m.gs) || (s.regrant && b_admin)),
        _ => false,
    };
    let x_keeps_a2 = s.x_a2 == 1 || s.x_a2 == 3;
    for (&n, (v, rd)) in &rds {
        if rd.circle {
            st.fail("settles", m, format!("node {n}: the vouches do not settle"));
        }
        if !rd.stray.is_empty() {
            st.fail("stray", m, format!("node {n}: {:?} dropped by a write that does not apply", rd.stray));
        }
        st.count("removal");
        if !rd.void.is_empty() {
            st.fail("removal", m, format!("node {n}: its trusted removal {:?} is void", rd.void));
        }
        // safety
        for &i in v.held.iter().filter(|&&i| m.hostile(i)) {
            st.count("safety");
            let c = &w.commits[i];
            // X's own writes along A2, a path it keeps (a vouch there showing is its right; what it names
            // is judged apart)
            let by_right = (c.signer == X && x_keeps_a2 && c.path == [A2] && !matches!(c.kind, Kind::Edge { .. }))
                // X leaving A by itself: a self-removal is always open to the holder, and takes nothing X still holds
                || (w.leave(i) && w.sets(i) == Some((X, A)));
            if rd.shows(i) && !by_right {
                st.fail("safety", m, format!("node {n}: the thief's commit {i} shows"));
            }
        }
        for (e, r) in &rd.roles {
            let x_holds = e.0 == X && (e.1 == A || (e.1 == A2 && !x_keeps_a2));
            if *r > Role::None && (e.0 == Z || x_holds) {
                st.fail("safety", m, format!("node {n}: {e:?} ends {r:?}"));
            }
        }
        // what no list keeps: X's lowering of the remover's own path never shows
        for &i in v.held.iter().filter(|&&i| w.commits[i].signer == X && m.lowers_remover(i)) {
            st.count("own path");
            if rd.shows(i) {
                st.fail("own path", m, format!("node {n}: X's lowering {i} of the remover's path shows"));
            }
        }
        if x_removed_a2 && !s.regrant && m.xrole.is_some_and(saved) {
            st.count("removal kept");
            if rd.role(A2, T1) > Role::None {
                st.fail("removal kept", m, format!("node {n}: A2 holds on T1 again"));
            }
        }
        // the last admin: every thing keeps a standing admin edge (no write in the story is
        // marked)
        for t in [A, A2, ORG, T1, D1, T2] {
            st.count("admin");
            if !rd.roles.iter().any(|(e, r)| e.1 == t && *r == Role::Admin) {
                st.fail("admin", m, format!("node {n}: {t} has no standing admin"));
            }
        }
        // liveness
        for &i in v.held.iter().filter(|&&i| !m.hostile(i)) {
            let c = &w.commits[i];
            let honest_now = c.signer != X;
            let want = match &c.kind {
                // M's leave applies iff the admin it names is standing: its write after shows
                // iff the leave is refused
                Kind::Content if c.signer == M => c.ts == 1 || s.mint == 2,
                Kind::Edge { holder, .. } if c.signer == M => *holder != M || s.mint == 1,
                Kind::Content if honest_now => stands(c.signer) && !(c.signer == K && x_removed_a2),
                Kind::Content => {
                    in_r(i)
                        || [H, B, N5, K].iter().any(|&a| {
                            m.sync.get(&a).is_some_and(|u| u.contains(&c.on)) && wrote(a) && m.got(i, a, REMOVAL) && m.recv[m.r].contains_key(&a)
                        })
                }
                Kind::Edge { .. } if honest_now => c.signer == H || c.signer == K || i == m.gs || (m.made[i] == AFTER && b_admin),
                Kind::Edge { .. } => saved(i) && !m.lowers_remover(i),
                _ => false,
            };
            if want {
                st.count("liveness");
                if !rd.shows(i) {
                    st.fail("liveness", m, format!("node {n}: commit {i} does not show"));
                }
            }
        }
    }
    // alike: two nodes read a commit they both hold in a unit they both sync alike
    for (&n, (vn, rn)) in &rds {
        for (&o, (vo, ro)) in rds.range(n + 1..) {
            for &i in vn.held.intersection(&vo.held) {
                if m.sync[&n].contains(&w.commits[i].on) && m.sync[&o].contains(&w.commits[i].on) {
                    st.count("alike");
                    if rn.shows(i) != ro.shows(i) {
                        st.fail("alike", m, format!("nodes {n} and {o} read commit {i} otherwise"));
                    }
                }
            }
        }
    }
}

/// Random world `i`: its own generator, so a search's worlds do not depend on the core count.
pub fn random_world(i: u64, rules: &Rules) -> Sim {
    let mut rng = Rng::thread(0x9a7b, i as usize);
    let b = |rng: &mut Rng| rng.below(2) == 0;
    let s = Setup {
        h_t1: b(&mut rng),
        h_t2: b(&mut rng),
        b_offline: b(&mut rng),
        sharer_x: b(&mut rng),
        n5: rng.below(3) as u8,
        x_role: rng.below(4) as u8,
        x_role_seen: b(&mut rng),
        x_a2: rng.below(4) as u8,
        b_side_x: rng.below(4) == 0,
        regrant: b(&mut rng),
        mint: rng.below(3) as u8,
        x_first: rng.below(4) == 0,
    };
    let moves: Vec<Move> = (0..rng.below(5)).map(|_| Move { kind: rng.below(MOVES), ts: 1 + rng.below(10) as u32, made: 7 + rng.below(4) as u32 }).collect();
    Sim::build(&s, rules, &moves, &mut rng)
}

/// Random worlds `0..n` on every core.
pub fn random(n: u64, rules: &Rules) -> Stats {
    crate::on_every_core(|th, threads, st: &mut Stats| {
        for i in (th as u64..n).step_by(threads) {
            check(&random_world(i, rules), rules, st);
        }
    })
}

/// The small family: every setup, each with one move of the thief stamped before or after the
/// removal; `mint` and `x_first` as one dimension (none, M naming H, M naming timed B, X
/// removing H first). `i` in `0..FAMILY`.
pub const FAMILY: usize = 2 * 2 * 2 * 2 * 3 * 4 * 2 * 4 * 2 * 2 * 4 * MOVES * 2;

pub fn family(mut i: usize, rules: &Rules) -> Sim {
    let mut take = |n: usize| {
        let v = i % n;
        i /= n;
        v
    };
    let mut s = Setup {
        h_t1: take(2) == 1,
        h_t2: take(2) == 1,
        b_offline: take(2) == 1,
        sharer_x: take(2) == 1,
        n5: take(3) as u8,
        x_role: take(4) as u8,
        x_role_seen: take(2) == 1,
        x_a2: take(4) as u8,
        b_side_x: take(2) == 1,
        regrant: take(2) == 1,
        ..Setup::default()
    };
    match take(4) {
        3 => s.x_first = true,
        k => s.mint = k as u8,
    }
    let mv = Move { kind: take(MOVES), ts: if take(2) == 1 { 3 } else { 8 }, made: 7 };
    Sim::build(&s, rules, &[mv], &mut Rng(0))
}

/// The small family on every core, every `stride`th world.
pub fn family_run(rules: &Rules, stride: usize) -> Stats {
    crate::on_every_core(|th, threads, st: &mut Stats| {
        for i in (th * stride..FAMILY).step_by(threads * stride) {
            check(&family(i, rules), rules, st);
        }
    })
}

/// The rules a mode runs: `paths` the fixed rules; `paths-design` the first round's reading;
/// controls, each the fixed rules with one rule undone: `-kept` (no list reads an entry as
/// absent), `-chain` (absent read from the static chain), `-any` (every lowering absent),
/// `-any-edge` (the last-admin rule reads every admin edge), `-timed` (a timed admin edge counts
/// as standing), `-own-vouch` (a vouch counts for its own signer's commit), `-first-applied` (a re-granted path counts
/// from the first point the settled walk gave it), `-once` (a node answers a removal only the first
/// time its walk applies it), `-leave` (a self-removal is never put in question). `-exh` runs the
/// small family in place of random worlds.
pub fn mode_rules(mode: &str) -> Option<Rules> {
    let f = Rules::fixed();
    Some(match mode.trim_start_matches("paths").trim_start_matches("-exh") {
        "" => f,
        "-design" => Rules::design(),
        "-kept" => Rules { list_own: ListOwn::Kept, ..f },
        "-chain" => Rules { list_own: ListOwn::Chain, ..f },
        "-any" => Rules { list_own: ListOwn::AnyLowering, ..f },
        "-any-edge" => Rules { last_admin: LastAdmin::AnyEdge, ..f },
        "-timed" => Rules { last_admin: LastAdmin::NamedTimed, ..f },
        "-own-vouch" => Rules { no_own_vouch: false, ..f },
        "-first-applied" => Rules { regrant: Regrant::FirstApplied, ..f },
        "-once" => Rules { rewrite: false, ..f },
        "-leave" => Rules { leave_in_question: false, ..f },
        _ => return None,
    })
}

/// `-- N paths[-control]` (random worlds), `-- 0 paths-exh[-control]` (the small family).
/// Returns the failing checks.
pub fn run(samples: u64, mode: &str) -> u64 {
    let Some(rules) = mode_rules(mode) else {
        eprintln!("unknown mode {mode}");
        return 1;
    };
    // `-- N paths-exh`: every Nth family world (N 0 or 1: all of them)
    let st = if mode.starts_with("paths-exh") { family_run(&rules, samples.max(1) as usize) } else { random(samples, &rules) };
    st.print(mode, &rules);
    st.failures()
}
