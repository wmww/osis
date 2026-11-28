//! Purge worlds (notes/purge-model.md): purge requests of every class and selector by honest
//! parties and by the thief, a destruction, a cover's copies, an own cover whose writer is removed
//! later, and the bodies each node erased on the way. The properties (`check`) are computed from
//! the generated history, never from a reading.
//!
//! Account A (mint H) administers T1 (record grant); X and B are admins of A (H's grants), W a
//! writer of T1 by its own grant, A2 (K's) holds write or admin on T1 (B's share) and X write or
//! admin on A2 or nothing (K's grant): [A2] is a path X keeps. Content on T1 at 2 to 4 by H, B, W,
//! K and X, each delta's purge-by and purge author drawn. X may purge at 4 (H and the witnesses
//! B, W receiving it in time or not). X is stolen at 5; H removes X at 6 listing what it received
//! through (X, A) by 5. Witnesses write addenda at 7 (purge requests listed only under
//! `Rules::purge_addenda`, the writing rule following the reading). K may compact T1 at 8. Honest
//! requests and a destruction at 9. In own-cover worlds H writes its own cover of T1 at 5 carrying
//! X's writes it holds, forgets them, names the cover in its removal, and B removes H at 9 having
//! received the cover in time or not. The thief's moves: requests along [A] (backdated, made before
//! the removal, racing it, or after) and along [A2], destructions along each, and a hidden write
//! that a request names. Nodes: H, B, W, K, readers RD (T1) and LJ (T1, joining at 8: it holds
//! only what was made from then, so earlier writes only as a cover's copies), N6 trusting nothing.
//! One world in four (`PSetup::o_cut`) adds a path with two cuts: X admin on ORG (M's), ORG admin
//! on T1 (B's), B removing ORG from T1 at 3, the thief requesting or destroying along [ORG] from
//! then, and M removing X from ORG at 6 listing everything X made through it.

use super::*;

pub const W: Thing = 23;
pub const LJ: Thing = 24;
const STOLEN: u32 = 5;
const REMOVAL: u32 = 6;
const JOIN: u32 = 8;
const SETTLE: u32 = 11;

/// One purge world's choices.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PSetup {
    /// A2's share on T1 is admin (else write).
    pub ra_admin: bool,
    /// X's grant on A2: 0 none, 1 write, 2 admin.
    pub rx: u8,
    /// X's request at 4 along [A]: 0 none, else `names` of it (1 author X, 2 author A, 3 aspect,
    /// 4 commit), and who received it in time.
    pub x_req: u8,
    pub h_saw: bool,
    pub b_saw: bool,
    pub w_saw: bool,
    pub cover: bool,
    /// H's own cover at 5 and B's removal of H at 9, B having received the cover by then or not.
    pub own: bool,
    pub b_saw_own: bool,
    /// A destruction of T1 at 9 by B.
    pub destroy: bool,
    /// Two cuts on two grants of one path (notes/evidence-model-findings.md 26): ORG (M's) holds
    /// admin on T1 (B's grant at 1) and X admin on ORG (M's grant at 1); B removes ORG from T1 at
    /// 3, listing what it received through it; the thief requests or destroys along [ORG] after
    /// that, and M, hoodwinked, removes X from ORG at the removal listing everything X made
    /// through it. M's list answers M's cut alone: the requests hold nothing.
    pub o_cut: bool,
}

/// A thief move: `kind` 0 a request along [A], 1 along [A2], 2 a destruction along [A], 3 along
/// [A2], 4 a hidden write and a request naming it, 5 a request along [ORG], 6 a destruction along
/// [ORG] (`PSetup::o_cut`); `sel` its names (as `PSetup::x_req`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PMove {
    pub kind: u8,
    pub sel: u8,
    pub ts: u32,
    pub made: u32,
}

#[derive(Clone, Debug)]
pub struct PWorld {
    pub w: World,
    pub setup: PSetup,
    pub moves: Vec<PMove>,
    pub made: Vec<u32>,
    pub recv: Vec<BTreeMap<Thing, u32>>,
    pub sync: BTreeMap<Thing, Things>,
    /// H's removal of X; B's removal of H; H's own cover; what H forgot under it; B's removal of
    /// ORG from T1 and M's of X from ORG (`PSetup::o_cut`).
    pub r: Id,
    pub rb: Option<Id>,
    pub rm: Option<Id>,
    pub rh: Option<Id>,
    pub own: Option<Id>,
    pub forgot: Set,
    /// The thief's commits (made from the theft on).
    pub thief: Set,
    pub index: u64,
}

fn path_of(n: Thing) -> Vec<Thing> {
    match n {
        H | B | X => vec![A],
        K => vec![A2],
        _ => vec![],
    }
}

impl PWorld {
    fn deliver(&mut self, i: Id, made: u32, rng: &mut Rng, late: bool, logged: &[Thing]) {
        let mut units = Things::from([self.w.commits[i].on]);
        units.extend(logged);
        let signer = self.w.commits[i].signer;
        self.made.push(made);
        let mut recv = BTreeMap::new();
        for (&n, s) in &self.sync {
            if !s.iter().any(|u| units.contains(u)) || (n == LJ && made < JOIN) {
                continue;
            }
            let t = if n == signer || n == X { made } else if late && rng.below(2) == 0 { SETTLE.max(made) } else { made + rng.below(2) as u32 };
            recv.insert(n, t);
        }
        self.recv.push(recv);
    }
    fn put(&mut self, signer: Thing, ts: u32, path: &[Thing], on: Thing, kind: Kind, made: u32, rng: &mut Rng, late: bool) -> Id {
        let i = self.w.push(signer, ts, path, on, kind);
        self.deliver(i, made, rng, late, &[]);
        i
    }
    pub fn got(&self, i: Id, n: Thing, by: u32) -> bool {
        self.recv[i].get(&n).is_some_and(|t| *t <= by)
    }
    pub fn held_at(&self, n: Thing, t: Option<u32>) -> Set {
        let avail: Set = (0..self.w.commits.len()).filter(|&i| t.is_none_or(|t| self.made[i] <= t)).collect();
        let unit: Set = avail.iter().copied().filter(|&i| self.recv[i].get(&n).is_some_and(|r| t.is_none_or(|t| *r <= t))).collect();
        let mut held = evidence(&self.w, &unit, &avail);
        if n == H && self.own.is_some_and(|s| t.is_none_or(|t| self.made[s] <= t)) {
            held.retain(|i| !self.forgot.contains(i));
        }
        held
    }
    pub fn view_at(&self, n: Thing, t: Option<u32>) -> View {
        let held = self.held_at(n, t);
        let trust = if n == N6 { Set::new() } else { [Some(self.r), self.rh].into_iter().flatten().filter(|i| held.contains(i)).collect() };
        View { held, leaves: None, trust }
    }
    pub fn nodes(&self) -> [Thing; 7] {
        [H, B, W, K, RD, LJ, N6]
    }
    fn names(&self, sel: u8, rng: &mut Rng) -> Names {
        match sel {
            1 => Names::Author(X),
            2 => Names::Author(A),
            3 => Names::Aspect,
            _ => {
                let on: Vec<Id> = (0..self.w.commits.len()).filter(|&i| matches!(self.w.commits[i].kind, Kind::Content)).collect();
                if on.is_empty() { Names::Aspect } else { Names::Commit(on[rng.below(on.len())]) }
            }
        }
    }
    /// An addendum per honest writer of T1 against removal `r` of `who`'s grant `h`, listing what
    /// it received through `h` on T1 by `r`'s `ts` that `r` does not list: content, and purge
    /// requests under `purge_addenda`.
    fn answer(&mut self, r: Id, h: Grant, rules: &Rules, rng: &mut Rng) {
        let rts = self.w.commits[r].ts;
        for n in [H, B, W, K] {
            if n == self.w.commits[r].signer || n == h.0 {
                continue;
            }
            let list: Vec<Id> = (0..self.w.commits.len())
                .filter(|&i| self.w.commits[i].on == T1 && self.w.hops(i).contains(&h) && self.got(i, n, rts) && !self.w.in_frontier(r, i))
                .filter(|&i| matches!(self.w.commits[i].kind, Kind::Content) || (rules.purge_addenda && matches!(self.w.commits[i].kind, Kind::Purge { .. })))
                .collect();
            if !list.is_empty() {
                self.put(n, rts + 1, &path_of(n), T1, Kind::Addendum { removal: r, list: list.into_iter().collect() }, rts + 1, rng, false);
            }
        }
    }
}

/// A content write on T1 by `n` at `t`, its purge-by and purge author drawn.
fn write(m: &mut PWorld, n: Thing, t: u32, path: &[Thing], rng: &mut Rng) -> Id {
    let i = m.put(n, t, path, T1, Kind::Content, t, rng, false);
    m.w.set_purge_by(i, [PurgeBy::Admin, PurgeBy::AuthorOrAdmin, PurgeBy::Writer][rng.below(3)]);
    if !path.is_empty() && rng.below(2) == 0 {
        m.w.authored(i, 1);
    }
    i
}

pub fn purge_build(setup: &PSetup, moves: &[PMove], rules: &Rules, rng: &mut Rng) -> PWorld {
    let s = *setup;
    let sync = BTreeMap::from([
        (H, Things::from([A, T1])),
        (B, Things::from([A, T1])),
        (X, Things::from([A, A2, T1])),
        (W, Things::from([T1])),
        (K, Things::from([A2, T1])),
        (RD, Things::from([T1])),
        (LJ, Things::from([T1])),
        (N6, Things::from([A, A2, T1])),
    ]);
    let w = World::new(&if s.o_cut { vec![(H, A), (K, A2), (A, T1), (M, ORG)] } else { vec![(H, A), (K, A2), (A, T1)] });
    let mut m = PWorld { w, setup: s, moves: moves.to_vec(), made: vec![], recv: vec![], sync, r: 0, rb: None, rm: None, rh: None, own: None, forgot: Set::new(), thief: Set::new(), index: 0 };
    let grant = Kind::set;
    m.put(H, 1, &[], A, grant(X, Role::Admin), 1, rng, false);
    m.put(H, 1, &[], A, grant(B, Role::Admin), 1, rng, false);
    m.put(H, 1, &[A], T1, grant(W, Role::Write), 1, rng, false);
    m.put(B, 1, &[A], T1, grant(A2, if s.ra_admin { Role::Admin } else { Role::Write }), 1, rng, false);
    if s.rx > 0 {
        m.put(K, 1, &[], A2, grant(X, if s.rx == 2 { Role::Admin } else { Role::Write }), 1, rng, false);
    }
    if s.o_cut {
        m.put(M, 1, &[], ORG, grant(X, Role::Admin), 1, rng, false);
        m.put(B, 1, &[A], T1, grant(ORG, Role::Admin), 1, rng, false);
    }
    for t in 2..=4 {
        for n in [H, B, W, K, X] {
            if rng.below(2) == 0 {
                write(&mut m, n, t, &path_of(n), rng);
            }
        }
        if s.rx > 0 && rng.below(2) == 0 {
            write(&mut m, X, t, &[A2], rng);
        }
    }
    if s.x_req > 0 {
        let names = m.names(s.x_req, rng);
        let q = m.put(X, 4, &[A], T1, Kind::Purge { names }, 4, rng, false);
        for (n, saw) in [(H, s.h_saw), (B, s.b_saw), (W, s.w_saw)] {
            m.recv[q].insert(n, if saw { 4 } else { SETTLE });
        }
    }
    if s.o_cut {
        let f = m.w.cut(&m.w.through((ORG, T1), |i| m.got(i, B, 3)));
        m.rb = Some(m.put(B, 3, &[A], T1, grant(ORG, Role::None).listing(f), 3, rng, false));
    }
    let thief = |m: &mut PWorld, mv: &PMove, rng: &mut Rng| {
        let first = m.w.commits.len();
        let late = mv.made > REMOVAL;
        let a2 = matches!(mv.kind, 1 | 3);
        if (a2 && s.rx == 0) || (mv.kind >= 5 && !s.o_cut) {
            return;
        }
        let path: &[Thing] = if a2 { &[A2] } else if mv.kind >= 5 { &[ORG] } else { &[A] };
        let names = match mv.kind {
            2 | 3 | 6 => Names::Destroy,
            4 => {
                let hidden = m.put(X, mv.ts.min(4), path, T1, Kind::Content, mv.made, rng, true);
                Names::Commit(hidden)
            }
            _ => m.names(mv.sel, rng),
        };
        m.put(X, mv.ts, path, T1, Kind::Purge { names }, mv.made, rng, late);
        for i in first..m.w.commits.len() {
            m.thief.insert(i);
            if mv.made <= STOLEN {
                // heard by H and B before the removal
                for n in [H, B] {
                    m.recv[i].insert(n, mv.made);
                }
            }
        }
    };
    for mv in moves.iter().filter(|mv| mv.made <= STOLEN) {
        thief(&mut m, mv, rng);
    }
    if s.own {
        // H's own cover of T1 carrying X's writes showing in its walk, then forgotten
        let v = m.view_at(H, Some(STOLEN));
        let rd = judge(&m.w, rules, &v);
        let carries: Set = rd.valid.iter().chain(&rd.copied).copied().filter(|&i| m.w.commits[i].signer == X && m.w.commits[i].on == T1 && matches!(m.w.commits[i].kind, Kind::Content) && !rd.purged.contains(&i)).collect();
        let c = m.put(H, STOLEN, &[A], T1, Kind::Cover { carries: carries.clone() }, STOLEN, rng, false);
        m.w.own_cover(c);
        m.recv[c].insert(B, if s.b_saw_own { STOLEN } else { SETTLE });
        m.own = Some(c);
        m.forgot = carries;
    }
    let mut listed = m.w.through((X, A), |i| m.got(i, H, STOLEN) && m.made[i] <= STOLEN && !m.forgot.contains(&i));
    listed.extend(m.own);
    let f = m.w.cut(&listed);
    m.r = m.w.push(H, REMOVAL, &[], A, grant(X, Role::None).listing(f));
    m.deliver(m.r, REMOVAL, rng, false, &[T1]);
    if s.o_cut {
        // M, hoodwinked, lists everything X made through (X, ORG) by the theft
        let f = m.w.cut(&m.w.through((X, ORG), |i| m.made[i] <= STOLEN));
        let rm = m.w.push(M, REMOVAL, &[], ORG, grant(X, Role::None).listing(f));
        m.deliver(rm, REMOVAL, rng, false, &[T1]);
        m.rm = Some(rm);
    }
    for mv in moves.iter().filter(|mv| mv.made > STOLEN) {
        thief(&mut m, mv, rng);
    }
    m.answer(m.r, (X, A), rules, rng);
    if s.cover {
        // K compacts T1: what shows in its walk, a purged write carried by nothing
        let v = m.view_at(K, Some(JOIN));
        let rd = judge(&m.w, rules, &v);
        let carries: Set = rd.valid.iter().chain(&rd.copied).copied().filter(|&i| m.w.commits[i].on == T1 && matches!(m.w.commits[i].kind, Kind::Content) && !rd.purged.contains(&i)).collect();
        m.put(K, JOIN, &[A2], T1, Kind::Cover { carries }, JOIN, rng, false);
    }
    for _ in 0..rng.below(3) {
        let n = [H, B, W, K][rng.below(4)];
        if s.own && n == H {
            continue;
        }
        let names = m.names(1 + rng.below(4) as u8, rng);
        m.put(n, 9, &path_of(n), T1, Kind::Purge { names }, 9, rng, false);
    }
    if s.destroy {
        m.put(B, 9, &[A], T1, Kind::Purge { names: Names::Destroy }, 9, rng, false);
    }
    if s.own {
        let all = m.w.through((H, A), |i| m.got(i, B, 9));
        let f = m.w.cut(&all);
        let rh = m.w.push(B, 9, &[], A, grant(H, Role::None).listing(f));
        m.rh = Some(rh);
        m.deliver(rh, 9, rng, false, &[T1]);
        m.answer(rh, (H, A), rules, rng);
    }
    // the settle: everything reaches every node syncing its unit (LJ what was made from 8)
    for i in 0..m.w.commits.len() {
        let mut units = Things::from([m.w.commits[i].on]);
        if Some(i) == Some(m.r) || Some(i) == m.rh {
            units.insert(T1);
        }
        for (&n, s) in &m.sync {
            if s.iter().any(|u| units.contains(u)) && !(n == LJ && m.made[i] < JOIN) {
                let t = m.recv[i].entry(n).or_insert(SETTLE);
                *t = (*t).min(SETTLE.max(m.made[i]));
            }
        }
    }
    m
}

pub fn purge_world(i: u64, rules: &Rules) -> PWorld {
    let mut rng = Rng::thread(0x9e7a, i as usize);
    let b = |rng: &mut Rng| rng.below(2) == 0;
    let s = PSetup {
        ra_admin: b(&mut rng),
        rx: rng.below(3) as u8,
        x_req: rng.below(5) as u8,
        h_saw: b(&mut rng),
        b_saw: b(&mut rng),
        w_saw: b(&mut rng),
        cover: b(&mut rng),
        own: rng.below(4) == 0,
        b_saw_own: b(&mut rng),
        destroy: rng.below(8) == 0,
        o_cut: false,
    };
    let mut moves: Vec<PMove> = (0..rng.below(4))
        .map(|_| {
            let made = [STOLEN, REMOVAL, 7, 8, 9][rng.below(5)];
            PMove { kind: rng.below(5) as u8, sel: 1 + rng.below(4) as u8, ts: 1 + rng.below(9) as u32, made }
        })
        .collect();
    // (drawn apart, so the worlds without it are drawn as before)
    let mut more = Rng::thread(0x9e7b, i as usize);
    let s = PSetup { o_cut: more.below(4) == 0, ..s };
    if s.o_cut {
        for _ in 0..1 + more.below(2) {
            moves.push(PMove { kind: 5 + more.below(2) as u8, sel: 1 + more.below(4) as u8, ts: 1 + more.below(STOLEN as usize) as u32, made: STOLEN });
        }
    }
    let mut m = purge_build(&s, &moves, rules, &mut rng);
    m.index = i;
    m
}

/// Failures and counts per check, the first world of each (index, what).
#[derive(Clone, Debug, Default)]
pub struct PStats {
    pub worlds: u64,
    pub checked: BTreeMap<&'static str, u64>,
    pub fails: BTreeMap<&'static str, u64>,
    pub noted: BTreeMap<&'static str, u64>,
    pub first: BTreeMap<&'static str, (u64, String)>,
}

impl crate::Tally for PStats {
    fn merge(&mut self, o: PStats) {
        self.worlds += o.worlds;
        crate::Tally::merge(&mut self.checked, o.checked);
        crate::Tally::merge(&mut self.fails, o.fails);
        crate::Tally::merge(&mut self.noted, o.noted);
        for (k, f) in o.first {
            let e = self.first.entry(k).or_insert(f.clone());
            if f.0 < e.0 {
                *e = f;
            }
        }
    }
}

impl PStats {
    pub fn failures(&self) -> u64 {
        self.fails.values().sum()
    }
    fn count(&mut self, k: &'static str) {
        *self.checked.entry(k).or_default() += 1;
    }
    fn fail(&mut self, k: &'static str, i: u64, what: String) {
        *self.fails.entry(k).or_default() += 1;
        self.first.entry(k).or_insert((i, what));
    }
    fn note(&mut self, k: &'static str, i: u64, what: String) {
        *self.noted.entry(k).or_default() += 1;
        self.first.entry(k).or_insert((i, what));
    }
    pub fn print(&self, name: &str) {
        println!("{name}: {} worlds, checks {:?}, noted {:?}, failing {:?}", self.worlds, self.checked, self.noted, self.fails);
        for (k, (i, what)) in &self.first {
            println!("{} {k}: world {i}: {what}", if self.fails.contains_key(k) { "FAIL" } else { "NOTED" });
        }
    }
}

/// What request `q` names among `cands`, by its selector alone.
fn named(w: &World, q: Id, d: Id) -> bool {
    let (Kind::Purge { names }, c) = (&w.commits[q].kind, &w.commits[d]) else { return false };
    let names = *names;
    c.on == w.commits[q].on
        && match names {
            Names::Author(a) => c.ts < w.commits[q].ts && w.purge_author(d) == a,
            Names::Aspect => c.ts < w.commits[q].ts,
            Names::Commit(j) => w.cid(j) == w.cid(d) && c.ts < w.commits[q].ts,
            Names::Destroy => true,
        }
}

/// Whether `q`'s right (admin, write) reaches `d`: the members of `d`'s purge-by set it holds.
fn reaches(w: &World, q: Id, d: Id, admin: bool, write: bool) -> bool {
    if matches!(w.commits[q].kind, Kind::Purge { names: Names::Destroy }) {
        return admin;
    }
    admin
        || (write
            && match w.commits[d].purge_by {
                PurgeBy::Admin => false,
                PurgeBy::AuthorOrAdmin => w.chain(q).contains(&w.purge_author(d)),
                PurgeBy::Writer => true,
            })
}

/// A store that cannot judge acts on a request that could hold the right (spec/commits.md §4
/// Could hold the right): each grant of its path a record grant or set at `r` or above by some held
/// grant write, whatever its validity.
pub fn could_hold(w: &World, held: &Set, q: Id, r: Role) -> bool {
    w.well(q) && w.hops(q).iter().all(|e| w.records.contains(e) || held.iter().any(|&j| w.sets(j) == Some(*e) && matches!(w.commits[j].kind, Kind::Grant { role, .. } if role >= r)))
}

/// The properties at every node's final reading, and the bodies erased along the way (counted).
pub fn purge_check(m: &PWorld, rules: &Rules, st: &mut PStats) {
    st.worlds += 1;
    let w = &m.w;
    let i = m.index;
    let s = &m.setup;
    let ra = if s.ra_admin { Role::Admin } else { Role::Write };
    let xa2 = [Role::None, Role::Write, Role::Admin][s.rx as usize].min(ra);
    // the own cover stands while H's removal applies: B listed it, or B removed nobody
    let own_stands = m.rh.is_none_or(|rh| w.in_frontier(rh, m.r));
    // the roles a request holds by the story (admin, write), with and without a witness's word;
    // a witness is an honest writer that received it by the removal's `ts` (B, W; K by A2's share)
    let story = |q: Id, held: &Set| -> ((bool, bool), (bool, bool)) {
        let c = &w.commits[q];
        let by = |r: Role| (r == Role::Admin, r >= Role::Write);
        let base = match (c.signer, c.path.as_slice()) {
            (H, _) => by(if m.rh.is_some_and(|rh| held.contains(&rh) && !w.in_frontier(rh, q)) { Role::None } else { Role::Admin }),
            (B, _) => by(Role::Admin),
            (W, _) => by(Role::Write),
            (K, _) => by(ra),
            // (X's grant on A2 is stamped 1: a request stamped 1 is ordered before it)
            (X, [A2]) => by(if c.ts > 1 { xa2 } else { Role::None }),
            // X along [ORG]: past B's cut of (ORG, T1) at 3 and M's of (X, ORG), each answered by
            // its own list alone, after X's grant (stamped 1); a destruction alike (§6)
            (X, [ORG]) => by(if c.ts > 1 && m.rb.is_some_and(|rb| w.in_frontier(rb, q)) && m.rm.is_some_and(|rm| w.in_frontier(rm, q)) { Role::Admin } else { Role::None }),
            // X along [A]: before the removal, kept by H's list where X's grant on A (stamped 1)
            // gave it admin: a list answers its cut, never a role the path did not give
            (X, _) => by(if w.in_frontier(m.r, q) && c.ts > 1 { Role::Admin } else { Role::None }),
            _ => (false, false),
        };
        let mut req = base;
        // (stamped after the removal, nothing vouches for it: it is no edit made before it)
        if c.signer == X && c.path == [A] && !w.in_frontier(m.r, q) && m.made[q] <= REMOVAL && c.ts > 1 && c.ts <= REMOVAL && held.contains(&m.r) {
            for (wit, r) in [(B, Role::Admin), (W, Role::Write), (K, ra)] {
                if m.got(q, wit, REMOVAL) {
                    req = (req.0 || r == Role::Admin, req.1 || r >= Role::Write);
                }
            }
        }
        (base, req)
    };
    let reads: BTreeMap<Thing, (View, Reading)> = m.nodes().into_iter().map(|n| {
        let v = m.view_at(n, None);
        let rd = judge(w, rules, &v);
        (n, (v, rd))
    }).collect();
    for (&n, (v, rd)) in &reads {
        // the deltas a node may purge: held content, and the content a cover it holds and the story
        // keeps standing carries
        let mut cands: Set = v.held.iter().copied().filter(|&d| matches!(w.commits[d].kind, Kind::Content)).collect();
        for &c in &v.held {
            if let Kind::Cover { carries } = &w.commits[c].kind {
                if Some(c) != m.own || own_stands {
                    cands.extend(carries.iter().copied());
                }
            }
        }
        let (mut rule, mut req) = (Set::new(), Set::new());
        for &q in v.held.iter().filter(|&&q| matches!(w.commits[q].kind, Kind::Purge { .. })) {
            let (base, with) = story(q, &v.held);
            let base = if rules.purge_addenda { with } else { base };
            for &d in cands.iter().filter(|&&d| named(w, q, d)) {
                if reaches(w, q, d, base.0, base.1) {
                    rule.insert(d);
                }
                if reaches(w, q, d, with.0, with.1) {
                    req.insert(d);
                }
            }
        }
        st.count("purge kept");
        if !rule.is_subset(&rd.purged) {
            st.fail("purge kept", i, format!("node {n}: purged {:?}, wanted at least {rule:?}", rd.purged));
        }
        st.count("purge safety");
        if !rd.purged.is_subset(&req) {
            st.fail("purge safety", i, format!("node {n}: purged {:?}, wanted at most {req:?}", rd.purged));
        }
        st.count("purge witnessed");
        if !req.is_subset(&rd.purged) && rule.is_subset(&rd.purged) && rd.purged.is_subset(&req) {
            st.fail("purge witnessed", i, format!("node {n}: a request only a witness received in time purges {:?}, nothing", req.difference(&rd.purged).collect::<Vec<_>>()));
        }
        // a store that cannot judge would have acted on every request that holds the right
        for &d in &rd.purged {
            st.count("could hold");
            let need = |q: Id| if w.commits[d].purge_by == PurgeBy::Admin || matches!(w.commits[q].kind, Kind::Purge { names: Names::Destroy }) { Role::Admin } else { Role::Write };
            if !v.held.iter().any(|&q| named(w, q, d) && could_hold(w, &v.held, q, need(q))) {
                st.fail("could hold", i, format!("node {n}: {d} purged by no request a store could act on"));
            }
        }
        // the own cover: X's writes H forgot under it show at H while H's removal applies
        if let (Some(c), H) = (m.own, n) {
            for &d in &m.forgot {
                st.count("own cover");
                let shows = rd.copied.contains(&d) || rd.valid.contains(&d);
                if shows != own_stands && !rd.purged.contains(&d) {
                    st.fail("own cover", i, format!("node H: X's {d} carried by its own cover {c} shows {shows}, its removal applying {own_stands}"));
                }
            }
        }
    }
    // alike: two nodes holding the same requests on T1 read a delta both may purge alike
    let reqs = |v: &View| -> Set { v.held.iter().copied().filter(|&q| matches!(w.commits[q].kind, Kind::Purge { .. })).collect() };
    let nodes: Vec<&Thing> = reads.keys().collect();
    for (k, &&n) in nodes.iter().enumerate() {
        for &&o in &nodes[k + 1..] {
            let ((vn, rn), (vo, ro)) = (&reads[&n], &reads[&o]);
            if reqs(vn) != reqs(vo) || n == N6 || o == N6 {
                continue;
            }
            let both = |d: &Id| (vn.held.contains(d) || rn.copied.contains(d)) && (vo.held.contains(d) || ro.copied.contains(d));
            for d in (0..w.commits.len()).filter(|&d| matches!(w.commits[d].kind, Kind::Content) && both(&d)) {
                st.count("alike");
                if rn.purged.contains(&d) != ro.purged.contains(&d) {
                    st.fail("alike", i, format!("nodes {n} and {o} read the purge of {d} otherwise"));
                }
            }
        }
    }
    // bodies: what each honest node erased along the way (a purge judged then); a write no final
    // reading purges is restored from a node that never erased it, or lost
    let mut erased: BTreeMap<Thing, Set> = BTreeMap::new();
    for n in [H, B, W, K, RD, LJ, N6] {
        let mut last = None;
        for t in 2..=SETTLE {
            let v = m.view_at(n, Some(t));
            if last.as_ref() == Some(&v) {
                continue;
            }
            let rd = judge(w, rules, &v);
            erased.entry(n).or_default().extend(rd.purged.intersection(&v.held));
            last = Some(v);
        }
    }
    for d in (0..w.commits.len()).filter(|&d| matches!(w.commits[d].kind, Kind::Content) && !m.thief.contains(&d)) {
        let shown = reads.iter().any(|(_, (_, rd))| rd.shows(d) && !rd.purged.contains(&d));
        let ever: Vec<Thing> = reads.keys().copied().filter(|n| erased[n].contains(&d)).collect();
        if !shown || ever.is_empty() {
            continue;
        }
        st.count("bodies");
        let survives = reads.iter().any(|(n, (v, _))| v.held.contains(&d) && !erased[n].contains(&d));
        let by_thief = reads.values().any(|(v, _)| v.held.iter().any(|&q| m.thief.contains(&q) && named(w, q, d)));
        let what = format!("{d} shows, erased at {ever:?} on the way");
        match (survives, by_thief) {
            (true, _) => st.note("restored from a body", i, what),
            (false, true) => st.note("lost to the thief's window", i, what),
            (false, false) => st.note("lost: an honest purge fell", i, what),
        }
    }
}

pub fn purge_run_from(start: u64, n: u64, rules: &Rules) -> PStats {
    crate::on_every_core(|th, threads, st: &mut PStats| {
        for i in (start + th as u64..start + n).step_by(threads) {
            purge_check(&purge_world(i, rules), rules, st);
        }
    })
}

/// The rules of `paths-purge[-variant]`: the draft's (`Rules::purging`), `-fixed` (the `author`
/// class alone), `-addenda` (an addendum vouches for a purge request: OPEN-proposed), `-at-key` (a
/// request's right read at its key alone: "gone means gone"), `-no-copies`, `-no-own-cover`.
pub fn purge_rules(mode: &str) -> Option<Rules> {
    let p = Rules::purging();
    Some(match mode.strip_prefix("paths-purge")? {
        "" => p,
        "-fixed" => Rules::fixed(),
        "-addenda" => Rules { purge_addenda: true, ..p },
        "-at-key" => Rules { purge_at_key: true, ..p },
        "-no-copies" => Rules { purge_copies: false, ..p },
        "-no-own-cover" => Rules { own_cover: false, ..p },
        "-list-any-cut" => Rules { answers: Answers::AnyCut, ..p },
        _ => return None,
    })
}

/// A world's commits, one a line.
pub fn purge_trace(m: &PWorld) -> String {
    let mut s = format!("{:?} moves {:?}\n", m.setup, m.moves);
    for (i, c) in m.w.commits.iter().enumerate() {
        let tag = if m.thief.contains(&i) { " (thief)" } else { "" };
        s += &format!("  {i}: {} ts {} made {} {:?} on {}: {:?} purge_by {:?} author {}{tag}; recv {:?}\n", c.signer, c.ts, m.made[i], c.path, c.on, c.kind, c.purge_by, m.w.purge_author(i), m.recv[i]);
    }
    s
}

#[cfg(test)]
mod tests;
