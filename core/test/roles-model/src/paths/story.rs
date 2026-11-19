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
/// A guest X invites to read T1 through A2 (`Setup::x_a2` 1, 2): an invite grant.
pub const G: Thing = 9;
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
/// Nodes that trust nothing (paired after the fact, or a reader that never chose a side): N6
/// syncs what B does, RD3 only T1 and D1. Neither writes.
pub const RD3: Thing = 22;

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
    /// 0: no N5; 1: X paired N5 and H received the grant before its removal; 2: H did not; 3:
    /// H paired N5 at 1 and X removed it at 3 listing that grant, H and B receiving it then (a
    /// party removed before the theft, whose key the thief holds: `N5_MOVES`).
    pub n5: u8,
    /// X's role write before the theft. 0: none; 1: demotes B to write on A; 2: removes A2 from
    /// T1 (when B shared it); 3: grants A2 admin on T2; 4: a purge request by author A on T1 (not
    /// a role write: content-class, kept only by H's list).
    pub x_role: u8,
    /// H received it before its removal.
    pub x_role_seen: bool,
    /// 0: X holds nothing on A2; 1: write on A2; 2: write, and K removes it as H does; 3: admin
    /// on A2, and A2 admin on T1 (X administers T1 through A2 for good); 4: as 3, and B removes A2
    /// from T1 at the removal's tick, stating [A] (a removal of more than one hop).
    pub x_a2: u8,
    /// B sides with X's removal of H until its user switches at `AFTER`.
    pub b_side_x: bool,
    /// At `AFTER` H grants N5 again and B grants A2 write on T1 again.
    pub regrant: bool,
    /// 0: H mints A. 1: M mints A, pairs H at 0, writes T1 at 1, leaves A at 2 naming B (paired
    /// by H at 1) as the remaining admin, writes T1 again at 3: a reader of T1 holds B's grant
    /// only as the leave's evidence where B wrote nothing there. 2: as 1, B's admin grant timed.
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

/// The thief's menu: 23 to 27 and 28, 29 are aimed at the remover (X, or a made-up key X grants
/// admin, granting H admin, standing or until just after the removal; X removing M listing nothing,
/// or listing M's grant of H; X demoting H listing its own grant); `N5_MOVES` are signed with the
/// key of N5, removed by X before the theft (`Setup::n5` 3); 35 is X's twin of that removal; 36 is
/// N5, paired by X and kept (`Setup::n5` 1), vouching for X's role writes on A (an accomplice); 37
/// is X removing A from T1 by [A2] (where it administers T1 through A2); 38 and 39 are X's own
/// edge set timed by itself (admin until the tick after its `ts`; write until after the story);
/// 40 to 42 are invite grants through A2 (where X writes A2, its share on T1 inviting read): Z
/// invited at write (beyond the invite), at read, and at read until the next tick, finalized by
/// X then and invited again; 43 to 45 are purge requests by author: by A on T1 along [A], by A2
/// on T1 along [A2] (X's right where it keeps writing A2), by A on T1 along [A2] (an author not
/// on its chain: no right); 46 withholds the removal from K until the settle and writes T1 after
/// it, which K receives at once and compacts T1 carrying (an honest writer compacting before it
/// holds the removal); 47 is X's own cover of T1, backdated, carrying its writes there; 48 is X
/// removing H and B in one commit (spec/commits.md §2), listing nothing.
pub const MOVES: usize = 49;
/// N5 grants H admin, standing or until just after the removal; N5 removes H; N5 demotes H; N5
/// vouches against H's removal for X's role writes on A. Each stamped before X's removal of N5
/// but the vouch.
pub const N5_MOVES: std::ops::Range<usize> = 30..35;
/// The moves the thief may make at tick 5, heard by H and B before the removal (`Move::made` 5):
/// X's removal of H, those aimed at the remover but through a made-up key, and N5's.
pub fn early(kind: usize) -> bool {
    matches!(kind, 11 | 23 | 24 | 27 | 28 | 29 | 35 | 48) || N5_MOVES.contains(&kind)
}

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
    /// B's removal of A2 from T1 by [A] (`Setup::x_a2` 4).
    pub r3: Option<Id>,
    pub rx: Option<Id>,
    pub xfirst: Option<Id>,
    pub gs: Id,
    pub g5: Option<Id>,
    pub xrole: Option<Id>,
    /// X's removal of N5 before the theft (`Setup::n5` 3), N5's grant of write on T1 to B before
    /// it (which it lists), and M's grant of H (`Setup::mint`).
    pub out5: Option<Id>,
    pub gb5: Option<Id>,
    pub gh: Option<Id>,
    pub gx: Id,
    /// X's invite of G to read T1 through A2 (`Setup::x_a2` 1, 2).
    pub gi: Option<Id>,
    /// Move 46: K compacts T1 at this tick, not yet holding the removal.
    cover_by_k: Option<(u32, Id)>,
    /// Covers made by a writer whose view then lacked a removal made by then, and what they carry:
    /// the accepted window (notes/path-model-findings.md 26). A later cover carrying such a copy
    /// carries it as state, as any copy.
    pub unaware: Set,
    pub smuggled: Set,
    /// The thief's commits, each with the kind of the move that made it.
    pub thief: BTreeMap<Id, usize>,
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
        self.deliver(i, made, rng, hostile);
        i
    }
    /// One commit of several edge writes (`World::commit`), received as one.
    fn put_parts(&mut self, c: (Thing, u32, &[Thing], Thing, Vec<Kind>), made: u32, rng: &mut Rng, hostile: bool) -> Vec<Id> {
        let (signer, ts, path, on, parts) = c;
        let ids = self.w.commit(signer, ts, path, on, parts);
        self.deliver(ids[0], made, rng, hostile);
        for _ in &ids[1..] {
            self.made.push(made);
            self.recv.push(self.recv[ids[0]].clone());
        }
        ids
    }
    /// Commit `i`'s receipt times.
    fn deliver(&mut self, i: Id, made: u32, rng: &mut Rng, hostile: bool) {
        let (signer, on) = (self.w.commits[i].signer, self.w.commits[i].on);
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
        sync.insert(N6, Things::from([A, ORG, T1, D1, T2]));
        sync.insert(RD3, Things::from([T1, D1]));
        let w = if s.mint > 0 { minted_by(M) } else { account() };
        let mut m = Sim { w, spec, setup: s, made: vec![], recv: vec![], sync, r: 0, r2: None, r3: None, rx: None, xfirst: None, gs: 0, g5: None, xrole: None, out5: None, gb5: None, gh: None, gx: 0, gi: None, cover_by_k: None, unaware: Set::new(), smuggled: Set::new(), thief: BTreeMap::new(), logged: BTreeMap::new() };
        let grant = Kind::set;
        if s.mint > 0 {
            m.gh = Some(m.put((M, 0, &[], A, grant(H, Role::Admin)), 0, rng, false));
        }
        m.gx = m.put((H, 1, &[], A, grant(X, Role::Admin)), 1, rng, false);
        let until = (s.mint == 2).then_some(B_UNTIL);
        m.put((H, 1, &[], A, match until { Some(u) => grant(B, Role::Admin).until(u), None => grant(B, Role::Admin) }), 1, rng, false);
        let a2 = if s.x_a2 >= 3 { Role::Admin } else { Role::Write };
        if s.x_a2 > 0 {
            m.put((K, 1, &[], A2, grant(X, a2)), 1, rng, false);
        }
        if s.mint > 0 {
            m.put((M, 1, &[A], T1, Kind::Content), 1, rng, false);
            let f = m.w.cut(&m.w.through((M, A), |_| true));
            m.put((M, 2, &[], A, grant(M, Role::None).listing(f).relying(B)), 2, rng, false);
            m.put((M, 3, &[A], T1, Kind::Content), 3, rng, false);
        }
        let sharer = if s.sharer_x { X } else { B };
        m.gs = m.put((sharer, 2, &[A], T1, grant(A2, a2).inviting(Role::Read)), 2, rng, false);
        if (1..=2).contains(&s.x_a2) {
            // an invite grant: X's path [A2] gives write on A2 and A2's invite on T1
            m.gi = Some(m.put((X, 2, &[A2], T1, grant(G, Role::Read)), 2, rng, false));
        }
        if s.n5 == 3 {
            let g = m.put((H, 1, &[], A, grant(N5, Role::Admin)), 1, rng, false);
            let gb5 = m.put((N5, 2, &[A], T1, grant(B, Role::Write)), 2, rng, false);
            m.recv[gb5].insert(H, 2);
            m.gb5 = Some(gb5);
            // equivocation (move 35): X's twin of its removal of N5, at its `ts`, ordered before it
            // (a commit ID the thief ground), listing H's grant of N5 and not N5's grant to B
            for mv in moves.iter().filter(|mv| mv.kind == 35) {
                let f = m.w.cut(&[g]);
                let twin = m.put((X, 3, &[], A, grant(N5, Role::None).listing(f)), mv.made, rng, true);
                m.thief.insert(twin, 35);
                if mv.made < REMOVAL {
                    m.recv[twin].insert(H, mv.made);
                    m.recv[twin].insert(B, mv.made);
                }
            }
            let f = m.w.cut(&[g, gb5]);
            let out = m.put((X, 3, &[], A, grant(N5, Role::None).listing(f)), 3, rng, false);
            m.recv[out].insert(H, 3);
            m.recv[out].insert(B, 3);
            m.out5 = Some(out);
        } else if s.n5 > 0 {
            let g = m.put((X, 2, &[], A, grant(N5, Role::Admin)), 2, rng, false);
            m.recv[g].insert(H, if s.n5 == 1 { 2 } else { SETTLE });
            m.g5 = Some(g);
        }
        let x_role = if s.x_role == 2 && s.sharer_x { 0 } else { s.x_role };
        if x_role == 4 {
            // a purge request by author A on T1, before the theft (H receiving it as x_role_seen)
            let g = m.put((X, 4, &[A], T1, Kind::Purge { author: A }), 4, rng, false);
            if m.sync[&H].contains(&T1) {
                m.recv[g].insert(H, if s.x_role_seen { 4 } else { SETTLE });
            }
            m.xrole = Some(g);
        } else if x_role > 0 {
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
                            let i = m.put((n, tick, &p, on, Kind::Content), tick, rng, false);
                            // authored as the first thing on the path at odd ticks, else as the signer
                            if tick % 2 == 1 && !p.is_empty() {
                                m.w.authored(i, 1);
                            }
                        }
                    }
                }
            }
            if tick == 5 {
                // the thief's moves heard before the removal
                for mv in moves.iter().filter(|mv| mv.made < REMOVAL) {
                    m.thief(mv, rng);
                }
                if s.x_first {
                    let f = m.w.cut(&m.w.through((H, A), |_| true));
                    let i = m.put((X, 5, &[], A, grant(H, Role::None).listing(f)), 5, rng, false);
                    m.recv[i].values_mut().for_each(|t| *t = 5);
                    m.xfirst = Some(i);
                }
                m.remove(rules, rng);
            }
        }
        for mv in moves.iter().filter(|mv| mv.made >= REMOVAL) {
            m.thief(mv, rng);
        }
        if let Some((t, _)) = m.cover_by_k.take() {
            let withheld: Vec<Id> = m.removals();
            m.cover(K, t, &withheld, rules, rng);
        }
        // honest purges by author at 9: B of what A authored on T2, K of what A2 authored on T1
        m.put((B, 9, &[A, ORG], T2, Kind::Purge { author: A }), 9, rng, false);
        m.put((K, 9, &[A2], T1, Kind::Purge { author: A2 }), 9, rng, false);
        // K compacts T1 at 10, carrying what shows there in its own walk
        m.cover(K, 10, &[], rules, rng);
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
        // an honest explicit write carries its author's frontier (spec/permissions.md §5.1 step
        // 4), a re-grant included, and keeps the invite the share had
        if s.regrant {
            if s.n5 > 0 && s.n5 < 3 {
                let f = m.w.cut(&m.w.through((N5, A), |i| m.got(i, H, AFTER)));
                m.put((H, AFTER, &[], A, grant(N5, Role::Admin).listing(f)), AFTER, rng, false);
            }
            let f = m.w.cut(&m.w.through((A2, T1), |i| m.got(i, B, AFTER)));
            m.put((B, AFTER, &[A], T1, grant(A2, Role::Write).inviting(Role::Read).listing(f)), AFTER, rng, false);
        }
        m.answers(rules, rng);
        m
    }
    /// `n`'s cover of T1 at `t` along its path: the content on T1 showing in its walk then, not
    /// holding `withheld` (the thief serving it alone: the evidence closure, complete in the
    /// model, would bring the removal with the write). Marked `unaware` where its view lacks a
    /// removal made by then.
    fn cover(&mut self, n: Thing, t: u32, withheld: &[Id], rules: &Rules, rng: &mut Rng) -> Id {
        let v = self.view_at(n, Some(t), rules).without(withheld);
        let rd = judge(&self.w, rules, &v);
        let carries: Set = rd.valid.iter().chain(&rd.copied).copied().filter(|&i| self.w.commits[i].on == T1 && matches!(self.w.commits[i].kind, Kind::Content)).collect();
        let path = role_path(n, T1).expect("a writer of T1");
        let unaware = self.removals().iter().any(|&r| self.made[r] <= t && !v.held.contains(&r));
        if unaware {
            self.smuggled.extend(&carries);
        }
        let c = self.put((n, t, &path, T1, Kind::Cover { carries }), t, rng, false);
        if unaware {
            self.unaware.insert(c);
        }
        c
    }
    /// The removals at tick 6, each listing what its author had received through the edge.
    fn remove(&mut self, rules: &Rules, rng: &mut Rng) {
        let all = self.w.through((X, A), |i| self.got(i, H, REMOVAL - 1));
        let i = self.w.commits.len();
        self.logged.insert(i, Things::from([ORG, T1, T2]));
        self.r = self.put((H, REMOVAL, &[], A, Kind::set(X, Role::None).listing(self.w.cut(&all))), REMOVAL, rng, false);
        self.stand(H, self.r, &all, rules);
        if self.setup.x_a2 == 2 {
            let all = self.w.through((X, A2), |i| self.got(i, K, REMOVAL - 1));
            let i = self.w.commits.len();
            self.logged.insert(i, Things::from([T1]));
            let r2 = self.put((K, REMOVAL, &[], A2, Kind::set(X, Role::None).listing(self.w.cut(&all))), REMOVAL, rng, false);
            self.r2 = Some(r2);
            self.stand(K, r2, &all, rules);
        }
        // B removes A2 from T1 where its own walk gives it admin on A (X may have demoted it)
        if self.setup.x_a2 == 4 && judge(&self.w, rules, &self.view_at(B, Some(REMOVAL - 1), rules)).role(B, A) == Role::Admin {
            let all = self.w.through((A2, T1), |i| self.got(i, B, REMOVAL - 1));
            let r3 = self.put((B, REMOVAL, &[A], T1, Kind::set(A2, Role::None).listing(self.w.cut(&all))), REMOVAL, rng, false);
            self.r3 = Some(r3);
            self.stand(B, r3, &all, rules);
        }
    }
    /// The honest removals.
    pub fn removals(&self) -> Vec<Id> {
        [Some(self.r), self.r2, self.r3].into_iter().flatten().collect()
    }
    /// Whether `n`'s walk at `t`, trusting `r` beside its own trust set, applies removal `r` with
    /// its seeds (it is not void): where the removal's list counts, whichever side `n` is on.
    fn applies(&self, n: Thing, t: u32, r: Id, rules: &Rules) -> bool {
        let rd = judge(&self.w, rules, &self.view_at(n, Some(t), rules).trusting_also(r));
        rd.applied.contains(&r) && !rd.void.contains(&r)
    }
    /// `ids` in the order `n` received them (control `Rules::key_order`: in key order).
    fn received(&self, n: Thing, ids: impl IntoIterator<Item = Id>, rules: &Rules) -> Vec<Id> {
        let mut v: Vec<Id> = ids.into_iter().collect();
        if rules.key_order {
            v.sort_by_key(|&i| self.w.key(i));
        } else {
            v.sort_by_key(|&i| (self.recv[i].get(&n).copied(), i));
        }
        v
    }
    /// The remover's list (`Rules::stands`): everything received where its own walk then applies
    /// the removal; else the role writes one by one in the order received, each kept only where
    /// the removal still applies with it.
    fn stand(&mut self, n: Thing, r: Id, all: &[Id], rules: &Rules) {
        if !rules.stands || self.applies(n, REMOVAL, r, rules) {
            return;
        }
        let mut kept: Vec<Id> = all.iter().copied().filter(|&i| !self.w.edge_class(i)).collect();
        for c in self.received(n, all.iter().copied().filter(|&i| self.w.edge_class(i)), rules) {
            kept.push(c);
            let f = self.w.cut(&kept);
            self.w.edit(r, |k| k.listing(f));
            if !self.applies(n, REMOVAL, r, rules) {
                kept.pop();
            }
        }
        let f = self.w.cut(&kept);
        self.w.edit(r, |k| k.listing(f));
    }
    /// A vouch's list (`Rules::stands`): `list` where `n`'s walk still applies `r` with it
    /// vouched; else its commits one by one in the order received, each kept only where `r`
    /// still applies with it.
    fn vouchable(&self, n: Thing, t: u32, path: &[Thing], on: Thing, r: Id, list: Set, rules: &Rules) -> Set {
        let with = |l: &Set| {
            let mut m = self.clone();
            m.put((n, t, path, on, Kind::Vouch { removal: r, list: l.clone() }), t, &mut Rng(0), false);
            m.applies(n, t, r, rules)
        };
        if with(&list) {
            return list;
        }
        let mut kept = Set::new();
        for c in self.received(n, list, rules) {
            kept.insert(c);
            if !with(&kept) {
                kept.remove(&c);
            }
        }
        kept
    }
    /// Per removal, thing and kind (addendum for plain content on T1 and T2, vouch for role
    /// writes): the commits through the removed edge node `n` had received by the removal's
    /// `ts` that the removal does not list.
    fn owed(&self, n: Thing, rules: &Rules) -> Vec<Owed> {
        let mut out = vec![];
        for r in self.removals() {
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
                    let list = if edge && rules.stands { self.vouchable(n, t, &path, on, r, list, rules) } else { list };
                    if list.iter().all(covered) {
                        continue;
                    }
                    let kind = if edge { Kind::Vouch { removal: r, list } } else { Kind::Addendum { removal: r, list } };
                    self.put((n, t, &path, on, kind), t, rng, false);
                }
            }
        }
    }
    /// One move of the thief: any `ts`, any path, as X, as the made-up key Z or as N5 (removed
    /// earlier). A move made at tick 5 (`early`) reaches H and B by then.
    fn thief(&mut self, mv: &Move, rng: &mut Rng) {
        let first = self.w.commits.len();
        self.thief_move(mv, rng);
        for i in first..self.w.commits.len() {
            self.thief.insert(i, mv.kind);
            if mv.made < REMOVAL {
                for n in [H, B] {
                    if self.sync[&n].contains(&self.w.commits[i].on) {
                        self.recv[i].insert(n, mv.made);
                    }
                }
            }
        }
    }
    fn thief_move(&mut self, mv: &Move, rng: &mut Rng) {
        let grant = Kind::set;
        if mv.kind == 35 {
            // made with the setup (`Setup::n5` 3)
            return;
        }
        if mv.kind == 46 {
            self.recv[self.r].insert(K, SETTLE);
            let i = self.put((X, mv.ts.max(REMOVAL + 1), &[A], T1, Kind::Content), mv.made, rng, true);
            self.recv[i].insert(K, mv.made);
            self.cover_by_k = Some((mv.made + 1, i));
            return;
        }
        if mv.kind == 48 {
            self.put_parts((X, mv.ts, &[], A, vec![grant(H, Role::None), grant(B, Role::None)]), mv.made, rng, true);
            return;
        }
        if mv.kind == 47 {
            let carries = (0..self.w.commits.len()).filter(|&i| self.w.commits[i].signer == X && self.w.commits[i].on == T1 && matches!(self.w.commits[i].kind, Kind::Content)).collect();
            self.put((X, mv.ts.min(REMOVAL - 1), &[A], T1, Kind::Cover { carries }), mv.made, rng, true);
            return;
        }
        if (43..46).contains(&mv.kind) {
            let (path, author): (&[Thing], _) = match mv.kind {
                43 => (&[A], A),
                44 => (&[A2], A2),
                _ => (&[A2], A),
            };
            self.put((X, mv.ts, path, T1, Kind::Purge { author }), mv.made, rng, true);
            return;
        }
        if (40..43).contains(&mv.kind) {
            // where X writes A2 (and K may remove it): invites of Z through A2
            if !(1..=2).contains(&self.setup.x_a2) {
                return;
            }
            let ts = mv.ts;
            match mv.kind {
                40 => {
                    self.put((X, ts, &[A2], T1, grant(Z, Role::Write)), mv.made, rng, true);
                }
                41 => {
                    self.put((X, ts, &[A2], T1, grant(Z, Role::Read)), mv.made, rng, true);
                }
                _ => {
                    self.put((X, ts, &[A2], T1, grant(Z, Role::Read).until(ts + 1)), mv.made, rng, true);
                    self.put((X, ts + 1, &[A2], T1, Kind::finalize(Z)), mv.made, rng, true);
                    self.put((X, ts + 2, &[A2], T1, grant(Z, Role::Read)), mv.made, rng, true);
                }
            }
            return;
        }
        if mv.kind == 37 && self.r3.is_none() {
            // where nobody removes A2 from T1, X administers T1 through A2 by right: no move
            return;
        }
        if mv.kind == 36 {
            if self.setup.n5 != 1 {
                return;
            }
            let list = (0..self.w.commits.len()).filter(|&i| self.w.commits[i].signer == X && self.w.commits[i].on == A && self.w.edge_class(i)).collect();
            self.put((N5, mv.ts.max(REMOVAL + 1), &[], A, Kind::Vouch { removal: self.r, list }), mv.made, rng, true);
            return;
        }
        if N5_MOVES.contains(&mv.kind) {
            // N5's key, removed by X at 3: stamped before that, but the vouch
            let Some(_) = self.out5 else { return };
            let ts = mv.ts.min(2);
            let c: (u32, Kind) = match mv.kind {
                30 => (ts, grant(H, Role::Admin)),
                31 => (ts, grant(H, Role::Admin).until(REMOVAL + 1)),
                32 => (ts, grant(H, Role::None)),
                33 => (ts, grant(H, Role::Write)),
                _ => {
                    let list = (0..self.w.commits.len()).filter(|&i| self.w.commits[i].signer == X && self.w.commits[i].on == A && self.w.edge_class(i)).collect();
                    (mv.ts.max(REMOVAL + 1), Kind::Vouch { removal: self.r, list })
                }
            };
            self.put((N5, c.0, &[], A, c.1), mv.made, rng, true);
            return;
        }
        let mine = |m: &Sim, on: Thing, edge: bool| -> Set { (0..m.w.commits.len()).filter(|&i| m.w.commits[i].signer == X && m.w.commits[i].on == on && m.w.edge_class(i) == edge && m.w.hops(i).contains(&(X, A))).collect() };
        if mv.kind == 19 {
            // a grant through the cut path, backdated, and X's own vouch for it along A2
            self.put((X, mv.ts.min(5), &[A], T1, grant(Z, Role::Write)), mv.made, rng, true);
            let list = mine(self, T1, true);
            self.put((X, mv.ts.max(REMOVAL + 1), &[A2], T1, Kind::Vouch { removal: self.r, list }), mv.made, rng, true);
            return;
        }
        if (23..27).contains(&mv.kind) {
            // a grant of admin to the remover, standing or timed, by X or by a key X made up
            let by = if mv.kind < 25 { X } else { Z };
            if by == Z {
                self.put((X, mv.ts.saturating_sub(1), &[], A, grant(Z, Role::Admin)), mv.made, rng, true);
            }
            let g = if mv.kind % 2 == 1 { grant(H, Role::Admin) } else { grant(H, Role::Admin).until(REMOVAL + 1) };
            self.put((by, mv.ts, &[], A, g), mv.made, rng, true);
            return;
        }
        let c: (Thing, &[Thing], Thing, Kind) = match mv.kind {
            // X removes A from T1 through A2, an edge above the signer's on B's removal's path,
            // listing the grant to A2 its own path rests on
            37 => (X, &[A2], T1, grant(A, Role::None).listing(self.w.cut(&[self.gs]))),
            // X removes the mint admin (the remover's granter where M minted A), listing nothing,
            // or listing M's grant of H
            27 => (X, &[], A, grant(M, Role::None)),
            28 => (X, &[], A, grant(H, Role::Write).listing(self.w.cut(&[self.gx]))),
            29 => (X, &[], A, grant(M, Role::None).listing(self.w.cut(&self.gh.into_iter().collect::<Vec<_>>()))),
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
            // the same carrying an `until` in place of none: admin until just after, write until
            // after the story
            38 => (X, &[], A, grant(X, Role::Admin).until(mv.ts + 1).relying(H)),
            39 => (X, &[], A, grant(X, Role::Write).until(B_UNTIL).relying(H)),
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
        let trust = if self.untrusting().contains(&n) {
            Set::new()
        } else if self.setup.b_side_x && n == B && t.is_some_and(|t| t < AFTER) { self.rx.into_iter().collect() } else { self.removals().into_iter().collect() };
        View { held, leaves: Some(leaves), trust }
    }
    pub fn view(&self, n: Thing, rules: &Rules) -> View {
        self.view_at(n, None, rules)
    }
    pub fn honest(&self) -> Vec<Thing> {
        [H, B, N5, K, RD, RD2].into_iter().filter(|n| self.sync.contains_key(n)).collect()
    }
    /// The nodes that trust nothing.
    pub fn untrusting(&self) -> [Thing; 2] {
        [N6, RD3]
    }
    /// The thief's commits made after the removal, and every commit of Z or of N5's key.
    fn hostile(&self, i: Id) -> bool {
        self.w.commits[i].signer == Z || (self.thief.contains_key(&i) && (self.made[i] > REMOVAL || self.w.commits[i].signer == N5)) || (self.w.commits[i].signer == X && self.made[i] > REMOVAL)
    }
    /// An early move of the thief (heard before the removal) whose write takes the remover's
    /// standing: a timed grant to H, a removal of H's granter listing nothing, a demotion of H.
    fn aims(&self, i: Id) -> bool {
        self.thief.get(&i).is_some_and(|k| matches!(k, 24 | 26 | 28) || (*k == 27 && self.gh.is_some()))
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
    /// Largest values seen: `rounds`, one reading's restarts and void rounds of its trusted writes.
    pub most: BTreeMap<&'static str, u64>,
    /// Known failures of a property, counted and printed but not failing the run: each names its
    /// finding (notes/path-model-findings.md).
    pub noted: BTreeMap<&'static str, u64>,
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
        for (k, n) in o.noted {
            *self.noted.entry(k).or_default() += n;
        }
        for (k, n) in o.most {
            let m = self.most.entry(k).or_default();
            *m = (*m).max(n);
        }
    }
}

impl Stats {
    pub fn failures(&self) -> u64 {
        self.fails.values().sum()
    }
    /// Prints the counts and, per failing property, its first world: shrunk under `rules` in a
    /// run of at most `SHRUNK` worlds, else as found (shrinking is one core's work, and a large
    /// run holds the box: shrink a printed world in a small run of its own).
    pub fn print(&self, name: &str, rules: &Rules) {
        const SHRUNK: u64 = 20_000;
        println!("{name}: {} worlds, checks {:?}, largest {:?}, noted {:?}, failing checks {:?}", self.worlds, self.checked, self.most, self.noted, self.fails);
        for (k, (what, spec)) in &self.first {
            let tag = if self.fails.contains_key(k) { "FAIL" } else { "NOTED" };
            if self.worlds > SHRUNK {
                println!("{tag} {k} (not shrunk): {what}\n{spec:?}");
                continue;
            }
            let small = shrink(spec, rules, k);
            let mut st = Stats::default();
            let m = Sim::build(&small.setup, rules, &small.moves, &mut Rng(small.rng));
            check(&m, rules, &mut st);
            let what = st.first.get(k).map_or(what.clone(), |x| x.0.clone());
            println!("{tag} {k} (shrunk): {what}\n{:?} moves {:?}\n{}", small.setup, small.moves, trace(&m));
        }
    }
    fn fail(&mut self, prop: &'static str, m: &Sim, what: String) {
        *self.fails.entry(prop).or_default() += 1;
        self.first.entry(prop).or_insert_with(|| (what, m.spec.clone()));
    }
    fn note(&mut self, prop: &'static str, m: &Sim, what: String) {
        *self.noted.entry(prop).or_default() += 1;
        self.first.entry(prop).or_insert_with(|| (what, m.spec.clone()));
    }
    fn count(&mut self, k: &'static str) {
        *self.checked.entry(k).or_default() += 1;
    }
    fn most(&mut self, k: &'static str, n: u64) {
        let m = self.most.entry(k).or_default();
        *m = (*m).max(n);
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
        st.fails.contains_key(prop) || st.noted.contains_key(prop)
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
    let name = |t: &Thing| ["?", "H", "B", "X", "N5", "K", "Z", "N6", "M", "G", "A", "A2", "ORG", "T1", "T2", "D1"].get(*t as usize).copied().unwrap_or("?");
    let mut s = String::new();
    for (i, c) in m.w.commits.iter().enumerate() {
        let path: Vec<&str> = c.path.iter().map(name).collect();
        let kind = match &c.kind {
            Kind::Content => "content".to_string(),
            Kind::Edge { holder, role, until, frontier, relies, adminless, invite, finalize } => {
                let mut k = format!("{} := {role:?}", name(holder));
                if *invite > Role::None {
                    k += &format!(" invite {invite:?}");
                }
                if *finalize {
                    k += " finalize";
                }
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
            Kind::Purge { author } => format!("purge by author {}", name(author)),
            Kind::Cover { carries } => format!("cover carrying {carries:?}"),
        };
        let kind = if matches!(c.kind, Kind::Content) && c.pa > 0 { format!("{kind} as {}", name(&m.w.purge_author(i))) } else { kind };
        let kind = if m.w.parts(c.cid) > 1 { format!("{kind} (commit {})", c.cid) } else { kind };
        let recv: Vec<String> = m.recv[i].iter().filter(|(n, _)| **n != X && **n != c.signer).map(|(n, t)| format!("{}@{t}", match *n { RD => "RD", RD2 => "RD2", RD3 => "RD3", _ => name(n) })).collect();
        s += &format!("  {i}: {} ts {} made {} [{}] on {}: {kind}; recv {}\n", name(&c.signer), c.ts, m.made[i], path.join(","), name(&c.on), recv.join(" "));
    }
    s
}

/// `w` with the commits `keep` pushed in that order (ids relabelled; a reference to a commit
/// left out is dropped from its list), and the map old id -> new.
pub fn rebuild(w: &World, keep: &[Id]) -> (World, BTreeMap<Id, Id>) {
    let mut out = World::new(&w.records);
    let map: BTreeMap<Id, Id> = keep.iter().enumerate().map(|(k, &i)| (i, k)).collect();
    let ids = |l: &Set| l.iter().filter_map(|j| map.get(j).copied()).collect::<Set>();
    for &i in keep {
        let c = &w.commits[i];
        let kind = match &c.kind {
            Kind::Edge { holder, role, until, frontier, relies, adminless, invite, finalize } => {
                let f = frontier.iter().map(|(t, l)| (*t, ids(l))).collect();
                Kind::Edge { holder: *holder, role: *role, until: *until, frontier: f, relies: *relies, adminless: *adminless, invite: *invite, finalize: *finalize }
            }
            Kind::Addendum { removal, list } => Kind::Addendum { removal: map[removal], list: ids(list) },
            Kind::Vouch { removal, list } => Kind::Vouch { removal: map[removal], list: ids(list) },
            Kind::Content => Kind::Content,
            Kind::Purge { author } => Kind::Purge { author: *author },
            Kind::Cover { carries } => Kind::Cover { carries: ids(carries) },
        };
        let j = out.push(c.signer, c.ts, &c.path, c.on, kind);
        out.authored(j, c.pa);
    }
    // a commit's parts kept stay one commit
    let mut groups: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for &i in keep {
        groups.entry(w.cid(i)).or_default().push(map[&i]);
    }
    for mut g in groups.into_values().filter(|g| g.len() > 1) {
        g.sort();
        out.group(&g);
    }
    (out, map)
}

/// A relabelling of `w`'s commits that keeps the walk's order: the ids reversed, commits sharing
/// `ts` and signer (ordered by id) kept in their order. As `rebuild`'s `keep`.
pub fn key_relabelling(w: &World) -> Vec<Id> {
    let mut perm: Vec<Id> = (0..w.commits.len()).rev().collect();
    let mut groups: BTreeMap<(u32, Thing), Vec<usize>> = BTreeMap::new();
    for (k, &i) in perm.iter().enumerate() {
        groups.entry((w.commits[i].ts, w.commits[i].signer)).or_default().push(k);
    }
    for slots in groups.values() {
        let mut olds: Vec<Id> = slots.iter().map(|&k| perm[k]).collect();
        olds.sort();
        for (&k, i) in slots.iter().zip(olds) {
            perm[k] = i;
        }
    }
    perm
}

/// Whether the reading of `w` at `v` is the reading of a relabelling keeping the walk's order.
pub fn one_reading_relabelled(w: &World, rules: &Rules, v: &View, rd: &Reading) -> bool {
    let (w2, map) = rebuild(w, &key_relabelling(w));
    let m = |s: &Set| s.iter().map(|i| map[i]).collect::<Set>();
    let v2 = View { held: m(&v.held), leaves: v.leaves.clone(), trust: m(&v.trust) };
    let r2 = judge(&w2, rules, &v2);
    r2.applied == m(&rd.applied) && r2.valid == m(&rd.valid) && r2.purged == m(&rd.purged) && r2.dropped == m(&rd.dropped) && r2.voided == m(&rd.voided) && r2.roles == rd.roles
}

/// Whether the reading without `x` held is `rd`, `x` aside.
pub fn no_effect(w: &World, rules: &Rules, v: &View, rd: &Reading, x: Id) -> bool {
    let o = judge(w, rules, &v.clone().without(&[x]));
    let less = |s: &Set| s.iter().copied().filter(|&i| i != x).collect::<Set>();
    o.applied == less(&rd.applied) && o.valid == less(&rd.valid) && o.purged == less(&rd.purged) && o.roles == rd.roles
}

/// The held lowerings the reading does not apply that it neither drops nor voids, and that are
/// not trusted: unapplied, as the author lacked the right.
pub fn unapplied(w: &World, v: &View, rd: &Reading) -> Vec<Id> {
    v.held.iter().copied().filter(|&i| w.lowers(i).is_some() && !w.leave(i) && !rd.applied.contains(&i) && !rd.dropped.contains(&i) && !rd.voided.contains(&i) && !v.trust.contains(&i)).collect()
}

/// Counted, not failing (notes/path-model-findings.md 16), at nodes trusting the removals (`t`)
/// or trusting nothing: `stray` (a drop whose dropper does not apply at the end). Failing: `void`
/// (a void lowering has no effect: the reading without it held is the same), `one reading` (a
/// relabelling of commit IDs keeping the walk's order reads the same).
fn void_checks(w: &World, rules: &Rules, v: &View, rd: &Reading, n: Thing, t: bool, m: &Sim, st: &mut Stats) {
    st.count("self-taken");
    if !rd.self_taken.is_empty() {
        st.fail("self-taken", m, format!("node {n}: commits {:?} lose their path's authority to their own drops", rd.self_taken));
    }
    st.count(if t { "stray T" } else { "stray N" });
    if !rd.stray.is_empty() {
        st.note(if t { "stray T" } else { "stray N" }, m, format!("node {n}: {:?} dropped by a write that does not apply", rd.stray));
    }
    for &x in &rd.voided {
        st.count("void");
        if !no_effect(w, rules, v, rd, x) {
            st.fail("void", m, format!("node {n}: the void lowering {x} has an effect"));
        }
    }
    st.count("one reading");
    if !one_reading_relabelled(w, rules, v, rd) {
        st.fail("one reading", m, format!("node {n}: a relabelling keeping the order reads otherwise"));
    }
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
    let regrant_n5 = s.regrant && (1..3).contains(&s.n5);
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
        // (A2 removed from T1 by B: K writes again only once B grants it again)
        K => !x_removed_a2 && (!s.sharer_x || saved(m.gs) || (s.regrant && b_admin)) && (m.r3.is_none() || (s.regrant && b_admin)),
        _ => false,
    };
    let x_keeps_a2 = matches!(s.x_a2, 1 | 3 | 4);
    // through A2 on T1 where B removed A2 from T1: what B's removal lists, or a writer of T1
    // received by then, or the path re-granted
    let in_r3 = |i: Id| m.r3.is_some_and(|r3| w.in_frontier(r3, i));
    // the accomplice (notes/disputes.md, Hole; membership §4, Role writes): a hostile party that
    // holds admin after the removal (N5, paired by X and kept by H's list) vouches for the thief's
    // writes. Counted, not a failure; where it voids a trusted removal, the vouch must be why (the
    // removal is not void without them) and its voucher must be such a party (the vouch counts
    // only where its voucher holds admin in the first walk; once the removal is void it may count
    // no more, X then removing N5): no wider. Nothing else is checked in such a world.
    let kept5 = s.n5 == 1 && m.g5.is_some_and(in_r);
    let accomplices: Vec<Id> = m.thief.iter().filter(|(_, &k)| k == 36).map(|(&i, _)| i).collect();
    if kept5 && !accomplices.is_empty() {
        for (&n, (v, rd)) in &rds {
            st.count("accomplice");
            if rd.void.is_empty() {
                continue;
            }
            let why = judge(w, rules, &v.clone().without(&accomplices)).void.is_empty();
            if !why {
                st.fail("removal", m, format!("node {n}: its trusted removal {:?} is void, no current admin's vouch why", rd.void));
            }
        }
        if rds.values().any(|(_, rd)| !rd.void.is_empty()) {
            st.note("accomplice", m, "a current admin's vouch voids the trusted removal".to_string());
        }
        return;
    }
    // X's removal of M listing M's grant of H, heard before the removal (kept)
    let m_cut = || m.thief.iter().any(|(&i, &k)| k == 29 && m.made[i] < REMOVAL);
    // X's lowering of H heard before the removal (a removal or a demotion, its list naming only
    // X's own grant) is kept where a grant of X heard with it gives H back its standing: what it
    // dropped (H's grants of B and N5, what was written under them, what only B's answers kept,
    // M's leave naming B) is lost, as with any
    // lowering X made that the remover heard (notes/path-model-findings.md 19)
    let heard_lowering = m.thief.iter().any(|(&i, &k)| matches!(k, 11 | 28 | 48) && m.made[i] < REMOVAL);
    let under_h = |i: Id| heard_lowering && (w.hops(i).contains(&(H, A)) || [B, N5, K, X, M].contains(&w.commits[i].signer));
    // safety: no commit the thief made after the removal shows (but content on a path it still
    // holds, and its own leave), and Z, X and N5 removed before the theft end with no role. At a
    // node trusting nothing (`late`) only what the thief stamped after the removal, or signed with
    // N5's key, counts: what X stamped before it is X's standing, which is the dispute.
    let rts = w.commits[m.r].ts;
    let safety = |n: Thing, v: &View, rd: &Reading, prop: &'static str, late: bool, st: &mut Stats| {
        // what it holds, and what the covers it holds carry
        let seen: Set = v.held.iter().flat_map(|&c| std::iter::once(c).chain(match &w.commits[c].kind { Kind::Cover { carries } => carries.iter().copied().collect(), _ => vec![] })).collect();
        for &i in seen.iter().filter(|&&i| m.hostile(i) && (!late || w.commits[i].ts > rts || w.commits[i].signer == N5)) {
            st.count(prop);
            let c = &w.commits[i];
            // X's own writes along A2, a path it keeps (a vouch there showing is its right; what it names
            // is judged apart)
            let by_right = (c.signer == X && x_keeps_a2 && c.path == [A2] && !matches!(c.kind, Kind::Edge { .. }) && !(m.r3.is_some() && !(s.regrant && b_admin) && [T1, D1].contains(&c.on)))
                // X leaving A by itself: a self-removal is always open to the holder, and takes nothing X still holds
                || (w.leave(i) && w.sets(i) == Some((X, A)))
                // X inviting (or finalizing) at read through A2, which it keeps writing, by A2's invite
                || (c.signer == X && s.x_a2 == 1 && c.path == [A2] && matches!(c.kind, Kind::Edge { role, .. } if role <= Role::Read));
            // the accepted window (spec/permissions.md §5.2 Copies, §5.3): shown only by a cover's
            // copy, carried first by a cover whose writer did not yet hold a removal when it made it
            let window = !rd.valid.contains(&i) && rd.copied.contains(&i) && m.smuggled.contains(&i);
            if rd.shows(i) && !by_right && window {
                st.note(if late { "window N" } else { "window" }, m, format!("node {n}: the thief's commit {i} shows by a cover made before its writer held the removal"));
            } else if rd.shows(i) && !by_right {
                st.fail(prop, m, format!("node {n}: the thief's commit {i} shows"));
            }
        }
        for (e, r) in &rd.roles {
            let x_holds = e.0 == X && (e.1 == A || (e.1 == A2 && !x_keeps_a2));
            // N5, removed before the theft, stays removed
            let n5_holds = s.n5 == 3 && *e == (N5, A);
            // Z invited to read T1 through A2 by X, which keeps writing A2: X's right
            let z_by_right = s.x_a2 == 1 && *e == (Z, T1) && *r <= Role::Read;
            if *r > Role::None && ((e.0 == Z && !z_by_right) || x_holds || n5_holds) {
                st.fail(prop, m, format!("node {n}: {e:?} ends {r:?}"));
            }
        }
    };
    // the last admin: every thing keeps a standing admin edge (no write in the story is marked)
    let admin = |n: Thing, rd: &Reading, prop: &'static str, st: &mut Stats| {
        for t in [A, A2, ORG, T1, D1, T2] {
            st.count(prop);
            if !rd.roles.iter().any(|(e, r)| e.1 == t && *r == Role::Admin) {
                st.fail(prop, m, format!("node {n}: {t} has no standing admin"));
            }
        }
    };
    // the remover keeps its own path: H ends a standing admin of A (X's lowering of it shows only
    // where a write of X kept with it gives it back)
    let own_path = |n: Thing, v: &View, rd: &Reading, prop: &'static str, st: &mut Stats| {
        if v.held.iter().any(|&i| w.commits[i].signer == X && m.lowers_remover(i)) {
            st.count(prop);
            if rd.role(H, A) != Role::Admin {
                st.fail(prop, m, format!("node {n}: H ends {:?} on A", rd.role(H, A)));
            }
        }
    };
    for (&n, (v, rd)) in &rds {
        if rd.circle {
            st.fail("settles", m, format!("node {n}: the vouches do not settle"));
        }
        st.most("rounds", rd.rounds as u64);
        void_checks(w, rules, v, rd, n, true, m, st);
        st.count("removal");
        if !rd.void.is_empty() {
            st.fail("removal", m, format!("node {n}: its trusted removal {:?} is void", rd.void));
        }
        safety(n, v, rd, "safety", false, st);
        own_path(n, v, rd, "own path", st);
        if x_removed_a2 && !s.regrant && m.xrole.is_some_and(saved) {
            st.count("removal kept");
            if rd.role(A2, T1) > Role::None {
                st.fail("removal kept", m, format!("node {n}: A2 holds on T1 again"));
            }
        }
        admin(n, rd, "admin", st);
        // liveness
        for &i in v.held.iter().filter(|&&i| !m.hostile(i)) {
            let c = &w.commits[i];
            let honest_now = c.signer != X;
            let want = match &c.kind {
                // M's leave applies iff the admin it names is standing: its write after shows
                // iff the leave is refused
                // (X's removal of M heard before the removal and kept cuts the leave, which it does
                // not list, and M's writes after it)
                Kind::Content if c.signer == M => !m_cut() && (c.ts == 1 || s.mint == 2),
                Kind::Edge { holder, .. } if c.signer == M => *holder != M || (s.mint == 1 && !m_cut()),
                // through A2 on T1 where B removed A2 from T1 (K's, or X's as a member of A2)
                Kind::Content | Kind::Purge { .. } | Kind::Cover { .. } if m.r3.is_some() && w.hops(i).contains(&(A2, T1)) => {
                    let r3 = m.r3.unwrap();
                    !(c.signer == K && x_removed_a2) && (s.regrant && b_admin && c.signer == K)
                        || (c.ts < REMOVAL
                            && !(c.signer == K && x_removed_a2)
                            && (c.signer == K || m.made[i] < REMOVAL)
                            && (in_r3(i) || [H, N5].iter().any(|&a| m.sync.get(&a).is_some_and(|u| u.contains(&c.on)) && wrote(a) && m.got(i, a, REMOVAL) && m.recv[r3].contains_key(&a))))
                }
                Kind::Content | Kind::Purge { .. } | Kind::Cover { .. } if honest_now => stands(c.signer) && !(c.signer == K && x_removed_a2),
                // X's purge before the theft: kept by H's list alone (an addendum vouches for no
                // purge request)
                Kind::Purge { .. } => in_r(i),
                Kind::Content => {
                    in_r(i)
                        || [H, B, N5, K].iter().any(|&a| {
                            m.sync.get(&a).is_some_and(|u| u.contains(&c.on)) && wrote(a) && m.got(i, a, REMOVAL) && m.recv[m.r].contains_key(&a)
                        })
                }
                // X's invite of G through A2 stands where the share it rests on does, and where
                // K removed X from A2, by K's list or an admin's vouch for it
                Kind::Edge { .. } if Some(i) == m.gi => {
                    (!s.sharer_x || saved(m.gs)) && (s.x_a2 == 1 || m.r2.is_some_and(|r2| w.in_frontier(r2, i)) || saved(i))
                }
                // N5's grant to B, listed by X's removal of N5, stays: X's twin, heard before the
                // removal, is kept and drops it
                Kind::Edge { .. } if Some(i) == m.gb5 => !m.thief.iter().any(|(&t, &k)| k == 35 && m.made[t] < REMOVAL),
                Kind::Edge { .. } if honest_now => c.signer == H || c.signer == K || i == m.gs || (m.made[i] == AFTER && b_admin),
                // (a write X made before the removal stamped after it never applies)
                Kind::Edge { .. } => saved(i) && c.ts < REMOVAL && !m.lowers_remover(i) && !m.aims(i),
                _ => false,
            };
            if want && !under_h(i) {
                st.count("liveness");
                if !rd.shows(i) {
                    st.fail("liveness", m, format!("node {n}: commit {i} does not show"));
                }
            }
        }
        // purge: a held delta is purged iff a purge request standing by the story (an honest one
        // the reading holds valid, liveness gating those it wants, or the thief's along [A2]
        // where X keeps writing A2) names it and its chain holds
        // the purge author it names (notes/write-path-design.md §1, What a purger must hold)
        if !heard_lowering {
            let x_right = |i: Id| w.commits[i].signer == X && m.thief.contains_key(&i) && x_keeps_a2 && w.commits[i].path == [A2] && !(m.r3.is_some() && !(s.regrant && b_admin));
            // what the requests in `reqs` purge, by the story's reading of the rule
            let named = |reqs: &[Id]| -> Set {
                v.held
                    .iter()
                    .copied()
                    .filter(|&d| {
                        matches!(w.commits[d].kind, Kind::Content)
                            && reqs.iter().any(|&q| {
                                let Kind::Purge { author } = w.commits[q].kind else { return false };
                                w.commits[q].on == w.commits[d].on && w.commits[d].ts < w.commits[q].ts && w.purge_author(d) == author && w.chain(q).contains(&author)
                            })
                    })
                    .collect()
            };
            let reqs = |thief: bool| -> Vec<Id> { v.held.iter().copied().filter(|&q| matches!(w.commits[q].kind, Kind::Purge { .. }) && ((!m.hostile(q) && rd.valid.contains(&q)) || (thief && x_right(q)))).collect() };
            let (least, most) = (named(&reqs(false)), named(&reqs(true)));
            st.count("purge");
            if !(least.is_subset(&rd.purged) && rd.purged.is_subset(&most)) {
                st.fail("purge", m, format!("node {n}: purged {:?}, wanted {least:?} to {most:?}", rd.purged));
            }
        }
    }
    // nodes trusting nothing: the walk settles; where the honest removals apply there, the thief
    // gains nothing past its standing and H keeps its own (a thing left adminless counted); a
    // removal not applied is a dispute shown there; a reading unlike the trusted side's comes with
    // a dispute, and trusting the honest ones shown reads as the trusting side
    let plain: BTreeMap<Thing, (View, Reading)> = m
        .untrusting()
        .into_iter()
        .map(|n| {
            let v = m.view(n, rules);
            let rd = judge(w, rules, &v);
            (n, (v, rd))
        })
        .collect();
    for (&n, (v, rd)) in &plain {
        st.count("untrusted");
        st.most("rounds", rd.rounds as u64);
        if rd.circle {
            st.fail("untrusted", m, format!("node {n}: the vouches do not settle"));
        }
        void_checks(w, rules, v, rd, n, false, m, st);
        // where every honest removal it holds applies (else X keeps its standing there: a dispute)
        if m.removals().iter().all(|r| !v.held.contains(r) || rd.applied.contains(r)) {
            st.count("admin N");
            if !rd.roles.iter().any(|(e, r)| e.1 == T1 && *r == Role::Admin) || ![A, A2, ORG, D1, T2].iter().all(|&t| rd.roles.iter().any(|(e, r)| e.1 == t && *r == Role::Admin)) {
                st.note("admin N", m, format!("node {n}: a thing has no standing admin"));
            }
            safety(n, v, rd, "safety N", true, st);
            own_path(n, v, rd, "own path N", st);
        }
        let shown = disputes(w, rules, v);
        // an honest history (no move of the thief, X removing H neither at the theft nor after)
        // shows none
        if m.thief.is_empty() && !s.x_first && !s.b_side_x {
            st.count("quiet");
            if !shown.is_empty() {
                st.fail("quiet", m, format!("node {n}: an honest history shows the disputes {shown:?}"));
            }
        }
        // trusting the honest removals among the disputes shown, and among those then shown,
        // applies every honest removal: never a silent loss
        let honest_shown = |d: Vec<Id>, t: &Set| -> Vec<Id> { d.into_iter().filter(|r| m.removals().contains(r) && !t.contains(r)).collect() };
        let mut sides = v.clone();
        let mut more = honest_shown(shown.clone(), &sides.trust);
        while !more.is_empty() {
            sides.trust.extend(more);
            more = honest_shown(disputes(w, rules, &sides), &sides.trust);
        }
        let sided = judge(w, rules, &sides);
        for r in m.removals().into_iter().filter(|r| v.held.contains(r)) {
            st.count("dispute");
            if !rd.applied.contains(&r) && !sided.applied.contains(&r) {
                st.fail("dispute", m, format!("node {n}: removal {r} is not applied, nor where the disputes shown are trusted {:?}", sides.trust));
            }
        }
        // a reading unlike the trusted side's (H's, on the things both sync), or unlike its own
        // held set's trusting every honest removal held, comes with a dispute shown, and trusting
        // the honest ones shown reads as that
        let t = judge(w, rules, &v.clone().trusting(&m.removals().into_iter().filter(|r| v.held.contains(r)).collect::<Vec<_>>()));
        if sided.applied != t.applied || sided.valid != t.valid || sided.roles != t.roles {
            st.fail("dispute", m, format!("node {n}: trusting the disputes shown {:?} does not read as trusting the honest removals", sides.trust));
        }
        let (vh, rh) = &rds[&H];
        let differs = v.held.intersection(&vh.held).any(|&i| m.sync[&n].contains(&w.commits[i].on) && m.sync[&H].contains(&w.commits[i].on) && rd.shows(i) != rh.shows(i))
            || t.applied != rd.applied
            || t.valid != rd.valid
            || t.roles != rd.roles;
        if differs {
            st.count("untrusted differs");
            if shown.is_empty() {
                st.fail("dispute", m, format!("node {n}: reads otherwise than the trusted side with no dispute shown"));
            }
            // shown under spec/permissions.md §5.1's rule only where a shown write is one the walk
            // does not apply (counted: what the reach-back leaves, finding 16)
            if !shown.iter().any(|r| !rd.applied.contains(r)) {
                st.note("silent under the spec's dispute rule", m, format!("node {n}: reads otherwise than the trusted side, every removal shown applying"));
            }
        }
    }
    let (n6, rd3) = (&plain[&N6], &plain[&RD3]);
    for &i in n6.0.held.intersection(&rd3.0.held) {
        if [T1, D1].contains(&w.commits[i].on) {
            st.count("alike");
            if n6.1.shows(i) != rd3.1.shows(i) || n6.1.purged.contains(&i) != rd3.1.purged.contains(&i) {
                st.fail("alike", m, format!("nodes trusting nothing read commit {i} otherwise"));
            }
        }
    }
    // the other reading of the audit (the applied writes before it in place of the held ones), at
    // the nodes trusting nothing, counted (notes/path-model-findings.md 18)
    let other = Rules { audit_held: !rules.audit_held, ..*rules };
    for (&n, (v, rd)) in &plain {
        st.count("drops");
        let o = judge(w, &other, v);
        if o.applied != rd.applied || o.valid != rd.valid || o.roles != rd.roles {
            let k = if o.roles == rd.roles { "drops differ, same roles" } else { "drops differ" };
            st.note(k, m, format!("node {n}: the audit over the {} writes reads otherwise: applied {:?} / {:?}", if other.audit_held { "held" } else { "applied" }, rd.applied, o.applied));
        }
    }
    // alike: two nodes read a commit they both hold in a unit they both sync alike
    for (&n, (vn, rn)) in &rds {
        for (&o, (vo, ro)) in rds.range(n + 1..) {
            for &i in vn.held.intersection(&vo.held) {
                if m.sync[&n].contains(&w.commits[i].on) && m.sync[&o].contains(&w.commits[i].on) {
                    st.count("alike");
                    if rn.shows(i) != ro.shows(i) || rn.purged.contains(&i) != ro.purged.contains(&i) {
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
        n5: rng.below(4) as u8,
        x_role: rng.below(5) as u8,
        x_role_seen: b(&mut rng),
        x_a2: rng.below(5) as u8,
        b_side_x: rng.below(4) == 0,
        regrant: b(&mut rng),
        mint: rng.below(3) as u8,
        x_first: rng.below(4) == 0,
    };
    let mut moves: Vec<Move> = (0..rng.below(5))
        .map(|_| {
            let (kind, ts) = (rng.below(MOVES), 1 + rng.below(10) as u32);
            let made = if early(kind) && rng.below(3) == 0 { 5 } else { 7 + rng.below(4) as u32 };
            Move { kind, ts, made }
        })
        .collect();
    // where N5 was removed before the theft, half the time the pair that makes key order and
    // receipt order differ (`a_remover_keeps_what_it_received_first`): X's demotion of H and N5's
    // grant of admin to H, both stamped before X's removal of N5 and heard after it
    if s.n5 == 3 && rng.below(2) == 0 {
        moves.extend([Move { kind: 28, ts: 1, made: 5 }, Move { kind: 30, ts: 2, made: 5 }]);
    }
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
/// removal (stamped before, an `early` move is made at 5, heard before the removal); `mint` and
/// `x_first` as one dimension (none, M naming H, M naming timed B, X removing H first). `i` in
/// `0..FAMILY`.
pub const FAMILY: usize = 2 * 2 * 2 * 2 * 4 * 5 * 2 * 5 * 2 * 2 * 4 * MOVES * 2;

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
        n5: take(4) as u8,
        x_role: take(5) as u8,
        x_role_seen: take(2) == 1,
        x_a2: take(5) as u8,
        b_side_x: take(2) == 1,
        regrant: take(2) == 1,
        ..Setup::default()
    };
    match take(4) {
        3 => s.x_first = true,
        k => s.mint = k as u8,
    }
    // stamped at 3, an early move is made at 5, heard before the removal
    let kind = take(MOVES);
    let ts = if take(2) == 1 { 3 } else { 8 };
    let mv = Move { kind, ts, made: if ts == 3 && early(kind) { 5 } else { 7 } };
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

/// The rules a mode runs: `paths` the design's (`Rules::fixed`); `paths-design` the first round's
/// reading; controls, each the design with one rule undone: `-no-void` (a lowering whose own
/// drops take its authority applies), `-listed` (the remover and vouchers name all they received), `-exempt` (the held chain
/// exempt from a lowering's drops), `-any-edge` (the last-admin rule reads every admin edge),
/// `-timed` (a timed admin edge counts as standing), `-own-vouch` (a vouch counts for its own
/// signer's commit), `-first-applied` (a re-granted path counts from the first point the settled
/// walk gave it), `-once` (a node answers a removal only the first time its walk applies it),
/// `-leave` (a self-removal is never put in question), `-key-order` (the remover and vouchers
/// keep the role writes in key order), `-audit-applied` (the audit puts in question the applied
/// writes before it, not the held ones), `-invite-role` (an invite grant needs only a role on its
/// path's last edge), `-admin-falls` (only a fall from admin is judged and audits), `-purge-any-path`
/// (a purge request holds the author right wherever its path gives write), `-purge-contains` (a
/// request by author matches every delta whose chain holds that author); the variant `-facts`
/// (a carried write judged by its own facts, not shown by a cover's copy: not the design). `-exh` runs the small family in place of
/// random worlds.
pub fn mode_rules(mode: &str) -> Option<Rules> {
    let f = Rules::fixed();
    let rest = mode.strip_prefix("paths").unwrap_or(mode);
    let rest = rest.strip_prefix("-exh").or_else(|| rest.strip_prefix("-tiny-invites")).or_else(|| rest.strip_prefix("-tiny")).unwrap_or(rest);
    Some(match rest {
        "" => f,
        "-design" => Rules::design(),
        "-no-void" => Rules { self_void: false, ..f },
        "-listed" => Rules { stands: false, ..f },
        "-exempt" => Rules { exempt_chain: true, ..f },
        "-any-edge" => Rules { last_admin: LastAdmin::AnyEdge, ..f },
        "-timed" => Rules { last_admin: LastAdmin::NamedTimed, ..f },
        "-own-vouch" => Rules { no_own_vouch: false, ..f },
        "-first-applied" => Rules { regrant: Regrant::FirstApplied, ..f },
        "-once" => Rules { rewrite: false, ..f },
        "-leave" => Rules { leave_in_question: false, ..f },
        "-audit-applied" => Rules { audit_held: false, ..f },
        "-key-order" => Rules { key_order: true, ..f },
        "-invite-role" => Rules { invite_check: false, ..f },
        "-admin-falls" => Rules { any_fall: false, ..f },
        "-purge-any-path" => Rules { purge_chain: false, ..f },
        "-purge-contains" => Rules { purge_exact: false, ..f },
        "-facts" => Rules { cover_facts: true, ..f },
        "-own-drops" => Rules { commit_drops: false, ..f },
        "-remains-unkept" => Rules { remains_kept: false, ..f },
        _ => return None,
    })
}

// ---- The void step in small worlds (notes/path-model-findings.md 16, 17) ----

/// A small world of admins removing and granting each other on A (H its mint): `n` commits, each
/// by a random party at a random `ts`, one in four carrying two or three edge writes on distinct
/// holders (spec/commits.md §2), each setting a random party's edge to admin (standing, or one in
/// three until two ticks on) or none, naming a random remaining admin half the time, listing each
/// earlier write with probability one half.
pub fn tiny(i: u64, n: usize) -> World {
    let mut rng = Rng::thread(0x701d, i as usize);
    let mut w = account();
    for _ in 0..n {
        tiny_commit(&mut w, &mut rng, n, |h, rng, ts| {
            let k = match rng.below(5) {
                0 | 1 => Kind::set(h, Role::Admin),
                2 => Kind::set(h, Role::Admin).until(ts + 2),
                _ => Kind::set(h, Role::None),
            };
            // naming a remaining admin, half the time
            if rng.below(2) == 0 { k.relying([H, B, N5, Z, N6][rng.below(5)]) } else { k }
        });
    }
    w
}

/// One commit of a small world: a random signer, `ts` in 1..=n, one part or (one in four) two
/// or three on distinct holders other than the signer, each from `part` with its own list.
fn tiny_commit(w: &mut World, rng: &mut Rng, n: usize, part: impl Fn(Thing, &mut Rng, u32) -> Kind) {
    let parties = [H, B, N5, Z, N6];
    let s = parties[rng.below(5)];
    let ts = 1 + rng.below(n) as u32;
    let k = if rng.below(4) == 0 { 2 + rng.below(2) } else { 1 };
    let mut parts: Vec<Kind> = vec![];
    let mut holders = vec![];
    for _ in 0..k {
        let h = parties[rng.below(5)];
        let list: Vec<Id> = (0..w.commits.len()).filter(|_| rng.below(2) == 0).collect();
        let kind = part(h, rng, ts);
        if s != h && !holders.contains(&h) {
            holders.push(h);
            let fin = matches!(kind, Kind::Edge { finalize: true, .. });
            parts.push(if fin { kind } else { kind.listing(w.cut(&list)) });
        }
    }
    match parts.len() {
        0 => {}
        1 => {
            w.push(s, ts, &[], A, parts.pop().unwrap());
        }
        _ => {
            w.commit(s, ts, &[], A, parts);
        }
    }
}

/// A small world of invites on A (H its mint): as `tiny`, each write setting admin, none, write
/// inviting write (standing or until two ticks on), or read, or finalizing its holder's grant. A
/// writer holding an invite grants as an invite grant; a lowering from write or of the invite is
/// judged (notes/path-model-findings.md 23).
pub fn tiny_invites(i: u64, n: usize) -> World {
    let mut rng = Rng::thread(0x1271, i as usize);
    let mut w = account();
    for _ in 0..n {
        tiny_commit(&mut w, &mut rng, n, |h, rng, ts| match rng.below(6) {
            0 => Kind::set(h, Role::Admin),
            1 => Kind::set(h, Role::None),
            2 => Kind::set(h, Role::Write).inviting(Role::Write),
            3 => Kind::set(h, Role::Read),
            4 => Kind::set(h, Role::Write).inviting(Role::Write).until(ts + 2),
            _ => Kind::finalize(h),
        });
    }
    w
}

/// Tiny world `i` (`n` from 3 to 12 writes; `invites`: `tiny_invites`, else `tiny`) and its view:
/// every commit held; trusting nothing, or (every third world) one held lowering.
pub fn tiny_world(i: u64, invites: bool) -> (World, View) {
    let n = 3 + (i % 10) as usize;
    let w = if invites { tiny_invites(i, n) } else { tiny(i, n) };
    let mut v = View::all(&w);
    let lows: Vec<Id> = (0..w.commits.len()).filter(|&k| w.lowers(k).is_some()).collect();
    if i % 3 == 0 && !lows.is_empty() {
        v.trust.insert(lows[(i / 3) as usize % lows.len()]);
    }
    (w, v)
}

#[derive(Clone, Debug, Default)]
pub struct TinyStats {
    pub worlds: u64,
    pub checked: BTreeMap<&'static str, u64>,
    pub fails: BTreeMap<&'static str, u64>,
    /// Counted, not failing (`tiny_check`).
    pub noted: BTreeMap<&'static str, u64>,
    /// Per check, the smallest world: (commits, index, what).
    pub first: BTreeMap<&'static str, (usize, u64, String)>,
    pub most_rounds: u32,
}

impl crate::Tally for TinyStats {
    fn merge(&mut self, o: TinyStats) {
        self.worlds += o.worlds;
        for (k, n) in o.checked {
            *self.checked.entry(k).or_default() += n;
        }
        for (k, n) in o.fails {
            *self.fails.entry(k).or_default() += n;
        }
        for (k, n) in o.noted {
            *self.noted.entry(k).or_default() += n;
        }
        for (k, f) in o.first {
            let e = self.first.entry(k).or_insert(f.clone());
            if (f.0, f.1) < (e.0, e.1) {
                *e = f;
            }
        }
        self.most_rounds = self.most_rounds.max(o.most_rounds);
    }
}

impl TinyStats {
    /// Check `k` at world `i`: `bad`, it fails where `gate`, else it is counted.
    fn hit(&mut self, k: &'static str, gate: bool, bad: bool, i: u64, w: &World, what: impl Fn() -> String) {
        *self.checked.entry(k).or_default() += 1;
        if !bad {
            return;
        }
        *if gate { self.fails.entry(k) } else { self.noted.entry(k) }.or_default() += 1;
        let n = w.commits.len();
        if self.first.get(k).is_none_or(|f| (n, i) < (f.0, f.1)) {
            self.first.insert(k, (n, i, what()));
        }
    }
    pub fn failures(&self) -> u64 {
        self.fails.values().sum()
    }
}

/// The checks on one small world, by its trust: `N` trusting nothing, `T` trusting a lowering
/// the settled walk applies, `V` trusting one it does not (void, its seeds lost: the walk is
/// redone, notes/write-path-design.md §1). Failing: `one reading` (a relabelling keeping the
/// order reads the same), `self-taken` (no applied commit's path loses its authority to the
/// commit's own drops), `void` (a void lowering has no effect: the reading without it held is
/// the same), `unapplied N`/`T` (likewise a lowering left with no verdict), `admin T` (A keeps a
/// standing admin). Counted: `stray` (a drop whose dropper does not apply at the end), `unapplied
/// V` (the trusted write's void round reads a lowering the final walk does not apply), `admin
/// N`/`V`.
pub fn tiny_check(i: u64, w: &World, v: &View, rules: &Rules, st: &mut TinyStats) {
    st.worlds += 1;
    let rd = judge(w, rules, v);
    let t = if v.trust.is_empty() { "N" } else if rd.void.is_empty() { "T" } else { "V" };
    let k = |c: &'static str| -> &'static str {
        match (c, t) {
            ("stray", "N") => "stray N",
            ("stray", "T") => "stray T",
            ("stray", _) => "stray V",
            ("unapplied", "N") => "unapplied N",
            ("unapplied", "T") => "unapplied T",
            ("unapplied", _) => "unapplied V",
            ("admin", "N") => "admin N",
            ("admin", "T") => "admin T",
            _ => "admin V",
        }
    };
    st.most_rounds = st.most_rounds.max(rd.rounds);
    st.hit(k("stray"), false, !rd.stray.is_empty(), i, w, || format!("stray {:?}", rd.stray));
    for &x in &rd.voided {
        st.hit("void", true, !no_effect(w, rules, v, &rd, x), i, w, || format!("void {x} has an effect (voided {:?}, applied {:?})", rd.voided, rd.applied));
    }
    for x in unapplied(w, v, &rd) {
        st.hit(k("unapplied"), t != "V", !no_effect(w, rules, v, &rd, x), i, w, || format!("unapplied {x} has an effect"));
    }
    st.hit("one reading", true, !one_reading_relabelled(w, rules, v, &rd), i, w, || "a relabelling reads otherwise".to_string());
    st.hit("self-taken", true, !rd.self_taken.is_empty(), i, w, || format!("commits {:?} lose their path's authority to their own drops", rd.self_taken));
    st.hit(k("admin"), t == "T", !rd.roles.iter().any(|(e, r)| e.1 == A && *r == Role::Admin), i, w, || format!("A has no admin: applied {:?}", rd.applied));
}

/// `w` less one commit at a time while `fails` holds of it.
pub fn shrink_world(w: &World, v: &View, fails: &dyn Fn(&World, &View) -> bool) -> (World, View) {
    let (mut w, mut v) = (w.clone(), v.clone());
    'step: loop {
        for k in 0..w.commits.len() {
            let keep: Vec<Id> = (0..w.commits.len()).filter(|&j| j != k).collect();
            let (w2, map) = rebuild(&w, &keep);
            let m = |s: &Set| s.iter().filter_map(|i| map.get(i).copied()).collect::<Set>();
            let v2 = View { held: m(&v.held), leaves: v.leaves.clone(), trust: m(&v.trust) };
            if fails(&w2, &v2) {
                (w, v) = (w2, v2);
                continue 'step;
            }
        }
        return (w, v);
    }
}

/// `-- N paths-tiny[-invites][-variant]`: N small worlds.
pub fn tiny_run(n: u64, rules: &Rules, invites: bool) -> TinyStats {
    crate::on_every_core(|th, threads, st: &mut TinyStats| {
        for i in (th as u64..n).step_by(threads) {
            let (w, v) = tiny_world(i, invites);
            tiny_check(i, &w, &v, rules, st);
        }
    })
}

fn tiny_print(st: &TinyStats, rules: &Rules, invites: bool) {
    println!("tiny: {} worlds, checks {:?}, noted {:?}, failing {:?}, most rounds {}", st.worlds, st.checked, st.noted, st.fails, st.most_rounds);
    for (k, (n, i, what)) in &st.first {
        let (w, v) = tiny_world(*i, invites);
        let prop = *k;
        let fails = |w: &World, v: &View| {
            let mut s = TinyStats::default();
            tiny_check(*i, w, v, rules, &mut s);
            s.fails.contains_key(prop) || s.noted.contains_key(prop)
        };
        let (w, v) = shrink_world(&w, &v, &fails);
        let tag = if st.fails.contains_key(k) { "FAIL" } else { "NOTED" };
        println!("{tag} {k}: world {i} ({n} commits; shrunk to {}), trust {:?}: {what}\n{}", w.commits.len(), v.trust, tiny_trace(&w));
    }
}

/// A small world's commits, one a line.
pub fn tiny_trace(w: &World) -> String {
    let name = |t: &Thing| ["?", "H", "B", "X", "N5", "K", "Z", "N6"].get(*t as usize).copied().unwrap_or("?");
    let mut s = String::new();
    for (i, c) in w.commits.iter().enumerate() {
        if let Kind::Edge { holder, role, frontier, until, invite, finalize, relies, .. } = &c.kind {
            let what = if *finalize { "finalize".to_string() } else { format!("{role:?}{}{}", if *invite > Role::None { format!(" invite {invite:?}") } else { String::new() }, until.map_or(String::new(), |u| format!(" until {u}"))) };
            let what = relies.map_or(what.clone(), |n| format!("{what} relying on {}", name(&n)));
            let part = if w.parts(c.cid) > 1 { format!(" (commit {})", c.cid) } else { String::new() };
            s += &format!("  {i}: {} ts {}{part}: {} := {what} listing {:?}\n", name(&c.signer), c.ts, name(holder), frontier.values().flatten().collect::<Vec<_>>());
        }
    }
    s
}

/// `-- N paths[-control]` (random worlds), `-- 0 paths-exh[-control]` (the small family),
/// `-- N paths-tiny[-control]` (small worlds of admins). Returns the failing checks.
pub fn run(samples: u64, mode: &str) -> u64 {
    let Some(rules) = mode_rules(mode) else {
        eprintln!("unknown mode {mode}");
        return 1;
    };
    if mode.starts_with("paths-tiny") {
        let invites = mode.starts_with("paths-tiny-invites");
        let st = tiny_run(samples, &rules, invites);
        tiny_print(&st, &rules, invites);
        return st.failures();
    }
    // `-- N paths-exh`: every Nth family world (N 0 or 1: all of them)
    let st = if mode.starts_with("paths-exh") { family_run(&rules, samples.max(1) as usize) } else { random(samples, &rules) };
    st.print(mode, &rules);
    st.failures()
}
