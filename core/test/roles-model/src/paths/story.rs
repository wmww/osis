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
/// A guest X grants to read T1 through A2 (`Setup::x_a2` 1, 2, 5): a may-grant grant.
pub const G: Thing = 9;
pub const A: Thing = 10;
pub const A2: Thing = 11;
pub const ORG: Thing = 12;
pub const T1: Thing = 13;
pub const T2: Thing = 14;
/// A dependent of T1 (minted with it, in T1's unit): written by descent.
pub const D1: Thing = 15;
/// A holder of admin on D1 (H's grant), writing T2 through D1, which holds write on T2 with the
/// may-grant flag (J grants RD2 read): a reader of T2 holds D1's grants on J's path as evidence and not
/// A's direct grant on D1.
pub const J: Thing = 16;
/// A2's guests (minted with A2), holding read with the may-grant flag on T1 where X writes A2
/// (`Setup::x_a2` 1, 2): the arrangement letting a writer of A2 add readers of T1 and no more
/// (notes/write-path-design.md §1 G3), reached from A2 by descent.
pub const GU: Thing = 17;
/// Readers outside A (nodes, not signers): holding only T1 and D1, only T2 (part of the evidence).
pub const RD: Thing = 20;
pub const RD2: Thing = 21;
/// Nodes that trust nothing (paired after the fact, or a reader that never chose a side): N6
/// syncs what B does, RD3 only T1 and D1. Neither writes.
pub const RD3: Thing = 22;
/// A key a thing's members wrote down, and one a thief made up (notes/write-path-design.md,
/// Keys).
pub const RK: Thing = KEYS | 0x40;
pub const TK: Thing = KEYS | 0x41;

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
    World::new(&[(mint, A), (K, A2), (A, ORG), (ORG, T2), (A, T1), (T1, D1), (A2, GU)])
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
    /// party removed before the theft, whose key the thief holds: `N5_MOVES`, moves 47, 48 and
    /// 53).
    pub n5: u8,
    /// X's role write before the theft. 0: none; 1: demotes B to write on A; 2: removes A2 from
    /// T1 (when B shared it); 3: grants A2 admin on T2; 4: a purge request by author A on T1 (not
    /// a role write: content-class, kept only by H's list); 5: one commit granting RD read on T1
    /// through [A] and A2 admin on T2 through [A, ORG] (two things).
    pub x_role: u8,
    /// H received it before its removal.
    pub x_role_seen: bool,
    /// 0: X holds nothing on A2; 1: write on A2; 2: write, and K removes it as H does; 3: admin
    /// on A2, and A2 admin on T1 (X administers T1 through A2 for good); 4: as 3, and B removes A2
    /// from T1 at the removal's tick, stating [A] (a removal of more than one hop); 5: as 1 but A2
    /// admin on T1, X's grant of G through [A2] at 4, and B demoting A2 on T1 to write with the
    /// flag at the removal's tick, stating [A] (a kiosk: a holder kept at write, the grants made
    /// by it kept). In 1 and 2, A2's share carries no flag and GU's does: X grants through
    /// [A2, GU].
    pub x_a2: u8,
    /// B sides with X's removal of H until its user switches at `AFTER`.
    pub b_side_x: bool,
    /// At `AFTER` H grants N5 again and B grants A2 write on T1 again.
    pub regrant: bool,
    /// 0: H mints A. 1: M mints A, pairs H at 0, writes T1 at 1, leaves A at 2, writes T1 again
    /// at 3. 2: as 1, B's admin grant (by H at 1) timed.
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

/// The thief's menu: 20 to 24 and 25, 26 are aimed at the remover (X, or a made-up key X grants
/// admin, granting H admin, standing or until just after the removal; X removing M listing nothing,
/// or listing M's grant of H; X demoting H listing its own grant); `N5_MOVES` are signed with the
/// key of N5, removed by X before the theft (`Setup::n5` 3); 31 is X's twin of that removal; 32 is
/// X removing A from T1 by [A2] (where it administers T1 through A2); 33 and 34 are X's own grant
/// set timed by itself (admin until the tick after its `ts`; write until after the story); 35 to 37
/// are may-grant grants through A2's arrangement (where X writes A2: [A2, GU], GU holding read with
/// the flag; [A2] in the kiosk's world): Z granted beyond it (at write through [A2, GU], and at
/// read through [A2] whose share carries no flag), at read, and at read until the next tick,
/// finalized by X then and granted again; 38 to 40 are purge requests by author: by A on T1 along [A], by A2 on T1 along
/// [A2] (X's right where it keeps writing A2), by A on T1 along [A2] (an author not on its chain: no
/// right); 41 withholds the removal from K until the settle and writes T1 after it, which K
/// receives at once and compacts T1 carrying (an honest writer compacting before it holds the
/// removal); 42 is X's own cover of T1, backdated, carrying its writes there; 43 is X removing H and
/// B in one commit (spec/commits.md §2), listing nothing; 44 to 46 put an end date on an admin grant
/// (`Until`): X ending H's admin at the removal, backdated; X ending H's admin a tick after its own
/// `ts`, stamped after the theft; X ending A's admin on T1 at the removal through A2, backdated (the
/// grant above the signer's on B's removal of A2 from T1, where B makes it). 47 to 53 lower an honest
/// admin: 47 and 48, with N5's key where X removed N5 before the theft (`Setup::n5` 3), N5
/// removing or demoting B, stamped before X's removal of N5 (the pair's first world); 49 and 50, X
/// removing or demoting B, stamped before X's role writes; 51, X removing K from A2 where it
/// administers A2 (`Setup::x_a2` 3, 4), backdated; 52, a made-up key Z X backdates admin to removing
/// B after the theft; 53, the same with Z made by N5's key before X's removal of N5. 54 and 55 use
/// a key the thief made up (TK): X grants it admin on A (an ordinary admin write: notes/
/// write-path-design.md, Keys K3), backdated before the removal, and acts as A by it,
/// removing H (listing H's grant of X, which the key's grant rests on) or writing T1.
pub const MOVES: usize = 56;
/// N5 grants H admin, standing or until just after the removal; N5 removes H; N5 demotes H. Each
/// stamped before X's removal of N5.
pub const N5_MOVES: std::ops::Range<usize> = 27..31;
/// The moves the thief may make at tick 5, heard by H and B before the removal (`Move::made` 5):
/// X's removal of H, those aimed at the remover but through a made-up key, and N5's.
pub fn early(kind: usize) -> bool {
    matches!(kind, 11 | 20 | 21 | 24 | 25 | 26 | 31 | 43 | 44 | 45 | 46) || N5_MOVES.contains(&kind)
}

/// What a world is built from: its setup, the thief's moves, and the receipts generator.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    pub setup: Setup,
    pub moves: Vec<Move>,
    pub rng: u64,
    /// The world's index in its run (random or family), for `-- 0 <mode> --only I`.
    pub index: u64,
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
    /// B's demotion of A2 on T1 to write with the flag by [A] (`Setup::x_a2` 5).
    pub kiosk: Option<Id>,
    pub rx: Option<Id>,
    pub xfirst: Option<Id>,
    pub gs: Id,
    /// GU's share of T1 (`Setup::x_a2` 1, 2).
    pub gg: Option<Id>,
    pub g5: Option<Id>,
    pub xrole: Option<Id>,
    /// X's removal of N5 before the theft (`Setup::n5` 3), N5's grant of write on T1 to B before
    /// it (which it lists), and M's grant of H (`Setup::mint`).
    pub out5: Option<Id>,
    pub gb5: Option<Id>,
    pub gh: Option<Id>,
    pub gx: Id,
    /// X's grant of G to read T1 through A2's arrangement (`Setup::x_a2` 1, 2, 5).
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
    /// The honest lowerings each node's user chose at `AFTER` (`choices`): every one it held, where
    /// it had no order.
    pub chose: BTreeMap<Thing, Vec<Id>>,
    /// `sides`' work so far, per node: after each tick, what it held and had recorded. A function
    /// of the commits made by that tick; `touch` forgets it from a tick on.
    sided: std::cell::RefCell<BTreeMap<Thing, Vec<(Set, Set)>>>,
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

/// The path X's may-grant grants on T1 state where it writes A2 (`Setup::x_a2` 1, 2, 5): through
/// GU, the arrangement holding read with the flag; in the kiosk's world through A2 itself.
pub fn x_route(s: &Setup) -> &'static [Thing] {
    if s.x_a2 == 5 {
        &[A2]
    } else {
        &[A2, GU]
    }
}

/// An addendum owed: against removal `r`, on thing `on` by `path`, listing what the node had
/// received by `r`'s `ts` that `r` does not list.
type Owed = (Id, Thing, Vec<Thing>, Set);

impl Sim {
    fn put(&mut self, c: (Thing, u32, &[Thing], Thing, Kind), made: u32, rng: &mut Rng, hostile: bool) -> Id {
        let key = own_key(c.0);
        self.put_signed(key, c, made, rng, hostile)
    }
    /// `put`, signed by key `key` as the signer.
    fn put_signed(&mut self, key: Thing, c: (Thing, u32, &[Thing], Thing, Kind), made: u32, rng: &mut Rng, hostile: bool) -> Id {
        let (signer, ts, path, on, kind) = c;
        let i = self.w.push_signed(key, signer, ts, path, on, kind);
        self.deliver(i, made, rng, hostile);
        i
    }
    /// One commit of several grant writes (`World::commit`), received as one.
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
    /// One commit of grant writes on several things, each `(path, on, kind)` (`World::group`),
    /// received as one by every node syncing one of them.
    fn put_group(&mut self, signer: Thing, ts: u32, parts: Vec<(&[Thing], Thing, Kind)>, made: u32, rng: &mut Rng, hostile: bool) -> Vec<Id> {
        let ids: Vec<Id> = parts.into_iter().map(|(path, on, kind)| self.w.push(signer, ts, path, on, kind)).collect();
        self.w.group(&ids);
        self.deliver(ids[0], made, rng, hostile);
        for _ in &ids[1..] {
            self.made.push(made);
            self.recv.push(self.recv[ids[0]].clone());
        }
        ids
    }
    /// The units commit `i` goes to: the things its commit's parts are on, and those a removal is
    /// logged under.
    fn units(&self, i: Id) -> Things {
        let mut units: Things = self.w.part_ids(self.w.cid(i)).map(|p| self.w.commits[p].on).collect();
        units.extend(self.logged.get(&i).into_iter().flatten());
        units
    }
    /// What `sides` worked out for tick `from` on is stale: a commit made then was added, its
    /// list or its receipts changed.
    fn touch(&mut self, from: u32) {
        for v in self.sided.get_mut().values_mut() {
            v.truncate(from as usize);
        }
    }
    /// Commit `i`'s receipt times.
    fn deliver(&mut self, i: Id, made: u32, rng: &mut Rng, hostile: bool) {
        self.touch(made);
        let signer = self.w.commits[i].signer;
        self.made.push(made);
        let units = self.units(i);
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
        let spec = Spec { setup: s, moves: moves.to_vec(), rng: rng.0, index: 0 };
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
        sync.insert(J, Things::from([D1, T2]));
        let w = if s.mint > 0 { minted_by(M) } else { account() };
        let mut m = Sim { w, spec, setup: s, made: vec![], recv: vec![], sync, r: 0, r2: None, r3: None, kiosk: None, rx: None, xfirst: None, gs: 0, gg: None, g5: None, xrole: None, out5: None, gb5: None, gh: None, gx: 0, gi: None, cover_by_k: None, unaware: Set::new(), smuggled: Set::new(), thief: BTreeMap::new(), logged: BTreeMap::new(), chose: BTreeMap::new(), sided: Default::default() };
        let grant = Kind::set;
        if s.mint > 0 {
            m.gh = Some(m.put((M, 0, &[], A, grant(H, Role::Admin)), 0, rng, false));
        }
        m.gx = m.put((H, 1, &[], A, grant(X, Role::Admin)), 1, rng, false);
        let until = (s.mint == 2).then_some(B_UNTIL);
        m.put((H, 1, &[], A, match until { Some(u) => grant(B, Role::Admin).until(u), None => grant(B, Role::Admin) }), 1, rng, false);
        let a2 = if s.x_a2 >= 3 { Role::Admin } else { Role::Write };
        if s.x_a2 > 0 {
            m.put((K, 1, &[], A2, grant(X, if s.x_a2 == 5 { Role::Write } else { a2 })), 1, rng, false);
        }
        if s.mint > 0 {
            m.put((M, 1, &[A], T1, Kind::Content), 1, rng, false);
            let f = m.w.cut(&m.w.through((M, A), |_| true));
            m.put((M, 2, &[], A, grant(M, Role::None).listing(f)), 2, rng, false);
            m.put((M, 3, &[A], T1, Kind::Content), 3, rng, false);
        }
        // A, two steps up D1's mint chain, holds a direct grant on D1 too; J holds admin on D1 and
        // writes T2 through D1, which holds write there with the flag
        // (by [A, T1]: a path ending at A, the holder, is a self-removal's)
        m.put((H, 1, &[A, T1], D1, grant(A, Role::Admin)), 1, rng, false);
        m.put((H, 1, &[A], D1, grant(J, Role::Admin)), 1, rng, false);
        m.put((H, 1, &[A, ORG], T2, grant(D1, Role::Write).may_grant()), 1, rng, false);
        m.put((J, 3, &[D1], T2, Kind::Content), 3, rng, false);
        // J grants RD2 read on T2 by D1's flag: a grant-class write resting on (D1, T2)
        m.put((J, 3, &[D1], T2, grant(RD2, Role::Read)), 3, rng, false);
        // B removes J from D1 by [A] at 4 (a descent of two steps); J writes T2 after it, and at 10
        // makes D1 leave T2 (an honest holder thing's leave)
        let f = m.w.cut(&m.w.through((J, D1), |i| m.got(i, B, 4)));
        m.put((B, 4, &[A], D1, grant(J, Role::None).listing(f)), 4, rng, false);
        m.put((J, 5, &[D1], T2, Kind::Content), 5, rng, false);
        m.put((J, 10, &[D1], T2, grant(D1, Role::None)), 10, rng, false);
        let sharer = if s.sharer_x { X } else { B };
        m.gs = m.put((sharer, 2, &[A], T1, grant(A2, a2)), 2, rng, false);
        if matches!(s.x_a2, 1 | 2) {
            m.gg = Some(m.put((sharer, 2, &[A], T1, grant(GU, Role::Read).may_grant()), 2, rng, false));
        }
        if matches!(s.x_a2, 1 | 2 | 5) {
            // a may-grant grant: X's path gives write on A2, and GU's read with the flag on T1
            // (A2's admin at 4 for the kiosk, which an offline B receives only at the settle)
            let t = if s.x_a2 == 5 { 4 } else { 2 };
            m.gi = Some(m.put((X, t, x_route(&s), T1, grant(G, Role::Read)), t, rng, false));
        }
        if s.n5 >= 3 {
            let g = m.put((H, 1, &[], A, grant(N5, Role::Admin)), 1, rng, false);
            let gb5 = m.put((N5, 2, &[A], T1, grant(B, Role::Write)), 2, rng, false);
            m.recv[gb5].insert(H, 2);
            m.gb5 = Some(gb5);
            // equivocation (move 31): X's twin of its removal of N5, at its `ts`, ordered before it
            // (a commit ID the thief ground), listing H's grant of N5 and not N5's grant to B
            for mv in moves.iter().filter(|mv| mv.kind == 31) {
                let f = m.w.cut(&[g]);
                let twin = m.put((X, 3, &[], A, grant(N5, Role::None).listing(f)), mv.made, rng, true);
                m.thief.insert(twin, 31);
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
            let g = m.put((X, 4, &[A], T1, Kind::purge(A)), 4, rng, false);
            if m.sync[&H].contains(&T1) {
                m.recv[g].insert(H, if s.x_role_seen { 4 } else { SETTLE });
            }
            m.xrole = Some(g);
        } else if x_role == 5 {
            // one commit writing two things: RD read on T1 through A, A2 admin on T2 through A, ORG
            let f1 = m.w.cut(&m.w.through((RD, T1), |_| true));
            let f2 = m.w.cut(&m.w.through((A2, T2), |_| true));
            let ids = m.put_group(X, 3, vec![(&[A], T1, grant(RD, Role::Read).listing(f1)), (&[A, ORG], T2, grant(A2, Role::Admin).listing(f2))], 3, rng, false);
            if m.sync[&H].contains(&T1) || m.sync[&H].contains(&T2) {
                for &g in &ids {
                    m.recv[g].insert(H, if s.x_role_seen { 3 } else { SETTLE });
                }
            }
            m.xrole = Some(ids[0]);
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
        m.put((B, 9, &[A, ORG], T2, Kind::purge(A)), 9, rng, false);
        m.put((K, 9, &[A2], T1, Kind::purge(A2)), 9, rng, false);
        // K compacts T1 at 10, carrying what shows there in its own walk
        m.cover(K, 10, &[], rules, rng);
        if s.b_side_x {
            let f = m.w.cut(&m.w.through((H, A), |i| i != m.r));
            m.rx = Some(m.put((X, 5, &[], A, grant(H, Role::None).listing(f)), 7, rng, false));
        }
        // the settle: whatever exists reaches every node syncing its unit
        m.touch(SETTLE);
        for i in 0..m.w.commits.len() {
            let units = m.units(i);
            for (&n, syncs) in &m.sync {
                if syncs.iter().any(|u| units.contains(u)) {
                    let t = m.recv[i].entry(n).or_insert(SETTLE);
                    *t = (*t).min(SETTLE.max(m.made[i]));
                }
            }
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
        // (or holds it on the other side: its walk does not apply it)
        let unaware = self.removals().iter().any(|&r| self.made[r] <= t && (!v.held.contains(&r) || !rd.applied.contains(&r)));
        if unaware {
            self.smuggled.extend(&carries);
        }
        let c = self.put((n, t, &path, T1, Kind::Cover { carries }), t, rng, false);
        if unaware {
            self.unaware.insert(c);
        }
        c
    }
    /// The removals at tick 6, each listing what its author had received through the grant.
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
        // the kiosk: where B's own walk gives it admin on A and A2 admin on T1
        let b = judge(&self.w, rules, &self.view_at(B, Some(REMOVAL - 1), rules));
        let at = |e: Grant| b.state.get(&e).is_some_and(|&v| alive(v, REMOVAL) == Role::Admin);
        if self.setup.x_a2 == 5 && at((B, A)) && at((A2, T1)) {
            let all = self.w.through((A2, T1), |i| self.got(i, B, REMOVAL - 1));
            let k = self.put((B, REMOVAL, &[A], T1, Kind::set(A2, Role::Write).may_grant().listing(self.w.cut(&all))), REMOVAL, rng, false);
            self.kiosk = Some(k);
            self.stand(B, k, &all, rules);
        }
    }
    /// The honest removals.
    pub fn removals(&self) -> Vec<Id> {
        [Some(self.r), self.r2, self.r3, self.kiosk].into_iter().flatten().collect()
    }
    /// `end(r)` in `n`'s walk at `t`, trusting `r` beside its own trust set (`end_of`): `Nothing`
    /// where it does not apply `r` with its seeds, whichever side `n` is on.
    fn end_at(&self, n: Thing, t: u32, r: Id, rules: &Rules) -> End {
        let rd = judge(&self.w, rules, &self.view_at(n, Some(t), rules).trusting_also(r));
        end_of(&self.w, &rd, r)
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
    /// The remover's list (`Rules::stands`): the writers' rule (`writers_keep`) over what it
    /// received, in the order received, read in its own walk at the removal.
    fn stand(&mut self, n: Thing, r: Id, all: &[Id], rules: &Rules) {
        if !rules.stands {
            return;
        }
        let base: Vec<Id> = all.iter().copied().filter(|&i| !self.w.grant_class(i)).collect();
        let classed = self.received(n, all.iter().copied().filter(|&i| self.w.grant_class(i)), rules);
        let kept = writers_keep(base, &classed, rules.own_end, |l| {
            let f = self.w.cut(l);
            self.w.edit(r, |k| k.listing(f));
            self.touch(REMOVAL);
            self.end_at(n, REMOVAL, r, rules)
        });
        let f = self.w.cut(&kept);
        self.w.edit(r, |k| k.listing(f));
        self.touch(REMOVAL);
    }
    /// Per removal and thing (T1, T2 and D1): the plain content through the removed grant node `n`
    /// had received by the removal's `ts` that the removal does not list.
    fn owed(&self, n: Thing) -> Vec<Owed> {
        let mut out = vec![];
        for r in self.removals() {
            let h = self.w.sets(r).unwrap();
            for on in [T1, D1, T2] {
                let Some(path) = role_path(n, on) else { continue };
                if !self.sync[&n].contains(&on) {
                    continue;
                }
                let list: Set = (0..self.w.commits.len())
                    .filter(|&i| i != r && self.w.commits[i].on == on && !self.w.grant_class(i) && self.w.hops(i).contains(&h) && self.got(i, n, REMOVAL) && self.made[i] <= REMOVAL && !self.w.in_frontier(r, i))
                    .collect();
                if !list.is_empty() {
                    out.push((r, on, path.clone(), list));
                }
            }
        }
        out
    }
    /// Honest writing, the state-based rule (`Rules::rewrite`): at every tick, a node whose own
    /// current walk applies a removal it holds writes, per thing, an addendum listing what it owes
    /// there whenever its path gives it write and some owed commit is named by no addendum of its
    /// own that vouches. So it writes at receipt, again once it holds the right after a re-grant
    /// or a switch of side, and again whenever its earlier one stops vouching.
    fn answers(&mut self, rules: &Rules, rng: &mut Rng) {
        let mut seen: BTreeMap<Thing, (Set, Set, Vec<(Id, Thing)>)> = BTreeMap::new();
        let mut done: BTreeSet<(Thing, Id, Thing)> = BTreeSet::new();
        for t in REMOVAL + 1..=END {
            if t == AFTER {
                self.choices(rules);
                self.regrants(rng);
            }
            for n in [H, B, N5, K] {
                if !self.sync.contains_key(&n) {
                    continue;
                }
                let owed: Vec<Owed> = self.owed(n).into_iter().filter(|o| self.got(o.0, n, t) && (rules.rewrite || !done.contains(&(n, o.0, o.1)))).collect();
                if owed.is_empty() {
                    continue;
                }
                let v = self.view_at(n, Some(t), rules);
                // what it holds may already carry a removal it has not received (as evidence):
                // the answers owed are part of what changed
                let key = (v.held.clone(), v.trust.clone(), owed.iter().map(|o| (o.0, o.1)).collect::<Vec<_>>());
                if seen.get(&n) == Some(&key) {
                    continue;
                }
                seen.insert(n, key);
                let rd = judge(&self.w, rules, &v);
                for (r, on, path, list) in owed {
                    if !rd.applied.contains(&r) {
                        continue;
                    }
                    done.insert((n, r, on));
                    let mut all = vec![n];
                    all.extend(&path);
                    all.push(on);
                    if !all.windows(2).flat_map(|p| self.w.joins(p[0], p[1])).all(|e| rd.state.get(&e).is_some_and(|&v| alive(v, t) >= Role::Write)) {
                        continue;
                    }
                    let covered = |c: &Id| {
                        rd.vouching.iter().any(|&a| self.w.commits[a].signer == n && matches!(&self.w.commits[a].kind, Kind::Addendum { removal, list } if *removal == r && list.contains(c)))
                    };
                    if list.iter().all(covered) {
                        continue;
                    }
                    self.put((n, t, &path, on, Kind::Addendum { removal: r, list }), t, rng, false);
                }
            }
        }
    }
    /// At `AFTER` the user of every honest node with no order (`held_first`, from the receipts)
    /// chooses the honest lowerings it holds (notes/write-path-design.md §1 F4): a step of the
    /// history, with its consequences (a witness answering once its walk applies the removal).
    fn choices(&mut self, rules: &Rules) {
        let hon = self.honest_lowerings();
        for n in self.honest() {
            let v = self.view_at(n, Some(AFTER), rules);
            let held: Vec<Id> = hon.iter().copied().filter(|r| v.held.contains(r)).collect();
            let arrivals = self.arrivals(n, rules);
            if !held.iter().all(|&r| self.held_first(n, r, &v, &arrivals, false, rules)) {
                self.chose.insert(n, held);
            }
        }
    }
    /// At `AFTER` (`Setup::regrant`) H grants N5 again and B grants A2 write on T1 again, after
    /// the answers written before: an honest explicit write carries its author's frontier
    /// (spec/permissions.md §5.1 step 4), a re-grant included, and keeps the flag the share had.
    fn regrants(&mut self, rng: &mut Rng) {
        let s = self.setup;
        if !s.regrant {
            return;
        }
        let grant = Kind::set;
        if s.n5 > 0 && s.n5 < 3 {
            let f = self.w.cut(&self.w.through((N5, A), |i| self.got(i, H, AFTER)));
            self.put((H, AFTER, &[], A, grant(N5, Role::Admin).listing(f)), AFTER, rng, false);
        }
        let f = self.w.cut(&self.w.through((A2, T1), |i| self.got(i, B, AFTER)));
        let g = if s.x_a2 == 5 { grant(A2, Role::Write).may_grant() } else { grant(A2, Role::Write) };
        self.put((B, AFTER, &[A], T1, g.listing(f)), AFTER, rng, false);
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
        if mv.kind == 31 {
            // made with the setup (`Setup::n5` 3)
            return;
        }
        if (47..54).contains(&mv.kind) {
            // a witness lowered: by N5's key before X's removal of N5, or by X backdated, or by a
            // made-up key after the theft
            let (early5, back) = (mv.ts.min(2), mv.ts.min(2));
            let late = mv.ts.max(REMOVAL + 1);
            if matches!(mv.kind, 47 | 48 | 53) && self.out5.is_none() {
                return;
            }
            match mv.kind {
                47 => {
                    self.put((N5, early5, &[], A, grant(B, Role::None)), mv.made, rng, true);
                }
                48 => {
                    self.put((N5, early5, &[], A, grant(B, Role::Write)), mv.made, rng, true);
                }
                49 => {
                    self.put((X, back, &[], A, grant(B, Role::None)), mv.made, rng, true);
                }
                50 => {
                    self.put((X, back, &[], A, grant(B, Role::Write)), mv.made, rng, true);
                }
                51 => {
                    if self.setup.x_a2 == 3 || self.setup.x_a2 == 4 {
                        self.put((X, back, &[], A2, grant(K, Role::None)), mv.made, rng, true);
                    }
                }
                _ => {
                    let by = if mv.kind == 52 { X } else { N5 };
                    let at = if mv.kind == 52 { mv.ts.min(REMOVAL - 1) } else { early5 };
                    self.put((by, at, &[], A, grant(Z, Role::Admin)), mv.made, rng, true);
                    self.put((Z, late, &[], A, grant(B, Role::None)), mv.made, rng, true);
                }
            }
            return;
        }
        if (54..56).contains(&mv.kind) {
            // a key the thief made up, granted admin on A by X backdated, acting as A
            let at = mv.ts.min(REMOVAL - 1);
            self.put((X, at, &[], A, grant(TK, Role::Admin)), mv.made, rng, true);
            let (on, kind) = if mv.kind == 54 { (A, grant(H, Role::None).listing(self.w.cut(&[self.gx]))) } else { (T1, Kind::Content) };
            self.put_signed(TK, (A, mv.ts.max(at), &[], on, kind), mv.made, rng, true);
            return;
        }
        if mv.kind == 41 {
            self.recv[self.r].insert(K, SETTLE);
            let i = self.put((X, mv.ts.max(REMOVAL + 1), &[A], T1, Kind::Content), mv.made, rng, true);
            self.recv[i].insert(K, mv.made);
            self.cover_by_k = Some((mv.made + 1, i));
            return;
        }
        if (44..47).contains(&mv.kind) {
            // an end date on the remover's admin (backdated to end at the removal, or stamped after
            // the theft), or on A's admin on T1 above B's removal of A2 (where B makes it)
            let c: (u32, &[Thing], Thing, Kind) = match mv.kind {
                44 => (mv.ts.min(REMOVAL - 1), &[], A, grant(H, Role::Admin).until(REMOVAL)),
                45 => (mv.ts.max(5), &[], A, grant(H, Role::Admin).until(mv.ts.max(5) + 1)),
                _ if self.r3.is_none() => return,
                _ => (mv.ts.min(REMOVAL - 1), &[A2], T1, grant(A, Role::Admin).until(REMOVAL)),
            };
            self.put((X, c.0, c.1, c.2, c.3), mv.made, rng, true);
            return;
        }
        if mv.kind == 43 {
            self.put_parts((X, mv.ts, &[], A, vec![grant(H, Role::None), grant(B, Role::None)]), mv.made, rng, true);
            return;
        }
        if mv.kind == 42 {
            let carries = (0..self.w.commits.len()).filter(|&i| self.w.commits[i].signer == X && self.w.commits[i].on == T1 && matches!(self.w.commits[i].kind, Kind::Content)).collect();
            self.put((X, mv.ts.min(REMOVAL - 1), &[A], T1, Kind::Cover { carries }), mv.made, rng, true);
            return;
        }
        if (38..41).contains(&mv.kind) {
            let (path, author): (&[Thing], _) = match mv.kind {
                38 => (&[A], A),
                39 => (&[A2], A2),
                _ => (&[A2], A),
            };
            self.put((X, mv.ts, path, T1, Kind::purge(author)), mv.made, rng, true);
            return;
        }
        if (35..38).contains(&mv.kind) {
            // where X writes A2 (and K may remove it): may-grant grants of Z through A2's
            // arrangement
            if !matches!(self.setup.x_a2, 1 | 2 | 5) {
                return;
            }
            let (ts, route) = (mv.ts, x_route(&self.setup));
            match mv.kind {
                35 => {
                    self.put((X, ts, route, T1, grant(Z, Role::Write)), mv.made, rng, true);
                    if route != [A2] {
                        // beyond it the other way: A2's own share carries no flag
                        self.put((X, ts, &[A2], T1, grant(Z, Role::Read)), mv.made, rng, true);
                    }
                }
                36 => {
                    self.put((X, ts, route, T1, grant(Z, Role::Read)), mv.made, rng, true);
                }
                _ => {
                    self.put((X, ts, route, T1, grant(Z, Role::Read).until(ts + 1)), mv.made, rng, true);
                    self.put((X, ts + 1, route, T1, Kind::finalize(Z)), mv.made, rng, true);
                    self.put((X, ts + 2, route, T1, grant(Z, Role::Read)), mv.made, rng, true);
                }
            }
            return;
        }
        if mv.kind == 32 && self.r3.is_none() {
            // where nobody removes A2 from T1, X administers T1 through A2 by right: no move
            return;
        }
        if N5_MOVES.contains(&mv.kind) {
            // N5's key, removed by X at 3: stamped before that
            let Some(_) = self.out5 else { return };
            let ts = mv.ts.min(2);
            let k = match mv.kind {
                27 => grant(H, Role::Admin),
                28 => grant(H, Role::Admin).until(REMOVAL + 1),
                29 => grant(H, Role::None),
                _ => grant(H, Role::Write),
            };
            self.put((N5, ts, &[], A, k), mv.made, rng, true);
            return;
        }
        let mine = |m: &Sim, on: Thing| -> Set { (0..m.w.commits.len()).filter(|&i| m.w.commits[i].signer == X && m.w.commits[i].on == on && !m.w.grant_class(i) && m.w.hops(i).contains(&(X, A))).collect() };
        if (20..24).contains(&mv.kind) {
            // a grant of admin to the remover, standing or timed, by X or by a key X made up
            let by = if mv.kind < 22 { X } else { Z };
            if by == Z {
                self.put((X, mv.ts.saturating_sub(1), &[], A, grant(Z, Role::Admin)), mv.made, rng, true);
            }
            let g = if mv.kind % 2 == 0 { grant(H, Role::Admin) } else { grant(H, Role::Admin).until(REMOVAL + 1) };
            self.put((by, mv.ts, &[], A, g), mv.made, rng, true);
            return;
        }
        let c: (Thing, &[Thing], Thing, Kind) = match mv.kind {
            // X removes A from T1 through A2, a grant above the signer's on B's removal's path,
            // listing the grant to A2 its own path rests on
            32 => (X, &[A2], T1, grant(A, Role::None).listing(self.w.cut(&[self.gs]))),
            // X removes the mint admin (the remover's granter where M minted A), listing nothing,
            // or listing M's grant of H
            24 => (X, &[], A, grant(M, Role::None)),
            25 => (X, &[], A, grant(H, Role::Write).listing(self.w.cut(&[self.gx]))),
            26 => (X, &[], A, grant(M, Role::None).listing(self.w.cut(&self.gh.into_iter().collect::<Vec<_>>()))),
            0 | 16 => (X, &[A], T1, Kind::Content),
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
            13 => (X, &[A2], T1, Kind::Addendum { removal: self.r, list: mine(self, T1) }),
            14 => (Z, &[], A, grant(X, Role::Admin)),
            15 => (X, &[], A, grant(N5, Role::None)),
            // by descent through the cut path
            17 => (X, &[A], D1, Kind::Content),
            // X leaves A by itself (a self-removal, its path ending at itself)
            18 => (X, &[], A, grant(X, Role::None)),
            // the same carrying an `until` in place of none: admin until just after, write until
            // after the story
            33 => (X, &[], A, grant(X, Role::Admin).until(mv.ts + 1)),
            34 => (X, &[], A, grant(X, Role::Write).until(B_UNTIL)),
            // X makes A leave T1, its path ending at A
            19 => (X, &[A], T1, grant(A, Role::None)),
            _ => unreachable!("move {}", mv.kind),
        };
        let ts = if mv.kind == 16 { 20 } else { mv.ts };
        self.put((c.0, ts, c.1, c.2, c.3), mv.made, rng, true);
    }
    /// What a node holds by `t` (None: at the final reading): its units' commits, the removals
    /// logged there, and their evidence among the commits made by then.
    pub fn held_at(&self, n: Thing, t: Option<u32>) -> Set {
        let avail: Set = (0..self.w.commits.len()).filter(|&i| t.is_none_or(|t| self.made[i] <= t)).collect();
        let unit: Set = avail.iter().copied().filter(|&i| self.recv[i].get(&n).is_some_and(|r| t.is_none_or(|t| *r <= t))).collect();
        evidence(&self.w, &unit, &avail)
    }
    /// `held_at`, given what the node held at an earlier tick.
    fn held_from(&self, before: &Set, n: Thing, t: Option<u32>) -> Set {
        let avail: Set = (0..self.w.commits.len()).filter(|&i| t.is_none_or(|t| self.made[i] <= t)).collect();
        let mut unit: Set = avail.iter().copied().filter(|&i| self.recv[i].get(&n).is_some_and(|r| t.is_none_or(|t| *r <= t))).collect();
        if unit.is_subset(before) && t.is_some_and(|t| !self.made.contains(&t)) {
            return before.clone();
        }
        unit.extend(before);
        evidence(&self.w, &unit, &avail)
    }
    pub fn held(&self, n: Thing) -> Set {
        self.held_at(n, None)
    }
    /// The node's view by `t`: leaves for the things it syncs, and with `Rules::evidence_leaves`
    /// for every thing a held grant write is on. Its trust set: the sides it recorded (`sides`:
    /// its own lowerings and those it held first); B's user (`Setup::b_side_x`) chooses X's
    /// removal of H until it chooses H's removal of X at `AFTER` (`choose`); from `AFTER` on, what
    /// its user chose then (`chose`). The nodes that trust nothing record nothing: a node with no
    /// order, by fiat.
    pub fn view_at(&self, n: Thing, t: Option<u32>, rules: &Rules) -> View {
        self.view_choosing(n, t, rules, true)
    }
    /// The node's final view as it stands without its user's choice at `AFTER` (`chose`): what it
    /// is shown before choosing.
    pub fn view_unchosen(&self, n: Thing, rules: &Rules) -> View {
        self.view_choosing(n, None, rules, false)
    }
    fn view_choosing(&self, n: Thing, t: Option<u32>, rules: &Rules, chosen: bool) -> View {
        let (held, trust) = if self.untrusting().contains(&n) { (self.held_at(n, t), Set::new()) } else { self.stood(n, t, rules) };
        let leaves = self.leaves(n, &held, rules);
        let mut v = View { held, leaves: Some(leaves), trust };
        let before = t.is_some_and(|t| t < AFTER);
        if self.setup.b_side_x && n == B {
            // its user's choices (F4): X's removal of H once held, then H's removal of X
            v = View { trust: v.trust.iter().copied().filter(|&i| i != self.r || !before).collect(), ..v };
            for on in if before { vec![self.rx] } else { vec![self.rx, Some(self.r)] }.into_iter().flatten() {
                if v.held.contains(&on) {
                    v = choose(&self.w, rules, &v, on);
                }
            }
        }
        for &r in self.chose.get(&n).into_iter().flatten().filter(|_| chosen && !before) {
            if v.held.contains(&r) {
                v = choose(&self.w, rules, &v, r);
            }
        }
        v
    }
    fn leaves(&self, n: Thing, held: &Set, rules: &Rules) -> Things {
        let mut leaves = self.sync[&n].clone();
        if rules.evidence_leaves {
            leaves.extend(held.iter().filter(|&&i| self.w.grant_class(i)).map(|&i| self.w.commits[i].on));
        }
        leaves
    }
    /// The sides `n` recorded by `t` (notes/write-path-design.md §1, First received), from its own
    /// history. F1: an explicit lowering it wrote, when it writes it. F2: an explicit lowering R
    /// its walk applied (over what it held and had recorded) just before an update bringing a
    /// write R leaves out, one of the seeds R would have trusted (`seeds`). F3: R and that write
    /// first held in one update, or the write first, record nothing. A side stays (F4). Controls:
    /// `Sides`.
    pub fn sides(&self, n: Thing, t: Option<u32>, rules: &Rules) -> Set {
        self.stood(n, t, rules).1
    }
    /// What `n` holds by `t` (`held_at`, worked out tick by tick on the way) and its `sides`.
    fn stood(&self, n: Thing, t: Option<u32>, rules: &Rules) -> (Set, Set) {
        let last = self.recv.iter().filter_map(|r| r.get(&n).copied()).max().unwrap_or(0).max(self.made.iter().copied().max().unwrap_or(0));
        let end = t.unwrap_or(last).min(last);
        let w = &self.w;
        // a lowering with a list: no self-removal (and not what a reading applies as a may-grant
        // grant)
        let explicit = |r: Id| candidate(w, rules, r);
        // the ticks worked out before, and on from there
        let done = self.sided.borrow().get(&n).map_or(0, |v| v.len().min(end as usize + 1));
        let (mut before, mut trust) = if done == 0 { (Set::new(), Set::new()) } else { self.sided.borrow()[&n][done - 1].clone() };
        for u in done as u32..=end + 1 {
            debug_assert!(u > end || self.sided.borrow().get(&n).map_or(0, Vec::len) == u as usize, "ticks are worked out in order");
            // (what it held before is within the closure: holdings only grow)
            let now = self.held_from(&before, n, if u > end { t } else { Some(u) });
            let new: Vec<Id> = now.difference(&before).copied().filter(|&i| w.grant_class(i)).collect();
            if new.is_empty() {
                if u <= end {
                    self.sided.borrow_mut().entry(n).or_default().push((now.clone(), trust.clone()));
                }
                before = now;
                continue;
            }
            // what the update brings: another party's writes (its own are no arrival)
            let arrived: Vec<Id> = new.iter().copied().filter(|&i| !self.own(n, i, rules)).collect();
            let leaves = self.leaves(n, &now, rules);
            let v_now = View { held: now.clone(), leaves: Some(leaves), trust: Set::new() };
            // F2: the lowerings held before this update that would seed a write it brings
            if rules.sides != Sides::NoReceipt {
                let tie = rules.sides == Sides::Tie;
                let pool = if tie { &now } else { &before };
                // each lowering's seeds over this update's held set, computed once
                let seeds_of = seeds_once(w, rules, &v_now);
                let cands: Vec<(Id, Vec<Id>)> = pool
                    .iter()
                    .copied()
                    // (a seed is ordered before it; the cheapest test first)
                    .filter(|&r| arrived.iter().any(|&j| w.key(j) < w.key(r)))
                    .filter(|&r| !trust.contains(&r) && explicit(r))
                    // no side in its fight yet: nothing recorded stands against it
                    .filter(|&r| rules.sides == Sides::Both || !trust.iter().any(|&l| against_by(w, rules, r, l, &seeds_of)))
                    .filter_map(|r| {
                        let late: Vec<Id> = seeds_of(r).into_iter().filter(|j| arrived.contains(j)).collect();
                        (!late.is_empty()).then_some((r, late))
                    })
                    .collect();
                if !cands.is_empty() {
                    let rd = (!tie).then(|| judge(w, rules, &View { held: before.clone(), leaves: Some(self.leaves(n, &before, rules)), trust: trust.clone() }));
                    for (r, late) in cands {
                        // its reading applied it (variant `Lowered`: and it took its hop down there)
                        let took = |rd: &Reading| !rd.by_flag.contains(&r) && if rules.sides == Sides::Lowered { rd.lowered.contains(&r) } else { rd.applied.contains(&r) };
                        let stood = match &rd {
                            _ if rules.sides == Sides::Unapplied => true,
                            Some(rd) => took(rd),
                            // control `Tie`: as if the lowering had come an update ahead of the writes
                            None => took(&judge(w, rules, &View { trust: trust.clone(), ..v_now.clone() }.without(&late))),
                        };
                        if stood {
                            trust.insert(r);
                        }
                    }
                }
            }
            // F1: its own, a choice (F4)
            if rules.sides != Sides::NoOwn {
                let mut own: Vec<Id> = new.iter().copied().filter(|&r| self.own(n, r, rules) && explicit(r)).collect();
                if own.iter().any(|&r| flag_grant(w, r).is_some()) {
                    let rd = judge(w, rules, &View { trust: trust.clone(), ..v_now.clone() });
                    own.retain(|r| !rd.by_flag.contains(r));
                }
                for r in own {
                    trust = choose(w, rules, &View { trust, ..v_now.clone() }, r).trust;
                }
            }
            if u <= end {
                self.sided.borrow_mut().entry(n).or_default().push((now.clone(), trust.clone()));
            }
            before = now;
        }
        (before, trust)
    }
    pub fn view(&self, n: Thing, rules: &Rules) -> View {
        self.view_at(n, None, rules)
    }
    /// Node `n` made commit `i` itself: signed with its key, and not by the thief holding that key
    /// (a node knows its own writes; a commit its stolen key signed reaches it like any other).
    pub fn wrote(&self, n: Thing, i: Id) -> bool {
        self.w.commits[i].signer == n && (n == X || !self.thief.contains_key(&i))
    }
    /// What `sides` takes as the node's own (control `Sides::KeyOwn`: whatever its key signed).
    fn own(&self, n: Thing, i: Id, rules: &Rules) -> bool {
        if rules.sides == Sides::KeyOwn { self.w.commits[i].signer == n } else { self.wrote(n, i) }
    }
    /// Node `n` joins at tick `at`: it holds nothing before, and everything made by then reaches
    /// it in one update (a new node's first sync); the users' choices at `AFTER` follow it.
    pub fn joins(&mut self, n: Thing, at: u32, rules: &Rules) {
        for r in &mut self.recv {
            if let Some(t) = r.get_mut(&n) {
                *t = (*t).max(at);
            }
        }
        self.touch(0);
        self.chose.clear();
        self.choices(rules);
    }
    /// The honest lowerings a node may side with: the honest removals, and X's removal of N5
    /// before the theft.
    pub fn honest_lowerings(&self) -> Vec<Id> {
        self.removals().into_iter().chain(self.out5).collect()
    }
    /// The tick each commit `n` holds at the final reading was first held there.
    fn arrivals(&self, n: Thing, rules: &Rules) -> BTreeMap<Id, u32> {
        let last = self.recv.iter().filter_map(|r| r.get(&n).copied()).max().unwrap_or(0).max(self.made.iter().copied().max().unwrap_or(0));
        let mut out = BTreeMap::new();
        // (`sides` keeps what the node held after each tick)
        let (all, _) = self.stood(n, None, rules);
        for (u, (held, _)) in self.sided.borrow()[&n].iter().enumerate() {
            for &i in held {
                out.entry(i).or_insert(u as u32);
            }
        }
        for i in all {
            out.entry(i).or_insert(last + 1);
        }
        out
    }
    /// The oracle's side of first received, from the story alone and never from a reading: `n`
    /// held lowering `r` first where it wrote it, its user chose it (B's switch, `chose`), or every write
    /// of its held set `r` leaves out (`seeds`: a function of the held set and the lists) arrived
    /// there after `r` did, as did every lowering that cannot stand beside it (`against`). A node
    /// trusting nothing has no order. `thiefs`: counting only what the thief made (a write X
    /// made before the theft that `r` leaves out came first at most nodes: it gives them no
    /// order, and takes nothing from `r` or from a witness's path).
    pub fn held_first(&self, n: Thing, r: Id, v: &View, arrivals: &BTreeMap<Id, u32>, thiefs: bool, rules: &Rules) -> bool {
        if self.untrusting().contains(&n) {
            return false;
        }
        if self.wrote(n, r) || (self.setup.b_side_x && n == B && r == self.r) || self.chose.get(&n).is_some_and(|c| c.contains(&r)) {
            return true;
        }
        // what contests `r` there: the writes it leaves out, and the lowerings leaving it out
        let w = &self.w;
        let seeds_of = seeds_once(w, rules, v);
        let mut contest: Set = seeds_of(r);
        contest.extend(v.held.iter().copied().filter(|&l| candidate(w, rules, l) && !self.wrote(n, l) && against_by(w, rules, r, l, &seeds_of)));
        let counts = |j: Id| !thiefs || self.thief.contains_key(&j) || self.hostile(j) || Some(j) == self.xfirst || Some(j) == self.rx;
        contest.iter().all(|&j| arrivals[&j] > arrivals[&r] || !counts(j))
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
        self.thief.get(&i).is_some_and(|k| matches!(k, 21 | 23 | 25 | 44 | 45 | 46) || (*k == 24 && self.gh.is_some()))
    }
    /// A lowering of a grant a removal of X's own path stands on.
    fn lowers_remover(&self, i: Id) -> bool {
        self.w.lowers(i).is_some_and(|e| [Some(self.r), self.r2].into_iter().flatten().any(|r| self.w.rests(r).contains(&e)))
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
    /// Per failing property, the indices of the first worlds failing it (`--only I` replays one).
    pub failing: BTreeMap<&'static str, BTreeSet<u64>>,
}

impl crate::Tally for Stats {
    fn merge(&mut self, o: Stats) {
        self.worlds += o.worlds;
        crate::Tally::merge(&mut self.fails, o.fails);
        crate::Tally::merge(&mut self.checked, o.checked);
        for (k, s) in o.first {
            self.first.entry(k).or_insert(s);
        }
        crate::Tally::merge(&mut self.noted, o.noted);
        for (k, n) in o.failing {
            let f = self.failing.entry(k).or_default();
            f.extend(n);
            while f.len() > 12 {
                f.pop_last();
            }
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
        for (k, f) in &self.failing {
            println!("failing {k}: worlds {f:?}");
        }
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
        let f = self.failing.entry(prop).or_default();
        f.insert(m.spec.index);
        while f.len() > 12 {
            f.pop_last();
        }
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
        let mut next: Vec<Spec> = (0..cur.moves.len()).map(|k| Spec { moves: cur.moves.iter().enumerate().filter(|&(i, _)| i != k).map(|(_, m)| m.clone()).collect(), ..cur.clone() }).collect();
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
    let name = |t: &Thing| ["?", "H", "B", "X", "N5", "K", "Z", "N6", "M", "G", "A", "A2", "ORG", "T1", "T2", "D1", "J", "GU"].get(*t as usize).copied().unwrap_or("?");
    let mut s = String::new();
    for (i, c) in m.w.commits.iter().enumerate() {
        let path: Vec<&str> = c.path.iter().map(name).collect();
        let kind = match &c.kind {
            Kind::Content => "content".to_string(),
            Kind::Grant { holder, role, until, frontier, may_grant, finalize } => {
                let mut k = format!("{} := {role:?}", name(holder));
                if *may_grant {
                    k += " may grant";
                }
                if *finalize {
                    k += " finalize";
                }
                if let Some(u) = until {
                    k += &format!(" until {u}");
                }
                k + &format!(" frontier {:?}", frontier.values().flatten().collect::<Vec<_>>())
            }
            Kind::Addendum { removal, list } => format!("addendum against {removal} {list:?}"),
            Kind::Purge { names: Names::Author(a) } => format!("purge by author {}", name(a)),
            Kind::Purge { names } => format!("purge {names:?}"),
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
            Kind::Grant { holder, role, until, frontier, may_grant, finalize } => {
                let f = frontier.iter().map(|(t, l)| (*t, ids(l))).collect();
                Kind::Grant { holder: *holder, role: *role, until: *until, frontier: f, may_grant: *may_grant, finalize: *finalize }
            }
            Kind::Addendum { removal, list } => Kind::Addendum { removal: map[removal], list: ids(list) },
            Kind::Content => Kind::Content,
            Kind::Purge { names: Names::Commit(j) } => Kind::Purge { names: Names::Commit(map[j]) },
            Kind::Purge { names } => Kind::Purge { names: *names },
            Kind::Cover { carries } => Kind::Cover { carries: ids(carries) },
        };
        let j = out.put(c.key, c.signer, c.ts, &c.path, c.on, kind, &c.direct);
        out.authored(j, c.pa);
        out.commits[j].purge_by = c.purge_by;
        out.commits[j].own = c.own;
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

/// Whether the reading without `x` held observes what `rd` does, `x` aside (`Reading::observed`:
/// roles over time, what each may grant, valid and purged content), and whether it applies the same
/// grant-class commits (counted, not a property: finding 33).
pub fn no_effect(w: &World, rules: &Rules, v: &View, rd: &Reading, x: Id) -> (bool, bool) {
    let (seen, same, _) = no_effect_of(w, rules, v, rd, &rd.observed(w), &[x]);
    (seen, same)
}

/// As `no_effect`, the writes `xs` (one commit's parts) taken out together, and whether what each
/// holder can do (roles over time, what it may grant, cuts) is the same, content aside. `seen`
/// is `rd.observed(w)`.
pub fn no_effect_of(w: &World, rules: &Rules, v: &View, rd: &Reading, seen: &Observed, xs: &[Id]) -> (bool, bool, bool) {
    let o = judge(w, rules, &v.clone().without(xs));
    let less = |s: &Set| s.iter().copied().filter(|i| !xs.contains(i)).collect::<Set>();
    let (mut a, b) = (seen.clone(), o.observed(w));
    for s in [&mut a.valid, &mut a.copied, &mut a.purged] {
        *s = less(s);
    }
    let roles = a.roles == b.roles && a.grantable == b.grantable && a.keys == b.keys && a.timeline == b.timeline && a.cuts == b.cuts;
    (a == b, o.applied == less(&rd.applied), roles)
}

/// The held commits whose grant-class parts all do nothing in the reading, each as its held parts:
/// grant writes it does not apply (void, refused, or never given a verdict), but those dropped (a
/// dropper's effect) or trusted (a trust set's). A node holds a
/// commit whole, so a commit is idle only where every part is.
pub fn idle(w: &World, v: &View, rd: &Reading) -> Vec<Vec<Id>> {
    let quiet = |i: Id| !rd.applied.contains(&i) && !rd.dropped.contains(&i) && !v.trust.contains(&i);
    let mut by: BTreeMap<Id, Vec<Id>> = BTreeMap::new();
    for &i in v.held.iter().filter(|&&i| w.grant_class(i)) {
        by.entry(w.cid(i)).or_default().push(i);
    }
    by.into_values().filter(|ps| ps.iter().all(|&i| quiet(i))).collect()
}

/// What an idle commit may change (notes/write-path-design.md §1, What judging once gives): for
/// each `idle` commit (`id` its first part, `parts` all), whether taking it out of the held set
/// changes what users observe, whether the reading then shows a dispute (`disputes`, computed once
/// and only where some commit has an effect), and whether it changes which writes apply (nobody
/// sees that: finding 33). `kind`: `void` (a void lowering among its parts), `unapplied` (a lowering
/// among them), else `idle` (grants, may-grant grants, finalizes, self-removals).
pub struct Effect {
    pub id: Id,
    pub parts: Vec<Id>,
    pub kind: &'static str,
    pub observed: bool,
    /// Of what is observed, what holders can do changes (else only which content counts).
    pub roles: bool,
    pub shown: bool,
    pub applies: bool,
}

pub fn effects(w: &World, rules: &Rules, v: &View, rd: &Reading) -> Vec<Effect> {
    let mut shown: Option<bool> = None;
    let observed = rd.observed(w);
    idle(w, v, rd)
        .into_iter()
        .map(|parts| {
            let (seen, same, roles_same) = no_effect_of(w, rules, v, rd, &observed, &parts);
            let shown = !seen && *shown.get_or_insert_with(|| !disputes(w, rules, v).is_empty());
            let kind = if parts.iter().any(|i| rd.voided.contains(i)) {
                "void"
            } else if parts.iter().any(|&i| rules.lowering(w, i).is_some() && !w.leave(i)) {
                "unapplied"
            } else {
                "idle"
            };
            Effect { id: parts[0], parts, kind, observed: !seen, roles: !roles_same, shown, applies: !same }
        })
        .collect()
}

/// Who an idle commit's effect is a fight among (notes/path-model-findings.md 34 to 36): its parts
/// and every grant-class commit whose applying it changes (`involved`); of them, those whose signer
/// held what they need at their key in no reading (`illegit`: the node's; without the commit; with
/// each held explicit lowering of another holder trusted besides, with and without it; trusting
/// nothing): applied in none, nor every grant of their path giving admin there (a key lowering
/// its own grant: its key hop giving a role there); and of those, the
/// ones the commit makes apply, or its own parts (`gains`).
pub struct Fight {
    pub involved: Set,
    pub illegit: Set,
    pub gains: Set,
}

pub fn fight_among(w: &World, rules: &Rules, v: &View, rd: &Reading, parts: &[Id]) -> Fight {
    let less = v.clone().without(parts);
    let o = judge(w, rules, &less);
    let mut involved: Set = parts.iter().copied().collect();
    involved.extend(rd.applied.symmetric_difference(&o.applied).copied());
    let mut views = vec![View { trust: Set::new(), ..v.clone() }, View { trust: Set::new(), ..less.clone() }];
    for &r in &v.held {
        let Kind::Grant { holder, .. } = &w.commits[r].kind else { continue };
        if *holder == w.commits[r].signer || rules.lowering(w, r).is_none() || w.leave(r) || v.trust.contains(&r) {
            continue;
        }
        views.push(v.clone().trusting_also(r));
        if !parts.contains(&r) {
            views.push(less.clone().trusting_also(r));
        }
    }
    let mut readings: Vec<Reading> = views.iter().map(|x| judge(w, rules, x)).collect();
    readings.push(rd.clone());
    readings.push(o.clone());
    let at = |r: &Reading, e: Grant, k: Key| {
        let rec = if w.is_record(e) { (Role::Admin, None) } else { (Role::None, None) };
        alive(r.hist.get(&e).and_then(|h| h.iter().rev().find(|(x, _)| *x < k)).map_or(rec, |x| x.1), k.0)
    };
    // a key lowering its own grant needs only to hold it (K4)
    let own_hop = |i: Id| w.well(i) && w.leave(i) && w.rests(i).is_empty() && w.sets(i) == Some(w.key_hop(i));
    let held = |i: Id| readings.iter().any(|r| r.applied.contains(&i) || (own_hop(i) && at(r, w.key_hop(i), w.key(i)) > Role::None) || (!w.rests(i).is_empty() && (!w.hops(i).is_empty() || w.commits[i].on == w.commits[i].signer) && w.rests(i).iter().all(|&e| at(r, e, w.key(i)) == Role::Admin)));
    let illegit: Set = involved.iter().copied().filter(|&i| !held(i)).collect();
    let gains = illegit.iter().copied().filter(|i| parts.contains(i) || (rd.applied.contains(i) && !o.applied.contains(i))).collect();
    Fight { involved, illegit, gains }
}

/// At one node's reading: `self-taken` (no applied commit's path loses its authority to the
/// commit's own drops) and, at the node `relabel` picks, `one reading` (a relabelling of commit IDs
/// keeping the walk's order reads the same), failing; `stray` (a drop whose dropper does not apply
/// at the end), counted. Of each idle write (`effects`), counted, not failing (an idle write may
/// decide a fight among admins, judged once: notes/path-model-findings.md 34 to 36): an effect
/// users observe with no dispute shown, as `void` (a void lowering), `unapplied` (any other
/// lowering) or `idle` (any other grant write), by trust (`unshown T`/`N`), whether it is
/// the thief's and which side of H's removal it decides; one with a dispute shown (`fight`); any
/// effect in an honest history (`honest`); `void shown`, `unapplied shown`, `idle shown` (only which
/// writes apply differs). Failing, `idle gains`: an unshown effect making a commit of the thief's
/// show that is signed by a key that never legitimately held the right (Z, N5's after its removal)
/// and that holds no right by a path X keeps (`by_right`, safety's own reading: Z granted by X
/// through A2 writes by that grant), at any node, or, at a node trusting the removal, made by X
/// after it through A.
#[allow(clippy::too_many_arguments)]
fn void_checks(w: &World, rules: &Rules, v: &View, rd: &Reading, n: Thing, t: bool, quiet: bool, relabel: bool, by_right: &dyn Fn(Id) -> bool, m: &Sim, st: &mut Stats) {
    st.count("self-taken");
    if !rd.self_taken.is_empty() {
        st.fail("self-taken", m, format!("node {n}: commits {:?} lose their path's authority to their own drops", rd.self_taken));
    }
    st.count(if t { "stray T" } else { "stray N" });
    if !rd.stray.is_empty() {
        st.note(if t { "stray T" } else { "stray N" }, m, format!("node {n}: {:?} dropped by a write that does not apply", rd.stray));
    }
    for e in effects(w, rules, v, rd) {
        let (k, ks) = match e.kind {
            "void" => ("void", "void shown"),
            "unapplied" => ("unapplied", "unapplied shown"),
            _ => ("idle", "idle shown"),
        };
        st.count(k);
        if e.observed && !e.shown && !e.roles {
            st.note("content only", m, format!("node {n}: the idle write {} changes which content counts, no role, unshown", e.id));
        }
        if e.observed && !e.shown {
            st.note(k, m, format!("node {n}: the idle write {} has an effect, no dispute shown", e.id));
            st.note(if t { "unshown T" } else { "unshown N" }, m, format!("node {n}: the idle write {} has an effect, no dispute shown", e.id));
            // who the fight is among, from the generated history: the thief's writes it makes show
            let o = judge(w, rules, &v.clone().without(&e.parts));
            let gained: Set = rd.applied.difference(&o.applied).chain(rd.valid.difference(&o.valid)).copied().filter(|i| m.thief.contains_key(i)).collect();
            if e.parts.iter().any(|i| m.thief.contains_key(i)) {
                st.note(if t { "unshown, the thief's T" } else { "unshown, the thief's N" }, m, format!("node {n}: the thief's idle write {} has an effect", e.id));
            }
            // whose side it decides: H's removal of X applying only with it (the remover's) or only
            // without it (the thief's)
            let side = match (rd.applied.contains(&m.r), o.applied.contains(&m.r)) {
                (true, false) => Some(if t { "unshown, the remover's side T" } else { "unshown, the remover's side N" }),
                (false, true) => Some(if t { "unshown, the thief's side T" } else { "unshown, the thief's side N" }),
                _ => None,
            };
            if let Some(s) = side {
                st.note(s, m, format!("node {n}: the idle write {} decides whether H's removal {} applies", e.id, m.r));
            }
            // a party that never legitimately held the right (a made-up key, a removed node's key)
            // gains nothing, at any node; a removed party gains nothing through its removed grant
            // that it made after the removal where the removal is trusted
            st.count("idle gains");
            for &i in &gained {
                let c = &w.commits[i];
                let late = m.made[i] >= w.commits[m.r].ts;
                let (bad, key) = match (c.signer, c.path.first() == Some(&A2)) {
                    // a key holding its write by a path X keeps (a may-grant grant through A2) gains
                    // nothing it did not hold: the effect only moves which content counts
                    (Z | N5, _) if by_right(i) => (false, if t { "thief gains T by right" } else { "thief gains N by right" }),
                    (Z | N5, _) => (true, ""),
                    (_, true) => (false, if t { "thief gains T by X through A2" } else { "thief gains N by X through A2" }),
                    _ if t => (late, "thief gains T by X through A, made before the removal"),
                    _ => (false, "thief gains N by X through A"),
                };
                let what = format!("node {n}: the idle write {} makes the thief's {i} (move {}) show", e.id, m.thief[&i]);
                if bad {
                    st.fail("idle gains", m, what);
                } else {
                    st.note(key, m, what);
                }
            }
        } else if e.observed {
            st.note("fight", m, format!("node {n}: the idle write {} has an effect, a dispute shown", e.id));
        }
        if quiet {
            st.count("honest");
            if e.observed {
                st.note("honest", m, format!("node {n}: in an honest history the idle write {} has an effect", e.id));
            }
        }
        st.count(ks);
        if e.applies && !e.observed {
            st.note(ks, m, format!("node {n}: the idle write {} changes which writes apply, nothing observed", e.id));
        }
    }
    if relabel {
        st.count("one reading");
        if !one_reading_relabelled(w, rules, v, rd) {
            st.fail("one reading", m, format!("node {n}: a relabelling keeping the order reads otherwise"));
        }
    }
}

/// The properties, at every honest node's final reading. The oracle is the wanted behaviour
/// (issues/role-vouch-contested.md: a removed party's role write shows where its remover's list
/// names it, and nowhere else; its content also where a witness's addendum names it), computed
/// from the story, never from a reading.
///
/// The honest side is per node (notes/write-path-design.md §1, First received). A node that held
/// every honest lowering it holds first (`Sim::held_first`, from the receipts: `held first`) is
/// checked on its own reading: safety, liveness, own path, removal, purge, alike. Any other
/// (`no order`: the thief's write came first or with the removal) has its user choose the honest
/// lowerings it holds at `AFTER` (`Sim::chose`), a step of the history whose consequences follow
/// (its answers once its walk applies the removal), and is checked on its own reading as the
/// first kind is, and, like the nodes trusting nothing, on what it was shown before choosing
/// (`Sim::view_unchosen`): each honest lowering it does not apply is an open dispute or a
/// counter-removal told (`disputes`, `countered`), and choosing those shown reads as choosing
/// them all. Content only a witness keeps is wanted wherever a witness received it.
pub fn check(m: &Sim, rules: &Rules, st: &mut Stats) {
    judging_once(&m.w, || check_world(m, rules, st))
}

fn check_world(m: &Sim, rules: &Rules, st: &mut Stats) {
    st.worlds += 1;
    let (w, s) = (&m.w, &m.setup);
    let nodes = m.honest();
    // each node as it stands: its held set, the sides it recorded, its reading, and (the oracle,
    // from the story's receipts alone) whether it held every honest lowering it holds first
    let hon = m.honest_lowerings();
    let hon_held = |v: &View| -> Vec<Id> { hon.iter().copied().filter(|r| v.held.contains(r)).collect() };
    let own: BTreeMap<Thing, (View, Reading, bool)> = nodes
        .iter()
        .copied()
        .chain(m.untrusting())
        .map(|n| {
            let v = m.view(n, rules);
            let rd = judge(w, rules, &v);
            let held = hon_held(&v);
            let first = !m.untrusting().contains(&n) && {
                let arrivals = m.arrivals(n, rules);
                held.iter().all(|&r| m.held_first(n, r, &v, &arrivals, false, rules))
            };
            (n, (v, rd, first))
        })
        .collect();
    // a witness of removal `r` (it received `i` by the removal and holds `r`) answers it once its
    // walk applies `r`: held first, or once its user chose at `AFTER`
    let witness = |a: Thing, r: Id, i: Id| m.sync.get(&a).is_some_and(|u| u.contains(&w.commits[i].on)) && m.got(i, a, REMOVAL) && m.recv[r].contains_key(&a);
    let vouched = |among: &[Thing], r: Id, i: Id, wrote: &dyn Fn(Thing) -> bool| among.iter().any(|&a| wrote(a) && witness(a, r, i));
    // the honest side at each honest node: its own reading, which holds every honest lowering
    // first or by its user's choice at `AFTER`
    let rds: BTreeMap<Thing, (View, Reading)> = nodes
        .iter()
        .map(|&n| {
            let (v, rd, first) = &own[&n];
            st.count(if m.chose.contains_key(&n) { "no order" } else { "held first" });
            st.count("honest side");
            if !*first {
                st.fail("honest side", m, format!("node {n}: holds an honest lowering neither first nor by its user's choice"));
            }
            (n, (v.clone(), rd.clone()))
        })
        .collect();
    // the remover's list names it: where a role write of X stands
    let in_r = |i: Id| w.in_frontier(m.r, i);
    let regrant_n5 = s.regrant && (1..3).contains(&s.n5);
    // N5's key is a removed party's
    let n5_out = s.n5 == 3;
    let x_removed_a2 = s.x_role == 2 && m.xrole.is_some();
    // B grants again only while it is an admin: X's demotion of it may stand
    let b_admin = !(s.x_role == 1 && m.xrole.is_some_and(in_r));
    let stands = |n: Thing| match n {
        H | B => true,
        N5 => m.g5.is_some_and(in_r) || regrant_n5,
        K => !x_removed_a2 && (!s.sharer_x || in_r(m.gs) || (s.regrant && b_admin)),
        _ => false,
    };
    // whose addendum vouches: a writer holding write at its addendum's key, which a node
    // re-granted writes after its new grant
    let wrote = |n: Thing| match n {
        H | B => true,
        N5 => m.g5.is_some_and(in_r) || regrant_n5,
        // (A2 removed from T1 by B: K writes again only once B grants it again)
        K => !x_removed_a2 && (!s.sharer_x || in_r(m.gs) || (s.regrant && b_admin)) && (m.r3.is_none() || (s.regrant && b_admin)),
        _ => false,
    };
    let x_keeps_a2 = matches!(s.x_a2, 1 | 3 | 4 | 5);
    // what X, writing A2 for good, may grant on T1 through A2's arrangement by right: read
    // through GU; write in the kiosk's world (A2 admin there, then write with the flag)
    let x_grants = match s.x_a2 {
        1 => Role::Read,
        5 => Role::Write,
        _ => Role::None,
    };
    // the share X's may-grant grants rest on
    let x_share = if s.x_a2 == 5 { Some(m.gs) } else { m.gg };
    // through A2 on T1 where B removed A2 from T1: what B's removal lists, or a writer of T1
    // received by then, or the path re-granted
    let in_r3 = |i: Id| m.r3.is_some_and(|r3| w.in_frontier(r3, i));
    // X's removal of M listing M's grant of H, heard before the removal (kept)
    let m_cut = || m.thief.iter().any(|(&i, &k)| k == 26 && m.made[i] < REMOVAL);
    // X's lowering of H heard before the removal (a removal or a demotion, its list naming only
    // X's own grant) is kept where a grant of X heard with it gives H back its standing: what it
    // dropped (H's grants of B and N5, what was written under them, what only B's answers kept,
    // M's leave naming B) is lost, as with any
    // lowering X made that the remover heard (notes/path-model-findings.md 19)
    let heard_lowering = m.thief.iter().any(|(&i, &k)| matches!(k, 11 | 25 | 43) && m.made[i] < REMOVAL);
    let under_h = |i: Id| heard_lowering && (w.hops(i).contains(&(H, A)) || [B, N5, K, X, M].contains(&w.commits[i].signer));
    // safety: no commit the thief made after the removal shows (but content on a path it still
    // holds, and its own leave), Z, X and N5 removed before the theft end with no role, and no key
    // the thief made up ends on A's list. At a
    // node trusting nothing (`late`) only what the thief stamped after the removal, or signed with
    // N5's key, counts: what X stamped before it is X's standing, which is the dispute.
    let rts = w.commits[m.r].ts;
    // a thief's commit that is its right by a path X keeps
    let by_right = |i: Id| {
        let c = &w.commits[i];
        // X's own writes along A2, a path it keeps
        (c.signer == X && x_keeps_a2 && c.path == [A2] && !matches!(c.kind, Kind::Grant { .. }) && !(m.r3.is_some() && !(s.regrant && b_admin) && [T1, D1].contains(&c.on)))
            // X leaving A by itself: a self-removal is always open to the holder, and takes nothing X still holds
            || (w.leave(i) && w.sets(i) == Some((X, A)))
            // X granting (or finalizing) through A2's arrangement, which it keeps writing, up to
            // what the arrangement gives
            || (c.signer == X && x_grants > Role::None && c.path == x_route(&s) && matches!(c.kind, Kind::Grant { role, .. } if role <= x_grants))
            // Z writing T1 by X's grant of write, where that is X's right
            || (c.signer == Z && x_grants >= Role::Write && c.on == T1 && c.path.is_empty() && matches!(c.kind, Kind::Content))
    };
    let safety = |n: Thing, v: &View, rd: &Reading, prop: &'static str, late: bool, st: &mut Stats| {
        // what it holds, and what the covers it holds carry
        let seen: Set = v.held.iter().flat_map(|&c| std::iter::once(c).chain(match &w.commits[c].kind { Kind::Cover { carries } => carries.iter().copied().collect(), _ => vec![] })).collect();
        for &i in seen.iter().filter(|&&i| m.hostile(i) && (w.commits[i].signer != N5 || n5_out) && (!late || w.commits[i].ts > rts || w.commits[i].signer == N5)) {
            st.count(prop);
            let by_right = by_right(i);
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
            let n5_holds = n5_out && *e == (N5, A);
            // Z granted on T1 through A2's arrangement by X, which keeps writing A2: X's right
            let z_by_right = *e == (Z, T1) && *r <= x_grants;
            if *r > Role::None && ((e.0 == Z && !z_by_right) || x_holds || n5_holds) {
                st.fail(prop, m, format!("node {n}: {e:?} ends {r:?}"));
            }
        }
        // no key the thief made up keeps a role on A
        if rd.key_role(TK, A) > Role::None {
            st.fail(prop, m, format!("node {n}: the thief's key keeps a role on A"));
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
    // an honest history: no move of the thief, X removing H neither at the theft nor after (every
    // explicit lowering is an honest node's, its list by the writers' rule)
    let quiet = m.thief.is_empty() && !s.x_first && !s.b_side_x;
    // `one reading` at one node per world, picked by the world's spec
    let pick = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        format!("{:?}", m.spec).hash(&mut h);
        let all: Vec<Thing> = nodes.iter().copied().chain(m.untrusting()).collect();
        all[(h.finish() % all.len() as u64) as usize]
    };
    for (&n, (v, rd)) in &rds {
        st.most("rounds", rd.rounds as u64);
        void_checks(w, rules, v, rd, n, true, quiet, n == pick, &by_right, m, st);
        // a lowering an honest node wrote, trusted, applies (a lowering of the thief's the node
        // recorded and then sided against is void there: counted)
        st.count("removal");
        let (ours, theirs): (Vec<Id>, Vec<Id>) = rd.void.iter().partition(|r| hon.contains(r));
        if !ours.is_empty() {
            st.fail("removal", m, format!("node {n}: its trusted removal {ours:?} is void"));
        }
        if !theirs.is_empty() {
            st.note("another recorded lowering void", m, format!("node {n}: {theirs:?}, its own or recorded by first received, is void beside the honest removals"));
        }
        safety(n, v, rd, "safety", false, st);
        own_path(n, v, rd, "own path", st);
        if x_removed_a2 && !s.regrant && m.xrole.is_some_and(in_r) {
            st.count("removal kept");
            if rd.role(A2, T1) > Role::None {
                st.fail("removal kept", m, format!("node {n}: A2 holds on T1 again"));
            }
        }
        // liveness
        for &i in v.held.iter().filter(|&&i| !m.hostile(i)) {
            let c = &w.commits[i];
            let honest_now = c.signer != X;
            let want = match &c.kind {
                // M's leave applies, so its write after does not show (X's removal of M heard
                // before the removal and kept cuts the leave, which it does not list, and M's
                // writes after it)
                Kind::Content if c.signer == M => !m_cut() && c.ts == 1,
                Kind::Grant { holder, .. } if c.signer == M => *holder != M || !m_cut(),
                // through A2 on T1 where B removed A2 from T1 (K's, or X's as a member of A2)
                Kind::Content | Kind::Purge { .. } | Kind::Cover { .. } if m.r3.is_some() && w.hops(i).contains(&(A2, T1)) => {
                    let r3 = m.r3.unwrap();
                    !(c.signer == K && x_removed_a2) && (s.regrant && b_admin && c.signer == K)
                        || (c.ts < REMOVAL
                            && (!s.sharer_x || in_r(m.gs))
                            && !(c.signer == K && x_removed_a2)
                            && (c.signer == K || m.made[i] < REMOVAL)
                            && (in_r3(i) || vouched(&[H, N5], r3, i, &wrote)))
                }
                Kind::Content | Kind::Purge { .. } | Kind::Cover { .. } if honest_now => stands(c.signer) && !(c.signer == K && x_removed_a2),
                // X's purge before the theft: kept by H's list alone (an addendum vouches for no
                // purge request)
                Kind::Purge { .. } => in_r(i),
                Kind::Content => {
                    in_r(i) || vouched(&[H, B, N5, K], m.r, i, &wrote)
                }
                // X's grant of G through A2 stands where the share it rests on does, and where
                // K removed X from A2, by K's list or H's
                Kind::Grant { .. } if Some(i) == m.gi => {
                    (!s.sharer_x || x_share.is_some_and(in_r)) && (x_grants > Role::None || m.r2.is_some_and(|r2| w.in_frontier(r2, i)) || in_r(i))
                        // the kiosk's grant at 4 follows X's removal of A2 from T1 at 3
                        && !(s.x_a2 == 5 && x_removed_a2 && m.xrole.is_some_and(in_r))
                }
                // N5's grant to B, listed by X's removal of N5, stays: X's twin, heard before the
                // removal, is kept and drops it
                Kind::Grant { .. } if Some(i) == m.gb5 => !m.thief.iter().any(|(&t, &k)| k == 31 && m.made[t] < REMOVAL),
                Kind::Grant { .. } if honest_now => c.signer == H || c.signer == K || i == m.gs || Some(i) == m.gg || (m.made[i] == AFTER && b_admin),
                // (a write X made before the removal stamped after it never applies)
                Kind::Grant { .. } => in_r(i) && c.ts < REMOVAL && !m.lowers_remover(i) && !m.aims(i),
                _ => false,
            };
            if want && !under_h(i) {
                st.count("liveness");
                if !rd.shows(i) {
                    st.fail("liveness", m, format!("node {n}: commit {i} does not show"));
                }
            }
            // unlisted: a role write of X resting on a grant an applied honest removal takes, ordered
            // before it, that its list does not name, shows nowhere
            if c.signer == X && w.grant_class(i) {
                let removes = |r: Id| matches!(w.commits[r].kind, Kind::Grant { role: Role::None, .. });
                let cut_by = m.removals().into_iter().find(|&r| removes(r) && rd.applied.contains(&r) && w.key(i) < w.key(r) && w.sets(r).is_some_and(|h| w.hops(i).contains(&h)) && !w.in_frontier(r, i));
                if let Some(r) = cut_by {
                    st.count("unlisted");
                    if rd.shows(i) {
                        st.fail("unlisted", m, format!("node {n}: X's role write {i}, which removal {r} does not list, shows"));
                    }
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
                                let Kind::Purge { names: Names::Author(author) } = w.commits[q].kind else { return false };
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
    // gains nothing past its standing and H keeps its own; a
    // removal not applied is a dispute shown there; a reading unlike the trusted side's comes with
    // a dispute, and trusting the honest ones shown reads as the trusting side
    let plain: BTreeMap<Thing, (View, Reading)> = m.untrusting().into_iter().map(|n| (n, (own[&n].0.clone(), own[&n].1.clone()))).collect();
    // the nodes trusting nothing as they stand, and the nodes whose user chose at `AFTER` as they
    // stood without the choice (what they were shown)
    let unchosen: BTreeMap<Thing, (View, Reading)> = m
        .chose
        .keys()
        .map(|&n| {
            let v = m.view_unchosen(n, rules);
            let rd = judge(w, rules, &v);
            (n, (v, rd))
        })
        .collect();
    for (&n, (v, rd)) in plain.iter().chain(&unchosen) {
        let no_sides = m.untrusting().contains(&n);
        st.count("untrusted");
        st.most("rounds", rd.rounds as u64);
        void_checks(w, rules, v, rd, n, false, quiet, no_sides && n == pick, &by_right, m, st);
        let held_hon = hon_held(v);
        // where every honest lowering it holds applies (else X keeps its standing there: a dispute)
        if held_hon.iter().all(|r| rd.applied.contains(r)) {
            safety(n, v, rd, "safety N", true, st);
            own_path(n, v, rd, "own path N", st);
        }
        // the open disputes, and the counter-removals of its recorded sides (F5)
        let all_shown = |v: &View| -> Vec<Id> { disputes(w, rules, v).into_iter().chain(countered(w, rules, v)).collect() };
        let shown = all_shown(v);
        // an honest history (no move of the thief, X removing H neither at the theft nor after)
        // shows none
        if quiet {
            st.count("quiet");
            if !shown.is_empty() {
                st.fail("quiet", m, format!("node {n}: an honest history shows the disputes {shown:?}"));
            }
        }
        // trusting the honest removals among the disputes shown, and among those then shown,
        // applies every honest removal: never a silent loss
        let honest_shown = |d: Vec<Id>, t: &Set| -> Vec<Id> { d.into_iter().filter(|r| hon.contains(r) && !t.contains(r)).collect() };
        let mut sides = v.clone();
        let mut more = honest_shown(shown.clone(), &sides.trust);
        let mut turns = 0;
        while !more.is_empty() && turns <= hon.len() {
            sides = more.into_iter().fold(sides, |v, r| choose(w, rules, &v, r));
            more = honest_shown(all_shown(&sides), &sides.trust);
            turns += 1;
        }
        let sided = judge(w, rules, &sides);
        for &r in &held_hon {
            st.count("dispute");
            if !rd.applied.contains(&r) && !sided.applied.contains(&r) {
                st.fail("dispute", m, format!("node {n}: removal {r} is not applied, nor where the disputes shown are trusted {:?}", sides.trust));
            }
        }
        // a reading unlike the trusted side's (H's, on the things both sync), or unlike its own
        // held set's trusting every honest removal held, comes with a dispute shown, and trusting
        // the honest ones shown reads as that
        let chosen = held_hon.iter().fold(v.clone(), |v, &r| choose(w, rules, &v, r));
        let t = judge(w, rules, &chosen);
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
        x_role: rng.below(6) as u8,
        x_role_seen: b(&mut rng),
        x_a2: rng.below(6) as u8,
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
    if s.n5 >= 3 && rng.below(2) == 0 {
        moves.extend([Move { kind: 25, ts: 1, made: 5 }, Move { kind: 27, ts: 2, made: 5 }]);
    }
    let mut m = Sim::build(&s, rules, &moves, &mut rng);
    m.spec.index = i;
    m
}

/// Random worlds `start..start + n` on every core (a large sample split across runs).
pub fn random_from(start: u64, n: u64, rules: &Rules) -> Stats {
    crate::on_every_core(|th, threads, st: &mut Stats| {
        for i in (start + th as u64..start + n).step_by(threads) {
            check(&random_world(i, rules), rules, st);
        }
    })
}

/// The small family: every setup, each with one move of the thief stamped before or after the
/// removal (stamped before, an `early` move is made at 5, heard before the removal); `mint` and
/// `x_first` as one dimension (none, M naming H, M naming timed B, X removing H first). `i` in
/// `0..FAMILY`.
pub const FAMILY: usize = 2 * 2 * 2 * 2 * 4 * 6 * 2 * 6 * 2 * 2 * 4 * MOVES * 2;

pub fn family(i0: usize, rules: &Rules) -> Sim {
    let mut i = i0;
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
        x_role: take(6) as u8,
        x_role_seen: take(2) == 1,
        x_a2: take(6) as u8,
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
    let mut m = Sim::build(&s, rules, &[mv], &mut Rng(0));
    m.spec.index = i0 as u64;
    m
}

/// The small family on every core, every `stride`th world.
pub fn family_run(rules: &Rules, stride: usize) -> Stats {
    crate::family_on_every_core(FAMILY, stride, |i, st: &mut Stats| check(&family(i, rules), rules, st))
}

/// The rules a mode runs: `paths` the design's (`Rules::fixed`); `paths-design` the first round's
/// reading; controls, each the design with one rule undone: `-no-void` (a lowering whose own
/// drops take its authority applies), `-listed` (the remover names all it received), `-exempt` (the held chain
/// exempt from a lowering's drops), `-first-applied` (a re-granted path counts from the first point the settled
/// walk gave it), `-once` (a node answers a removal only the first time its walk applies it),
/// `-leave` (a self-removal is never put in question), `-key-order` (the remover keeps
/// the role writes in key order), `-audit-applied` (the audit puts in question the applied
/// writes before it, not the held ones), `-no-flag` (a may-grant grant needs only a role on its
/// path's last hop), `-last-hop` (only on its last hop), `-role-falls` (clearing the flag puts
/// nothing in question), `-admin-falls` (only a fall from admin is judged and audits), `-purge-any-path`
/// (a purge request holds the author right wherever its path gives write), `-purge-contains` (a
/// request by author matches every delta whose chain holds that author); the variants `-facts`
/// (a carried write judged by its own facts, not shown by a cover's copy: not the design),
/// `-until-at-key` (an end date on admin as a lowering: `Until`, failing a required gate); what a
/// drop takes of a commit (`Drops`): the control `-part-drops` (each part by its own need);
/// `-list-any-cut` (one answering cut of a delta's path makes it valid: `Answers`); `-no-end` (the
/// remover keeps a role write wherever its removal applies with it, L3's end clause off); how a
/// node records its sides (`Sides`): `-no-own`, `-no-receipt`, `-unapplied`, `-tie`, `-lowered`, `-both`,
/// `-choice-adds`, `-choice-seeds`, `-key-own`, `-untold`, `-told-all`; keys: `-no-key-hop`
/// (the key hop unread).
/// `-exh` runs the small family in place of random worlds.
pub fn mode_rules(mode: &str) -> Option<Rules> {
    let f = Rules::fixed();
    let rest = mode.strip_prefix("paths").unwrap_or(mode);
    let rest = rest.strip_prefix("-exh").or_else(|| rest.strip_prefix("-tiny-flags")).or_else(|| rest.strip_prefix("-tiny-detached")).or_else(|| rest.strip_prefix("-tiny-keys")).or_else(|| rest.strip_prefix("-tiny")).unwrap_or(rest);
    let rest = rest.strip_prefix("-honest-writers").or_else(|| rest.strip_prefix("-honest")).unwrap_or(rest);
    Some(match rest {
        "" => f,
        "-design" => Rules::design(),
        "-no-void" => Rules { self_void: false, ..f },
        "-listed" => Rules { stands: false, ..f },
        "-no-end" => Rules { own_end: false, ..f },
        "-no-own" => Rules { sides: Sides::NoOwn, ..f },
        "-no-receipt" => Rules { sides: Sides::NoReceipt, ..f },
        "-tie" => Rules { sides: Sides::Tie, ..f },
        "-unapplied" => Rules { sides: Sides::Unapplied, ..f },
        "-choice-adds" => Rules { sides: Sides::ChoiceAdds, ..f },
        "-choice-seeds" => Rules { sides: Sides::ChoiceSeeds, ..f },
        "-key-own" => Rules { sides: Sides::KeyOwn, ..f },
        "-untold" => Rules { sides: Sides::Untold, ..f },
        "-told-all" => Rules { sides: Sides::ToldAll, ..f },
        "-lowered" => Rules { sides: Sides::Lowered, ..f },
        "-both" => Rules { sides: Sides::Both, ..f },
        "-exempt" => Rules { exempt_chain: true, ..f },
        "-first-applied" => Rules { regrant: Regrant::FirstApplied, ..f },
        "-once" => Rules { rewrite: false, ..f },
        "-leave" => Rules { leave_in_question: false, ..f },
        "-audit-applied" => Rules { audit_held: false, ..f },
        "-key-order" => Rules { key_order: true, ..f },
        "-no-flag" => Rules { flag_check: false, ..f },
        "-last-hop" => Rules { min_check: false, ..f },
        "-role-falls" => Rules { flag_falls: false, ..f },
        "-admin-falls" => Rules { any_fall: false, ..f },
        "-purge-any-path" => Rules { purge_chain: false, ..f },
        "-purge-contains" => Rules { purge_exact: false, ..f },
        "-facts" => Rules { cover_facts: true, ..f },
        "-own-drops" => Rules { commit_drops: false, ..f },
        "-all-candidates" => Rules { candidates: Candidates::All, ..f },
        "-alone" => Rules { joint: false, ..f },
        "-seeds-all" => Rules { seeds_by_need: false, ..f },
        "-refuse-shapes" => Rules { refuse_shapes: true, ..f },
        "-until-at-key" => Rules { until: Until::AtKey, ..f },
        "-part-drops" => Rules { drops: Drops::Part, ..f },
        "-list-any-cut" => Rules { answers: Answers::AnyCut, ..f },
        "-no-key-hop" => Rules { key_hop: false, ..f },
        _ => return None,
    })
}

// ---- The void step in small worlds (notes/path-model-findings.md 16, 17) ----

/// A small world of admins removing and granting each other on A (H its mint): `n` commits, each
/// by a random party at a random `ts`, one in four carrying two or three grant writes on distinct
/// holders (`tiny_commit`), each setting a random party's grant to admin (standing, or one in three
/// until two ticks on) or none, listing each earlier write with probability one half.
pub fn tiny(i: u64, n: usize) -> World {
    let mut rng = Rng::thread(0x701d, i as usize);
    let mut w = account();
    for _ in 0..n {
        tiny_commit(&mut w, &mut rng, n, |h, rng, ts| {
            match rng.below(5) {
                0 | 1 => Kind::set(h, Role::Admin),
                2 => Kind::set(h, Role::Admin).until(ts + 2),
                _ => Kind::set(h, Role::None),
            }
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
            let fin = matches!(kind, Kind::Grant { finalize: true, .. });
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

/// A small world of may-grant on A (H its mint): as `tiny`, each write setting admin, none, write
/// or read with the may-grant flag or without (write with it also until two ticks on), or
/// finalizing its holder's grant. A writer holding the flag grants as a may-grant grant; a
/// lowering in role or of the flag is judged (notes/write-path-design.md §1 G1 to G5).
pub fn tiny_flags(i: u64, n: usize) -> World {
    let mut rng = Rng::thread(0x1271, i as usize);
    let mut w = account();
    for _ in 0..n {
        tiny_commit(&mut w, &mut rng, n, |h, rng, ts| match rng.below(8) {
            0 => Kind::set(h, Role::Admin),
            1 => Kind::set(h, Role::None),
            2 => Kind::set(h, Role::Write).may_grant(),
            3 => Kind::set(h, Role::Read),
            4 => Kind::set(h, Role::Write).may_grant().until(ts + 2),
            5 => Kind::set(h, Role::Write),
            6 => Kind::set(h, Role::Read).may_grant(),
            _ => Kind::finalize(h),
        });
    }
    w
}

/// A small world of a thing detached from its folder (spec/permissions.md §1 Path,
/// Direct mark): T1 minted with admin A, A with admin H, so H is T1's mint ancestor two record grants up. `n` commits by
/// a random party at a random `ts`, one in five on A (granting or removing a party's admin there,
/// so it reaches T1 through [A]), else on T1: content, or setting a random holder's grant (A's is
/// T1's record grant, a third of the time: removing it detaches T1) to admin (standing or until two
/// ticks on) or none (half the time),
/// listing each earlier write with probability one half. Each commit on T1 states, for H: the
/// descent [], the descent through [A], [] with its hop marked direct (H's direct grant), or one in
/// eight each [A] with a one-step hop marked or [] with a mark past its hops; for another party: []
/// (its direct grant), [A], or one in eight each [] marked (a mark on no descent), [A] with its
/// one-step hop A to T1 marked, [] with a mark past its hops (each mark off a descent of two steps
/// or more: the part applies nowhere). Half the worlds open with H
/// granting itself admin on T1 by [A] (its direct grant) at 1. A stolen key of the far
/// ancestor, a removed far ancestor backdating by its direct grant, a mark where no direct grant
/// stands, and a party holding both routes using the one a removal did not cut are each some
/// world's commits.
pub fn tiny_detached(i: u64, n: usize) -> World {
    let mut rng = Rng::thread(0xde7a, i as usize);
    let mut w = account();
    let parties = [H, B, N5, Z, N6];
    if rng.below(2) == 0 {
        w.push(H, 1, &[A], T1, Kind::set(H, Role::Admin));
    }
    for _ in 0..n {
        let s = parties[rng.below(5)];
        let ts = 1 + rng.below(n) as u32;
        let list: Vec<Id> = (0..w.commits.len()).filter(|_| rng.below(2) == 0).collect();
        if rng.below(5) == 0 {
            let h = parties[rng.below(5)];
            let k = if rng.below(2) == 0 { Kind::set(h, Role::Admin) } else { Kind::set(h, Role::None) };
            let k = k.listing(w.cut(&list));
            w.push(s, ts, &[], A, k);
            continue;
        }
        let (path, direct): (&[Thing], &[usize]) = match (s == H, rng.below(8)) {
            (true, 0 | 1) => (&[], &[]),
            (true, 2 | 3) => (&[], &[0]),
            (true, 4 | 5) => (&[A], &[]),
            (true, 6) => (&[A], if rng.below(2) == 0 { &[0] } else { &[1] }),
            (true, _) => (&[], &[1]),
            (false, 0) => (&[], &[0]),
            (false, 1 | 2) => (&[A], &[]),
            (false, 3) => (&[A], &[1]),
            (false, 4) => (&[], &[1]),
            (false, _) => (&[], &[]),
        };
        let kind = match rng.below(5) {
            0 => Kind::Content,
            r => {
                // A, T1's mint admin, a third of the time: its record grant, lowered to detach T1
                let h = if rng.below(3) == 0 { A } else { parties[rng.below(5)] };
                let k = match r {
                    1 => Kind::set(h, Role::Admin),
                    2 => Kind::set(h, Role::Admin).until(ts + 2),
                    _ => Kind::set(h, Role::None),
                };
                k.listing(w.cut(&list))
            }
        };
        w.push_marked(s, ts, path, T1, kind, direct);
    }
    w
}

/// A small world of accounts as ordinary things (spec/permissions.md §1, §8): node things H, B,
/// N5, Z, N6, each minted with its own key (so its key holds admin on it), and A minted with
/// H as mint admin, T1 with A. `n` commits at random `ts`, each signed by a party's own key as
/// itself, or (one in two) by RK or TK as A or as a party (the key's grant there, `signers.0`);
/// on A (one in two), T1 or a party's node thing; acting as itself where it writes its own thing,
/// else by its direct grant or (one in two, past a party) through A: [N, A, T1] and [N, A, N']. Half
/// the worlds open with H granting RK admin on A at 1, half with B granting RK admin on B (a
/// node's second key), a quarter with N5 granting TK write on N5; a key signs as A, as the party
/// the opening grants it on, or as any party, a third each. Content one in five, else one part or (one in four) two or three on
/// distinct holders: a key's grant (one in three: admin, write or read, standing or timed, with or
/// without the flag, or none; a key lowering its own among them), A's (one in six off A), else a
/// party's (admin, standing or until two ticks on, write, read or none), listing each earlier
/// write with probability one half. Pairing is a grant to a node thing, removal the ordinary
/// removal, a node's key rotation a key grant on its node thing and the lowering of the old one.
pub fn tiny_keys(i: u64, n: usize) -> World {
    let mut rng = Rng::thread(0x0e75, i as usize);
    let mut w = account();
    let parties = [H, B, N5, Z, N6];
    let keys = [RK, TK];
    if rng.below(2) == 0 {
        w.push(H, 1, &[], A, Kind::set(RK, Role::Admin));
    }
    if rng.below(2) == 0 {
        w.push(B, 1, &[], B, Kind::set(RK, Role::Admin));
    }
    if rng.below(4) == 0 {
        w.push(N5, 1, &[], N5, Kind::set(TK, Role::Write));
    }
    for _ in 0..n {
        let (k, s) = if rng.below(2) == 0 {
            let k = keys[rng.below(2)];
            // as A, as the party the opening grants it on, or as any party
            (k, match rng.below(3) {
                0 => A,
                1 => if k == RK { B } else { N5 },
                _ => parties[rng.below(5)],
            })
        } else {
            let p = parties[rng.below(5)];
            (own_key(p), p)
        };
        let on = match rng.below(4) {
            0 | 1 => A,
            2 => T1,
            _ => parties[rng.below(5)],
        };
        let path: &[Thing] = if s == on || s == A || on == A || rng.below(2) == 0 { &[] } else { &[A] };
        let ts = 1 + rng.below(n) as u32;
        if rng.below(5) == 0 {
            w.push_signed(k, s, ts, path, on, Kind::Content);
            continue;
        }
        let m = if rng.below(4) == 0 { 2 + rng.below(2) } else { 1 };
        let mut parts: Vec<Kind> = vec![];
        let mut holders = vec![];
        for _ in 0..m {
            let list: Vec<Id> = (0..w.commits.len()).filter(|_| rng.below(2) == 0).collect();
            let (h, kind) = if rng.below(3) == 0 {
                let h = keys[rng.below(2)];
                (h, match rng.below(12) {
                    0..=3 => Kind::set(h, Role::Admin),
                    4..=6 => Kind::set(h, Role::None),
                    7 => Kind::set(h, Role::Admin).until(ts + 2),
                    8 => Kind::set(h, Role::Write),
                    9 => Kind::set(h, Role::Write).may_grant(),
                    10 => Kind::set(h, Role::Write).may_grant().until(ts + 2),
                    _ => Kind::set(h, Role::Read),
                })
            } else {
                let h = if on != A && rng.below(6) == 0 { A } else { parties[rng.below(5)] };
                (h, match rng.below(7) {
                    0 | 1 => Kind::set(h, Role::Admin),
                    2 => Kind::set(h, Role::Admin).until(ts + 2),
                    3 => Kind::set(h, Role::Write),
                    4 => Kind::set(h, Role::Read),
                    _ => Kind::set(h, Role::None),
                })
            };
            if h != s && h != on && !holders.contains(&h) {
                holders.push(h);
                parts.push(kind.listing(w.cut(&list)));
            }
        }
        match parts.len() {
            0 => {}
            1 => {
                w.push_signed(k, s, ts, path, on, parts.pop().expect("one part"));
            }
            _ => {
                w.commit_signed(k, s, ts, path, on, parts, &[]);
            }
        }
    }
    w
}

/// A small world to check: its commits, the view, and per commit (by ID) what its writer had
/// received when writing it, in the order received.
#[derive(Clone, Debug)]
pub struct Tiny {
    pub w: World,
    pub v: View,
    pub recv: Vec<Vec<Id>>,
}

/// Which small worlds: `tiny`, `tiny_flags` or `tiny_detached`, and how honest their writers
/// are.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TinyMode {
    pub flags: bool,
    pub detached: bool,
    pub keys: bool,
    pub honest: Honesty,
}

impl TinyMode {
    /// The mode a `paths-tiny[-flags|-detached][-honest[-writers]]` name gives.
    pub fn named(mode: &str) -> TinyMode {
        let flags = mode.starts_with("paths-tiny-flags");
        let detached = mode.starts_with("paths-tiny-detached");
        let keys = mode.starts_with("paths-tiny-keys");
        let rest = mode.strip_prefix("paths-tiny").unwrap_or("");
        let rest = rest.strip_prefix(if flags { "-flags" } else if detached { "-detached" } else if keys { "-keys" } else { "" }).unwrap_or(rest);
        let honest = if rest.starts_with("-honest-writers") { Honesty::Writers } else if rest.starts_with("-honest") { Honesty::Lists } else { Honesty::None };
        TinyMode { flags, detached, keys, honest }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Honesty {
    /// Each writer received every commit made before it; lists are drawn at random.
    None,
    /// Each writer received its own earlier commits and each other earlier commit with
    /// probability one half, in the order made, and every lowering's list is the writers' rule's
    /// over that (`writers_list`); the world is otherwise the one `None` gives.
    Lists,
    /// As `Lists`, with honest writers: a commit is stamped after everything its writer received
    /// (a clock never behind what it saw: one drawn earlier moves later, its `until`s with it), and
    /// is kept only where its writer's own walk over what it received applies it (its lowerings
    /// trusted there, with their lists). A writer receives only commits kept.
    Writers,
}

/// Tiny world `i` (`n` from 3 to 12 writes; `tiny_flags`, `tiny_detached` or `tiny`) and its view: every commit
/// held; trusting nothing, or (every third world) one held lowering.
pub fn tiny_world(i: u64, mode: TinyMode, rules: &Rules) -> Tiny {
    let n = 3 + (i % 10) as usize;
    let mut w = if mode.flags { tiny_flags(i, n) } else if mode.detached { tiny_detached(i, n) } else if mode.keys { tiny_keys(i, n) } else { tiny(i, n) };
    let mut recv: Vec<Vec<Id>> = (0..w.commits.len()).map(|k| (0..w.cid(k)).collect()).collect();
    if mode.honest != Honesty::None {
        let mut rng = Rng::thread(0x4e57, i as usize);
        let mut kept: Vec<Id> = vec![];
        let cids: Vec<Id> = (0..w.commits.len()).filter(|&k| w.cid(k) == k).collect();
        for cid in cids {
            let parts: Vec<Id> = (cid..w.commits.len()).take_while(|&k| w.cid(k) == cid).collect();
            let got: Vec<Id> = kept.iter().copied().filter(|&j| w.commits[j].signer == w.commits[cid].signer || rng.below(2) == 0).collect();
            // an honest clock is never behind what its writer saw: the commit moves later, its
            // `until`s with it
            let floor = got.iter().map(|&j| w.commits[j].ts + 1).max().unwrap_or(0);
            if mode.honest == Honesty::Writers && floor > w.commits[cid].ts {
                let shift = floor - w.commits[cid].ts;
                for &r in &parts {
                    w.commits[r].ts += shift;
                    if let Kind::Grant { until: Some(u), .. } = &mut w.commits[r].kind {
                        *u += shift;
                    }
                }
            }
            for &r in &parts {
                recv[r] = got.clone();
                if rules.lowering(&w, r).is_some() && !w.leave(r) {
                    let l = writers_list(&w, rules, r, &got);
                    let f = w.cut(&l);
                    w.edit(r, |k| k.listing(f));
                }
            }
            let honest = mode.honest == Honesty::Lists || {
                let lows: Set = parts.iter().copied().filter(|&r| rules.lowering(&w, r).is_some() && !w.leave(r)).collect();
                let v = View { held: got.iter().chain(&parts).copied().collect(), leaves: None, trust: lows };
                let rd = judge(&w, rules, &v);
                parts.iter().all(|r| rd.applied.contains(r)) && rd.void.is_empty()
            };
            if honest {
                kept.extend(&parts);
            }
        }
        if mode.honest == Honesty::Writers {
            let (w2, map) = rebuild(&w, &kept);
            recv = kept.iter().map(|&j| recv[j].iter().filter_map(|i| map.get(i).copied()).collect()).collect();
            w = w2;
        }
    }
    let mut v = View::all(&w);
    // (a write below admin: the same worlds under every `Until`)
    let lows: Vec<Id> = (0..w.commits.len()).filter(|&k| w.lowers(k).is_some()).collect();
    if i % 3 == 0 && !lows.is_empty() {
        v.trust.insert(lows[(i / 3) as usize % lows.len()]);
    }
    Tiny { w, v, recv }
}

/// The commits of `recv` resting on lowering `r`'s grant, its own commit's parts aside.
fn resting(w: &World, r: Id, among: impl IntoIterator<Item = Id>) -> Vec<Id> {
    let h = w.sets(r).expect("a lowering sets a grant");
    among.into_iter().filter(|&j| w.cid(j) != w.cid(r) && (w.rests(j).contains(&h) || (w.leave(j) && w.sets(j) == Some(h)))).collect()
}

/// The list the writers' rule gives lowering `r`, its writer having received `recv` (in that order)
/// when writing it (notes/write-path-design.md §1, L3; `Sim::stand`): `writers_keep` over the
/// received commits resting on its grant, read in the writer's walk holding `recv` and `r`, trusting
/// `r`.
pub fn writers_list(w: &World, rules: &Rules, r: Id, recv: &[Id]) -> Vec<Id> {
    let all = resting(w, r, recv.iter().copied());
    let mut v = View { held: recv.iter().copied().collect(), leaves: None, trust: Set::from([r]) };
    v.held.insert(r);
    let base: Vec<Id> = all.iter().copied().filter(|&j| !w.grant_class(j)).collect();
    let classed: Vec<Id> = all.iter().copied().filter(|&j| w.grant_class(j)).collect();
    let mut w = w.clone();
    writers_keep(base, &classed, rules.own_end, |l| {
        let f = w.cut(l);
        w.edit(r, |k| k.listing(f));
        end_of(&w, &judge(&w, rules, &v), r)
    })
}

/// Whether every lowering's list (on the commits resting on its grant) is the writers' rule's
/// over what its writer received: computed from the generated history, never from a node.
pub fn lists_honest(w: &World, rules: &Rules, recv: &[Vec<Id>]) -> bool {
    (0..w.commits.len()).filter(|&r| rules.lowering(w, r).is_some() && !w.leave(r)).all(|r| {
        let names = |l: &[Id], j: Id| l.iter().any(|&c| w.names(c, j));
        let rest = resting(w, r, 0..w.commits.len());
        let listed: Vec<Id> = rest.iter().copied().filter(|&j| w.in_frontier(r, j)).collect();
        // a list naming what its writer had not received is no writer's
        if !listed.iter().all(|&j| recv[r].iter().any(|&c| w.cid(c) == w.cid(j))) {
            return false;
        }
        let honest = writers_list(w, rules, r, &recv[r]);
        rest.iter().all(|&j| w.in_frontier(r, j) == names(&honest, j))
    })
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
        crate::Tally::merge(&mut self.checked, o.checked);
        crate::Tally::merge(&mut self.fails, o.fails);
        crate::Tally::merge(&mut self.noted, o.noted);
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

/// The may-grant grants of `rd` its signer held no right to make (notes/write-path-design.md §1
/// G1, G2), read from the reading's own history (`Reading::hist`), not from the walk's rule: each
/// sets a grant with no current grant, its role below admin, every hop before its last (its key
/// hop first) giving that role and the last giving admin or that role with the flag, at its `ts`.
pub fn unright_flag_grants(w: &World, rd: &Reading) -> Vec<Id> {
    // grant `e`'s value and flag just before `i` in key order (a record grant starts at admin)
    let before = |e: Grant, i: Id| -> (Role, bool) {
        let start = if w.is_record(e) { (Role::Admin, false) } else { (Role::None, false) };
        let k = w.key(i);
        rd.hist.get(&e).and_then(|h| h.iter().rev().find(|(kj, _)| *kj < k)).map_or(start, |&(kj, v)| {
            let flag = matches!(w.commits[kj.2].kind, Kind::Grant { may_grant: true, .. });
            (alive(v, w.commits[i].ts), flag)
        })
    };
    rd.by_flag
        .iter()
        .copied()
        .filter(|&i| {
            let Kind::Grant { role: r, .. } = w.commits[i].kind else { return true };
            let Some((&last, hops)) = w.rests(i).split_last() else { return true };
            let (lr, lf) = before(last, i);
            let held = before(w.sets(i).expect("a grant write"), i).0 > Role::None;
            held || r >= Role::Admin || hops.iter().any(|&e| before(e, i).0 < r) || !(lr == Role::Admin || (lf && lr >= r))
        })
        .collect()
}

/// The may-grant grants of `rd` standing past an applied explicit lowering of their path's last
/// hop that does not list them and takes from the hop what they need there, its role with the
/// flag (G5), read from the reading's own history (`Reading::hist`). The hop's value before the
/// lowering is read as written (its `until` and any self-removal after it aside), never above the
/// value the walk audits against, so a grant this names was in question there.
pub fn unaudited_flag_grants(w: &World, v: &View, rd: &Reading) -> Vec<Id> {
    let gives = |i: Id, role: Role| match w.commits[i].kind {
        Kind::Grant { may_grant, .. } if role == Role::Admin || may_grant => role,
        _ => Role::None,
    };
    rd.by_flag
        .iter()
        .copied()
        .filter(|&j| {
            let (Kind::Grant { role: r, .. }, Some(&last)) = (&w.commits[j].kind, w.rests(j).last()) else { return false };
            let h = rd.hist.get(&last).map_or(&[][..], |h| &h[..]);
            h.iter().enumerate().any(|(n, &(kl, val))| {
                let l = kl.2;
                let explicit = !w.leave(l) && !rd.by_flag.contains(&l) && !matches!(w.commits[l].kind, Kind::Grant { finalize: true, .. });
                let prev = if n == 0 { if w.is_record(last) { Role::Admin } else { Role::None } } else { gives(h[n - 1].0 .2, h[n - 1].1 .0) };
                kl > w.key(j) && explicit && w.cid(l) != w.cid(j) && !listed(w, v, l, j) && prev >= *r && gives(l, alive(val, w.commits[l].ts)) < *r
            })
        })
        .collect()
}

/// The value grant or key hop `e` gives just before `i` in the reading's own history (a record grant
/// or record key hop starting at admin), its `until` read at `i`'s `ts`.
fn before_in(w: &World, rd: &Reading, e: Grant, i: Id) -> Role {
    let start = if w.is_record(e) { (Role::Admin, None) } else { (Role::None, None) };
    alive(rd.hist.get(&e).and_then(|h| h.iter().rev().find(|(k, _)| *k < w.key(i))).map_or(start, |x| x.1), w.commits[i].ts)
}

/// The applied writes of `rd` giving a key hop admin that no right allows (notes/write-path-design.md,
/// Keys K3: a key's grant is written as any grant), read from the reading's own history
/// (`Reading::hist`), not from the walk's rule: each explicit write whose value gives admin at its
/// `ts` (a grant or an end: no lowering) has every hop it rests on giving admin just before it.
/// May-grant grants are `unright_flag_grants`'; a lowering is judged once and keeps its verdict
/// (W1), so its shape alone is read.
pub fn unright_key_writes(w: &World, rd: &Reading) -> Vec<Id> {
    rd.applied
        .iter()
        .copied()
        .filter(|&i| w.key_write(i) && !w.leave(i) && !rd.by_flag.contains(&i))
        .filter(|&i| {
            let c = &w.commits[i];
            let Kind::Grant { role, until, finalize: false, .. } = &c.kind else { return false };
            alive((*role, *until), c.ts) == Role::Admin && !w.rests(i).iter().all(|&h| before_in(w, rd, h, i) == Role::Admin)
        })
        .collect()
}

/// The commits signed by a key that show past an applied explicit lowering of that key hop, after
/// them, not listing them, which takes the hop from what they applied by (admin for an explicit
/// write, its role as what the hop lets grant for a may-grant grant, write for a finalize and
/// content) to below the least they could apply by (W3: for a grant write adding a grant its role
/// as what the hop lets grant; else the same), read from the reading's own history (K4: a lowered
/// key's commits fall unless the lowering lists them), each with that lowering. Content whose key
/// gives write in the end is left to re-grant.
pub fn unaudited_key_commits(w: &World, v: &View, rd: &Reading) -> Vec<(Id, Id)> {
    // what a value written by `l` gives (`flag`: as what it lets grant)
    let gives = |l: Id, role: Role, flag: bool| match w.commits[l].kind {
        Kind::Grant { may_grant, .. } if flag && !(role == Role::Admin || may_grant) => Role::None,
        _ => role,
    };
    rd.applied
        .iter()
        .chain(rd.valid.iter().filter(|&&j| !w.grant_class(j) && rd.keys.get(&w.key_hop(j)).copied().unwrap_or(Role::None) < Role::Write))
        .copied()
        .filter_map(|j| {
            let h = w.key_hop(j);
            if w.rests(j) != [h] {
                return None;
            }
            // (what it applied by, the least it could apply by), each a role and whether read
            // as what the hop lets grant
            let (by, least) = match &w.commits[j].kind {
                Kind::Grant { finalize: true, .. } => ((Role::Write, false), (Role::Write, false)),
                Kind::Grant { .. } => {
                    let least = flag_grant(w, j).map_or((Role::Admin, false), |r| (r, true));
                    (if rd.by_flag.contains(&j) { least } else { (Role::Admin, false) }, least)
                }
                _ => ((Role::Write, false), (Role::Write, false)),
            };
            let at = if w.grant_class(j) { w.key(j) } else { w.pos(j) };
            let hist = rd.hist.get(&h).map_or(&[][..], |x| &x[..]);
            hist.iter().enumerate().find_map(|(n, &(kl, val))| {
                let l = kl.2;
                let explicit = !w.leave(l) && !rd.by_flag.contains(&l) && !matches!(w.commits[l].kind, Kind::Grant { finalize: true, .. });
                let prev = if n == 0 { if w.is_record(h) { Role::Admin } else { Role::None } } else { gives(hist[n - 1].0 .2, alive(hist[n - 1].1, w.commits[l].ts), by.1) };
                (kl > at && explicit && gives(l, alive(val, w.commits[l].ts), least.1) < least.0 && prev >= by.0 && w.cid(l) != w.cid(j) && !listed(w, v, l, j)).then_some((j, l))
            })
        })
        .collect()
}

/// The checks on one small world, by its trust: `N` trusting nothing, `T` trusting a lowering
/// the settled walk applies, `V` trusting one it does not (void, its seeds lost: the walk is
/// redone, notes/write-path-design.md §1). Failing: `one reading` (a relabelling keeping the
/// order reads the same), `self-taken` (no applied commit's path loses its authority to the
/// commit's own drops), `may-grant right` (every may-grant grant applied by a right its history shows: `unright_flag_grants`), `may-grant audited` (none stands past a lowering taking what it
/// needs that does not list it: `unaudited_flag_grants`), `key right` (every grant of admin to a key applied by
/// a right its history shows: `unright_key_writes`), `key audited` (no commit a key signed shows
/// past a lowering of that key's grant taking the least it could apply by and not listing it,
/// but where the node is shown that lowering as a dispute, counted `key unaudited, shown`:
/// `unaudited_key_commits`),
/// `illegit gains N`/`T`/`V` (an idle write's unshown effect never makes apply, nor is, a write whose signer held its right in no
/// reading: `fight_among`). Counted: of each idle write (a void lowering, any other lowering, any
/// other grant write, held and doing nothing), an effect users observe (`Reading::observed`)
/// with no dispute shown (`void`, `unapplied N`/`T`/`V`, `idle N`/`T`/`V`; findings 34 to 36), each
/// classified as a fight among parties holding their right in some reading (`fight legit`) or not
/// (`fight illegit`); any effect in a world whose lists all follow the writers' rule (`honest`,
/// `lists_honest`); `fight` (an effect, a dispute shown), `void shown`, `unapplied shown`, `idle
/// shown` (only which grant writes apply changes: nobody sees it, finding 33), `stray` (a drop
/// whose dropper does not apply at the end), and the worlds whose lists are honest
/// (`honest worlds`).
pub fn tiny_check(i: u64, t: &Tiny, rules: &Rules, st: &mut TinyStats) {
    let (w, v) = (&t.w, &t.v);
    st.worlds += 1;
    let rd = judge(w, rules, v);
    let tr = if v.trust.is_empty() { "N" } else if rd.void.is_empty() { "T" } else { "V" };
    let k = |c: &'static str| -> &'static str {
        match (c, tr) {
            ("stray", "N") => "stray N",
            ("stray", "T") => "stray T",
            ("stray", _) => "stray V",
            ("unapplied", "N") => "unapplied N",
            ("unapplied", "T") => "unapplied T",
            ("unapplied", _) => "unapplied V",
            ("idle", "N") => "idle N",
            ("idle", "T") => "idle T",
            ("idle", _) => "idle V",
            ("gains", "N") => "illegit gains N",
            ("gains", "T") => "illegit gains T",
            _ => "illegit gains V",
        }
    };
    st.most_rounds = st.most_rounds.max(rd.rounds);
    st.hit(k("stray"), false, !rd.stray.is_empty(), i, w, || format!("stray {:?}", rd.stray));
    let fx = effects(w, rules, v, &rd);
    let honest = lists_honest(w, rules, &t.recv);
    *st.checked.entry("honest worlds").or_default() += honest as u64;
    for e in fx {
        let x = e.id;
        let (kk, ks) = match e.kind {
            "void" => ("void", "void shown"),
            "unapplied" => (k("unapplied"), "unapplied shown"),
            _ => (k("idle"), "idle shown"),
        };
        st.hit(kk, false, e.observed && !e.shown, i, w, || format!("{x} has an effect, no dispute shown (voided {:?}, applied {:?})", rd.voided, rd.applied));
        if e.observed && !e.shown {
            let f = fight_among(w, rules, v, &rd, &e.parts);
            let what = || format!("{x}: involved {:?}, illegit {:?}, gains {:?}", f.involved, f.illegit, f.gains);
            st.hit(if f.illegit.is_empty() { "fight legit" } else { "fight illegit" }, false, true, i, w, what);
            st.hit(k("gains"), true, !f.gains.is_empty(), i, w, what);
        }
        st.hit("fight", false, e.observed && e.shown, i, w, || format!("{x} has an effect, a dispute shown"));
        st.hit("content only", false, e.observed && !e.shown && !e.roles, i, w, || format!("{x} changes which content counts, no role"));
        if honest {
            st.hit("honest", false, e.observed, i, w, || format!("{x} has an effect, every list the writers' rule's"));
        }
        st.hit(ks, false, e.applies && !e.observed, i, w, || format!("{x} changes which writes apply"));
    }
    st.hit("one reading", true, !one_reading_relabelled(w, rules, v, &rd), i, w, || "a relabelling reads otherwise".to_string());
    st.hit("self-taken", true, !rd.self_taken.is_empty(), i, w, || format!("commits {:?} lose their path's authority to their own drops", rd.self_taken));
    let unright = unright_flag_grants(w, &rd);
    st.hit("may-grant right", true, !unright.is_empty(), i, w, || format!("may-grant grants {unright:?} made with no right"));
    let unaudited = unaudited_flag_grants(w, v, &rd);
    st.hit("may-grant audited", true, !unaudited.is_empty(), i, w, || format!("may-grant grants {unaudited:?} stand past a lowering taking their need"));
    // reach: a key's grant written by a key and by a member, by may-grant, a key acting below
    // admin, and drops made by a lowering of a key's grant
    let n = |f: &dyn Fn(Id) -> bool| rd.applied.iter().filter(|&&j| f(j)).count() as u64;
    *st.checked.entry("reach: key grant by key").or_default() += n(&|j| w.key_write(j) && w.hops(j).is_empty());
    *st.checked.entry("reach: key grant by member").or_default() += n(&|j| w.key_write(j) && !w.hops(j).is_empty());
    *st.checked.entry("reach: key grant by flag").or_default() += n(&|j| w.key_write(j) && rd.by_flag.contains(&j));
    *st.checked.entry("reach: key below admin writes").or_default() += rd.valid.iter().filter(|&&j| is_key(w.key_hop(j).0) && w.key_hop(j).0 != own_key(w.key_hop(j).1) && before_in(w, &rd, w.key_hop(j), j) == Role::Write).count() as u64;
    let node_key = |j: Id| is_key(w.key_hop(j).0) && w.key_hop(j).0 != own_key(w.key_hop(j).1) && w.commits[j].signer != A;
    *st.checked.entry("reach: a node signed by a granted key").or_default() += n(&node_key) + rd.valid.iter().filter(|&&j| node_key(j)).count() as u64;
    *st.checked.entry("reach: through A").or_default() += n(&|j| w.commits[j].path == [A]) + rd.valid.iter().filter(|&&j| w.commits[j].path == [A]).count() as u64;
    *st.checked.entry("reach: key drops").or_default() += rd.dropped.iter().filter(|j| rd.dropper.get(j).is_some_and(|&d| w.sets(d).is_some_and(|e| is_key(e.0)))).count() as u64;
    let keys = unright_key_writes(w, &rd);
    st.hit("key right", true, !keys.is_empty(), i, w, || format!("key grants {keys:?} made with no right"));
    // a node not trusting the lowering reads by the walk, each lowering judged once: a commit it
    // keeps past one is its failure only where the node is not shown that lowering as a dispute
    // (W10); shown, it is counted
    let kept = unaudited_key_commits(w, v, &rd);
    let shown = if kept.is_empty() { vec![] } else { disputes(w, rules, v) };
    let (told, kept): (Vec<_>, Vec<_>) = kept.into_iter().partition(|(_, l)| shown.contains(l));
    st.hit("key audited", true, !kept.is_empty(), i, w, || format!("(commit, lowering) {kept:?}: commits show past a lowering of their key's grant, unlisted, no dispute shown"));
    st.hit("key unaudited, shown", false, !told.is_empty(), i, w, || format!("(commit, lowering) {told:?}: commits show past a lowering of their key's grant shown as a dispute"));
}

/// `t` less one commit at a time while `fails` holds of it (receipts follow the relabelling).
pub fn shrink_world(t: &Tiny, fails: &dyn Fn(&Tiny) -> bool) -> Tiny {
    let mut t = t.clone();
    'step: loop {
        for k in 0..t.w.commits.len() {
            let keep: Vec<Id> = (0..t.w.commits.len()).filter(|&j| j != k).collect();
            let (w2, map) = rebuild(&t.w, &keep);
            let m = |s: &Set| s.iter().filter_map(|i| map.get(i).copied()).collect::<Set>();
            let v2 = View { held: m(&t.v.held), leaves: t.v.leaves.clone(), trust: m(&t.v.trust) };
            let recv = keep.iter().map(|&j| t.recv[j].iter().filter_map(|i| map.get(i).copied()).collect()).collect();
            let t2 = Tiny { w: w2, v: v2, recv };
            if fails(&t2) {
                t = t2;
                continue 'step;
            }
        }
        return t;
    }
}

/// Small worlds `start..start + n`.
pub fn tiny_run_from(start: u64, n: u64, rules: &Rules, mode: TinyMode) -> TinyStats {
    crate::on_every_core(|th, threads, st: &mut TinyStats| {
        for i in (start + th as u64..start + n).step_by(threads) {
            tiny_check(i, &tiny_world(i, mode, rules), rules, st);
        }
    })
}

fn tiny_print(st: &TinyStats, rules: &Rules, mode: TinyMode) {
    println!("tiny {mode:?}: {} worlds, checks {:?}, noted {:?}, failing {:?}, most rounds {}", st.worlds, st.checked, st.noted, st.fails, st.most_rounds);
    for (k, (n, i, what)) in &st.first {
        let t = tiny_world(*i, mode, rules);
        let prop = *k;
        let fails = |t: &Tiny| {
            let mut s = TinyStats::default();
            tiny_check(*i, t, rules, &mut s);
            s.fails.contains_key(prop) || s.noted.contains_key(prop)
        };
        let t = shrink_world(&t, &fails);
        let mut s = TinyStats::default();
        tiny_check(*i, &t, rules, &mut s);
        let what = s.first.get(prop).map_or(what.clone(), |f| f.2.clone());
        let tag = if st.fails.contains_key(k) { "FAIL" } else { "NOTED" };
        println!("{tag} {k}: world {i} ({n} commits; shrunk to {}), trust {:?}, received {:?}: {what}\n{}", t.w.commits.len(), t.v.trust, t.recv, tiny_trace(&t.w));
    }
}

/// A small world's commits, one a line.
pub fn tiny_trace(w: &World) -> String {
    let name = |t: &Thing| match *t {
        A => "A",
        RK => "RK",
        TK => "TK",
        t if is_key(t) => "own key",
        T1 => "T1",
        t => ["?", "H", "B", "X", "N5", "K", "Z", "N6"].get(t as usize).copied().unwrap_or("?"),
    };
    let mut s = String::new();
    for (i, c) in w.commits.iter().enumerate() {
        let by = if c.key == own_key(c.signer) { String::new() } else { format!(" by {}", name(&c.key)) };
        // the thing written and the path, where it is not A by the direct grant
        let at = if c.on == A && c.path.is_empty() { String::new() } else { format!(" on {} via {:?}", name(&c.on), c.path.iter().map(name).collect::<Vec<_>>()) };
        if let Kind::Grant { holder, role, frontier, until, may_grant, finalize } = &c.kind {
            let what = if *finalize { "finalize".to_string() } else { format!("{role:?}{}{}", if *may_grant { " may grant" } else { "" }, until.map_or(String::new(), |u| format!(" until {u}"))) };
            let part = if w.parts(c.cid) > 1 { format!(" (commit {})", c.cid) } else { String::new() };
            s += &format!("  {i}: {}{by} ts {}{part}{at}: {} := {what} listing {:?}\n", name(&c.signer), c.ts, name(holder), frontier.values().flatten().collect::<Vec<_>>());
        } else if matches!(c.kind, Kind::Content) {
            s += &format!("  {i}: {}{by} ts {}{at}: content\n", name(&c.signer), c.ts);
        }
    }
    s
}

/// `-- N paths[-control]` (random worlds), `-- 0 paths-exh[-control]` (the small family),
/// `-- N paths-tiny[-flags|-detached][-honest[-writers]][-control]` (small worlds); random and small worlds from
/// index `from` on (`-- N paths --from K`). Returns the failing checks.
pub fn run(samples: u64, from: u64, mode: &str) -> u64 {
    // `-- N paths-purge[-variant]`: purge worlds (`purge_rules`; `paths-purge-any-path` and
    // `paths-purge-contains` are story controls, below)
    if let Some(rules) = purge_rules(mode) {
        let st = purge_run_from(from, samples, &rules);
        st.print(mode);
        return st.failures();
    }
    let Some(rules) = mode_rules(mode) else {
        eprintln!("unknown mode {mode}");
        return 1;
    };
    if mode.starts_with("paths-tiny") {
        let mode = TinyMode::named(mode);
        let st = tiny_run_from(from, samples, &rules, mode);
        tiny_print(&st, &rules, mode);
        return st.failures();
    }
    // `-- N paths-exh`: every Nth family world (N 0 or 1: all of them)
    let st = if mode.starts_with("paths-exh") { family_run(&rules, samples.max(1) as usize) } else { random_from(from, samples, &rules) };
    st.print(mode, &rules);
    st.failures()
}
