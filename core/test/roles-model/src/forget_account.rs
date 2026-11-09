//! Forgetting at the account level (candidate C, `forget` for the member level): account P's
//! commits at one epoch, which a rotation closes. Nothing here reads `ts`: a name (rotation
//! list, listing, addendum) follows the one cutoff, "received before the earliest counting
//! closer the namer holds" (spec/permissions.md §5.5), or the namer's own device's commit.
//! Devices Y (rotator), X (removed), Z (sibling that may rotate unaware or reject by merge),
//! W an outside writer (witness), E a holder that does not judge.
//!
//! "Own" must be something a reader can see. `Cover::Account`: a commit forgets under any
//! snapshot by P. `Cover::Session`: only under one of its session; a session nonce is public
//! and any device of P signs any session, so X can claim Y's.
//! `claims`: a lying snapshot, covering a write it does not carry.

use std::collections::{BTreeSet, HashMap, HashSet};

pub const Y: usize = 0;
pub const X: usize = 1;
pub const Z: usize = 2;
pub const W: usize = 3;
pub const E: usize = 4;
const NN: usize = 5;
const NEVER: u32 = u32::MAX;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cover {
    /// Lists every received commit; nothing forgotten.
    ListAll,
    Account,
    Session,
}

#[derive(Clone, Debug)]
enum Kind {
    Plain,
    Snap { carries: Vec<u32>, claims: Vec<u32> },
    /// A rotation (`rejects` a rotation by merge) or a listing or addendum (no rejects, not a closer).
    Word { names: Vec<u32>, closer: bool, rejects: Option<u32> },
}

#[derive(Clone, Debug)]
struct C {
    id: u32,
    kind: Kind,
    session: u32,
    device: usize,
}

/// One scripted action.
#[derive(Clone, Debug)]
pub enum Act {
    /// (time, id, device, session, deliveries)
    Plain(u32, u32, usize, u32, Vec<(usize, u32)>),
    /// A snapshot of what its device reads (`claims`: writes covered without their value).
    Snap(u32, u32, usize, u32, Vec<u32>, Vec<(usize, u32)>),
    /// A rotation closing the epoch; by a device; `rejects` an earlier rotation.
    Rotate(u32, u32, usize, Option<u32>, Vec<(usize, u32)>),
}

struct Run {
    cover: Cover,
    items: Vec<C>,
    idx: HashMap<u32, usize>,
    /// [node][item] arrival order.
    got: Vec<Vec<Option<u64>>>,
    body: Vec<Vec<bool>>,
    seq: u64,
    forgot: Vec<BTreeSet<u32>>,
    wrote: HashSet<(usize, u64)>,
    next_word: u32,
}

impl Run {
    fn new(cover: Cover) -> Run {
        Run { cover, items: vec![], idx: HashMap::new(), got: vec![vec![]; NN], body: vec![vec![]; NN], seq: 0, forgot: vec![BTreeSet::new(); NN], wrote: HashSet::new(), next_word: 500 }
    }
    fn add(&mut self, c: C) -> usize {
        let i = self.items.len();
        self.idx.insert(c.id, i);
        self.items.push(c);
        for v in 0..NN {
            self.got[v].push(None);
            self.body[v].push(false);
        }
        i
    }
    fn held(&self, v: usize, i: usize) -> bool {
        self.got[v][i].is_some()
    }
    fn rejected(&self, v: usize, i: usize) -> bool {
        (0..self.items.len()).any(|m| self.held(v, m) && matches!(&self.items[m].kind, Kind::Word { rejects: Some(r), .. } if *r == self.items[i].id))
    }
    /// A counting word: a rotation not rejected at v, any listing or addendum.
    fn counting_word(&self, v: usize, i: usize) -> bool {
        self.held(v, i) && matches!(self.items[i].kind, Kind::Word { .. }) && !self.rejected(v, i)
    }
    fn closers(&self, v: usize) -> Vec<usize> {
        (0..self.items.len()).filter(|&i| self.counting_word(v, i) && matches!(self.items[i].kind, Kind::Word { closer: true, .. })).collect()
    }
    fn valid(&self, v: usize, i: usize) -> bool {
        if !self.held(v, i) {
            return false;
        }
        if matches!(self.items[i].kind, Kind::Word { .. }) {
            return !self.rejected(v, i);
        }
        if self.closers(v).is_empty() {
            return true;
        }
        let id = self.items[i].id;
        (0..self.items.len()).any(|w| self.counting_word(v, w) && matches!(&self.items[w].kind, Kind::Word { names, .. } if names.contains(&id)))
    }
    fn visible(&self, v: usize) -> BTreeSet<u32> {
        let mut out = BTreeSet::new();
        for i in 0..self.items.len() {
            if matches!(self.items[i].kind, Kind::Plain) && self.valid(v, i) && self.body[v][i] {
                out.insert(self.items[i].id);
            }
            if let Kind::Snap { carries, .. } = &self.items[i].kind {
                if self.valid(v, i) && self.body[v][i] {
                    out.extend(carries.iter().copied());
                }
            }
        }
        out
    }
    fn covers(&self, s: usize, c: usize) -> bool {
        let cid = self.items[c].id;
        matches!(&self.items[s].kind, Kind::Snap { carries, claims } if carries.contains(&cid) || claims.contains(&cid))
    }
    fn settle(&mut self, v: usize) {
        for _ in 0..30 {
            let n = self.items.len();
            let mut drop_body = vec![];
            let mut forget = vec![];
            let mut covered = vec![false; n];
            for s in 0..n {
                if !matches!(self.items[s].kind, Kind::Snap { .. }) || !self.valid(v, s) || !self.body[v][s] {
                    continue;
                }
                for c in 0..n {
                    if c != s && self.held(v, c) && !matches!(self.items[c].kind, Kind::Word { .. }) && self.covers(s, c) {
                        covered[c] = true;
                        drop_body.push(c);
                        let f = match self.cover {
                            Cover::ListAll => false,
                            Cover::Account => true,
                            Cover::Session => self.items[c].session == self.items[s].session,
                        };
                        if f {
                            forget.push(c);
                        }
                    }
                }
            }
            for i in 0..n {
                if v != E && self.held(v, i) && !self.valid(v, i) && !matches!(self.items[i].kind, Kind::Word { .. }) {
                    self.body[v][i] = false;
                }
            }
            for c in drop_body {
                self.body[v][c] = false;
            }
            for c in forget {
                self.got[v][c] = None;
                self.forgot[v].insert(self.items[c].id);
            }
            let mut fetched = false;
            for i in 0..n {
                if self.held(v, i) && !covered[i] && self.valid(v, i) && !self.body[v][i] && (0..NN).any(|u| self.body[u][i]) {
                    self.body[v][i] = true;
                    fetched = true;
                }
            }
            if !fetched {
                return;
            }
        }
        panic!("settle");
    }
    /// The IDs v would name: P's commits it holds received before `before`, or its device's,
    /// that no counting word it holds names; `cover`: less what a held valid snapshot carries,
    /// that snapshot named instead.
    fn names(&self, v: usize, before: u64, plain_only: bool) -> Vec<u32> {
        let n = self.items.len();
        let in_time = |i: usize| self.got[v][i].map_or(false, |g| g < before) || (self.held(v, i) && self.items[i].device == v);
        let named = |id: u32| (0..n).any(|w| self.counting_word(v, w) && matches!(&self.items[w].kind, Kind::Word { names, .. } if names.contains(&id)));
        let mut carried = HashSet::new();
        if self.cover != Cover::ListAll {
            for s in 0..n {
                if in_time(s) && matches!(self.items[s].kind, Kind::Snap { .. }) && self.body[v][s] {
                    if let Kind::Snap { carries, claims } = &self.items[s].kind {
                        carried.extend(carries.iter().copied());
                        carried.extend(claims.iter().copied());
                    }
                }
            }
        }
        (0..n)
            .filter(|&i| {
                let c = &self.items[i];
                in_time(i) && !named(c.id) && !carried.contains(&c.id) && match c.kind {
                    Kind::Plain => true,
                    Kind::Snap { .. } => !plain_only || self.cover != Cover::ListAll,
                    _ => false,
                }
            })
            .map(|i| self.items[i].id)
            .collect()
    }
    fn earliest_closer(&self, v: usize) -> u64 {
        self.closers(v).iter().map(|&c| self.got[v][c].unwrap()).min().unwrap_or(u64::MAX)
    }
    /// After a change in what closes the epoch at v, P's devices and witnesses write what no
    /// counting word they hold names (a listing or addendum).
    fn answer(&mut self, v: usize) {
        if v == X || v == E || self.closers(v).is_empty() {
            return;
        }
        let e = self.earliest_closer(v);
        let names = self.names(v, e, v == W);
        if names.is_empty() || !self.wrote.insert((v, names.iter().fold(0u64, |a, x| a.wrapping_mul(1009).wrapping_add(*x as u64)))) {
            return;
        }
        self.next_word += 1;
        let i = self.add(C { id: self.next_word, kind: Kind::Word { names, closer: false, rejects: None }, session: 0, device: v });
        self.seq += 1;
        for u in 0..NN {
            self.got[u][i] = Some(self.seq);
            self.body[u][i] = true;
        }
        for u in 0..NN {
            self.settle(u);
        }
    }
    fn deliver(&mut self, v: usize, i: usize) {
        if self.got[v][i].is_none() {
            self.seq += 1;
            self.got[v][i] = Some(self.seq);
            self.body[v][i] = true;
            self.settle(v);
            self.answer(v);
        }
    }
}

/// What each node reads after the script and a full exchange.
pub fn run(script: &[Act], cover: Cover) -> Vec<BTreeSet<u32>> {
    let mut r = Run::new(cover);
    // (time, order, deliver to, item index or pending act)
    let mut acts: Vec<(u32, usize)> = script
        .iter()
        .enumerate()
        .map(|(k, a)| {
            (
                match a {
                    Act::Plain(t, ..) | Act::Snap(t, ..) | Act::Rotate(t, ..) => *t,
                },
                k,
            )
        })
        .collect();
    acts.sort();
    let mut deliveries: Vec<(u32, usize, usize)> = vec![];
    let flush = |r: &mut Run, deliveries: &mut Vec<(u32, usize, usize)>, until: u32| {
        deliveries.sort();
        let (now, later): (Vec<_>, Vec<_>) = deliveries.iter().copied().partition(|d| d.0 < until);
        *deliveries = later;
        for (_, v, i) in now {
            r.deliver(v, i);
        }
    };
    for (t, k) in acts {
        flush(&mut r, &mut deliveries, t);
        let (c, dev, recv) = match &script[k] {
            Act::Plain(_, id, d, ses, recv) => (C { id: *id, kind: Kind::Plain, session: *ses, device: *d }, *d, recv),
            Act::Snap(_, id, d, ses, claims, recv) => {
                let carries: Vec<u32> = r.visible(*d).into_iter().filter(|x| !claims.contains(x)).collect();
                (C { id: *id, kind: Kind::Snap { carries, claims: claims.clone() }, session: *ses, device: *d }, *d, recv)
            }
            Act::Rotate(_, id, d, rejects, recv) => {
                let names = r.names(*d, u64::MAX, false);
                (C { id: *id, kind: Kind::Word { names, closer: true, rejects: *rejects }, session: 0, device: *d }, *d, recv)
            }
        };
        let i = r.add(c);
        r.deliver(dev, i);
        for &(v, at) in recv {
            if at != NEVER {
                deliveries.push((at, v, i));
            }
        }
    }
    flush(&mut r, &mut deliveries, u32::MAX);
    for _ in 0..30 {
        let before = (r.got.iter().map(|g| g.iter().map(|x| x.is_some()).collect::<Vec<_>>()).collect::<Vec<_>>(), r.body.clone());
        for v in 0..NN {
            for i in 0..r.items.len() {
                if !r.held(v, i) && (0..NN).any(|u| r.held(u, i)) {
                    let has = (0..NN).any(|u| r.body[u][i]);
                    r.seq += 1;
                    r.got[v][i] = Some(r.seq);
                    r.body[v][i] = has;
                    r.settle(v);
                    r.answer(v);
                }
            }
        }
        if (r.got.iter().map(|g| g.iter().map(|x| x.is_some()).collect::<Vec<_>>()).collect::<Vec<_>>(), r.body.clone()) == before {
            break;
        }
    }
    (0..NN).map(|v| r.visible(v)).collect()
}

/// Small exhaustive family: sibling's write c (device Y) and X's write d, each reaching Z, W,
/// E early or never; a snapshot at t=3 by X, Z or Y (hostile X claiming c without its value,
/// or honest), reaching each node at 4 (before the rotation), 8 (after) or never; Y rotates at
/// 6, reaching each node at 7 or 10; Z rotates unaware at 5, or merges rejecting Y's at 9.
pub fn family(mut f: impl FnMut(&[Act])) {
    let at = |m: u32, k: u32, opts: &[u32]| opts[(m / (opts.len() as u32).pow(k) % opts.len() as u32) as usize];
    for cm in 0..8u32 {
        for dm in 0..8u32 {
            for snap in 0..7u32 {
                for sm in 0..81u32 {
                    for rm in 0..16u32 {
                        for extra in 0..3u32 {
                            let others = |m: u32, t: u32| vec![(Z, at(m, 0, &[t, NEVER])), (W, at(m, 1, &[t, NEVER])), (E, at(m, 2, &[t, NEVER]))];
                            let mut s = vec![Act::Plain(1, 1, Y, 7, others(cm, 2)), Act::Plain(2, 2, X, 8, others(dm, 3))];
                            // 0 none; 1-3 honest X, Z, Y; 4-6 lying X claiming c (in Y's session, or X's).
                            if snap > 0 {
                                let dev = [X, Z, Y, X, X, X][snap as usize - 1];
                                let ses = [8, 9, 7, 8, 7, 8][snap as usize - 1];
                                let claims = if snap >= 4 { vec![1] } else { vec![] };
                                let recv: Vec<(usize, u32)> = [Y, X, Z, W, E].iter().enumerate().filter(|(_, n)| **n != dev).map(|(k, n)| (*n, at(sm, k as u32, &[4, 8, NEVER]))).collect();
                                s.push(Act::Snap(3, 100, dev, ses, claims, recv));
                            }
                            let r = |b: u32| if rm >> b & 1 == 1 { 7 } else { 10 };
                            s.push(Act::Rotate(6, 200, Y, None, vec![(X, r(0)), (Z, r(1)), (W, r(2)), (E, r(3))]));
                            if extra == 1 {
                                s.push(Act::Rotate(5, 201, Z, None, vec![(Y, 8), (W, 8), (E, 8), (X, 8)]));
                            }
                            if extra == 2 {
                                s.push(Act::Rotate(9, 202, Z, Some(200), vec![(Y, 11), (W, 11), (E, 11), (X, 11)]));
                            }
                            f(&s);
                        }
                    }
                }
            }
        }
    }
}

pub fn exhaustive() {
    for cover in [Cover::Account, Cover::Session] {
        let (mut worlds, mut honest_loses, mut lying_loses, mut disagree, mut gains) = (0u64, 0u64, 0u64, 0u64, 0u64);
        let mut ex: Option<Vec<Act>> = None;
        let mut best: Option<Vec<Act>> = None;
        family(|s| {
            worlds += 1;
            let lying = s.iter().any(|a| matches!(a, Act::Snap(_, _, _, _, c, _) if !c.is_empty()));
            let b = run(s, Cover::ListAll);
            let o = run(s, cover);
            if (0..NN).any(|v| o[v] != o[0]) {
                disagree += 1;
            }
            let lose = (0..NN).any(|v| b[v].difference(&o[v]).next().is_some());
            gains += (0..NN).any(|v| o[v].difference(&b[v]).next().is_some()) as u64;
            if lose {
                if lying {
                    lying_loses += 1;
                    if s.len() < best.as_ref().map_or(99, |b: &Vec<Act>| b.len()) {
                        best = Some(s.to_vec());
                    }
                } else {
                    honest_loses += 1;
                    ex.get_or_insert_with(|| s.to_vec());
                }
            }
        });
        println!("account {cover:?}: {worlds} worlds | honest snapshots lose {honest_loses} | lying snapshot loses {lying_loses} | gains {gains} | disagree {disagree}");
        if let Some(e) = best {
            println!("  a lying loss: {e:?}\n   list all {:?}\n   {cover:?} {:?}", run(&e, Cover::ListAll), run(&e, cover));
        }
        if let Some(e) = ex {
            println!("  first honest loss: {e:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Y's edit, honest snapshot by the removed sibling X, named by Y's rotation: holds.
    #[test]
    fn removed_devices_honest_cover_holds() {
        let s = [Act::Plain(1, 1, Y, 7, vec![(X, 2), (E, 2)]), Act::Snap(3, 100, X, 8, vec![], vec![(Y, 4), (E, 4)]), Act::Rotate(6, 200, Y, None, vec![(X, 7), (E, 7)])];
        for cover in [Cover::ListAll, Cover::Account] {
            assert!(run(&s, cover)[Y].contains(&1), "{cover:?}");
        }
    }

    /// X's lying snapshot covers Y's edit without its value: once named it drops the body
    /// wherever it reaches, listing or not (today's limit), so forgetting is no worse.
    #[test]
    fn lying_snapshot_no_worse_than_listing() {
        let s = [Act::Plain(1, 1, Y, 7, vec![(E, 2)]), Act::Snap(3, 100, X, 8, vec![1], vec![(Y, 4)]), Act::Rotate(6, 200, Y, None, vec![(X, 7), (E, 7)])];
        assert_eq!(run(&s, Cover::ListAll)[Y].contains(&1), false);
        assert_eq!(run(&s, Cover::Account)[Y].contains(&1), false);
    }

    /// Why "own" cannot be narrowed: X's lying snapshot, on its own session, covers Y's edit.
    /// Witness W held it before the rotation and names it, so it stands and drops the edit's
    /// body; listing every commit never lets an addendum name a snapshot. Neither account
    /// nor session as "own" stops it.
    #[test]
    fn lying_snapshot_named_by_a_witness_erases_a_sibling() {
        let s = [Act::Plain(1, 1, Y, 7, vec![(W, 2), (E, 2)]), Act::Snap(3, 100, X, 8, vec![1], vec![(W, 4), (E, 4)]), Act::Rotate(6, 200, Y, None, vec![(X, 7), (Z, 7), (W, 7), (E, 7)])];
        assert!(run(&s, Cover::ListAll)[Y].contains(&1));
        assert!(!run(&s, Cover::Account)[Y].contains(&1));
        assert!(!run(&s, Cover::Session)[Y].contains(&1));
    }

    /// With the cutoff by arrival there is no late-snapshot window: a snapshot arriving after
    /// the rotation is unnamed and invalid, so nothing was forgotten under it.
    #[test]
    fn late_snapshot_forgets_nothing() {
        let s = [Act::Plain(1, 1, Y, 7, vec![(Z, 2), (E, 2)]), Act::Snap(3, 100, Z, 9, vec![], vec![(E, 4)]), Act::Rotate(6, 200, Y, None, vec![(Z, 7), (E, 7)])];
        assert!(run(&s, Cover::Account)[Z].contains(&1));
    }
}
