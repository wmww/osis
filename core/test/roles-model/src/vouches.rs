//! Vouches and what no list keeps (notes/account-membership-design.md §4, Role writes: vouched
//! for like content, and What no list keeps; notes/redesign-plan.md S3 briefs 2-3) under today's
//! walk: authority as `edges` gives it
//! (one thing, every node a key actor, a frontier is what its demoter received), with trust sets
//! (`trust`). Not the stated-path design (`paths`).
//!
//! **A vouch** by W names a removal R (a commit ID) and lists commit IDs of R's victim X. An entry
//! c **counts** iff, in the **first walk** (the ordinary walk under the node's trust set, every
//! vouch disregarded):
//! - R applies an explicit write (an op attributed to admin) taking something from X's edge;
//! - c is X's and ordered before R; the vouch is ordered after R (its position is the start of
//!   its `ts`, as any role-class write that is not an edge write);
//! - W's own commit with c's ops at the vouch's position would apply (`EHist::would_apply`): the
//!   voucher's authority is "an edge write of the same kind by it at the vouch's key";
//! - no applied explicit write by another author lowering W's edge, ordered after the vouch, by
//!   an author that had not received the vouch before its `ts`, leaves W without that authority
//!   (W's vouch survives W's later removals by their frontiers, as its role-class writes do).
//!
//! **The second walk** is the ordinary walk with each counting entry added to its removal's
//! frontier (`edges::Lists::extra`), in the audit and in a trusted write's seeds alike: that is
//! the timeline. Nothing judges a vouch again in it.
//!
//! **What no list keeps** (`Rules::absent`, `edges::Lists::absent`): a frontier entry, received or
//! added by a vouch, naming an op of X that takes something from the demoter's own edge is read as
//! absent. One thing, so the demoter's path is its own edge; a vouch's entries are struck against
//! the removal's author, the frontier they join (the simplest reading: the entry is in R's list).
//!
//! **Honest writing**: each node W but X and R's author that received R writes, at receipt and
//! (`Rules::rewrite`) at every later time it newly holds the authority for a listed commit in the
//! first walk, one vouch listing X's commits before R it had received by R's `ts` that R's
//! author had not. Which times W holds that authority is read off the canonical first walk.
//!
//! Properties (`check`), at the judgment of the whole held set under the empty trust set and
//! under each removal trusted alone:
//! - **kept**: an op of X that an honest node other than X and R's author received by R's `ts`,
//!   where it holds the authority for it in the first walk as it applies R (and no node that had
//!   not received its vouch written then later lowers its edge below it) or at the end, is kept:
//!   every node ends with the authority it has where R's frontier names every such op (the
//!   reference: `Lists::extra` set to every such entry). Compared on final authority, not op by
//!   op: keeping one witnessed op may leave a later one of X without effect;
//! - **safety**: an op of X no node but X received before a removal of X after it applied in the
//!   second walk (unwitnessed) never applies in the second walk where it does not in the first,
//!   with forged vouches by X and by nodes that never hold admin; finalizes (never audited, they
//!   remove only ended edges), ops on their author's own edge but raises, and ops on a voucher's
//!   own edge it names aside (nobody gains: a vouch counting for an op on its author's edge is
//!   one its author could write). Ops named by a vouch of their own author
//!   (X still holding the authority after R, by an invite) are counted apart: "nobody vouches for
//!   its own signer's commit" closes them and lands with stated paths (notes/redesign-plan.md S3,
//!   A1; `a_demoted_node_vouches_for_its_own_backdated_invite`);
//! - **listing**: a trusted removal R by A of X (an op removing X's edge) that applies with an
//!   empty frontier and no vouch against it also applies with A's honest frontier and its vouches. Worlds
//!   where a third node sets A's edge below admin, before or after R, are counted apart (an
//!   accomplice: struck from A's removal of it, not of X:
//!   `an_accomplices_removal_is_answered_by_removing_the_accomplice`);
//! - **alike**: one result for every input order.
//!
//! Negative controls (`Rules`): `vouches: false` fails kept; `rewrite: false` fails kept (a node
//! granted the authority after R); `absent: false` fails listing.
//! Search: `roles-model -- N vouches` (random), `-- 0 vouches-exh`
//! (the small family); controls `vouches-off`, `vouches-no-rewrite`, `vouches-no-absent` (random)
//! and `vouches-exh-off` and so on (the family).

use crate::edges::{self, takes_from, Attr, EHist, EOut, EWrite, Edge, Lists, NEVER};
use crate::shrink::LATE;
use crate::trust::{self, Trusting};
use crate::{Rng, Role};

/// A time after every write and receipt but `LATE`: the first walk's final state is read here.
const END: u32 = 40;

#[derive(Clone, Debug)]
pub struct Vouch {
    pub author: usize,
    pub t: u32,
    /// The removal's commit ID.
    pub removal: u32,
    /// Commit IDs it lists.
    pub lists: Vec<u32>,
    /// [node] receipt time; `LATE` never.
    pub recv: Vec<u32>,
    pub forged: bool,
}

#[derive(Clone, Debug)]
pub struct World {
    pub h: EHist,
    pub vouches: Vec<Vouch>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    pub vouches: bool,
    pub rewrite: bool,
    pub absent: bool,
}

pub const FIXED: Rules = Rules { vouches: true, rewrite: true, absent: true };

pub type Res = (Vec<(Role, Role)>, Vec<u32>);

pub struct Judged {
    pub res: Res,
    /// Ops applied in the first and the second walk.
    pub first: u64,
    pub applied: u64,
    /// Trusted ops in force after the second walk.
    pub active: u64,
    /// Counting entries (removal ID, commit ID).
    pub counted: Vec<(u32, u32)>,
    /// The second walk's history and settled `EOut`.
    pub h2: EHist,
    pub o2: EOut,
}

fn key(w: &EWrite) -> (u32, usize, u32) {
    (w.t, w.author, w.id)
}

/// The edges of `o` just after commit `i` (its applied ops on top of those before it).
fn edges_after(h: &EHist, o: &EOut, i: usize) -> Vec<Option<Edge>> {
    let w = &h.writes[i];
    let mut e = h.edges_before(o, key(w));
    for (k, &(x, v)) in w.ops.iter().enumerate() {
        if o.attr[o.base[i] + k] != Attr::Skipped {
            e[x] = v;
        }
    }
    e
}

/// The victims commit `i` lowers by an applied explicit write in `o`.
fn victims(h: &EHist, o: &EOut, i: usize) -> Vec<usize> {
    let w = &h.writes[i];
    let before = h.edges_before(o, key(w));
    w.ops.iter().enumerate().filter(|&(k, &(x, e))| x != w.author && o.attr[o.base[i] + k] == Attr::Admin && takes_from(e, before[x])).map(|(_, &(x, _))| x).collect()
}

/// W's own commit with commit c's ops at time `t` would apply against `edges`.
fn could_write(h: &EHist, w: usize, c: usize, t: u32, edges: &[Option<Edge>]) -> bool {
    let cw = &h.writes[c];
    h.would_apply(&EWrite { author: w, t, id: 0, ops: cw.ops.clone(), fin: cw.fin }, edges)
}

/// The counting entries of `vouches` against the first walk `o` of `h`.
fn counting(h: &EHist, o: &EOut, vouches: &[Vouch]) -> Vec<(u32, u32)> {
    let mut out = vec![];
    let idx = |id: u32| h.writes.iter().position(|w| w.id == id);
    for v in vouches {
        let Some(r) = idx(v.removal) else { continue };
        let rw = &h.writes[r];
        if rw.t >= v.t {
            continue;
        }
        let vic = victims(h, o, r);
        let at = h.edges_before(o, (v.t, 0, 0));
        // explicit writes lowering W's edge after the vouch by an author that had not received it
        let later: Vec<usize> = (0..h.writes.len())
            .filter(|&q| {
                let qw = &h.writes[q];
                qw.t >= v.t && qw.author != v.author && v.recv[qw.author] >= qw.t && victims(h, o, q).contains(&v.author)
            })
            .collect();
        for &cid in &v.lists {
            let Some(c) = idx(cid) else { continue };
            let cw = &h.writes[c];
            if !vic.contains(&cw.author) || key(cw) >= key(rw) || !could_write(h, v.author, c, v.t, &at) {
                continue;
            }
            if later.iter().any(|&q| !could_write(h, v.author, c, h.writes[q].t, &edges_after(h, o, q))) {
                continue;
            }
            out.push((v.removal, cid));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn with_lists(h: &EHist, extra: Vec<(u32, u32)>, absent: bool) -> EHist {
    let mut h = h.clone();
    h.lists = Lists { extra, absent };
    h
}

/// The first walk under `trust` and its settled `EOut`.
fn first_walk(w: &World, rules: Rules, trust: u64) -> (EHist, trust::Side<Res>, EOut) {
    let h1 = with_lists(&w.h, vec![], rules.absent);
    let s1 = trust::side(&h1, trust);
    let o1 = h1.eval_from(true, s1.d0).0;
    (h1, s1, o1)
}

/// The timeline of `w` under `rules` and trust set `trust` (bits over ops).
pub fn judge(w: &World, rules: Rules, trust: u64) -> Judged {
    let (h1, s1, o1) = first_walk(w, rules, trust);
    let counted = if rules.vouches { counting(&h1, &o1, &w.vouches) } else { vec![] };
    let h2 = with_lists(&w.h, counted.clone(), rules.absent);
    let s2 = trust::side(&h2, trust);
    let o2 = h2.eval_from(true, s2.d0).0;
    Judged { res: s2.res, first: s1.applied, applied: s2.applied, active: s2.active, counted, h2, o2 }
}

impl World {
    /// The world with the honest vouches (module doc, Honest writing) added; receipts of each
    /// from `recv(author, t)`.
    pub fn derive(&mut self, rules: Rules, mut recv: impl FnMut(usize, u32) -> Vec<u32>) {
        let h = &self.h;
        let (h1, _, o1) = first_walk(self, rules, 0);
        let n = h.n();
        let mut out = vec![];
        for (r, rw) in h.writes.iter().enumerate() {
            for &x in rw.ops.iter().map(|(x, _)| x).filter(|&&x| x != rw.author && !rw.fin) {
                for wn in (0..n).filter(|&wn| wn != x && wn != rw.author && h.recv[r][wn] < LATE) {
                    let lists: Vec<usize> = (0..h.writes.len()).filter(|&c| h.writes[c].author == x && key(&h.writes[c]) < key(rw) && h.recv[c][wn] < rw.t && h.recv[c][rw.author] >= rw.t).collect();
                    if lists.is_empty() {
                        continue;
                    }
                    let first = h.recv[r][wn].max(rw.t) + 1;
                    let mut held_before: Vec<bool> = vec![false; lists.len()];
                    for t in first..END {
                        let at = h1.edges_before(&o1, (t, 0, 0));
                        let held: Vec<bool> = lists.iter().map(|&c| could_write(&h1, wn, c, t, &at)).collect();
                        let newly = held.iter().zip(&held_before).any(|(a, b)| *a && !*b);
                        if t == first || newly && rules.rewrite {
                            out.push(Vouch { author: wn, t, removal: rw.id, lists: lists.iter().map(|&c| h.writes[c].id).collect(), recv: recv(wn, t), forged: false });
                        }
                        held_before = held;
                        if !rules.rewrite {
                            break;
                        }
                    }
                }
            }
        }
        out.dedup_by(|a, b| a.author == b.author && a.t == b.t && a.removal == b.removal);
        self.vouches.extend(out);
    }

    fn permuted(&self, rng: &mut Rng) -> World {
        let p = rng.perm(self.h.writes.len());
        let q = rng.perm(self.vouches.len());
        World { h: Trusting::permute(&self.h, &p), vouches: q.iter().map(|&i| self.vouches[i].clone()).collect() }
    }
}

// ---------- properties ----------

/// The ops of commit `c` (`base` from any walk of the history).
fn ops_of(o: &EOut, c: usize) -> std::ops::Range<usize> {
    o.base[c]..o.base[c + 1]
}

/// Kept: the judgment gives every node the authority the reference does. Returns (entries the
/// reference lists, failing worlds).
fn kept(w: &World, rules: Rules, trust: u64) -> (u64, u64) {
    let honest = World { h: w.h.clone(), vouches: w.vouches.iter().filter(|v| !v.forged).cloned().collect() };
    let w = &honest;
    let h = &w.h;
    let (h1, _, o1) = first_walk(w, rules, trust);
    let fin = h1.edges_before(&o1, (END, 0, 0));
    let mut extra = vec![];
    for r in 0..h.writes.len() {
        let rw = &h.writes[r];
        for x in victims(&h1, &o1, r) {
            for c in (0..h.writes.len()).filter(|&c| h.writes[c].author == x && key(&h.writes[c]) < key(rw)) {
                let witness = (0..h.n()).any(|wn| {
                    let first = h.recv[r][wn].max(rw.t) + 1;
                    // lowered later by another node that had not received its vouch written then
                    let v = w.vouches.iter().find(|v| v.author == wn && v.removal == rw.id && v.t == first);
                    let removed = (0..h.writes.len()).any(|q| {
                        let qw = &h.writes[q];
                        qw.t >= first && qw.author != wn && v.map_or(true, |v| v.recv[qw.author] >= qw.t) && victims(&h1, &o1, q).contains(&wn) && !could_write(&h1, wn, c, qw.t, &edges_after(&h1, &o1, q))
                    });
                    let then = !removed && could_write(&h1, wn, c, first, &h1.edges_before(&o1, (first, 0, 0)));
                    wn != x && wn != rw.author && h.recv[r][wn] < LATE && h.recv[c][wn] < rw.t && (then || could_write(&h1, wn, c, END, &fin))
                });
                if witness {
                    extra.push((rw.id, h.writes[c].id));
                }
            }
        }
    }
    if extra.is_empty() {
        return (0, 0);
    }
    let reference = trust::side(&with_lists(h, extra.clone(), rules.absent), trust);
    let j = judge(w, rules, trust);
    (extra.len() as u64, (reference.res.0 != j.res.0) as u64)
}

/// Safety: unwitnessed ops of a node removed in the second walk newly applied by vouches.
/// (checked, failures, of those named by a vouch of their own author)
fn safety(w: &World, rules: Rules, trust: u64) -> (u64, u64, u64) {
    let h = &w.h;
    let (_, _, o1) = first_walk(w, rules, trust);
    let j = judge(w, rules, trust);
    let removals: Vec<(usize, usize)> = (0..h.writes.len()).flat_map(|r| victims(&j.h2, &j.o2, r).into_iter().map(move |x| (r, x))).collect();
    let (mut checked, mut bad, mut own) = (0, 0, 0);
    for c in 0..h.writes.len() {
        let cw = &h.writes[c];
        let after: Vec<usize> = removals.iter().filter(|&&(r, x)| x == cw.author && key(&h.writes[r]) > key(cw)).map(|&(r, _)| r).collect();
        if after.is_empty() || after.iter().any(|&r| (0..h.n()).any(|v| v != cw.author && h.recv[c][v] < h.writes[r].t)) {
            continue;
        }
        for (k, op) in ops_of(&o1, c).enumerate() {
            let (x, e) = cw.ops[k];
            // a self-lowering, or a lowering of a voucher's own edge it names: no one gains
            let prior = h.prior(c, x);
            let raise = e != prior && !takes_from(e, prior);
            if cw.fin || x == cw.author && !raise || w.vouches.iter().any(|v| v.author == x && v.lists.contains(&cw.id)) {
                continue;
            }
            checked += 1;
            if j.applied >> op & 1 == 1 && j.first >> op & 1 == 0 {
                if w.vouches.iter().any(|v| v.author == cw.author && v.lists.contains(&cw.id)) {
                    own += 1;
                } else {
                    bad += 1;
                }
            }
        }
    }
    (checked, bad, own)
}

/// Removals a trust set may hold (an op removing another holder's edge): (op, commit, victim).
fn trustable(h: &EHist) -> Vec<(usize, usize, usize)> {
    let mut v = vec![];
    let mut op = 0;
    for (i, w) in h.writes.iter().enumerate() {
        for &(x, e) in &w.ops {
            if x != w.author && !w.fin && e.is_none() {
                v.push((op, i, x));
            }
            op += 1;
        }
    }
    v
}

/// Listing: for each trustable removal R, trusted alone: R applies with an empty frontier and no
/// vouch against it, but not as written. Returns (checked, failures, accomplice-shaped failures).
fn listing(w: &World, rules: Rules) -> (u64, u64, u64) {
    let h = &w.h;
    let (mut checked, mut bad, mut accomplice) = (0, 0, 0);
    for (op, r, x) in trustable(h) {
        let rw = &h.writes[r];
        let mut empty = World { h: h.clone(), vouches: w.vouches.iter().filter(|v| v.removal != rw.id).cloned().collect() };
        for c in (0..h.writes.len()).filter(|&c| h.writes[c].author == x && key(&h.writes[c]) < key(rw)) {
            empty.h.recv[c][rw.author] = LATE;
        }
        checked += 1;
        if judge(&empty, rules, 1 << op).active >> op & 1 == 1 && judge(w, rules, 1 << op).active >> op & 1 == 0 {
            let third = h.writes.iter().any(|qw| qw.author != x && qw.author != rw.author && qw.ops.iter().any(|&(y, e)| y == rw.author && edges::auth(e, rw.t).0 < Role::Admin));
            if third {
                accomplice += 1;
            } else {
                bad += 1;
            }
        }
    }
    (checked, bad, accomplice)
}

#[derive(Default)]
pub struct Stats {
    pub worlds: u64,
    pub vouches: u64,
    pub counted: u64,
    pub kept_checked: u64,
    pub kept_fail: u64,
    pub safety_checked: u64,
    pub safety_fail: u64,
    pub safety_own: u64,
    pub listing_checked: u64,
    pub listing_fail: u64,
    pub listing_accomplice: u64,
    pub order_fail: u64,
    pub ex: Vec<(&'static str, World)>,
}

impl crate::Tally for Stats {
    fn merge(&mut self, o: Stats) {
        self.worlds += o.worlds;
        self.vouches += o.vouches;
        self.counted += o.counted;
        self.kept_checked += o.kept_checked;
        self.kept_fail += o.kept_fail;
        self.safety_checked += o.safety_checked;
        self.safety_fail += o.safety_fail;
        self.safety_own += o.safety_own;
        self.listing_checked += o.listing_checked;
        self.listing_fail += o.listing_fail;
        self.listing_accomplice += o.listing_accomplice;
        self.order_fail += o.order_fail;
        for (l, w) in o.ex {
            if !self.ex.iter().any(|(m, x)| *m == l && x.h.writes.len() <= w.h.writes.len()) {
                self.ex.retain(|(m, _)| *m != l);
                self.ex.push((l, w));
            }
        }
    }
}

impl Stats {
    pub fn failures(&self) -> u64 {
        self.kept_fail + self.safety_fail + self.listing_fail + self.order_fail
    }
    pub fn print(&self, name: &str, rules: Rules) {
        println!(
            "{name}: {} worlds, {} vouches, {} counting entries | kept {} checked, FAIL {} | safety {} checked, FAIL {}, by its own author's vouch {} | listing {} checked, FAIL {}, accomplice {} | FAIL order {}",
            self.worlds, self.vouches, self.counted, self.kept_checked, self.kept_fail, self.safety_checked, self.safety_fail, self.safety_own, self.listing_checked, self.listing_fail, self.listing_accomplice, self.order_fail
        );
        for (label, w) in &self.ex {
            let w = crate::shrink::shrink(w.clone(), |x| fails(label, x, rules));
            println!("  smallest {label} example:\n{w}");
        }
    }
}

fn fails(label: &str, w: &World, rules: Rules) -> bool {
    match label {
        "kept" => kept(w, rules, 0).1 > 0,
        "safety" => safety(w, rules, 0).1 > 0,
        "own" => safety(w, rules, 0).2 > 0,
        "listing" => listing(w, rules).1 > 0,
        "accomplice" => listing(w, rules).2 > 0,
        _ => true,
    }
}

/// Every check on one world.
pub fn check(w: &World, rules: Rules, st: &mut Stats, rng: &mut Rng) {
    st.worlds += 1;
    st.vouches += w.vouches.len() as u64;
    let j = judge(w, rules, 0);
    st.counted += j.counted.len() as u64;
    let note = |st: &mut Stats, label: &'static str, bad: bool| {
        if bad && !st.ex.iter().any(|(l, _)| *l == label) {
            st.ex.push((label, w.clone()));
        }
    };
    let (c, b) = kept(w, rules, 0);
    st.kept_checked += c;
    st.kept_fail += b;
    note(st, "kept", b > 0);
    let (c, b, o) = safety(w, rules, 0);
    st.safety_checked += c;
    st.safety_fail += b;
    st.safety_own += o;
    note(st, "safety", b > 0);
    note(st, "own", o > 0);
    let (c, b, a) = listing(w, rules);
    st.listing_checked += c;
    st.listing_fail += b;
    st.listing_accomplice += a;
    note(st, "listing", b > 0);
    note(st, "accomplice", a > 0);
    let p = w.permuted(rng);
    let bad = judge(&p, rules, 0).res != j.res;
    st.order_fail += bad as u64;
    note(st, "order", bad);
}

// ---------- worlds ----------

fn recv_row(rng: &mut Rng, n: usize, author: usize, t: u32) -> Vec<u32> {
    (0..n).map(|v| if v == author { t } else if rng.below(3) == 0 { LATE } else { t + rng.below(4) as u32 }).collect()
}

/// A random world: `edges::random_shaped` (anyone lowers anyone, a third of receipts never),
/// the honest vouches, and in half the worlds one or two forged vouches by a removal's victim
/// or a node that never holds admin, naming any write and listing any of the victim's commits.
pub fn random_world(rng: &mut Rng, rules: Rules) -> World {
    let h = edges::random_shaped(rng, edges::Who::Anyone, edges::Net::Offline);
    let n = h.n();
    let mut w = World { h, vouches: vec![] };
    let mut rows: Vec<Vec<u32>> = vec![];
    // receipts drawn whatever the rules decide, so controls share the base world
    for _ in 0..64 {
        rows.push(recv_row(rng, n, 0, 0));
    }
    let mut k = 0;
    w.derive(rules, |a, t| {
        let mut r: Vec<u32> = rows[k % rows.len()].iter().map(|&x| if x == LATE { LATE } else { x + t }).collect();
        r[a] = t;
        k += 1;
        r
    });
    if rng.below(2) == 0 && !w.h.writes.is_empty() {
        let na = w.h.never_admin();
        for _ in 0..1 + rng.below(2) {
            let r = rng.below(w.h.writes.len());
            let rw = &w.h.writes[r];
            let x = rw.ops[0].0;
            let liars: Vec<usize> = (0..n).filter(|&v| v == x || na[v]).collect();
            let author = liars[rng.below(liars.len())];
            let lists = w.h.writes.iter().filter(|c| c.author == x && rng.below(2) == 0).map(|c| c.id).collect();
            let t = rng.below(12) as u32;
            let recv = recv_row(rng, n, author, t);
            w.vouches.push(Vouch { author, t, removal: rw.id, lists, recv, forged: true });
        }
    }
    w
}

pub fn random(samples: u64, rules: Rules) -> Stats {
    crate::on_every_core(|th, threads, st: &mut Stats| {
        let mut rng = Rng::thread(0x5eed, th);
        for _ in 0..samples / threads as u64 {
            let w = random_world(&mut rng, rules);
            check(&w, rules, st, &mut rng);
        }
    })
}

/// The small family. Nodes: 0 the remover H (admin), 1 X (admin), 2 W (admin), 3 K (no edge).
/// Up to three writes of X from {grant K admin, grant K write, demote W to write, remove H,
/// remove W} at t 1 or 3, each received by H and by W early or never; H removes X at 4, W
/// receiving it at 5 or never; then one of: nothing, H granting W admin at 6, H removing W at 6;
/// then one of: nothing, K granting W admin at 7, K removing W at 7. The honest vouches, received
/// by every node a tick after they are written or never by H.
pub fn exhaustive(rules: Rules, stride: usize) -> Stats {
    let full = Some(Edge { role: Role::Admin, until: NEVER, invite: Role::Admin });
    let write = Some(Edge { role: Role::Write, until: NEVER, invite: Role::None });
    let genesis = vec![full, full, full, None];
    let xops: Vec<(usize, Option<Edge>)> = vec![(3, full), (3, write), (2, write), (0, None), (2, None)];
    let mut xmenu = vec![];
    for &op in &xops {
        for t in [1u32, 3] {
            for rh in [t, LATE] {
                for rw in [t, LATE] {
                    xmenu.push((op, t, rh, rw));
                }
            }
        }
    }
    let mut sets: Vec<Vec<usize>> = vec![vec![]];
    for a in 0..xmenu.len() {
        sets.push(vec![a]);
        for b in a + 1..xmenu.len() {
            sets.push(vec![a, b]);
            for c in b + 1..xmenu.len() {
                sets.push(vec![a, b, c]);
            }
        }
    }
    let total = sets.len() * 2 * 3 * 3 * 2;
    crate::on_every_core(|th, threads, st: &mut Stats| {
        let mut rng = Rng::thread(0x5eed, th);
        let mut i = th * stride;
        while i < total {
            let mut z = i;
            i += threads * stride;
            let set = &sets[z % sets.len()];
            z /= sets.len();
            let (wr, hw, kw, hv) = (z % 2, z / 2 % 3, z / 6 % 3, z / 18 % 2);
            let mut h = EHist { genesis: genesis.clone(), writes: vec![], recv: vec![], lists: Lists::default() };
            let mut push = |author: usize, op: (usize, Option<Edge>), t: u32, r: [u32; 4]| {
                let id = h.writes.len() as u32;
                let mut r = r.to_vec();
                r[author] = t;
                h.writes.push(EWrite { author, t, id, ops: vec![op], fin: false });
                h.recv.push(r);
            };
            for &a in set {
                let (op, t, rh, rw) = xmenu[a];
                // K holds the grant naming it; others but H and W never receive X's writes
                let rk = if op.0 == 3 { t } else { LATE };
                push(1, op, t, [rh, t, rw, rk]);
            }
            push(0, (1, None), 4, [4, LATE, if wr == 0 { 5 } else { LATE }, 4]);
            match hw {
                1 => push(0, (2, full), 6, [6, LATE, 6, 6]),
                2 => push(0, (2, None), 6, [6, LATE, 6, 6]),
                _ => {}
            }
            match kw {
                1 => push(3, (2, full), 7, [7, LATE, 7, 7]),
                2 => push(3, (2, None), 7, [7, LATE, 7, 7]),
                _ => {}
            }
            let mut w = World { h, vouches: vec![] };
            w.derive(rules, |a, t| {
                let mut r = vec![t + 1; 4];
                if hv == 1 {
                    r[0] = LATE;
                }
                r[a] = t;
                r
            });
            check(&w, rules, st, &mut rng);
        }
    })
}

/// Search driver: `vouches`, `vouches-exh` and the controls (module doc). Failures found.
pub fn run(samples: u64, mode: &str) -> u64 {
    let exh = mode.starts_with("vouches-exh");
    let rules = match mode.trim_start_matches("vouches").trim_start_matches("-exh") {
        "-off" => Rules { vouches: false, ..FIXED },
        "-no-rewrite" => Rules { rewrite: false, ..FIXED },
        "-no-absent" => Rules { absent: false, ..FIXED },
        _ => FIXED,
    };
    let st = if exh { exhaustive(rules, 1) } else { random(samples, rules) };
    st.print(mode, rules);
    st.failures()
}

// ---------- trace ----------

impl std::fmt::Display for World {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "{}", self.h)?;
        for v in &self.vouches {
            let forged = if v.forged { " FORGED" } else { "" };
            writeln!(f, "    vouch by {} at t={} against removal {} listing {:?}{forged} | {}", v.author, v.t, v.removal, v.lists, crate::fmt_recv(&v.recv, v.author))?;
        }
        Ok(())
    }
}

/// Smaller worlds keep the forged vouches and write the honest ones again (under `FIXED`'s
/// writing, received by every node a tick after), so a shrunk world stays honest.
impl crate::shrink::Shrink for World {
    fn smaller(&self) -> Vec<World> {
        let forged: Vec<Vouch> = self.vouches.iter().filter(|v| v.forged).cloned().collect();
        let mut hs = vec![];
        let mut out = vec![];
        for i in 0..forged.len() {
            out.push(World { h: self.h.clone(), vouches: crate::shrink::without(&forged, i) });
        }
        for i in 0..self.h.writes.len() {
            let mut h = self.h.clone();
            h.writes.remove(i);
            h.recv.remove(i);
            hs.push(h);
        }
        for i in 0..self.h.writes.len() {
            for m in (0..self.h.n()).filter(|&m| m != self.h.writes[i].author && self.h.recv[i][m] < LATE) {
                let mut h = self.h.clone();
                h.recv[i][m] = LATE;
                hs.push(h);
            }
        }
        for h in hs {
            out.push(World { h, vouches: forged.clone() });
        }
        for w in &mut out {
            let n = w.h.n();
            w.derive(FIXED, |a, t| {
                let mut r = vec![t + 1; n];
                r[a] = t;
                r
            });
        }
        out
    }
}

#[cfg(test)]
mod tests;
