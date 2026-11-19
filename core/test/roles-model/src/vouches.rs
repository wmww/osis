//! Vouches (notes/account-membership-design.md §4, Role writes: vouched for like content;
//! notes/redesign-plan.md S3 brief 2) under today's walk: authority as `edges` gives it (one
//! thing, every node a key actor, a frontier is what its demoter received), with trust sets
//! (`trust`). Not the stated-path design (`paths`). Of what no list keeps only today's first half
//! is here (spec/permissions.md §5.1 step 4, R never demotes its own author); the rest needs a
//! stated path (notes/redesign-plan.md A1; M2 brief 2 is to model it in `paths`).
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
//! frontier (`EHist::extra`), in the audit and in a trusted write's seeds alike: that is the
//! timeline. Nothing judges a vouch again in it.
//!
//! **Honest writing**: each node W but X and R's author that received R writes, at receipt and
//! (`Rules::rewrite`) at every later time it newly holds the authority for a listed commit, one
//! vouch listing X's commits before R it had received by R's `ts` that R's author had not.
//! `FIXED` is the **idealised writing**: whether W holds that authority is read off the canonical
//! first walk of the whole history, which no node can compute. With `Rules::held` W reads it off
//! its own walk of what it holds then (`EHist::held_by`), as a node would; kept then fails where
//! W never received a lowering of its own edge that the remover's list keeps: its vouch at
//! receipt does not count and its view never shows it newly holding the right
//! (`a_witness_unaware_of_its_own_demotion_never_vouches_again`). `Rules::state` is the
//! state-based writing from the held set: every commit reaches every node by `SYNC` (eventual
//! delivery), and W keeps each listed commit it could write itself, in its own current walk,
//! named by a counting vouch of its own, writing one whenever one is not. It holds kept and stays
//! made in the family; two of 1,000,000 random worlds fail, the one traced where W held the
//! authority as it applied R only in the canonical walk (a commit it had not yet received) and
//! lost it, by its own later write, before receiving that commit: kept's "as it applies R" asks
//! more than any node writing from its held set can know (README.md, Vouches).
//!
//! Properties (`check`), at the judgment of the whole held set under the empty trust set and
//! under each removal trusted alone:
//! - **kept**: an op of X that an honest node other than X and R's author received by R's `ts`,
//!   where it holds the authority for it in the first walk as it applies R (and no node that had
//!   not received its vouch written then later lowers its edge below it) or at the end
//!   (`witnessed`), is kept: every node ends with the authority it has where R's frontier names
//!   every such op (the reference: `EHist::extra` set to every such entry). Compared on final
//!   authority, not op by op: keeping one witnessed op may leave a later one of X without effect;
//! - **kept as promised** (`kept_end`, under `Rules::state`): the spec's form of kept
//!   (spec/permissions.md §5.1 What vouches keep): `witnessed` reduced to its end clause, the
//!   reference's entries joined with the judgment's counting ones;
//! - **stays made**: op by op for X's lowerings: a lowering of another node's edge by X that
//!   every removal of X after it lists or has witnessed, and that applies in the reference,
//!   applies in the judgment;
//! - **safety**: an op of X no node but X received before a removal of X after it applied in the
//!   second walk (unwitnessed) never applies in the second walk where it does not in the first,
//!   with forged vouches by X and by nodes that never hold admin (one listing a backdated commit
//!   of X); finalizes (never audited, they remove only ended edges), ops on their author's own
//!   edge but raises, ops on a voucher's own edge it names, and ops that also apply with only
//!   the entries whose voucher is not the op's author and could write the commit itself at its
//!   vouch's position (the bargain: a vouch is its author's word, as an addendum is) aside. Ops named by a vouch of their own author (X still holding the authority
//!   after R, by an invite) are counted apart: "nobody vouches for its own signer's commit"
//!   closes them and lands with stated paths (notes/redesign-plan.md A1;
//!   `a_demoted_node_vouches_for_its_own_backdated_invite`);
//! - **listing**: a trusted removal R by A of X (an op removing X's edge) that applies with an
//!   empty frontier and no vouch against it also applies with A's honest frontier and its
//!   vouches. Set apart (the first two read off the generated world): `lowered`, X writing before R an
//!   edge R may rest on (`above`: A's, and its grantors', closed) to a value without admin at R's
//!   `ts`, in a commit A received before R or a witness's vouch would name (`wanted`): listing it
//!   keeps it and voids R, which only the rest of what no list keeps, on a stated path, closes
//!   (`a_removal_listing_the_thiefs_removal_of_its_author_is_void`); `accomplice`, a third node
//!   writing such an edge so at any time (notes/disputes.md, Hole: an accomplice); `revived`, the
//!   empty list's R applying where A's own leaving, applied with the honest list, is dropped (by an
//!   audit whose removal ends void: D only grows within a walk, spec/permissions.md §5.1 step 5),
//!   where the honest result is the right one;
//! - **alike**: one result for every input order.
//!
//! Negative controls (`Rules`): `vouches: false` fails kept and stays made; `rewrite: false`
//! fails kept (a node granted the authority after R). Search: `roles-model -- N vouches`
//! (random), `-- 0 vouches-exh` (the small family); controls `vouches-off`, `vouches-no-rewrite`
//! (random) and `vouches-exh-off`, `vouches-exh-no-rewrite` (the family); `vouches-held` and
//! `vouches-exh-held` the writing from each node's held set, which fails kept
//! (`a_witness_unaware_of_its_own_demotion_never_vouches_again`); `vouches-state`,
//! `vouches-exh-state` the state-based writing. Random worlds are a function of their index.

use crate::edges::{self, auth, takes_from, Attr, EHist, EOut, EWrite, Edge, NEVER};
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
    /// Honest nodes read their authority off their own held set; false is the idealised writing
    /// (module doc, Honest writing).
    pub held: bool,
    /// The state-based writing from each node's held set, with eventual delivery (`SYNC`): an
    /// honest node holding the right keeps, per removal it holds, a vouch of its own that counts
    /// in its own current walk, writing one whenever none does.
    pub state: bool,
}

pub const FIXED: Rules = Rules { vouches: true, rewrite: true, held: false, state: false };

/// Under `Rules::state`, when every commit some node besides its author received has reached
/// every node: after every write's `ts`, before `END`.
const SYNC: u32 = 30;

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

/// W's own commit with `c`'s ops at time `t` would apply against `edges`.
fn could_write(h: &EHist, w: usize, c: &EWrite, t: u32, edges: &[Option<Edge>]) -> bool {
    h.would_apply(&EWrite { author: w, t, id: 0, ops: c.ops.clone(), fin: c.fin }, edges)
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
            if !vic.contains(&cw.author) || key(cw) >= key(rw) || !could_write(h, v.author, cw, v.t, &at) {
                continue;
            }
            if later.iter().any(|&q| !could_write(h, v.author, cw, h.writes[q].t, &edges_after(h, o, q))) {
                continue;
            }
            out.push((v.removal, cid));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn with_extra(h: &EHist, extra: Vec<(u32, u32)>) -> EHist {
    let mut h = h.clone();
    h.extra = extra;
    h
}

/// The first walk under `trust` and its settled `EOut`.
fn first_walk(w: &World, trust: u64) -> (EHist, trust::Side<Res>, EOut) {
    let h1 = with_extra(&w.h, vec![]);
    let s1 = trust::side(&h1, trust);
    let o1 = h1.eval_from(true, s1.d0).0;
    (h1, s1, o1)
}

/// The timeline of `w` under `rules` and trust set `trust` (bits over ops).
pub fn judge(w: &World, rules: Rules, trust: u64) -> Judged {
    let (h1, s1, o1) = first_walk(w, trust);
    let counted = if rules.vouches { counting(&h1, &o1, &w.vouches) } else { vec![] };
    let h2 = with_extra(&w.h, counted.clone());
    let s2 = trust::side(&h2, trust);
    let o2 = h2.eval_from(true, s2.d0).0;
    Judged { res: s2.res, first: s1.applied, applied: s2.applied, active: s2.active, counted, h2, o2 }
}

impl World {
    /// The world with the honest vouches (module doc, Honest writing) added; receipts of each
    /// from `recv(author, t)`.
    pub fn derive(&mut self, rules: Rules, mut recv: impl FnMut(usize, u32) -> Vec<u32>) {
        if rules.state {
            // eventual delivery: every commit of the judged held set reaches every node by `SYNC`
            self.h.recv.iter_mut().flatten().for_each(|x| *x = (*x).min(SYNC));
        }
        let h = &self.h;
        let (h1, _, o1) = first_walk(self, 0);
        // whether `wn` holds the authority for commit `c` at `t`, as it reads it
        let holds = |wn: usize, c: &EWrite, t: u32| {
            if rules.held {
                let mine = h1.held_by(wn, t);
                let o = mine.eval(true);
                could_write(&mine, wn, c, t, &mine.edges_before(&o, (t, 0, 0)))
            } else {
                could_write(&h1, wn, c, t, &h1.edges_before(&o1, (t, 0, 0)))
            }
        };
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
                    if rules.state {
                        // keep each listed commit it could write named by a counting vouch of its own, in
                        // its own current walk
                        let mut mine: Vec<Vouch> = vec![];
                        for t in first..END {
                            let view = h1.held_by(wn, t);
                            let o = view.eval(true);
                            let counted = counting(&view, &o, &mine);
                            let at = view.edges_before(&o, (t, 0, 0));
                            if lists.iter().any(|&c| !counted.contains(&(rw.id, h.writes[c].id)) && could_write(&view, wn, &h.writes[c], t, &at)) {
                                mine.push(Vouch { author: wn, t, removal: rw.id, lists: lists.iter().map(|&c| h.writes[c].id).collect(), recv: recv(wn, t), forged: false });
                            }
                        }
                        out.extend(mine);
                        continue;
                    }
                    let mut held_before: Vec<bool> = vec![false; lists.len()];
                    for t in first..END {
                        let held: Vec<bool> = lists.iter().map(|&c| holds(wn, &h.writes[c], t)).collect();
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

    fn honest(&self) -> World {
        World { h: self.h.clone(), vouches: self.vouches.iter().filter(|v| !v.forged).cloned().collect() }
    }
}

// ---------- properties ----------

/// The ops of commit `c` (`base` from any walk of the history).
fn ops_of(o: &EOut, c: usize) -> std::ops::Range<usize> {
    o.base[c]..o.base[c + 1]
}

/// Commit `c` of R's victim is witnessed for removal `r` (module doc, kept): by an honest node
/// other than its author and R's author that received R and `c` by R's `ts`, holding the
/// authority for `c` in the first walk (`h1`, `o1`) as it applies R, not lowered below it later
/// by a node that had not received its vouch written then, or at the end.
fn witnessed(w: &World, h1: &EHist, o1: &EOut, r: usize, c: usize) -> bool {
    let h = &w.h;
    let (rw, cw) = (&h.writes[r], &h.writes[c]);
    let fin = h1.edges_before(o1, (END, 0, 0));
    (0..h.n()).any(|wn| {
        if wn == cw.author || wn == rw.author || h.recv[r][wn] >= LATE || h.recv[c][wn] >= rw.t {
            return false;
        }
        let first = h.recv[r][wn].max(rw.t) + 1;
        let v = w.vouches.iter().find(|v| v.author == wn && v.removal == rw.id && v.t == first);
        let removed = (0..h.writes.len()).any(|q| {
            let qw = &h.writes[q];
            qw.t >= first && qw.author != wn && v.map_or(true, |v| v.recv[qw.author] >= qw.t) && victims(h1, o1, q).contains(&wn) && !could_write(h1, wn, cw, qw.t, &edges_after(h1, o1, q))
        });
        let then = !removed && could_write(h1, wn, cw, first, &h1.edges_before(o1, (first, 0, 0)));
        then || could_write(h1, wn, cw, END, &fin)
    })
}

/// The reference frontiers: every witnessed (removal ID, commit ID) of the honest world.
fn wanted(w: &World, trust: u64) -> Vec<(u32, u32)> {
    let h = &w.h;
    let (h1, _, o1) = first_walk(w, trust);
    let mut extra = vec![];
    for r in 0..h.writes.len() {
        let rw = &h.writes[r];
        for x in victims(&h1, &o1, r) {
            for c in (0..h.writes.len()).filter(|&c| h.writes[c].author == x && key(&h.writes[c]) < key(rw)) {
                if witnessed(w, &h1, &o1, r, c) {
                    extra.push((rw.id, h.writes[c].id));
                }
            }
        }
    }
    extra
}

/// Kept: the judgment gives every node the authority the reference does. Returns (entries the
/// reference lists, failing worlds).
fn kept(w: &World, rules: Rules, trust: u64) -> (u64, u64) {
    let w = &w.honest();
    let extra = wanted(w, trust);
    if extra.is_empty() {
        return (0, 0);
    }
    let reference = trust::side(&with_extra(&w.h, extra.clone()), trust);
    let j = judge(w, rules, trust);
    (extra.len() as u64, (reference.res.0 != j.res.0) as u64)
}

/// The reference of what vouches keep in the spec's form (spec/permissions.md §5.1 Vouches, What
/// vouches keep): beside the counting entries, each commit c of R's victim X ordered before R
/// that R's frontier does not list and that an honest node other than X and R's author, holding
/// R, received by R's `ts` and could write at the end of the first walk (`witnessed` reduced to
/// its end clause). Promised once every node holds every commit and owes no vouch: checked under
/// `Rules::state`.
pub fn kept_end_extra(w: &World, rules: Rules, trust: u64) -> Vec<(u32, u32)> {
    let w = &w.honest();
    let h = &w.h;
    let (h1, _, o1) = first_walk(w, trust);
    let fin = h1.edges_before(&o1, (END, 0, 0));
    let mut extra = judge(w, rules, trust).counted;
    for (r, rw) in h.writes.iter().enumerate() {
        for x in victims(&h1, &o1, r) {
            for (c, cw) in h.writes.iter().enumerate().filter(|(_, cw)| cw.author == x && key(cw) < key(rw)) {
                if h.recv[c][rw.author] < rw.t || extra.contains(&(rw.id, cw.id)) {
                    continue;
                }
                if (0..h.n()).any(|wn| wn != x && wn != rw.author && h.recv[r][wn] < LATE && h.recv[c][wn] < rw.t && could_write(&h1, wn, cw, END, &fin)) {
                    extra.push((rw.id, cw.id));
                }
            }
        }
    }
    extra.sort();
    extra.dedup();
    extra
}

/// What vouches keep, as the spec promises it (`kept_end_extra`): the judgment gives every node
/// the authority the reference does. Returns (entries the reference lists, failing worlds).
fn kept_end(w: &World, rules: Rules, trust: u64) -> (u64, u64) {
    let extra = kept_end_extra(w, rules, trust);
    let j = judge(&w.honest(), rules, trust);
    if extra.len() == j.counted.len() {
        // the counting entries alone: the reference is the judgment
        return (extra.len() as u64, 0);
    }
    let n = extra.len() as u64;
    let reference = trust::side(&with_extra(&w.h, extra), trust);
    (n, (reference.res.0 != j.res.0) as u64)
}

/// Stays made: X's lowerings of others' edges that every removal of X after them lists or has
/// witnessed, applied in the reference, apply in the judgment. Returns (checked, failures).
fn stays_made(w: &World, rules: Rules, trust: u64) -> (u64, u64) {
    let w = &w.honest();
    let h = &w.h;
    let extra = wanted(w, trust);
    let (h1, _, o1) = first_walk(w, trust);
    let reference = trust::side(&with_extra(h, extra.clone()), trust);
    let j = judge(w, rules, trust);
    let (mut checked, mut bad) = (0, 0);
    for (c, cw) in h.writes.iter().enumerate() {
        let after: Vec<usize> = (0..h.writes.len()).filter(|&r| key(&h.writes[r]) > key(cw) && victims(&h1, &o1, r).contains(&cw.author)).collect();
        let covered = after.iter().all(|&r| {
            let rw = &h.writes[r];
            h.recv[c][rw.author] < rw.t || extra.contains(&(rw.id, cw.id))
        });
        if after.is_empty() || !covered || cw.fin {
            continue;
        }
        for (k, op) in ops_of(&o1, c).enumerate() {
            let (y, e) = cw.ops[k];
            if y == cw.author || !takes_from(e, h.prior(c, y)) || reference.applied >> op & 1 == 0 {
                continue;
            }
            checked += 1;
            bad += (j.applied >> op & 1 == 0) as u64;
        }
    }
    (checked, bad)
}

/// Safety: unwitnessed ops of a node removed in the second walk newly applied by vouches.
/// (checked, failures, of those named by a vouch of their own author)
fn safety(w: &World, rules: Rules, trust: u64) -> (u64, u64, u64) {
    let h = &w.h;
    let (h1, _, o1) = first_walk(w, trust);
    // the bargain: only the entries whose voucher is not the commit's author and could write the
    // commit itself at the vouch's position; an op applying with those alone is set aside
    let idx = |id: u32| h.writes.iter().position(|cw| cw.id == id);
    let fair = World {
        h: h.clone(),
        vouches: w
            .vouches
            .iter()
            .map(|v| {
                let at = h1.edges_before(&o1, (v.t, 0, 0));
                let lists = v.lists.iter().copied().filter(|&id| idx(id).is_some_and(|c| h.writes[c].author != v.author && could_write(&h1, v.author, &h.writes[c], v.t, &at))).collect();
                Vouch { lists, ..v.clone() }
            })
            .collect(),
    };
    let bargain = judge(&fair, rules, trust).applied;
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
            if j.applied >> op & 1 == 1 && j.first >> op & 1 == 0 && bargain >> op & 1 == 0 {
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

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Listing {
    pub checked: u64,
    pub fail: u64,
    /// X writing, before R, an edge R may rest on (`above`) below admin: the gap stated paths close.
    pub lowered: u64,
    /// A third node writing such an edge below admin.
    pub accomplice: u64,
    /// R applies with an empty list only where an op of its own author applied as written is
    /// dropped: the empty baseline revives its author (an audit's cause outlives the write that
    /// caused it, so a removal by X that ends void still drops A's own leaving).
    pub revived: u64,
}

/// The holders a removal `r`'s authority may rest on: its author, and the author of every commit
/// ordered before it giving one of them admin at its `ts`, closed. Static, so broad: it sets
/// worlds aside, never decides one.
fn above(h: &EHist, r: usize) -> Vec<usize> {
    let rw = &h.writes[r];
    let mut g = vec![rw.author];
    loop {
        let more: Vec<usize> = h.writes.iter().filter(|w| key(w) < key(rw) && !g.contains(&w.author) && w.ops.iter().any(|&(y, e)| g.contains(&y) && auth(e, rw.t).0 == Role::Admin)).map(|w| w.author).collect();
        if more.is_empty() {
            return g;
        }
        g.extend(more);
        g.sort();
        g.dedup();
    }
}

/// Listing: for each trustable removal R, trusted alone: R applies with an empty frontier and no
/// vouch against it, but not as written (module doc).
fn listing(w: &World, rules: Rules) -> Listing {
    let h = &w.h;
    let mut l = Listing::default();
    for (op, r, x) in trustable(h) {
        let rw = &h.writes[r];
        let mut empty = World { h: h.clone(), vouches: w.vouches.iter().filter(|v| v.removal != rw.id).cloned().collect() };
        for c in (0..h.writes.len()).filter(|&c| h.writes[c].author == x && key(&h.writes[c]) < key(rw)) {
            empty.h.recv[c][rw.author] = LATE;
        }
        l.checked += 1;
        let (je, jw) = (judge(&empty, rules, 1 << op), judge(w, rules, 1 << op));
        if je.active >> op & 1 == 1 && jw.active >> op & 1 == 0 {
            let up = above(h, r);
            let below = |cw: &EWrite| cw.ops.iter().any(|&(y, e)| up.contains(&y) && auth(e, rw.t).0 < Role::Admin);
            // what A's honest list keeps: received by A before R, or witnessed (`wanted`)
            let honest = wanted(&w.honest(), 1 << op);
            let kept = |c: usize| h.recv[c][rw.author] < rw.t || honest.contains(&(rw.id, h.writes[c].id));
            // A's own leavings (ops on its own edge taking from it)
            let leaving = |a: u64| (0..h.writes.len()).filter(|&c| h.writes[c].author == rw.author).flat_map(|c| ops_of(&jw.o2, c).zip(&h.writes[c].ops).filter(move |&(_, &(y, e))| y == rw.author && takes_from(e, h.prior(c, y))).map(|(q, _)| q)).fold(0u64, |m, q| m | (a & 1 << q));
            if leaving(jw.applied) & !leaving(je.applied) != 0 {
                l.revived += 1;
            } else if (0..h.writes.len()).any(|c| h.writes[c].author == x && key(&h.writes[c]) < key(rw) && below(&h.writes[c]) && kept(c)) {
                l.lowered += 1;
            } else if h.writes.iter().any(|cw| cw.author != x && cw.author != rw.author && below(cw)) {
                l.accomplice += 1;
            } else {
                l.fail += 1;
            }
        }
    }
    l
}

#[derive(Default)]
pub struct Stats {
    pub worlds: u64,
    pub vouches: u64,
    pub counted: u64,
    pub kept_checked: u64,
    pub kept_fail: u64,
    /// `kept_end`, under `Rules::state` only.
    pub kept_end_checked: u64,
    pub kept_end_fail: u64,
    pub made_checked: u64,
    pub made_fail: u64,
    pub safety_checked: u64,
    pub safety_fail: u64,
    pub safety_own: u64,
    pub listing: Listing,
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
        self.kept_end_checked += o.kept_end_checked;
        self.kept_end_fail += o.kept_end_fail;
        self.made_checked += o.made_checked;
        self.made_fail += o.made_fail;
        self.safety_checked += o.safety_checked;
        self.safety_fail += o.safety_fail;
        self.safety_own += o.safety_own;
        self.listing.checked += o.listing.checked;
        self.listing.fail += o.listing.fail;
        self.listing.lowered += o.listing.lowered;
        self.listing.accomplice += o.listing.accomplice;
        self.listing.revived += o.listing.revived;
        self.order_fail += o.order_fail;
        for (l, w) in o.ex {
            if !self.ex.iter().any(|(m, x)| *m == l && x.h.writes.len() <= w.h.writes.len()) {
                self.ex.retain(|(m, _)| *m != l);
                self.ex.push((l, w));
            }
        }
    }
}

/// The labels of `Stats::ex` that `Stats::failures` counts; the rest are set-asides.
const FAILURES: [&str; 6] = ["kept", "kept_end", "made", "safety", "listing", "order"];

impl Stats {
    pub fn failures(&self) -> u64 {
        self.kept_fail + self.kept_end_fail + self.made_fail + self.safety_fail + self.listing.fail + self.order_fail
    }
    pub fn print(&self, name: &str, rules: Rules) {
        let l = &self.listing;
        println!(
            "{name}: {} worlds, {} vouches, {} counting entries | kept {} checked, FAIL {} | kept as promised {} checked, FAIL {} | stays made {} checked, FAIL {} | safety {} checked, FAIL {}, by its own author's vouch {} | listing {} checked, FAIL {}, X lowered A {}, accomplice {}, author revived {} | FAIL order {}",
            self.worlds, self.vouches, self.counted, self.kept_checked, self.kept_fail, self.kept_end_checked, self.kept_end_fail, self.made_checked, self.made_fail, self.safety_checked, self.safety_fail, self.safety_own, l.checked, l.fail, l.lowered, l.accomplice, l.revived, self.order_fail
        );
        // shrinking costs minutes on one core: failures only; a set-aside example prints as found
        for (label, w) in &self.ex {
            if FAILURES.contains(label) {
                println!("  smallest {label} example:\n{}", shrunk(w, label, rules));
            } else {
                println!("  {label} example (set aside, not shrunk):\n{w}");
            }
        }
    }
}

/// The smallest world reachable from `w` that still fails `label`'s property under `rules`, its
/// honest vouches written by `rules` (`Shrinking`), so it is a world the search could have made.
pub fn shrunk(w: &World, label: &str, rules: Rules) -> World {
    crate::shrink::shrink(Shrinking { w: w.clone(), rules }, |x| fails(label, &x.w, rules)).w
}

fn fails(label: &str, w: &World, rules: Rules) -> bool {
    match label {
        "kept" => kept(w, rules, 0).1 > 0,
        "kept_end" => kept_end(w, rules, 0).1 > 0,
        "made" => stays_made(w, rules, 0).1 > 0,
        "safety" => safety(w, rules, 0).1 > 0,
        "own" => safety(w, rules, 0).2 > 0,
        "listing" => listing(w, rules).fail > 0,
        "lowered" => listing(w, rules).lowered > 0,
        "accomplice" => listing(w, rules).accomplice > 0,
        "revived" => listing(w, rules).revived > 0,
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
    if rules.state {
        let (c, b) = kept_end(w, rules, 0);
        st.kept_end_checked += c;
        st.kept_end_fail += b;
        note(st, "kept_end", b > 0);
    }
    let (c, b) = stays_made(w, rules, 0);
    st.made_checked += c;
    st.made_fail += b;
    note(st, "made", b > 0);
    let (c, b, o) = safety(w, rules, 0);
    st.safety_checked += c;
    st.safety_fail += b;
    st.safety_own += o;
    note(st, "safety", b > 0);
    note(st, "own", o > 0);
    let l = listing(w, rules);
    note(st, "listing", l.fail > 0);
    note(st, "lowered", l.lowered > 0);
    note(st, "accomplice", l.accomplice > 0);
    note(st, "revived", l.revived > 0);
    st.listing.checked += l.checked;
    st.listing.fail += l.fail;
    st.listing.lowered += l.lowered;
    st.listing.accomplice += l.accomplice;
    st.listing.revived += l.revived;
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
/// the honest vouches, and in three worlds of four the thief's attack: one commit of a removal's
/// victim ordered before it received by no other node (backdated), and one or two forged vouches
/// by the victim or a node that never holds admin, naming a removal that applies in the first
/// walk (any write where none does) and listing the backdated commit and any of the victim's.
pub fn random_world(rng: &mut Rng, rules: Rules) -> World {
    let mut h = edges::random_shaped(rng, edges::Who::Anyone, edges::Net::Offline);
    let n = h.n();
    // removals applying in the first walk, else any write
    let o1 = h.eval(true);
    let mut named: Vec<(usize, usize)> = (0..h.writes.len()).flat_map(|r| victims(&h, &o1, r).into_iter().map(move |x| (r, x))).collect();
    if named.is_empty() {
        named = (0..h.writes.len()).map(|r| (r, h.writes[r].ops[0].0)).collect();
    }
    let attack = rng.below(4) > 0 && !named.is_empty();
    let mut hidden = None;
    if attack {
        let (r, x) = named[rng.below(named.len())];
        let before: Vec<usize> = (0..h.writes.len()).filter(|&c| h.writes[c].author == x && key(&h.writes[c]) < key(&h.writes[r])).collect();
        if !before.is_empty() {
            let c = before[rng.below(before.len())];
            for v in (0..n).filter(|&v| v != x) {
                h.recv[c][v] = LATE;
            }
            hidden = Some((r, x, h.writes[c].id));
        }
    }
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
    if attack {
        let na = w.h.never_admin();
        for i in 0..1 + rng.below(2) {
            let (r, x, c) = match hidden {
                Some(rxc) if i == 0 => rxc,
                _ => {
                    let (r, x) = named[rng.below(named.len())];
                    (r, x, u32::MAX)
                }
            };
            let liars: Vec<usize> = (0..n).filter(|&v| v == x || na[v]).collect();
            let author = liars[rng.below(liars.len())];
            let lists = w.h.writes.iter().filter(|cw| cw.author == x && (cw.id == c || rng.below(2) == 0)).map(|cw| cw.id).collect();
            let t = w.h.writes[r].t + 1 + rng.below(4) as u32;
            let recv = recv_row(rng, n, author, t);
            w.vouches.push(Vouch { author, t, removal: w.h.writes[r].id, lists, recv, forged: true });
        }
    }
    w
}

pub fn random(samples: u64, rules: Rules) -> Stats {
    crate::each_world(0x5eed, 0..samples, |rng, st: &mut Stats| {
        let w = random_world(rng, rules);
        check(&w, rules, st, rng);
    })
}

/// The small family. Nodes: 0 the remover H (admin), 1 X (admin), 2 W (admin), 3 K (no edge).
/// Up to three writes of X from {grant K admin, grant K write, demote W to write, remove H,
/// remove W} at t 1 or 3, each received by H and by W early or never; H removes X at 4, W
/// receiving it at 5 or never; then one of: nothing, H granting W admin at 6, H removing W at 6;
/// then one of: nothing, K granting W admin at 7, K removing W at 7. The honest vouches, received
/// by every node a tick after they are written or never by H.
pub fn exhaustive(rules: Rules, stride: usize) -> Stats {
    let total = family_size();
    crate::on_every_core(|th, threads, st: &mut Stats| {
        let mut i = th * stride;
        while i < total {
            let mut rng = Rng::thread(0x5eed, i);
            let w = family_world(rules, i);
            i += threads * stride;
            check(&w, rules, st, &mut rng);
        }
    })
}

/// X's write menu of the small family (`exhaustive`): (op, t, H's receipt, W's receipt).
fn family_menu() -> Vec<((usize, Option<Edge>), u32, u32, u32)> {
    let full = Some(Edge { role: Role::Admin, until: NEVER, invite: Role::Admin });
    let write = Some(Edge { role: Role::Write, until: NEVER, invite: Role::None });
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
    xmenu
}

/// The number of worlds of the small family (`family_world`).
pub fn family_size() -> usize {
    let m = family_menu().len();
    (1 + m + m * (m - 1) / 2 + m * (m - 1) * (m - 2) / 6) * 2 * 3 * 3 * 2
}

/// World `i` of the small family (`exhaustive`), `i` below `family_size`, its honest vouches
/// written by `rules`.
pub fn family_world(rules: Rules, i: usize) -> World {
    let full = Some(Edge { role: Role::Admin, until: NEVER, invite: Role::Admin });
    let genesis = vec![full, full, full, None];
    let xmenu = family_menu();
    // the subsets of up to three menu entries, in a fixed order: index `z % sets` decoded
    let m = xmenu.len();
    let sets = 1 + m + m * (m - 1) / 2 + m * (m - 1) * (m - 2) / 6;
    let mut k = i % sets;
    let mut z = i / sets;
    let set: Vec<usize> = 'found: {
        if k == 0 {
            break 'found vec![];
        }
        k -= 1;
        for a in 0..m {
            if k == 0 {
                break 'found vec![a];
            }
            k -= 1;
            for b in a + 1..m {
                if k == 0 {
                    break 'found vec![a, b];
                }
                k -= 1;
                let rest = m - b - 1;
                if k < rest {
                    break 'found vec![a, b, b + 1 + k];
                }
                k -= rest;
            }
        }
        unreachable!("index below the family size")
    };
    let (wr, hw, kw, hv) = (z % 2, z / 2 % 3, z / 6 % 3, z / 18 % 2);
    z /= 36;
    debug_assert_eq!(z, 0, "index below the family size");
    let mut h = EHist { genesis, writes: vec![], recv: vec![], extra: vec![] };
    let mut push = |author: usize, op: (usize, Option<Edge>), t: u32, r: [u32; 4]| {
        let id = h.writes.len() as u32;
        let mut r = r.to_vec();
        r[author] = t;
        h.writes.push(EWrite { author, t, id, ops: vec![op], fin: false });
        h.recv.push(r);
    };
    for &a in &set {
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
    w
}

/// Search driver: `vouches`, `vouches-exh` and the controls (module doc). Failures found.
pub fn run(samples: u64, mode: &str) -> u64 {
    let exh = mode.starts_with("vouches-exh");
    let rules = match mode.trim_start_matches("vouches").trim_start_matches("-exh") {
        "-off" => Rules { vouches: false, ..FIXED },
        "-no-rewrite" => Rules { rewrite: false, ..FIXED },
        "-held" => Rules { held: true, ..FIXED },
        "-state" => Rules { state: true, ..FIXED },
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

/// A world being shrunk under the rules it was searched with.
pub struct Shrinking {
    pub w: World,
    pub rules: Rules,
}

impl World {
    /// The world's history and forged vouches with the honest vouches `rules` writes, received by
    /// every node a tick after.
    pub fn rederived(&self, rules: Rules) -> World {
        let mut w = World { h: self.h.clone(), vouches: self.vouches.iter().filter(|v| v.forged).cloned().collect() };
        let n = w.h.n();
        w.derive(rules, |a, t| {
            let mut r = vec![t + 1; n];
            r[a] = t;
            r
        });
        w
    }
}

/// Smaller worlds keep the forged vouches and write the honest ones again under the searched
/// rules (`World::rederived`), so a shrunk world stays honest under them.
impl crate::shrink::Shrink for Shrinking {
    fn smaller(&self) -> Vec<Shrinking> {
        let (w, rules) = (&self.w, self.rules);
        let forged: Vec<Vouch> = w.vouches.iter().filter(|v| v.forged).cloned().collect();
        let mut out = vec![];
        for i in 0..forged.len() {
            out.push(World { h: w.h.clone(), vouches: crate::shrink::without(&forged, i) });
        }
        for i in 0..w.h.writes.len() {
            let mut h = w.h.clone();
            h.writes.remove(i);
            h.recv.remove(i);
            out.push(World { h, vouches: forged.clone() });
        }
        for i in 0..w.h.writes.len() {
            for m in (0..w.h.n()).filter(|&m| m != w.h.writes[i].author && w.h.recv[i][m] < LATE) {
                let mut h = w.h.clone();
                h.recv[i][m] = LATE;
                out.push(World { h, vouches: forged.clone() });
            }
        }
        out.into_iter().map(|w| Shrinking { w: w.rederived(rules), rules }).collect()
    }
}

#[cfg(test)]
mod tests;
