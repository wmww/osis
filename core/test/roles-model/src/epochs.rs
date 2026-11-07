//! Account signing epochs (issues/account-signing.md): one account P whose nodes sign as P at
//! a signing epoch. Removing a node is a rotation of the signing epoch; what still counts of
//! a closed epoch is decided as for any ended standing (the demoter-frontier rule with addenda,
//! spec/permissions.md §5): by what the rotator had received (the rotation's list), by what
//! other writers of the thing had received by the rotation's `ts` (addenda, as built), and by
//! P's own later word at a counting epoch (a vouch: P listing its own commits, as a re-grant
//! revives a holder's). Nothing reads the author's `ts`, nothing reads the inner (node)
//! signature: it only guides what P's honest nodes list.
//!
//! The chain: rotations form a DAG; a rotation signed at e closes e; concurrent rotations at
//! one epoch fork and both count. A rotation supersedes its own epoch and epochs of lines
//! that do not pass through it (a line is contested from below: a removed node holding the
//! closed epoch cannot void its removal from above, only fork); a merge names the forks it
//! accepts, and a rotation it supersedes without naming is rejected with everything below
//! it, if the merge itself counts (counting is decided well-foundedly: once a rotation's
//! parent and every rotation rejecting it are decided). Two lines each rejecting the other
//! are an account-level dispute, settled per node by its side, as admin disputes are
//! (notes/disputes.md): the trust set names a line; the default is the line holding the
//! first-received contested rotation; P's own nodes side with their remover's line.
//!
//! Honest policies (what the generator's parties write; none is a judgment input): a node of
//! P lists its own commits at closed epochs and others' it received before the earliest
//! counting rotation it holds closing their epoch, leaving out commits a snapshot it judges
//! valid covers when `omit_covered`; a witness writer answers every rotation it holds (its
//! receipts are facts, whatever its side) with what it received before that rotation's `ts`
//! (as built; a later concurrent closer's window is today's stated limit); both answer
//! again after every change; the remover merges out every fork it receives,
//! superseding the other line whole. A witness's snapshot may fall (`Kind::Fall`, a held
//! event standing for its author's demotion).
//!
//! One thing, written by P (its nodes 0..np, node 1 = X the removed one, node 0 its remover),
//! by witness writers W of other accounts, and optionally demoted on by an admin A (the
//! account-level demotion, as built, to check the two levels are independent conjuncts).
//! Every node is also an observer with its own receipts. Judgment is a pure function of the
//! held set and the side; worlds are checked at every observer and every prefix of its
//! receipts.
//!
//! Search: `roles-model -- N epochs` (random), `-- 0 epochs-exh` (exhaustive small family).

use crate::shrink::LATE;
use crate::Rng;
use std::collections::HashSet;

/// Epoch ids: 0 the first; rotations mint the rest.
pub type Epoch = u32;

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// Plain content, or a special write (role-class, admin-only, purge: witnesses never
    /// list it).
    Content { plain: bool },
    /// Compaction snapshot carrying these content items.
    Snap { carries: Vec<u32> },
    /// A witness's snapshot (by item id) turning invalid everywhere this is held (its author
    /// demoted by a frontier that missed it).
    Fall { snap: u32 },
    /// Signed at `at`, supersedes `supersedes` (a plain rotation: just `at`), accepts the
    /// fork rotations `names` (by item id), mints `new`, lists P's commits at the epochs it
    /// closes that count.
    Rotation { at: Epoch, new: Epoch, supersedes: Vec<Epoch>, names: Vec<u32>, lists: Vec<u32> },
    /// P's word at epoch `at`: these commits at closed epochs count.
    Vouch { at: Epoch, lists: Vec<u32> },
    /// A witness writer's addendum against a rotation or a demotion (by item id).
    Addendum { against: u32, lists: Vec<u32> },
    /// A's explicit demotion of P below write on the thing, with A's frontier.
    Demotion { frontier: Vec<u32> },
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: u32,
    pub kind: Kind,
    pub author: usize,
    /// The signing epoch, for P's commits.
    pub epoch: Option<Epoch>,
    /// Real time it was made.
    pub t: u32,
    /// Its own stamp (a hostile write may backdate).
    pub ts: u32,
    /// [node] receipt time (the author's its `t`); `LATE` never.
    pub recv: Vec<u32>,
    /// Written by X after its removal.
    pub hostile: bool,
}

#[derive(Clone, Debug)]
pub struct World {
    /// P's nodes are 0..np; X = 1.
    pub np: usize,
    pub nodes: usize,
    /// Per node: a writer of the thing from another account.
    pub writer: Vec<bool>,
    pub admin: Option<usize>,
    /// Real time of X's removal (node 0's rotation).
    pub tr: u32,
    pub items: Vec<Item>,
    /// The rotator leaves out commits a snapshot it holds valid covers.
    pub omit_covered: bool,
}

pub const X: usize = 1;

#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub counting: Vec<bool>,
    /// Epochs a counting rotation closes (its own, and those of non-sibling rotations it
    /// supersedes).
    pub closed: Vec<Epoch>,
    pub as_p: Vec<bool>,
    pub valid: Vec<bool>,
    pub visible: Vec<bool>,
    /// Two held merges reject each other.
    pub dispute: bool,
}

impl World {
    fn is_p(&self, i: usize) -> bool {
        self.items[i].epoch.is_some()
    }

    /// Rotations in a mutual contest among the held ones: a rejects a rotation on b's chain
    /// and b one on a's.
    pub fn parties(&self, held: &[bool]) -> Vec<usize> {
        let rot = |i: usize| match &self.items[i].kind {
            Kind::Rotation { at, new, supersedes, names, .. } => Some((*at, *new, supersedes.clone(), names.clone())),
            _ => None,
        };
        let n = self.items.len();
        let minted = |e: Epoch| (0..n).find(|&i| held[i] && rot(i).map_or(false, |r| r.1 == e));
        let chain_of = |s: usize| {
            let mut chain = vec![s];
            let mut e = rot(s).unwrap().0;
            while e != 0 {
                match minted(e) {
                    Some(p) if !chain.contains(&p) => {
                        chain.push(p);
                        e = rot(p).unwrap().0;
                    }
                    _ => break,
                }
            }
            chain
        };
        let rejects = |m: usize, r: usize| {
            let (rm, rr) = (rot(m).unwrap(), rot(r).unwrap());
            rr.1 != rm.0 && rm.2.contains(&rr.1) && !rm.3.contains(&self.items[r].id) && !self.chain_of(held, m).contains(&r) && self.chain_of(held, r).iter().all(|&c| rot(c).unwrap().0 != rm.0)
        };
        let contests = |a: usize, b: usize| chain_of(b).iter().any(|&c| c != a && rejects(a, c));
        let rots: Vec<usize> = (0..n).filter(|&i| held[i] && rot(i).is_some()).collect();
        rots.iter().copied().filter(|&a| rots.iter().any(|&b| a != b && contests(a, b) && contests(b, a))).collect()
    }

    /// The side an observer takes: P's honest nodes side with the remover's line (they read
    /// the devices actor's roster); anyone else with the party it received first.
    pub fn default_side(&self, o: usize, held: &[bool]) -> Option<usize> {
        if o < self.np && o != X {
            // The remover's newest rotation: its own line.
            return (0..self.items.len()).filter(|&i| held[i] && self.items[i].author == 0 && matches!(self.items[i].kind, Kind::Rotation { .. })).max_by_key(|&i| self.items[i].t);
        }
        let parties = self.parties(held);
        if parties.is_empty() {
            return None;
        }
        // The party whose line holds the first-received rotation not common to every party.
        let chains: Vec<Vec<usize>> = parties.iter().map(|&p| self.chain_of(held, p)).collect();
        let common = |i: usize| chains.iter().all(|c| c.contains(&i));
        parties
            .iter()
            .copied()
            .zip(chains.iter())
            .min_by_key(|(_, c)| c.iter().copied().filter(|&i| !common(i)).map(|i| (self.items[i].recv[o], self.items[i].id)).min().unwrap_or((LATE, u32::MAX)))
            .map(|(p, _)| p)
    }

    /// A rotation and the rotations minting its ancestors, among the held ones.
    pub fn chain_of(&self, held: &[bool], s: usize) -> Vec<usize> {
        let at = |i: usize| match &self.items[i].kind {
            Kind::Rotation { at, .. } => *at,
            _ => 0,
        };
        let minted = |e: Epoch| (0..self.items.len()).find(|&i| held[i] && matches!(&self.items[i].kind, Kind::Rotation { new, .. } if *new == e));
        let mut chain = vec![s];
        let mut e = at(s);
        while e != 0 {
            match minted(e) {
                Some(p) if !chain.contains(&p) => {
                    chain.push(p);
                    e = at(p);
                }
                _ => break,
            }
        }
        chain
    }

    /// Validity as a pure function of the held set and the side (`trust`: the merge sided
    /// with, if any).
    pub fn judge(&self, held: &[bool], trust: Option<usize>) -> Verdict {
        let n = self.items.len();
        let rot = |i: usize| match &self.items[i].kind {
            Kind::Rotation { at, new, supersedes, names, lists } => Some((*at, *new, supersedes, names, lists)),
            _ => None,
        };
        // Epoch e is minted by this held rotation.
        let minted = |e: Epoch| (0..n).find(|&i| held[i] && rot(i).map_or(false, |r| r.1 == e));
        // m rejects r: m supersedes r's epoch without naming r. A rotation never rejects its
        // own chain, and one signed at e rejects nothing on a line through e (forks only
        // fork; a line is contested from below, by a merge signed under the other fork).
        let rejects = |m: usize, r: usize| {
            let (rm, rr) = (rot(m).unwrap(), rot(r).unwrap());
            rr.1 != rm.0 && rm.2.contains(&rr.1) && !rm.3.contains(&self.items[r].id) && !self.chain_of(held, m).contains(&r) && self.chain_of(held, r).iter().all(|&c| rot(c).unwrap().0 != rm.0)
        };
        // Chain of a rotation: itself and the rotations minting its ancestors.
        let chain_of = |s: usize| {
            let mut chain = vec![s];
            let mut e = rot(s).unwrap().0;
            while e != 0 {
                match minted(e) {
                    Some(p) if !chain.contains(&p) => {
                        chain.push(p);
                        e = rot(p).unwrap().0;
                    }
                    _ => break,
                }
            }
            chain
        };
        // Status: None undetermined, Some(true) counting, Some(false) void. Seeds: siding
        // with s, whatever rejects a rotation on s's chain is void. Then a rotation is
        // decided once its parent and every held rotation that rejects it are: void if the
        // parent is void or a counting one rejects it, else counting. A contest no side
        // settles stays undetermined, and counts for nothing.
        let mut status: Vec<Option<bool>> = (0..n).map(|i| if held[i] && rot(i).is_some() { None } else { Some(false) }).collect();
        if let Some(s) = trust {
            let chain = chain_of(s);
            for m in 0..n {
                if held[m] && rot(m).is_some() && chain.iter().any(|&c| c != m && rejects(m, c)) {
                    status[m] = Some(false);
                }
            }
        }
        loop {
            let mut changed = false;
            for r in 0..n {
                if status[r].is_some() {
                    continue;
                }
                let at = rot(r).unwrap().0;
                let parent = if at == 0 { Some(true) } else { minted(at).map_or(Some(false), |p| status[p]) };
                if parent == Some(false) {
                    status[r] = Some(false);
                    changed = true;
                    continue;
                }
                let rejectors: Vec<usize> = (0..n).filter(|&m| held[m] && m != r && rot(m).is_some() && rejects(m, r)).collect();
                if rejectors.iter().any(|&m| status[m] == Some(true)) {
                    status[r] = Some(false);
                    changed = true;
                } else if parent == Some(true) && rejectors.iter().all(|&m| status[m] == Some(false)) {
                    status[r] = Some(true);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let void: Vec<bool> = status.iter().map(|s| *s != Some(true)).collect();
        let counting: Vec<bool> = (0..n).map(|i| held[i] && rot(i).is_some() && !void[i]).collect();
        let epoch_counts = |e: Epoch| e == 0 || minted(e).map_or(false, |r| counting[r]);
        // m supersedes e when e is its own epoch or minted by a rotation not signed at m's.
        let supersedes = |m: usize, e: Epoch| {
            let rm = rot(m).unwrap();
            rm.2.contains(&e) && (e == rm.0 || minted(e).map_or(true, |r| self.chain_of(held, r).iter().all(|&c| rot(c).unwrap().0 != rm.0)))
        };
        let closed_list: Vec<Epoch> = {
            let mut c: Vec<Epoch> = (0..n).filter(|&r| counting[r]).flat_map(|r| rot(r).unwrap().2.iter().copied().filter(move |&e| supersedes(r, e)).collect::<Vec<_>>()).collect();
            c.sort_unstable();
            c.dedup();
            c
        };
        let closed = |e: Epoch| closed_list.contains(&e);
        let dispute = !self.parties(held).is_empty();
        // A's demotion (at most one held).
        let dem = (0..n).find(|&i| held[i] && matches!(self.items[i].kind, Kind::Demotion { .. }));
        let plain = |i: usize| matches!(self.items[i].kind, Kind::Content { plain: true });
        // Witness addendum a (held, by a writer) lists i against `against`, i stamped before
        // it and a after it, i plain content.
        let vouched_by_witness = |i: usize, against: usize| {
            (0..n).any(|a| {
                held[a] && self.writer[self.items[a].author] && plain(i) && match &self.items[a].kind {
                    Kind::Addendum { against: ag, lists } => *ag == self.items[against].id && lists.contains(&self.items[i].id) && self.items[i].ts < self.items[against].ts && self.items[against].ts < self.items[a].ts,
                    _ => false,
                }
            })
        };
        // Counts as P's: least fixpoint over vouches (a vouch at a closed epoch needs listing).
        let mut as_p = vec![false; n];
        loop {
            let next: Vec<bool> = (0..n)
                .map(|i| {
                    if !held[i] {
                        return false;
                    }
                    let Some(e) = self.items[i].epoch else { return true };
                    if !epoch_counts(e) {
                        return false;
                    }
                    if !closed(e) || rot(i).is_some() {
                        return true;
                    }
                    let id = self.items[i].id;
                    let listed = (0..n).any(|r| counting[r] && rot(r).unwrap().4.contains(&id))
                        || (0..n).any(|v| as_p[v] && matches!(&self.items[v].kind, Kind::Vouch { lists, .. } if lists.contains(&id)))
                        || (0..n).any(|r| counting[r] && supersedes(r, e) && vouched_by_witness(i, r));
                    listed
                })
                .collect();
            if next == as_p {
                break;
            }
            as_p = next;
        }
        // Standing on the thing against A's demotion (P's content and snapshots only).
        let standing = |i: usize| match dem {
            Some(d) if self.is_p(i) && matches!(self.items[i].kind, Kind::Content { .. } | Kind::Snap { .. }) => {
                if self.items[i].ts >= self.items[d].ts {
                    return false;
                }
                let Kind::Demotion { frontier } = &self.items[d].kind else { unreachable!() };
                frontier.contains(&self.items[i].id) || vouched_by_witness(i, d)
            }
            _ => true,
        };
        let fallen = |i: usize| (0..n).any(|f| held[f] && matches!(&self.items[f].kind, Kind::Fall { snap } if *snap == self.items[i].id));
        let valid: Vec<bool> = (0..n)
            .map(|i| {
                held[i] && match &self.items[i].kind {
                    Kind::Snap { .. } if fallen(i) => false,
                    _ if self.is_p(i) => as_p[i] && standing(i),
                    _ => true,
                }
            })
            .collect();
        let visible: Vec<bool> = (0..n)
            .map(|i| {
                matches!(self.items[i].kind, Kind::Content { .. })
                    && (valid[i] || (0..n).any(|s| valid[s] && matches!(&self.items[s].kind, Kind::Snap { carries, .. } if carries.contains(&self.items[i].id))))
            })
            .collect();
        Verdict { counting, closed: closed_list, as_p, valid, visible, dispute }
    }

    /// What observer o holds by `tau`.
    pub fn held_at(&self, o: usize, tau: u32) -> Vec<bool> {
        self.items.iter().map(|i| i.recv[o] <= tau).collect()
    }

    /// Honest attestations: vouches by P's honest nodes, witnesses' addenda.
    fn honest_attestation(&self, i: usize) -> bool {
        match self.items[i].kind {
            Kind::Vouch { .. } => self.items[i].author != X,
            Kind::Addendum { .. } => true,
            _ => false,
        }
    }

    /// The side taken is the owner's line, or there is nothing to side on.
    fn owner_sided(&self, _held: &[bool], trust: Option<usize>) -> bool {
        trust.map_or(true, |s| self.items[s].author != X)
    }

    /// A hostile commit listed by an honest sibling's rotation made before the removal
    /// reached that sibling (today's concurrent-demoter limit).
    fn listed_by_unaware_closer(&self, c: usize) -> bool {
        let r0 = self.items.iter().position(|i| i.author == 0 && matches!(i.kind, Kind::Rotation { .. }));
        let id = self.items[c].id;
        self.items.iter().any(|r| {
            r.author != X
                && r.author != 0
                && matches!(r.kind, Kind::Rotation { .. })
                && r0.map_or(true, |r0| self.items[r0].recv[r.author] >= r.t)
                && (matches!(&r.kind, Kind::Rotation { lists, .. } if lists.contains(&id)) || self.items.iter().any(|a| matches!(&a.kind, Kind::Addendum { against, lists } if *against == r.id && lists.contains(&id))))
        })
    }

    /// Expected final visibility of a legitimate content commit c of P's: some honest standing
    /// party received it in time at every level that ended its standing.
    /// `at_least`: the lower bound (received before the earliest honest closer); else the
    /// upper bound (before any honest closer's `ts`: a later concurrent closer's receipts).
    fn expected(&self, c: usize, at_least: bool) -> bool {
        let it = &self.items[c];
        let plain = matches!(it.kind, Kind::Content { plain: true });
        let witness_in_time = |t: u32| (0..self.nodes).any(|w| self.writer[w] && it.recv[w] < t) && plain;
        // Honest closers: rotations by a member at the time (X's before its removal included).
        let closers: Vec<(usize, u32)> = self.items.iter().filter(|r| !r.hostile && matches!(&r.kind, Kind::Rotation { supersedes, .. } if supersedes.contains(&it.epoch.unwrap()))).map(|r| (r.author, r.ts)).collect();
        let earliest = closers.iter().map(|c| c.1).min().unwrap_or(0);
        let chain = it.author != X
            || if at_least {
                (0..self.np).any(|n| n != X && it.recv[n] < earliest) || witness_in_time(earliest)
            } else {
                closers.iter().any(|&(a, t)| it.recv[a] < t || witness_in_time(t)) || (0..self.np).any(|n| n != X && it.recv[n] < earliest)
            };
        let level1 = match (0..self.items.len()).find(|&i| matches!(self.items[i].kind, Kind::Demotion { .. })) {
            None => true,
            Some(d) => {
                let td = self.items[d].ts;
                it.ts < td && (it.recv[self.items[d].author] < td || witness_in_time(td))
            }
        };
        chain && level1
    }
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub worlds: u64,
    pub hostile_valid_owner_sided: u64,
    pub hostile_valid_fork_window: u64,
    pub hostile_valid_unaware_closer: u64,
    pub hostile_visible_through_witness_snapshot: u64,
    pub liveness_fail: u64,
    pub saved_by_later_closer: u64,
    pub monotone_fail: u64,
    pub dispute_worlds: u64,
    pub thief_sided_observers: u64,
    pub side_changes_reading: u64,
    pub omit_loses: u64,
    pub omit_loses_snapshot_fallen: u64,
    pub omit_saves_ids: u64,
    pub list_all_ids: u64,
    pub vouch_rounds_max: usize,
    pub fail: Option<World>,
    pub fail_live: Option<World>,
}

impl Stats {
    pub fn merge(&mut self, o: Stats) {
        self.worlds += o.worlds;
        self.hostile_valid_owner_sided += o.hostile_valid_owner_sided;
        self.hostile_valid_fork_window += o.hostile_valid_fork_window;
        self.hostile_valid_unaware_closer += o.hostile_valid_unaware_closer;
        self.hostile_visible_through_witness_snapshot += o.hostile_visible_through_witness_snapshot;
        self.liveness_fail += o.liveness_fail;
        self.saved_by_later_closer += o.saved_by_later_closer;
        self.monotone_fail += o.monotone_fail;
        self.dispute_worlds += o.dispute_worlds;
        self.thief_sided_observers += o.thief_sided_observers;
        self.side_changes_reading += o.side_changes_reading;
        self.omit_loses += o.omit_loses;
        self.omit_loses_snapshot_fallen += o.omit_loses_snapshot_fallen;
        self.omit_saves_ids += o.omit_saves_ids;
        self.list_all_ids += o.list_all_ids;
        self.vouch_rounds_max = self.vouch_rounds_max.max(o.vouch_rounds_max);
        if self.fail.is_none() {
            self.fail = o.fail;
        }
        if self.fail_live.is_none() {
            self.fail_live = o.fail_live;
        }
    }
    pub fn hard_failures(&self) -> u64 {
        self.hostile_valid_owner_sided + self.liveness_fail + self.monotone_fail
    }
    pub fn print(&self, name: &str) {
        println!(
            "{name}: {} worlds; hard failures {} (hostile valid at owner-sided observer {}, liveness {}, monotone {}); saved only by a later concurrent closer's receipts {}; fork window: hostile valid {}; listed by an unaware sibling's concurrent rotation (stated limit) {}; hostile visible via a witness snapshot (stated limit) {}; disputes {} worlds, thief-sided observers {}, side changes the reading {}; omit-covered loses a write in {} worlds ({} with the snapshot fallen), ids listed {} vs {} listing all",
            self.worlds,
            self.hard_failures(),
            self.hostile_valid_owner_sided,
            self.liveness_fail,
            self.monotone_fail,
            self.saved_by_later_closer,
            self.hostile_valid_fork_window,
            self.hostile_valid_unaware_closer,
            self.hostile_visible_through_witness_snapshot,
            self.dispute_worlds,
            self.thief_sided_observers,
            self.side_changes_reading,
            self.omit_loses,
            self.omit_loses_snapshot_fallen,
            self.omit_saves_ids,
            self.list_all_ids,
        );
    }
}

/// Every check on one world.
pub fn check(w: &World, st: &mut Stats) {
    st.worlds += 1;
    let n = w.items.len();
    let mut failed = false;
    let times: Vec<u32> = {
        let mut t: Vec<u32> = w.items.iter().flat_map(|i| i.recv.iter().copied()).filter(|&t| t < LATE).collect();
        t.push(LATE);
        t.sort_unstable();
        t.dedup();
        t
    };
    let mut disputed = false;
    for o in (0..w.nodes).filter(|&o| o != X) {
        for &tau in &times {
            let held = w.held_at(o, tau);
            let trust = w.default_side(o, &held);
            let v = w.judge(&held, trust);
            if v.dispute {
                disputed = true;
                if !w.owner_sided(&held, trust) {
                    st.thief_sided_observers += 1;
                }
                // The side decides the reading.
                let other = w.parties(&held).into_iter().find(|&i| Some(i) != trust && w.items[i].author != w.items[trust.unwrap()].author);
                if other.is_some() && w.judge(&held, other) != v {
                    st.side_changes_reading += 1;
                }
            }
            // A counting rotation of an honest node is held (one whose chain has not arrived
            // counts for nothing yet).
            let holds_r = (0..n).any(|i| v.counting[i] && w.items[i].author != X);
            for i in 0..n {
                if !w.items[i].hostile || !matches!(w.items[i].kind, Kind::Content { .. }) {
                    continue;
                }
                if v.valid[i] {
                    if w.owner_sided(&held, trust) && holds_r {
                        let fork_counts = (0..n).any(|r| v.counting[r] && w.items[r].author == X);
                        if fork_counts {
                            st.hostile_valid_fork_window += 1;
                        } else if w.listed_by_unaware_closer(i) {
                            st.hostile_valid_unaware_closer += 1;
                        } else {
                            st.hostile_valid_owner_sided += 1;
                            failed = true;
                        }
                    }
                } else if v.visible[i] {
                    st.hostile_visible_through_witness_snapshot += 1;
                }
            }
        }
    }
    if disputed {
        st.dispute_worlds += 1;
    }
    // Final state at observers that received everything honest.
    let all: Vec<bool> = w.items.iter().map(|_| true).collect();
    for o in 0..w.nodes {
        let held = w.held_at(o, LATE - 1);
        if (0..n).any(|i| !held[i] && !w.items[i].hostile) {
            continue;
        }
        let trust = w.default_side(o, &held);
        if !w.owner_sided(&held, trust) {
            continue;
        }
        let v = w.judge(&held, trust);
        for i in 0..n {
            if w.items[i].hostile || !w.is_p(i) || !matches!(w.items[i].kind, Kind::Content { .. }) {
                continue;
            }
            let carried = (0..n).any(|s| v.valid[s] && matches!(&w.items[s].kind, Kind::Snap { carries, .. } if carries.contains(&w.items[i].id)));
            let (lo, hi) = (w.expected(i, true) || carried, w.expected(i, false) || carried);
            if v.visible[i] && !hi && !lo {
                st.liveness_fail += 1;
                failed = true;
            } else if v.visible[i] && !lo {
                st.saved_by_later_closer += 1;
            }
            let exp = lo;
            if exp && !v.visible[i] && !(w.omit_covered && !v.visible[i]) {
                st.liveness_fail += 1;
                failed = true;
                if std::env::var_os("EPOCHS_DEBUG").is_some() {
                    println!("liveness: observer n{o} item #{} invalid; side {:?}; counting {:?}; as_p {:?}", w.items[i].id, trust.map(|t| w.items[t].id), v.counting, v.as_p);
                }
                if st.fail_live.is_none() {
                    st.fail_live = Some(w.clone());
                }
            }
        }
        // Monotone: dropping an honest attestation never makes more valid.
        for a in 0..n {
            if !held[a] || !w.honest_attestation(a) {
                continue;
            }
            let mut less = held.clone();
            less[a] = false;
            let v2 = w.judge(&less, trust);
            if (0..n).any(|i| v2.valid[i] && !v.valid[i]) {
                st.monotone_fail += 1;
                failed = true;
            }
        }
        // Omit-covered against listing everything, at the fully informed owner-sided observer.
        if o == 0 && w.omit_covered {
            let mut full = w.clone();
            full.omit_covered = false;
            relist(&mut full);
            let v2 = full.judge(&all, full.default_side(0, &all));
            let va = w.judge(&all, w.default_side(0, &all));
            let lost = (0..n).any(|i| v2.visible[i] && !va.visible[i]);
            if lost {
                st.omit_loses += 1;
                if w.items.iter().any(|i| matches!(i.kind, Kind::Fall { .. })) {
                    st.omit_loses_snapshot_fallen += 1;
                }
            }
            if (0..n).any(|i| va.visible[i] && !v2.visible[i]) {
                st.liveness_fail += 1;
                failed = true;
            }
            let ids = |w: &World| w.items.iter().map(|i| match &i.kind { Kind::Rotation { lists, .. } => lists.len() as u64, _ => 0 }).sum::<u64>();
            st.omit_saves_ids += ids(w);
            st.list_all_ids += ids(&full);
        }
    }
    if failed && st.fail.is_none() {
        st.fail = Some(w.clone());
    }
}

/// Recomputes every rotation's list from its author's receipts under `w.omit_covered`.
pub fn relist(w: &mut World) {
    for r in 0..w.items.len() {
        let Kind::Rotation { supersedes, .. } = &w.items[r].kind else { continue };
        let (author, t, supersedes) = (w.items[r].author, w.items[r].t, supersedes.clone());
        let lists = rotation_list(w, author, t, &supersedes);
        if let Kind::Rotation { lists: l, .. } = &mut w.items[r].kind {
            *l = lists;
        }
    }
}

/// P's commits at `closing` epochs that `author` had received before `t`, less, when
/// `omit_covered`, those a snapshot it holds (received before `t`, and that it then judges
/// valid: at a counting epoch or a witness's) covers.
fn rotation_list(w: &World, author: usize, t: u32, closing: &[Epoch]) -> Vec<u32> {
    let recvd = |i: usize| w.items[i].recv[author] < t && !matches!(w.items[i].kind, Kind::Rotation { .. });
    let candidates: Vec<usize> = (0..w.items.len()).filter(|&i| recvd(i) && w.items[i].epoch.map_or(false, |e| closing.contains(&e))).collect();
    if !w.omit_covered {
        return candidates.iter().map(|&i| w.items[i].id).collect();
    }
    let covered: HashSet<u32> = covered_at(w, author, t);
    candidates.iter().filter(|&&i| !covered.contains(&w.items[i].id)).map(|&i| w.items[i].id).collect()
}

/// Commits a snapshot `node` holds valid at `t` (received before `t`, by its own judgment
/// then) carries.
fn covered_at(w: &World, node: usize, t: u32) -> HashSet<u32> {
    let held: Vec<bool> = w.items.iter().map(|i| i.recv[node] < t).collect();
    let v = w.judge(&held, w.default_side(node, &held));
    (0..w.items.len())
        .filter(|&s| held[s] && v.valid[s])
        .flat_map(|s| match &w.items[s].kind {
            Kind::Snap { carries } => carries.clone(),
            _ => vec![],
        })
        .collect()
}

/// A world from choices. `np` P nodes, `nw` witness writers, an admin if `admin`, one
/// outsider; `T` ticks.
pub struct Gen {
    pub np: usize,
    pub nw: usize,
    pub admin: bool,
    pub tr: u32,
    pub t_max: u32,
    pub omit_covered: bool,
}

pub struct Builder {
    pub w: World,
    next_id: u32,
    pub t_max: u32,
}

impl Builder {
    pub fn new(g: &Gen) -> Builder {
        let nodes = g.np + g.nw + usize::from(g.admin) + 1;
        let mut writer = vec![false; nodes];
        for i in g.np..g.np + g.nw {
            writer[i] = true;
        }
        let admin = g.admin.then_some(g.np + g.nw);
        Builder { w: World { np: g.np, nodes, writer, admin, tr: g.tr, items: vec![], omit_covered: g.omit_covered }, next_id: 1, t_max: g.t_max }
    }

    pub fn add(&mut self, kind: Kind, author: usize, epoch: Option<Epoch>, t: u32, ts: u32, recv: Vec<u32>, hostile: bool) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        let mut recv = recv;
        recv[author] = t;
        self.w.items.push(Item { id, kind, author, epoch, t, ts, recv, hostile });
        self.w.items.len() - 1
    }

    /// Receipts: the author at `t`, others at `t + d` (`d` from `delay`), `LATE` when it says.
    pub fn recv(&self, t: u32, mut delay: impl FnMut(usize) -> Option<u32>) -> Vec<u32> {
        (0..self.w.nodes).map(|n| delay(n).map_or(LATE, |d| t + d)).collect()
    }

    fn rotations_held_by(&self, n: usize, t: u32) -> Vec<bool> {
        self.w.items.iter().map(|i| i.recv[n] <= t && matches!(i.kind, Kind::Rotation { .. })).collect()
    }

    /// An honest node's signing epoch at `t`: the newest counting open epoch in what it
    /// holds the key of (X's forks box nobody else).
    pub fn epoch_of(&self, n: usize, t: u32) -> Epoch {
        let held = self.rotations_held_by(n, t);
        let v = self.w.judge(&held, self.w.default_side(n, &held));
        let mut best = 0;
        for i in 0..self.w.items.len() {
            if let Kind::Rotation { new, .. } = &self.w.items[i].kind {
                if v.counting[i] && self.w.items[i].author != X && *new > best && !v.closed.contains(new) {
                    best = *new;
                }
            }
        }
        best
    }

    /// X's epoch at `t`: its own forks first.
    pub fn epoch_of_x(&self, t: u32) -> Epoch {
        let mut best = 0;
        for i in &self.w.items {
            if let Kind::Rotation { new, supersedes, .. } = &i.kind {
                if i.author == X && i.t <= t && *new > best && !self.w.items.iter().any(|r| r.author == X && r.t <= t && matches!(&r.kind, Kind::Rotation { supersedes: s, .. } if s.contains(new))) {
                    let _ = supersedes;
                    best = *new;
                }
            }
        }
        best
    }

    /// Rotation r counts in node n's own view at t (its side: `World::default_side`).
    fn counts_for(&self, n: usize, r: usize, t: u32) -> bool {
        let held: Vec<bool> = self.w.items.iter().map(|i| i.recv[n] <= t).collect();
        held[r] && self.w.judge(&held, self.w.default_side(n, &held)).counting[r]
    }

    /// Node n holds a counting rotation by another node whose epoch no rotation of n's own
    /// line supersedes.
    pub fn holds_unmerged_fork(&self, n: usize, t: u32) -> bool {
        let held = self.rotations_held_by(n, t);
        // Counting without a side (as an outsider may read it), and not closed by its own
        // line's effective supersedes (the sibling rule may void a supersedes entry).
        let v = self.w.judge(&held, None);
        let own = self.w.judge(&held, self.w.default_side(n, &held));
        (0..self.w.items.len()).any(|i| held[i] && v.counting[i] && self.w.items[i].author != n && matches!(&self.w.items[i].kind, Kind::Rotation { new, .. } if !own.closed.contains(new) && !v.closed.contains(new)))
    }

    /// Closed epochs in what node n holds at t (counting rotations, owner-sided).
    fn closed_for(&self, n: usize, t: u32) -> Vec<Epoch> {
        let held = self.rotations_held_by(n, t);
        self.w.judge(&held, self.w.default_side(n, &held)).closed
    }

    /// Commit ids a held counting listing names, as node n sees it at t.
    fn listed_for(&self, n: usize, t: u32) -> HashSet<u32> {
        let held: Vec<bool> = self.w.items.iter().map(|i| i.recv[n] <= t).collect();
        let v = self.w.judge(&held, self.w.default_side(n, &held));
        let mut s = HashSet::new();
        for i in 0..self.w.items.len() {
            match &self.w.items[i].kind {
                Kind::Rotation { lists, .. } if v.counting[i] => s.extend(lists.iter().copied()),
                Kind::Vouch { lists, .. } if v.as_p[i] => s.extend(lists.iter().copied()),
                _ => {}
            }
        }
        s
    }

    /// Honest node n (not X) answers rotation r (held at `t`) with a vouch at `t`: its own
    /// commits at the epochs r closed, and others' it received before r's `ts`, that nothing
    /// held lists.
    pub fn vouch(&mut self, n: usize, r: usize, t: u32, delay: impl FnMut(usize) -> Option<u32>) -> Option<usize> {
        let Kind::Rotation { supersedes, .. } = &self.w.items[r].kind else { return None };
        if !self.counts_for(n, r, t) {
            return None;
        }
        let closing = supersedes.clone();
        let listed = self.listed_for(n, t);
        let closed = self.closed_for(n, t);
        // Another node's commit at e counts as received in time when it arrived before the
        // earliest counting rotation n holds that closes e.
        let held: Vec<bool> = self.w.items.iter().map(|i| i.recv[n] <= t).collect();
        let v = self.w.judge(&held, self.w.default_side(n, &held));
        let cutoff = |e: Epoch| (0..self.w.items.len()).filter(|&i| v.counting[i] && matches!(&self.w.items[i].kind, Kind::Rotation { at, supersedes, .. } if *at == e || supersedes.contains(&e))).map(|i| self.w.items[i].ts).min().unwrap_or(0);
        let covered = if self.w.omit_covered { covered_at(&self.w, n, t + 1) } else { HashSet::new() };
        let lists: Vec<u32> = (0..self.w.items.len())
            .filter(|&i| {
                let it = &self.w.items[i];
                it.recv[n] <= t
                    && !covered.contains(&it.id)
                    && it.epoch.map_or(false, |e| closing.contains(&e) && closed.contains(&e))
                    && !matches!(it.kind, Kind::Rotation { .. })
                    && !listed.contains(&it.id)
                    && (it.author == n || it.recv[n] < cutoff(it.epoch.unwrap()))
            })
            .map(|i| self.w.items[i].id)
            .collect();
        if lists.is_empty() {
            return None;
        }
        let epoch = self.epoch_of(n, t);
        let recv = self.recv(t, delay);
        Some(self.add(Kind::Vouch { at: epoch, lists }, n, Some(epoch), t, t, recv, false))
    }

    /// Witness w answers `against` (a rotation closing epochs, or A's demotion) at `t`,
    /// listing P's plain content it received before its `ts` that it does not list.
    pub fn addendum(&mut self, wn: usize, against: usize, t: u32, delay: impl FnMut(usize) -> Option<u32>) -> Option<usize> {
        // A witness answers every rotation it holds, whatever side it takes: its receipts are
        // facts, and its side may differ from its readers'.
        let ag = &self.w.items[against];
        let (closing, listed): (Option<Vec<Epoch>>, Vec<u32>) = match &ag.kind {
            Kind::Rotation { supersedes, lists, .. } => (Some(supersedes.clone()), lists.clone()),
            Kind::Demotion { frontier } => (None, frontier.clone()),
            _ => return None,
        };
        // As built: what the witness received before the answered write's own `ts`.
        let ts = ag.ts;
        let covered = if self.w.omit_covered { covered_at(&self.w, wn, t + 1) } else { HashSet::new() };
        let lists: Vec<u32> = (0..self.w.items.len())
            .filter(|&i| {
                let it = &self.w.items[i];
                !covered.contains(&it.id) && it.recv[wn] < ts && it.epoch.is_some() && matches!(it.kind, Kind::Content { plain: true }) && !listed.contains(&it.id) && closing.as_ref().map_or(true, |c| c.contains(&it.epoch.unwrap()))
            })
            .map(|i| self.w.items[i].id)
            .collect();
        if lists.is_empty() {
            return None;
        }
        let recv = self.recv(t, delay);
        Some(self.add(Kind::Addendum { against: ag.id, lists }, wn, None, t, t, recv, false))
    }

    /// Node 0's rotation (or merge) at `t`: closes the epochs it holds current, names the
    /// forks it accepts (every one not X's), lists what it received.
    pub fn rotate(&mut self, n: usize, t: u32, new: Epoch, delay: impl FnMut(usize) -> Option<u32>) -> usize {
        let at = self.epoch_of(n, t);
        let held = self.rotations_held_by(n, t);
        // Every epoch current in the rotator's own view (its side), and every epoch of a
        // held rotation by X its own line has not superseded: the other line whole.
        let v = self.w.judge(&held, self.w.default_side(n, &held));
        let own_supersedes = |e: &Epoch| self.w.items.iter().any(|r| r.author == n && r.t <= t && matches!(&r.kind, Kind::Rotation { supersedes, .. } if supersedes.contains(e)));
        let mut supersedes = vec![at];
        let mut names = vec![];
        for i in 0..self.w.items.len() {
            if let Kind::Rotation { new: e, .. } = &self.w.items[i].kind {
                let current = held[i] && ((v.counting[i] && !v.closed.contains(e)) || (self.w.items[i].author == X && !own_supersedes(e)));
                if current && *e != at && self.w.items[i].author != X {
                    supersedes.push(*e);
                    names.push(self.w.items[i].id);
                } else if current && *e != at {
                    supersedes.push(*e);
                }
            }
        }
        supersedes.sort_unstable();
        supersedes.dedup();
        let lists = rotation_list(&self.w, n, t, &supersedes);
        let recv = self.recv(t, delay);
        self.add(Kind::Rotation { at, new, supersedes, names, lists }, n, Some(at), t, t, recv, false)
    }

    /// X's rotation at `t`: a fork at its epoch, rejecting every rotation of the others it
    /// holds; it lists its own commits.
    pub fn rotate_x(&mut self, t: u32, new: Epoch, delay: impl FnMut(usize) -> Option<u32>) -> usize {
        let at = self.epoch_of_x(t);
        let mut supersedes = vec![at];
        let mut names = vec![];
        for i in &self.w.items {
            if let Kind::Rotation { new: e, .. } = &i.kind {
                if i.recv[X] <= t && *e != at {
                    supersedes.push(*e);
                }
                if i.author == X && *e == at {
                    names.push(i.id);
                }
            }
        }
        supersedes.sort_unstable();
        supersedes.dedup();
        let lists: Vec<u32> = self.w.items.iter().filter(|i| i.author == X && i.epoch.map_or(false, |e| supersedes.contains(&e)) && !matches!(i.kind, Kind::Rotation { .. })).map(|i| i.id).collect();
        let recv = self.recv(t, delay);
        let hostile = t >= self.w.tr;
        self.add(Kind::Rotation { at, new, supersedes, names, lists }, X, Some(at), t, t, recv, hostile)
    }
}

/// A random world.
pub fn random_world(rng: &mut Rng) -> World {
    let g = Gen { np: 2 + rng.below(2), nw: rng.below(3), admin: rng.below(3) == 0, tr: 3 + rng.below(5) as u32, t_max: 14, omit_covered: rng.below(2) == 0 };
    let mut b = Builder::new(&g);
    let np = g.np;
    let nodes = b.w.nodes;
    let delay = |rng: &mut Rng| {
        let v: Vec<Option<u32>> = (0..nodes).map(|_| if rng.below(4) == 0 { None } else { Some(rng.below(4) as u32) }).collect();
        move |n: usize| v[n]
    };
    // X's rotations go under P's labels, so P's honest nodes get them when they sync.
    let thief_delay = |rng: &mut Rng| {
        let v: Vec<Option<u32>> = (0..nodes).map(|n| if n >= np && rng.below(4) == 0 { None } else { Some(rng.below(4) as u32) }).collect();
        move |n: usize| v[n]
    };
    // A role change by an honest party reaches every honest party in the end.
    let honest_delay = |rng: &mut Rng| {
        let v: Vec<Option<u32>> = (0..nodes).map(|n| if n == X && rng.below(4) == 0 { None } else { Some(rng.below(4) as u32) }).collect();
        move |n: usize| v[n]
    };
    // Content before the removal (any node), and X's after it.
    let n_items = 1 + rng.below(4);
    let mut pending: Vec<(usize, u32)> = vec![];
    for _ in 0..n_items {
        let author = rng.below(np);
        let t = 1 + rng.below(g.t_max as usize) as u32;
        pending.push((author, t));
    }
    pending.sort_by_key(|p| p.1);
    // Events in real time: content, the removal, X's fork and merges, the demotion,
    // snapshots; then every honest answer.
    let thief_fork = rng.below(2) == 0;
    let tx = g.tr + rng.below(4) as u32;
    let honest_fork = np == 3 && rng.below(4) == 0;
    let t2 = (g.tr as i32 - 1 + rng.below(3) as i32).max(1) as u32;
    let owner_merge_t = g.tr + 2 + rng.below(3) as u32;
    let thief_merge = thief_fork && rng.below(2) == 0;
    let thief_merge_t = owner_merge_t + rng.below(3) as u32;
    let demotion_t = if g.admin { Some(2 + rng.below(10) as u32) } else { None };
    let snap_t = if rng.below(2) == 0 { Some(2 + rng.below(10) as u32) } else { None };
    let snap_by = if rng.below(2) == 0 && g.nw > 0 { np } else { rng.below(np) };
    let snap_fallen = snap_by >= np && rng.below(3) == 0;
    let mut answered: Vec<usize> = vec![];
    for t in 1..=g.t_max {
        // honest answers to rotations received by now (before anything else at t)
        for r in 0..b.w.items.len() {
            if !matches!(b.w.items[r].kind, Kind::Rotation { .. }) || answered.contains(&r) {
                continue;
            }
            let mut all_in = true;
            for n in 0..b.w.nodes {
                if b.w.items[r].recv[n] < LATE && b.w.items[r].recv[n] < t {
                    if n < np && n != X {
                        let d = delay(rng);
                        b.vouch(n, r, t, d);
                    } else if b.w.writer[n] {
                        let d = delay(rng);
                        b.addendum(n, r, t, d);
                    }
                } else if b.w.items[r].recv[n] < LATE {
                    all_in = false;
                }
            }
            if all_in {
                answered.push(r);
            }
        }
        if let Some(d) = demotion_t {
            if d == t {
                if let Some(a) = b.w.admin {
                    let frontier: Vec<u32> = b.w.items.iter().filter(|i| i.epoch.is_some() && i.recv[a] < t && matches!(i.kind, Kind::Content { .. } | Kind::Snap { .. })).map(|i| i.id).collect();
                    let dl = honest_delay(rng);
                    let r = b.recv(t, dl);
                    let di = b.add(Kind::Demotion { frontier }, a, None, t, t, r, false);
                    for wn in 0..b.w.nodes {
                        if b.w.writer[wn] {
                            let dl = delay(rng);
                            let at = t + 1 + rng.below(3) as u32;
                            b.addendum(wn, di, at, dl);
                        }
                    }
                }
            }
        }
        while let Some(&(author, pt)) = pending.first() {
            if pt != t {
                break;
            }
            pending.remove(0);
            let hostile = author == X && t >= g.tr;
            let epoch = if author == X { b.epoch_of_x(t) } else { b.epoch_of(author, t) };
            let ts = if hostile { rng.below(g.t_max as usize) as u32 } else { t };
            let plain = rng.below(4) != 0;
            let dl = delay(rng);
            let r = b.recv(t, dl);
            b.add(Kind::Content { plain }, author, Some(epoch), t, ts, r, hostile);
        }
        if let Some(s) = snap_t {
            if s == t {
                let carries: Vec<u32> = b.w.items.iter().filter(|i| i.epoch.is_some() && i.recv[snap_by] < t && matches!(i.kind, Kind::Content { .. })).map(|i| i.id).collect();
                if !carries.is_empty() {
                    let epoch = if snap_by < np { Some(if snap_by == X { b.epoch_of_x(t) } else { b.epoch_of(snap_by, t) }) } else { None };
                    let hostile = snap_by == X && t >= g.tr;
                    let dl = delay(rng);
                    let r = b.recv(t, dl);
                    let si = b.add(Kind::Snap { carries }, snap_by, epoch, t, t, r, hostile);
                    if snap_fallen {
                        let ft = t + 1 + rng.below(6) as u32;
                        let dl = honest_delay(rng);
                        let r = b.recv(ft, dl);
                        let id = b.w.items[si].id;
                        b.add(Kind::Fall { snap: id }, snap_by, None, ft, ft, r, false);
                    }
                }
            }
        }
        if honest_fork && t2 == t && b.w.items[..].iter().all(|i| !(i.author == 0 && matches!(i.kind, Kind::Rotation { .. }) && i.recv[2] <= t)) {
            let dl = honest_delay(rng);
            b.rotate(2, t, 20, dl);
        }
        if g.tr == t {
            let dl = honest_delay(rng);
            b.rotate(0, t, 1, dl);
        }
        if thief_fork && tx == t {
            let dl = thief_delay(rng);
            b.rotate_x(t, 10, dl);
        }
        // The owner merges whenever it holds a fork its own line has not superseded, within
        // a tick or two of receiving it (its nodes merge every fork they receive).
        if t >= owner_merge_t - 2 && b.holds_unmerged_fork(0, t) && (t >= owner_merge_t || rng.below(2) == 0) {
            let dl = honest_delay(rng);
            b.rotate(0, t, 30 + t, dl);
        }
        if thief_merge && t >= thief_merge_t && b.w.items.iter().any(|i| i.author == 0 && i.recv[X] <= t && matches!(&i.kind, Kind::Rotation { new, .. } if !b.w.items.iter().any(|r| r.author == X && matches!(&r.kind, Kind::Rotation { supersedes, .. } if supersedes.contains(new))))) && rng.below(2) == 0 {
            let dl = thief_delay(rng);
            b.rotate_x(t, 40 + t, dl);
        }
    }
    // Final honest answers, everyone having received everything that arrives (receipts
    // run to t_max + 3).
    let t = g.t_max + 4;
    if b.holds_unmerged_fork(0, t) {
        b.rotate(0, t, 90, |_| Some(0));
    }
    for r in 0..b.w.items.len() {
        if !matches!(b.w.items[r].kind, Kind::Rotation { .. }) {
            continue;
        }
        for n in 0..b.w.nodes {
            if b.w.items[r].recv[n] >= LATE {
                continue;
            }
            if n < np && n != X {
                b.vouch(n, r, t, |_| Some(0));
            } else if b.w.writer[n] {
                b.addendum(n, r, t, |_| Some(0));
            }
        }
    }
    // X's hostile vouch at its fork for its hostile writes.
    if thief_fork && rng.below(2) == 0 {
        let lists: Vec<u32> = b.w.items.iter().filter(|i| i.hostile && matches!(i.kind, Kind::Content { .. })).map(|i| i.id).collect();
        if !lists.is_empty() {
            let e = b.epoch_of_x(t);
            let r = b.recv(t, |_| Some(0));
            b.add(Kind::Vouch { at: e, lists }, X, Some(e), t, t, r, true);
        }
    }
    b.w
}

/// Exhaustive small family: 2 P nodes, 1 witness, 1 outsider, tr = 3, one or two content
/// commits (author, time 1..4, backdated or not, each other node's receipt immediate, late
/// or never), X's fork before or after the removal or none (the owner merges out every fork
/// it holds), X's counter-merge or not, a snapshot none / by node 0 / by the witness (falling
/// or not), covered commits omitted or listed. Honest answers always.
pub fn exhaustive(f: &mut impl FnMut(World)) -> u64 {
    let mut count = 0;
    let recv_opts = [0u32, 2, LATE];
    let item_choices: Vec<(usize, u32, bool, [u32; 4])> = {
        let mut v = vec![];
        for author in [0usize, X] {
            for t in 1..=4u32 {
                for backdated in [false, true] {
                    if backdated && !(author == X && t >= 3) {
                        continue;
                    }
                    for a in recv_opts {
                        for b in recv_opts {
                            for c in recv_opts {
                                let mut r = [0u32; 4];
                                let others: Vec<usize> = (0..4).filter(|&n| n != author).collect();
                                r[others[0]] = a;
                                r[others[1]] = b;
                                r[others[2]] = c;
                                v.push((author, t, backdated, r));
                            }
                        }
                    }
                }
            }
        }
        v
    };
    let mut item_sets: Vec<Vec<(usize, u32, bool, [u32; 4])>> = item_choices.iter().map(|c| vec![*c]).collect();
    for (i, a) in item_choices.iter().enumerate() {
        for b in item_choices.iter().skip(i) {
            if a.3.iter().all(|&r| r != LATE) && b.3.iter().all(|&r| r != LATE) || (a.1 <= b.1 && (a.0 == X || b.0 == X)) {
                item_sets.push(vec![*a, *b]);
            }
        }
    }
    for items in &item_sets {
        for thief in 0..3u8 {
            for merges in 0..3u8 {
                // The owner merges out every fork it holds; `merges` 2 adds X's counter-merge.
                if (merges > 0) != (thief > 0) || merges == 1 && thief == 0 {
                    continue;
                }
                for snap in 0..4u8 {
                    for omit in [false, true] {
                        if !omit && snap == 0 {
                            continue;
                        }
                        count += 1;
                        let g = Gen { np: 2, nw: 1, admin: false, tr: 3, t_max: 8, omit_covered: omit };
                        let mut b = Builder::new(&g);
                        let tx = if thief == 1 { 2 } else { 4 };
                        let snap_t = 3u32;
                        for t in 1..=8u32 {
                            for n in [0usize, 2] {
                                for r in 0..b.w.items.len() {
                                    if matches!(b.w.items[r].kind, Kind::Rotation { .. }) && b.w.items[r].recv[n] < t && b.w.items[r].recv[n] + 1 == t {
                                        if n == 0 {
                                            b.vouch(0, r, t, |_| Some(0));
                                        } else {
                                            b.addendum(2, r, t, |_| Some(0));
                                        }
                                    }
                                }
                            }
                            for &(author, it, backdated, r) in items {
                                if it != t {
                                    continue;
                                }
                                let hostile = author == X && t >= 3;
                                let epoch = if author == X { b.epoch_of_x(t) } else { b.epoch_of(author, t) };
                                let recv: Vec<u32> = r.iter().map(|&d| if d >= LATE { LATE } else { t + d }).collect();
                                b.add(Kind::Content { plain: true }, author, Some(epoch), t, if backdated { 1 } else { t }, recv, hostile);
                            }
                            if snap > 0 && snap_t == t {
                                let by = if snap == 1 { 0 } else { 2 };
                                let carries: Vec<u32> = b.w.items.iter().filter(|i| i.epoch.is_some() && i.recv[by] < t && matches!(i.kind, Kind::Content { .. })).map(|i| i.id).collect();
                                if !carries.is_empty() {
                                    let epoch = (by == 0).then(|| b.epoch_of(0, t));
                                    let recv = vec![t; 4];
                                    let si = b.add(Kind::Snap { carries }, by, epoch, t, t, recv, false);
                                    if snap == 3 {
                                        let id = b.w.items[si].id;
                                        b.add(Kind::Fall { snap: id }, by, None, t + 2, t + 2, vec![t + 2; 4], false);
                                    }
                                }
                            }
                            if thief > 0 && tx == t {
                                b.rotate_x(t, 10, |_| Some(1));
                            }
                            if t == 3 {
                                b.rotate(0, t, 1, |_| Some(1));
                            }
                            if t >= 5 && b.holds_unmerged_fork(0, t) {
                                b.rotate(0, t, 30 + t, |_| Some(1));
                            }
                            if merges == 2 && t == 7 {
                                b.rotate_x(t, 40, |n| Some(if n == 2 { 0 } else { 2 }));
                            }
                        }
                        let t = 11;
                        if b.holds_unmerged_fork(0, t) {
                            b.rotate(0, t, 90, |_| Some(0));
                        }
                        for r in 0..b.w.items.len() {
                            if matches!(b.w.items[r].kind, Kind::Rotation { .. }) {
                                if b.w.items[r].recv[0] < LATE {
                                    b.vouch(0, r, t, |_| Some(0));
                                }
                                if b.w.items[r].recv[2] < LATE {
                                    b.addendum(2, r, t, |_| Some(0));
                                }
                            }
                        }
                        f(b.w);
                    }
                }
            }
        }
    }
    count
}

fn print_world(w: &World) {
    println!("np {} nodes {} writers {:?} admin {:?} tr {} omit_covered {}", w.np, w.nodes, w.writer, w.admin, w.tr, w.omit_covered);
    for i in &w.items {
        println!("  #{} {:?} by n{} epoch {:?} t {} ts {} recv {:?}{}", i.id, i.kind, i.author, i.epoch, i.t, i.ts, i.recv, if i.hostile { " HOSTILE" } else { "" });
    }
}

pub fn run(samples: u64, exhaustive_family: bool) {
    let mut st = Stats::default();
    if exhaustive_family {
        let n = exhaustive(&mut |w| check(&w, &mut st));
        println!("exhaustive family: {n} worlds");
        st.print("epochs-exh");
    } else {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let stats: Vec<Stats> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..threads)
                .map(|th| {
                    s.spawn(move || {
                        let mut rng = Rng(0x5eed ^ (th as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
                        let mut st = Stats::default();
                        for _ in 0..samples / threads as u64 {
                            let w = random_world(&mut rng);
                            check(&w, &mut st);
                        }
                        st
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for s in stats {
            st.merge(s);
        }
        st.print("epochs");
    }
    if let Some(w) = &st.fail {
        println!("first failing world:");
        print_world(w);
    }
    if let Some(w) = &st.fail_live {
        println!("first liveness failure:");
        print_world(w);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn world(f: impl FnOnce(&mut Builder)) -> World {
        let g = Gen { np: 3, nw: 1, admin: false, tr: 3, t_max: 8, omit_covered: false };
        let mut b = Builder::new(&g);
        f(&mut b);
        b.w
    }

    fn all(w: &World) -> Vec<bool> {
        vec![true; w.items.len()]
    }

    /// X's backdated write after its removal never counts once the rotation is held; its
    /// write before it, received by the remover, counts.
    #[test]
    fn removal_closes_the_epoch() {
        let w = world(|b| {
            b.add(Kind::Content { plain: true }, X, Some(0), 1, 1, vec![1, 1, 1, 1, 1], false);
            b.rotate(0, 3, 1, |_| Some(0));
            b.add(Kind::Content { plain: true }, X, Some(0), 4, 2, vec![4, 4, 4, 4, 4], true);
        });
        let v = w.judge(&all(&w), None);
        assert_eq!(v.valid, vec![true, true, false]);
        let before = w.held_at(3, 2);
        assert!(w.judge(&before, None).valid[0]);
    }

    /// A sibling's late write at the closed epoch counts once it vouches for it.
    #[test]
    fn sibling_vouches_its_late_write() {
        let w = world(|b| {
            b.rotate(0, 3, 1, |n| if n == 2 { Some(3) } else { Some(0) });
            b.add(Kind::Content { plain: true }, 2, Some(0), 4, 4, vec![6, 6, 4, 6, 6], false);
            let r = 0;
            b.vouch(2, r, 7, |_| Some(0));
        });
        assert_eq!(w.items.len(), 3);
        let v = w.judge(&all(&w), None);
        assert!(v.valid[1]);
        let without = vec![true, true, false];
        assert!(!w.judge(&without, None).valid[1]);
    }

    /// A witness that received X's pre-removal write in time saves it; X's later write it
    /// received after the removal's `ts` is not listed.
    #[test]
    fn witness_saves_what_it_received_in_time() {
        let w = world(|b| {
            b.add(Kind::Content { plain: true }, X, Some(0), 1, 1, vec![LATE, 1, LATE, 1, LATE], false);
            b.rotate(0, 3, 1, |_| Some(0));
            b.add(Kind::Content { plain: true }, X, Some(0), 4, 1, vec![LATE, 4, LATE, 4, LATE], true);
            b.addendum(3, 1, 5, |_| Some(0));
        });
        assert_eq!(w.items.len(), 4);
        let v = w.judge(&all(&w), None);
        assert_eq!(v.valid[0], true);
        assert_eq!(v.valid[2], false);
        if let Kind::Addendum { lists, .. } = &w.items[3].kind {
            assert_eq!(lists, &vec![1]);
        }
    }

    /// The thief's fork counts until the owner's merge; two merges are a dispute, read by side.
    #[test]
    fn thief_fork_and_dispute() {
        let w = world(|b| {
            b.rotate(0, 3, 1, |n| if n == X { None } else { Some(0) });
            b.rotate_x(4, 10, |_| Some(0));
            b.add(Kind::Content { plain: true }, X, Some(10), 5, 5, vec![5; 5], true);
            b.rotate(0, 6, 30, |_| Some(0));
            b.rotate_x(7, 40, |_| Some(0));
        });
        let fork_only: Vec<bool> = vec![true, true, true, false, false];
        assert!(w.judge(&fork_only, None).valid[2], "fork counts before the merge");
        let merged: Vec<bool> = vec![true, true, true, true, false];
        assert!(!w.judge(&merged, None).valid[2]);
        let both = all(&w);
        let v = w.judge(&both, Some(3));
        assert!(v.dispute && !v.valid[2] && v.counting[0] && !v.counting[1]);
        let vx = w.judge(&both, Some(4));
        assert!(vx.dispute && vx.valid[2] && !vx.counting[3] && vx.counting[1] && vx.counting[4]);
    }

    /// Account-level demotion and the epoch filter are independent conjuncts.
    #[test]
    fn demotion_and_epoch_independent() {
        let g = Gen { np: 2, nw: 0, admin: true, tr: 3, t_max: 8, omit_covered: false };
        let mut b = Builder::new(&g);
        // listed by the rotation, but not by A's demotion
        b.add(Kind::Content { plain: true }, 0, Some(0), 1, 1, vec![1, 1, LATE, 1], false);
        b.rotate(0, 3, 1, |_| Some(0));
        b.add(Kind::Demotion { frontier: vec![] }, 2, None, 5, 5, vec![5, 5, 5, 5], false);
        let w = b.w;
        let v = w.judge(&all(&w), None);
        assert!(v.as_p[0] && !v.valid[0]);
    }

    #[test]
    fn random_worlds_hold() {
        let mut rng = Rng(7);
        let mut st = Stats::default();
        for _ in 0..3000 {
            let w = random_world(&mut rng);
            check(&w, &mut st);
        }
        if let Some(w) = &st.fail {
            print_world(w);
        }
        assert_eq!(st.hard_failures(), 0, "{st:?}");
    }
}

