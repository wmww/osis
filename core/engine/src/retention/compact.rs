//! The compaction trigger (spec/sync.md §7 Trigger), one for durable and ephemeral aspects: a
//! node that may write a content aspect writes a snapshot of it once the bodies it holds of it
//! that the snapshot would drop, two at least, cost more than `FACTOR` times the snapshot. What a
//! body costs is what dropping it frees, what holders and hosts pay for it: its deltas' bytes,
//! the pages they link, the tree blobs its values link that no live state links (`body_bytes`,
//! `freed_under`), `PART_OVERHEAD` per part (`apply::memory::part_weight`, what the node cap
//! charges) and `ENTRY_CHARGE`. Bodies kept by history (a replaced one in history, a live one
//! kept while live, spec/commits.md §5) are not counted: no snapshot drops them; nor are bodies a
//! held snapshot already covers (`covered_already`): they drop without a new one. An aspect
//! holding an expired write's leftover is also compacted once quiet for `QUIET_MS`, whatever
//! `FACTOR` says (`Trigger::quiet`): the snapshot is the leftover's only carrier.

use crate::apply::memory::{each_page, part_weight};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, BlobId, CommitId, Link, Tid};
use osis_commit::{CommitBlob, Form, Header};
use std::collections::{BTreeMap, BTreeSet};

/// A node compacts an aspect once the bodies held of it a snapshot would drop cost more than
/// this many times the snapshot (spec/sync.md §7 Trigger). Performance switch between correct
/// strategies: 0 compacts whenever two bodies are held (at every write), infinity never (live
/// bodies pile up: a map's every key written apart keeps its own body, an ephemeral aspect's
/// pile up to the node and host caps, past which entries are refused). Snapshots cost O(1) per
/// byte written, amortized, for any value above 1; a host cap of this many times the sum of the
/// aspects' snapshots holds every ephemeral entry.
pub const FACTOR: usize = 2;

/// Bytes charged per held commit besides its parts (`part_weight`) when a node weighs the bodies
/// it holds against their snapshot: about a host's per-entry and log record overhead plus the
/// commit header. Performance switch: 0 lets small writes pile up as entries whose overhead
/// dwarfs their bytes (a host's cap fills with overhead the trigger never sees), infinity
/// compacts at every write.
pub const ENTRY_CHARGE: usize = 1024;

/// How long an aspect with a leftover held here must be quiet (no write held, no expiry) before
/// this node covers its leftovers whatever `FACTOR` says (spec/sync.md §7 Trigger, cover once
/// quiet): `MAX_DRIFT`, the window in which nodes may already read an expiring write
/// differently by their clocks. 0 is one snapshot per expiry (a collection of expiring elements
/// pays its whole state per element), infinity never covers (a node that missed the write
/// reads differently for good).
pub const QUIET_MS: u64 = osis_base::format::MAX_DRIFT_MS;

/// Whether the trigger compacts `ak`: content (not role-class, `created.0` or `retention^.0`),
/// no fixed retention, not a signal (no state).
pub(crate) fn compactable(ak: &Ak) -> bool {
    osis_schema::core_types::is_content(ak.as_str()) && osis_commit::retention::fixed_retention(ak.as_str()).is_none() && !ak.signal()
}

/// The trigger's state per aspect, in memory. An aspect is weighed (its bodies read) only once
/// what it may hold (`Est::held`: the cost found when last weighed plus every body counted
/// since) passes `FACTOR` times the snapshot cost last found, so the work of weighing is O(1)
/// per byte written, amortized; a change that may let bodies count without a write (a validity
/// flip, an expiry, a setting) asks for a weighing (`weigh`). Bodies held behind a gap in their
/// session count once a held body or snapshot passes it (`Est::stops`, `Trigger::gap_passed`).
#[derive(Clone, Debug, Default)]
pub struct Trigger {
    est: BTreeMap<(Tid, Ak), Est>,
    /// Aspects whose `est` grew, or asked to be weighed, since the last step.
    due: BTreeSet<(Tid, Ak)>,
    /// Aspects weighed at the next step whatever their `est`.
    forced: BTreeSet<(Tid, Ak)>,
    /// By wall ms, aspects whose live bodies a setting keeps until then (a `keep` until T
    /// alone): uncounted when applied, weighed once the bound passes (`Engine::tick`).
    at: BTreeMap<u64, BTreeSet<(Tid, Ak)>>,
    /// Per aspect holding a value-less write here, when it will have been quiet for `QUIET_MS`
    /// (wall ms): a write held or an expiry on it moves that on (`stirred`); a snapshot does
    /// not, so writers' quiet snapshots never set each other off. `quiet_at` orders them.
    quiet: BTreeMap<(Tid, Ak), u64>,
    quiet_at: BTreeSet<(u64, (Tid, Ak))>,
    /// Aspects quiet since the last step: weighed then, and a leftover a snapshot would drop
    /// fires it whatever `FACTOR` says (`Engine::compactions`).
    quiet_due: BTreeSet<(Tid, Ak)>,
}

/// What the trigger knows of an aspect (`Trigger::est`).
#[derive(Clone, Debug, Default)]
struct Est {
    /// The held cost found when last weighed (0 after a snapshot) plus the cost of every body
    /// counted since.
    held: usize,
    /// The snapshot cost found then.
    snapshot: usize,
    /// Per session source with bodies held behind a gap when last weighed: the first counter its
    /// frontier walk did not pass (`snapshot::walk_source`; a missing, invalid or purged body, or
    /// counters not held). A body behind it counts for nothing (no snapshot drops it) until a
    /// held body or snapshot passes the gap (`Trigger::gap_passed`), which counts every body the walk
    /// then passes: O(the bodies that start to count), so a gap that stays costs writes nothing
    /// and one closed bit by bit costs each body once.
    stops: Stops,
    /// Weighed while this node could not write the aspect: weighed again whatever the estimate
    /// once it may (`Trigger::wake`), `quiet` when the quiet rule asked it (`Trigger::quiet`).
    owed: bool,
    quiet: bool,
}

impl Trigger {
    /// Notes the bodies of applied commit `blob` (`id`, header `h`): each part on a compactable
    /// aspect is held (`part_held`).
    pub(crate) fn applied(tx: &mut Tx<'_>, id: &CommitId, h: &Header, blob: &CommitBlob) -> Result<()> {
        for ai in 0..h.aspects.len() {
            Trigger::part_held(tx, id, h, blob, ai)?;
        }
        Ok(())
    }

    /// Part `ai` of commit `id` (header `h`, blob `blob`) is held from now on, applied or late:
    /// what its aspect may hold grows by its cost (`counts`). A snapshot adds nothing of its own:
    /// only writes make one stale, and only what they add makes the trigger weigh (so two
    /// writers never compact each other's snapshots in turn); but its frontier may pass a gap
    /// bodies were held behind, and a body may fill one: those bodies count then (`gap_passed`). A
    /// body behind a gap counts for nothing.
    pub(crate) fn part_held(tx: &mut Tx<'_>, id: &CommitId, h: &Header, blob: &CommitBlob, ai: usize) -> Result<()> {
        let Some(a) = h.aspects.get(ai) else { return Ok(()) };
        if !compactable(&a.ak) {
            return Ok(());
        }
        let k = (a.tid, a.ak.clone());
        if h.kind.is_compaction() {
            return Trigger::snapshot_held(tx, id, &k);
        }
        Trigger::stirred(tx, &k);
        if !h.kind.has_own_writes() {
            return Ok(());
        }
        if let Some(crate::engine::Owned::Range { src, lo, hi }) = crate::engine::Owned::of(h, id, ai)
            && let Some(stop) = tx.core.compaction.est.get(&k).and_then(|e| e.stops.get(&src)).copied()
        {
            // it fills the gap (holds its first counter), or may pass it as a durable own whole
            // replace: the walk goes on from the gap (a replace passes it only as the first
            // range held past it, as in the writer's walk)
            let fills = lo <= stop && stop < hi || lo > stop && !a.ak.ephemeral() && super::snapshot::own_replace(tx.core, id, &k.0, &k.1);
            if fills {
                return Trigger::gap_passed(tx, &k, &src, stop, lo.min(stop), Some((id, blob)));
            }
            if lo > stop {
                return Ok(());
            }
        }
        Trigger::held_counts(tx, id, &k, blob, ai)
    }

    /// Snapshot `s` on `k` is held: each source whose gap its frontier passes counts the bodies
    /// held behind it (`gap_passed`).
    fn snapshot_held(tx: &mut Tx<'_>, s: &CommitId, k: &(Tid, Ak)) -> Result<()> {
        let Some(stops) = tx.core.compaction.est.get(k).map(|e| e.stops.clone()).filter(|x| !x.is_empty()) else { return Ok(()) };
        if !super::snapshot::claims(tx.core, s, &k.0, &k.1, tx.now().0) {
            return Ok(());
        }
        let Some(fr) = tx.core.ix.snapshots.get(k).and_then(|v| v.iter().find(|x| x.1 == *s)).map(|x| x.2.clone()) else { return Ok(()) };
        for (src, stop) in stops {
            let f = fr.of(&src);
            if f >= stop {
                Trigger::gap_passed(tx, k, &src, f.saturating_add(1), stop, None)?;
            }
        }
        Ok(())
    }

    /// A gap of session `src` on `k` is passed: its frontier walk goes on from `next` (its first
    /// counter not reflected now) through the held ranges starting at `from` on
    /// (`snapshot::walk_source`, the writer's own walk). Each body it passes counts
    /// (`held_counts`; `filler`, the one passing it, by its blob in hand), and the source's stop
    /// moves to where the walk stops, if it does. O(the bodies passed).
    fn gap_passed(tx: &mut Tx<'_>, k: &(Tid, Ak), src: &osis_crdt::Source, next: u64, from: u64, filler: Option<(&CommitId, &CommitBlob)>) -> Result<()> {
        let now = tx.now().0;
        let mut passed = Vec::new();
        let (stop, stopped) = {
            let core = &*tx.core;
            let valid_on = |c: &CommitId| super::snapshot::claims(core, c, &k.0, &k.1, now);
            let ranges = core.ix.ranges.get(&(k.0, k.1.clone(), src.clone())).into_iter().flat_map(|r| r.range((from, CommitId([0; 32]))..));
            let resets = |c: &CommitId| !k.1.ephemeral() && super::snapshot::own_replace(core, c, &k.0, &k.1);
            super::snapshot::walk_source(&valid_on, &resets, ranges, next, u64::MAX, &mut |c| passed.push(c))
        };
        if let Some(e) = tx.core.compaction.est.get_mut(k) {
            if stopped {
                e.stops.insert(src.clone(), stop);
            } else {
                e.stops.remove(src);
            }
        }
        for c in passed {
            let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(&k.0, &k.1)) else { continue };
            match filler {
                Some((f, b)) if *f == c => Trigger::held_counts(tx, &c, k, b, ai)?,
                _ => {
                    if let Some(b) = tx.get_commit(&c)? {
                        Trigger::held_counts(tx, &c, k, &b, ai)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// `counts` for a held part, unless its setting keeps it while live (spec/commits.md §5 Kept
    /// while live) and it is in history, as the weighing looks at it (`droppable`): no
    /// snapshot's to drop, it counts once it leaves history (`leaving::left`) or the live bound
    /// passes. One passed by a gap may have left already, uncounted then (`Est::stops`).
    fn held_counts(tx: &mut Tx<'_>, c: &CommitId, k: &(Tid, Ak), blob: &CommitBlob, ai: usize) -> Result<()> {
        let live = super::history::of(tx.core, &k.0, &k.1).live_until();
        if live > tx.now().0 && !super::leaving::out_of_history(tx.core, c, &k.0, &k.1) && !super::valueless(tx.core, c, ai) {
            Trigger::live_until(tx, k.clone(), live);
            return Ok(());
        }
        Trigger::counts(tx, c, &k.0, &k.1, blob, ai)
    }

    /// Part `ai` of `blob` (commit `c`) on `(tid, ak)` may count for the trigger from now on
    /// (applied, or out of history): what `(tid, ak)` may hold grows by its deltas' cost; by
    /// nothing where no cover drops it (`retention::drops_as_covered`: a purge's leftover), as
    /// the weighing counts it. Its tree blobs a drop frees are those the joins since unlinked,
    /// counted as they unlink them (`unlinked`). A snapshot (out of history) counts no deltas,
    /// as the weighing (`Candidate::body`); a body behind a gap of its session (`Est::stops`)
    /// nothing.
    pub(crate) fn counts(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, blob: &CommitBlob, ai: usize) -> Result<()> {
        let now = tx.now().0;
        if !compactable(ak) || tx.core.ix.commits.get(c).is_some_and(|m| !super::drops_as_covered(m, ai, now)) {
            return Ok(());
        }
        let k = (*tid, ak.clone());
        if let Some(crate::engine::Owned::Range { src, lo, .. }) = crate::engine::Owned::of(&blob.header, c, ai)
            && tx.core.compaction.est.get(&k).and_then(|e| e.stops.get(&src)).is_some_and(|stop| lo > *stop)
        {
            return Ok(());
        }
        if blob.header.kind.is_compaction() {
            return Ok(());
        }
        let w = body_bytes(tx, blob, ai)?;
        tx.core.compaction.add((*tid, ak.clone()), part_weight(w.bytes).saturating_add(ENTRY_CHARGE));
        Ok(())
    }

    fn add(&mut self, k: (Tid, Ak), cost: usize) {
        let e = self.est.entry(k.clone()).or_default();
        e.held = e.held.saturating_add(cost);
        self.due.insert(k);
    }

    /// A join on `(tid, ak)` turned the large values its reach linked from `before` to `after`
    /// (`roots`): what `(tid, ak)` may hold grows by the bytes of the trees it unlinked that the
    /// new ones do not link (an edit's replaced chunks, a large value set to a small one's whole
    /// tree), which a drop of the bodies linking them frees (`unlinked_len`).
    pub(crate) fn unlinked(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, before: &BTreeMap<BlobId, Link>, after: &BTreeMap<BlobId, Link>) -> Result<()> {
        let gone: Vec<Link> = before.values().filter(|l| !after.contains_key(&l.blob)).copied().collect();
        if gone.is_empty() {
            return Ok(());
        }
        let new: Vec<Link> = after.values().filter(|l| !before.contains_key(&l.blob)).copied().collect();
        let len = unlinked_len(tx, &gone, &new)?;
        if len > 0 {
            tx.core.compaction.add((*tid, ak.clone()), usize::try_from(len).unwrap_or(usize::MAX));
        }
        Ok(())
    }

    /// `k` keeps its live bodies until wall ms `live` (past the clock): weighed then, unless
    /// that is never.
    pub(crate) fn live_until(tx: &mut Tx<'_>, k: (Tid, Ak), live: u64) {
        if live < osis_commit::retention::NEVER && compactable(&k.1) {
            tx.core.compaction.at.entry(live).or_default().insert(k);
            tx.core.timer_floor = tx.core.timer_floor.min(live);
        }
    }

    /// A write was held on `k` or one of its writes expired (or turned valid or invalid): where
    /// `k` holds a value-less write here, its quiet time starts again (`quiet`). O(log aspects).
    pub(crate) fn stirred(tx: &mut Tx<'_>, k: &(Tid, Ak)) {
        if !compactable(&k.1) || tx.core.ix.valueless.get(k).is_none_or(|l| l.is_empty()) {
            return;
        }
        let at = tx.now().0.saturating_add(QUIET_MS);
        tx.core.compaction.arm(k.clone(), at);
        tx.core.timer_floor = tx.core.timer_floor.min(at);
    }

    /// `k` is quiet at wall ms `at` unless stirred again before.
    pub(crate) fn arm(&mut self, k: (Tid, Ak), at: u64) {
        if let Some(old) = self.quiet.insert(k.clone(), at) {
            self.quiet_at.remove(&(old, k.clone()));
        }
        self.quiet_at.insert((at, k));
    }

    /// Asks a weighing of every aspect whose live bound passed by `now` (`at`).
    pub(crate) fn passed(&mut self, now: u64) {
        let later = self.at.split_off(&now.saturating_add(1));
        for k in std::mem::replace(&mut self.at, later).into_values().flatten() {
            self.weigh(k);
        }
    }

    /// Asks a weighing, for the quiet rule, of every aspect whose quiet time passed by `now`
    /// (`quiet`). After the expiries due by `now` ran: one stirs its aspect again.
    pub(crate) fn quiet_passed(&mut self, now: u64) {
        while let Some((at, k)) = self.quiet_at.first().cloned().filter(|x| x.0 <= now) {
            self.quiet_at.remove(&(at, k.clone()));
            self.quiet.remove(&k);
            self.quiet_due.insert(k.clone());
            self.weigh(k);
        }
    }

    /// When the first live bound in `at` or quiet time passes (`u64::MAX`: none).
    pub(crate) fn next_at(&self) -> u64 {
        let live = self.at.keys().next().copied().unwrap_or(u64::MAX);
        live.min(self.quiet_at.first().map_or(u64::MAX, |x| x.0))
    }

    /// `k` was due at a node that may not write it: owed a weighing once it may (`wake`), its
    /// estimate kept (`quiet`: the quiet rule asked it).
    pub(crate) fn owe(&mut self, k: (Tid, Ak), quiet: bool) {
        let e = self.est.entry(k).or_default();
        e.owed = true;
        e.quiet |= quiet;
    }

    /// This node may now write on `t` (a role, its minting or delete keys arrived): each aspect
    /// of `t` owed a weighing (`owe`) is weighed at the next step. O(log aspects) plus `t`'s
    /// estimates; nothing for an aspect not owed one.
    pub(crate) fn wake(&mut self, t: &Tid) {
        let owed: Vec<((Tid, Ak), bool)> = self.est.range((*t, Ak::MIN)..).take_while(|(k, _)| k.0 == *t).filter(|(_, e)| e.owed).map(|(k, e)| (k.clone(), e.quiet)).collect();
        for (k, quiet) in owed {
            if quiet {
                self.quiet_due.insert(k.clone());
            }
            self.weigh(k);
        }
    }

    /// `k` is weighed at the next step whatever its estimate.
    pub(crate) fn weigh(&mut self, k: (Tid, Ak)) {
        if compactable(&k.1) {
            self.forced.insert(k.clone());
            self.due.insert(k);
        }
    }
}

/// The large values state `st` links at delta `d`'s reach, by root (`Trigger::unlinked`); none
/// where `ak` is not compactable.
pub(crate) fn roots(ak: &Ak, st: &osis_crdt::Fragment, d: &osis_crdt::Fragment) -> BTreeMap<BlobId, Link> {
    let mut v = Vec::new();
    if compactable(ak) {
        st.reach(d).values(&mut |x| crate::engine::large::links_in(x, &mut v));
    }
    v.into_iter().map(|l| (l.blob, l)).collect()
}

/// One node of a tree as `unlinked_len` walks it: its link, its level (0 a chunk, or a node not
/// held, walked no further) and the plaintext length its parent states under it.
type Walked = (Link, u64, u64);

/// A tree node's level and links with their lengths.
type Node = (u64, Vec<(Link, u64)>);

/// A held tree node (`Node`); `None` when not held or no node (a chunk). Unchecked against its
/// content hash: the trigger's estimate.
fn node_at(tx: &mut Tx<'_>, link: &Link) -> Result<Option<Node>> {
    let Some(blob) = tx.blobs.get(&link.blob)? else { return Ok(None) };
    let Ok((_, pt)) = osis_label::open(&blob, &osis_crypto::Secret32::from_bytes(link.key)) else { return Ok(None) };
    Ok(osis_label::tree::parse_node(&pt).ok())
}

/// A root as `unlinked_len` starts from it: its level and the length its node states.
fn rooted(tx: &mut Tx<'_>, l: &Link) -> Result<Walked> {
    Ok(match node_at(tx, l)? {
        Some((level, kids)) => (*l, level, kids.iter().fold(0u64, |a, (_, n)| a.saturating_add(*n))),
        None => (*l, 0, 0),
    })
}

/// The plaintext bytes under the trees `gone` that the trees `kept` do not hold, by the lengths
/// their nodes state. Both are walked down from their roots, level by level, the higher first,
/// only where they differ: a blob both reach holds the same subtree (a node is immutable), so an
/// edit's walk costs its changed nodes and their links, whatever the value's size; with nothing
/// kept, the roots' lengths alone. Each side reads a blob once, and a node only at the level its
/// parent gives it (else it counts as a chunk of its length), so a hostile tree costs no more
/// than its blobs.
fn unlinked_len(tx: &mut Tx<'_>, gone: &[Link], kept: &[Link]) -> Result<u64> {
    let mut a: Vec<Walked> = gone.iter().map(|l| rooted(tx, l)).collect::<Result<_>>()?;
    let mut b: Vec<Walked> = kept.iter().map(|l| rooted(tx, l)).collect::<Result<_>>()?;
    let (mut seen_a, mut seen_b) = (BTreeSet::new(), BTreeSet::new());
    loop {
        a.retain(|x| seen_a.insert(x.0.blob));
        b.retain(|x| seen_b.insert(x.0.blob));
        a.retain(|x| !seen_b.contains(&x.0.blob));
        b.retain(|x| !seen_a.contains(&x.0.blob));
        let top = a.iter().chain(&b).map(|x| x.1).max().unwrap_or(0);
        if a.is_empty() || b.is_empty() || top == 0 {
            return Ok(a.iter().fold(0u64, |s, x| s.saturating_add(x.2)));
        }
        for side in [&mut a, &mut b] {
            let mut next = Vec::with_capacity(side.len());
            for x in std::mem::take(side) {
                if x.1 < top {
                    next.push(x);
                    continue;
                }
                // a node not held, or not at its level, is walked no further: as a chunk
                match node_at(tx, &x.0)? {
                    Some((level, kids)) if level == x.1 => next.extend(kids.into_iter().map(|(l, n)| (l, level - 1, n))),
                    _ => next.push((x.0, 0, x.2)),
                }
            }
            *side = next;
        }
    }
}

/// What part `ai` of a body weighs before its trees (`body_bytes`).
struct Weighed {
    /// Its deltas' bytes and the pages held here they link.
    bytes: usize,
    /// Those pages.
    pages: BTreeSet<BlobId>,
}

/// What part `ai` of `blob` weighs: its deltas and the pages held here they link
/// (`apply::memory::each_page`), either class. A delta that is not one CBOR value weighs its
/// bytes.
fn body_bytes(tx: &mut Tx<'_>, blob: &CommitBlob, ai: usize) -> Result<Weighed> {
    let mut sum = 0usize;
    let mut pages = BTreeSet::new();
    if let Some(p) = blob.part(ai) {
        sum = sum.saturating_add(p.delta.len());
        let r = each_page(tx, &p.delta, &mut |b, _| {
            sum = sum.saturating_add(b.len());
            pages.insert(osis_label::blob_id(b));
            Ok(())
        });
        match r {
            Ok(()) | Err(Error::BadInput(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Weighed { bytes: sum, pages })
}

/// The blobs under part `ai` of commit `c` (its values' trees, through its pages and held nodes)
/// that no live state of `tid` links, none in `seen` (a blob two bodies link is freed once), not
/// `pages`: what a drop of the part frees of its trees (spec/sync.md §7). The walk stops at a
/// blob a live state links (a node is immutable: its subtree is linked too), so it costs what it
/// frees and the nodes above it. `None` while a live tree is not all held (as
/// `retention::freed` judges, nothing is freed then).
fn freed_under(tx: &mut Tx<'_>, tid: &Tid, c: &CommitId, ai: usize, pages: &BTreeSet<BlobId>, seen: &mut BTreeSet<BlobId>) -> Result<Option<Vec<BlobId>>> {
    let Some(dedup) = tx.core.dedup(tid) else { return Ok(Some(Vec::new())) };
    let mut level: Vec<(Link, bool)> = super::freed::part_links(tx, c, ai)?.into_iter().map(|l| (l, false)).collect();
    let mut out = Vec::new();
    while !level.is_empty() {
        level.retain(|(l, _)| seen.insert(l.blob));
        let ids: BTreeSet<BlobId> = level.iter().map(|(l, _)| l.blob).collect();
        let linked = crate::engine::tree_refs::state_refs_in(tx, tid, &ids)?;
        if !linked.missing.is_empty() {
            return Ok(None);
        }
        let mut next = Vec::new();
        for (l, leaf) in std::mem::take(&mut level) {
            if linked.blobs.contains(&l.blob) {
                continue;
            }
            if !pages.contains(&l.blob) {
                out.push(l.blob);
            }
            if leaf {
                continue;
            }
            if let Some(b) = tx.blobs.get(&l.blob)?
                && let Some((chunks, kids)) = crate::engine::large::kids_of(Some(&dedup), &l, &b)
            {
                next.extend(kids.into_iter().map(|k| (k, chunks)));
            }
        }
        level = next;
    }
    Ok(Some(out))
}

/// The bytes of the blobs among `blobs` held here, by length (none read).
fn held_bytes<'b>(tx: &mut Tx<'_>, blobs: impl Iterator<Item = &'b BlobId>) -> Result<usize> {
    let mut sum = 0usize;
    let mut n = 0u64;
    for b in blobs {
        n += 1;
        if tx.blobs.held(b)? {
            sum = sum.saturating_add(tx.blobs.len(b)?.map_or(0, |l| usize::try_from(l).unwrap_or(usize::MAX)));
        }
    }
    // counted: tests read that the trigger's work per write is flat in a value's size
    crate::costs::count("compact: tree blobs sized", n);
    Ok(sum)
}

/// The bodies held of `(tid, ak)` a snapshot written now would cover and drop, with their part
/// and its cost: those a cover drops (`retention::drops_as_covered`, the drop's own judgment: a
/// purge's leftover stays), whose writes the snapshot claims (its frontier walk passes them or
/// `Absorbed` lists them: `snapshot::claims`, the writer's own judgment; not one behind an
/// invalid, missing or purged body of its session), and not ones with an expiry before it,
/// which a snapshot covers only as their leftover. Counted otherwise, a body no snapshot drops
/// would fire the trigger at every step. A leftover counts as a part with no delta bytes. Also,
/// per session source with a body held behind a gap its walk did not pass, where it stopped
/// (`Est::stops`). Whether each is past its keep bound is the caller's (`Load::of`). Where
/// the setting keeps live bodies, only bodies out of history and leftovers are looked at
/// (`droppable`): kept ones are neither read nor walked past, so a weighing costs what it may
/// drop, not the kept history.
fn candidates(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, me: Tid) -> Result<(Vec<Candidate>, Stops)> {
    let memory = ak.ephemeral();
    let now = tx.now().0;
    let pool = droppable(tx, tid, ak);
    // (commit, part, judged by ID, a snapshot, a leftover)
    let ids: Vec<(CommitId, usize, bool, bool, bool)> = pool
        .into_iter()
        .filter_map(|c| {
            let m = tx.core.ix.commits.get(&c)?;
            let ai = m.aspect(tid, ak).filter(|ai| m.holds(*ai) && m.valid_at(*ai) && super::drops_as_covered(m, *ai, now))?;
            m.header.aspects.get(ai).filter(|_| m.header.expires.is_none() || m.bare(ai))?;
            let snapshot = m.view.kind.is_compaction();
            Some((c, ai, super::snapshot::by_id(m.header.kind, m.header.form), snapshot, !snapshot && m.header.expires.is_some()))
        })
        .collect();
    // counted: tests read how many bodies the trigger weighs
    crate::costs::count("compact: bodies weighed", ids.len() as u64);
    // per session source of a candidate, the last counter to walk to
    let mut upto: BTreeMap<osis_crdt::Source, u64> = BTreeMap::new();
    for (c, ai, by_id, snapshot, _) in &ids {
        if *by_id || *snapshot {
            continue;
        }
        if let Some(crate::engine::Owned::Range { src, lo, .. }) = tx.core.ix.commits.get(c).and_then(|m| crate::engine::Owned::of(&m.header, c, *ai)) {
            let e = upto.entry(src).or_insert(lo);
            *e = (*e).max(lo);
        }
    }
    let valid_on = |c: &CommitId| super::snapshot::claims(tx.core, c, tid, ak, now);
    let (frontiers, reflected) = super::snapshot::frontiers_upto(tx, tid, ak, memory, &valid_on, Some(&upto));
    let mut stops = Stops::new();
    // (commit, part, its weight, a snapshot, a leftover)
    let mut weighed = Vec::new();
    for (c, ai, by_id, snapshot, leftover) in ids {
        // a snapshot is no body the trigger counts: each author keeps its own ephemeral one until
        // its next (spec/sync.md §9), so two authors' would make each compact the other's forever.
        // But the tree blobs it links that no live state links go with it when the new snapshot
        // covers it (durable; ephemeral, the author's own): the bulk of a large value's replaced
        // tree, linked by the snapshot that last carried it
        if snapshot && memory && tx.core.ix.commits.get(&c).is_none_or(|m| m.header.author != me) {
            continue;
        }
        if !snapshot && !by_id && !reflected.contains(&c) {
            if let Some(crate::engine::Owned::Range { src, .. }) = tx.core.ix.commits.get(&c).and_then(|m| crate::engine::Owned::of(&m.header, &c, ai)) {
                let stop = frontiers.of(&src).saturating_add(1);
                stops.insert(src, stop);
            }
            continue;
        }
        if !snapshot && !memory && covered_already(tx, &c, ai, tid, ak)? {
            continue;
        }
        let Some(blob) = tx.get_commit(&c)? else { continue };
        weighed.push((c, ai, body_bytes(tx, &blob, ai)?, snapshot, leftover));
    }
    // the tree blobs a drop frees: those no live state of the thing links (the tree memo,
    // `tree_refs::state_refs_in`), none while a tree is not all held (as `retention::freed` judges)
    let mut seen = BTreeSet::new();
    let mut trees = Vec::with_capacity(weighed.len());
    for (c, ai, w, _, _) in &weighed {
        trees.push(freed_under(tx, tid, c, *ai, &w.pages, &mut seen)?);
    }
    let all = trees.iter().all(Option::is_some);
    let mut out = Vec::new();
    for ((c, ai, w, snapshot, leftover), mine) in weighed.into_iter().zip(trees) {
        let mine = mine.filter(|_| all).unwrap_or_default();
        let tree = held_bytes(tx, mine.iter())?;
        let cost = if snapshot { tree } else { part_weight(w.bytes.saturating_add(tree)).saturating_add(ENTRY_CHARGE) };
        if cost > 0 {
            out.push(Candidate { c, ai, cost, body: !snapshot, leftover });
        }
    }
    Ok((out, stops))
}

/// Whether a held valid content snapshot of `(tid, ak)` already covers durable body `c` (part
/// `ai`) so that it drops whether or not this node writes one (node-sync's covered drops, the
/// compaction agreement): a new snapshot frees nothing by it, and counting it would make the
/// trigger turn on whether a redundant body (a stale host's, a lagging holder's) passed through
/// before its drop. A live own body that is not replaced drops only under an own snapshot
/// (spec/sync.md §9 Own bodies), so another node's snapshot leaves it counted.
fn covered_already(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<bool> {
    let own = |tx: &Tx<'_>, x: &CommitId| tx.core.ix.commits.get(x).is_some_and(|m| m.origin == crate::events::Origin::Local);
    let snaps: Vec<CommitId> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).filter(|s| s != c).collect();
    let mut own_live = None;
    for s in snaps {
        let held = tx.core.ix.commits.get(&s).is_some_and(|m| m.view.kind.is_compaction() && m.aspect(tid, ak).is_some_and(|si| !m.body_gone(si) && !m.missing(si) && m.valid_at(si)));
        if !held {
            continue;
        }
        if !own(tx, &s) && own(tx, c) {
            let kept = match own_live {
                Some(k) => k,
                // as `Engine::replaced`: a bare part is never replaced
                None => {
                    let bare = tx.core.ix.commits.get(c).is_none_or(|m| m.bare(ai));
                    *own_live.insert(bare || !super::replace::replaced(tx, c, ai, tid, ak)?)
                }
            };
            if kept {
                continue;
            }
        }
        if super::snapshot::covered(tx, &s, c, tid, ak)? == Some(true) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Per session source, the first counter its frontier walk did not pass (`Est::stops`).
type Stops = BTreeMap<osis_crdt::Source, u64>;

/// What a snapshot written now would drop of one held body (`candidates`).
struct Candidate {
    c: CommitId,
    ai: usize,
    /// What the drop frees.
    cost: usize,
    /// A body the trigger counts (not a snapshot: only its replaced tree blobs count).
    body: bool,
    /// An expired write's leftover (held value-less past its expiry).
    leftover: bool,
}

/// The held bodies of `(tid, ak)` a snapshot may drop now. Where its setting keeps live bodies
/// (spec/commits.md §5 Kept while live), a body is kept while live or in history, so only the
/// replaced ones out of history (`leaving` rows up to the cursor) and the leftovers (value-less,
/// named by `Indexes::valueless`) may go; elsewhere every held body (history then keeps only
/// under a setting that changed, or a purge floor: `Load::of` reads the keep bounds).
fn droppable(tx: &Tx<'_>, tid: &Tid, ak: &Ak) -> BTreeSet<CommitId> {
    let key = (*tid, ak.clone());
    let ix = &tx.core.ix;
    if super::history::of(tx.core, tid, ak).live_until() <= tx.now().0 {
        return ix.by_aspect.get(&key).into_iter().flatten().map(|(_, c)| *c).collect();
    }
    let mut out = BTreeSet::new();
    if let Some((_, Some(last))) = ix.leave_from.get(&key).copied() {
        out.extend(ix.leaving.get(&key).into_iter().flat_map(|s| s.range(..=last)).map(|p| p.1));
    }
    for o in ix.valueless.get(&key).into_iter().flatten() {
        match o {
            crate::engine::Owned::Commit(c) => {
                out.insert(*c);
            }
            crate::engine::Owned::Range { src, lo, .. } => {
                let r = ix.ranges.get(&(*tid, ak.clone(), src.clone()));
                out.extend(r.into_iter().flat_map(|m| m.range((*lo, CommitId([0; 32]))..)).take_while(|((l, _), _)| l == lo).map(|((_, c), _)| *c));
            }
            crate::engine::Owned::Dots { src, ctrs } => {
                let Some(r) = ix.ranges.get(&(*tid, ak.clone(), src.clone())) else { continue };
                for ctr in ctrs {
                    // the range holding the counter
                    out.extend(r.range(..=(*ctr, CommitId([0xff; 32]))).next_back().filter(|(_, hi)| *ctr < **hi).map(|((_, c), _)| *c));
                }
            }
        }
    }
    out
}

/// What a snapshot of `(tid, ak)` would cost as a held body: its state (the expiring writes
/// value-less) encoded, weighed as a part plus `ENTRY_CHARGE`. `None`: no state.
fn snapshot_cost(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, me: Tid) -> Result<Option<usize>> {
    let Some(st) = super::snapshot_state(tx, tid, ak)? else { return Ok(None) };
    let cx = osis_commit::writer_ctx(Form::Commit, osis_commit::Kind::ContentSnapshot, osis_base::Ts::default(), me, 0, 0);
    let s = osis_crdt::Snapshot { nonce: [0; osis_crdt::NONCE_LEN], fragment: st, frontiers: osis_crdt::Frontiers::default(), absorbed: BTreeMap::new(), facts: Default::default() };
    // encoding fails only on a malformed fragment: counted as nothing
    let bytes = osis_crdt::encode_snapshot(&s, &cx, Some(&mut osis_crdt::Unpaged)).unwrap_or_default();
    Ok(Some(part_weight(bytes.len()).saturating_add(ENTRY_CHARGE)))
}

/// An aspect's load at this node (`Engine::compaction_load`): what the bodies held of it a
/// snapshot would drop cost (`held`), what the snapshot would (`snapshot`), the costliest body and
/// how many, and how many of those are expired writes' leftovers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Load {
    pub tid: Tid,
    pub ak: Ak,
    pub held: usize,
    pub snapshot: usize,
    pub largest: usize,
    pub bodies: usize,
    pub leftovers: usize,
}

impl Load {
    /// What the bodies held of `(tid, ak)` a snapshot written now would drop cost (`candidates`
    /// past their keep-at-least bound, a live one kept while live included, read from the
    /// per-commit memo: one judgment per commit), and what the snapshot would, in the class of
    /// its aspect, with where its sources' walks stopped short of held bodies (`Est::stops`).
    /// `None`: no state.
    fn of(e: &mut Engine, tid: &Tid, ak: &Ak, me: Tid) -> Result<Option<(Load, Stops)>> {
        let class = |tx: &mut Tx<'_>| {
            if ak.ephemeral() {
                tx.set_memory();
            }
        };
        let (cands, stops) = e.run(|tx| {
            class(tx);
            candidates(tx, tid, ak, me)
        })?;
        let now = e.now().0;
        let (mut held, mut largest, mut bodies, mut leftovers) = (0usize, 0usize, 0usize, 0usize);
        for Candidate { c, ai, cost, body, leftover } in cands {
            if e.part_keeps(&c)?.get(ai).copied().unwrap_or(0) > now {
                continue;
            }
            held = held.saturating_add(cost);
            if body {
                largest = largest.max(cost);
                bodies += 1;
            }
            leftovers += usize::from(leftover);
        }
        let Some(snapshot) = e.run(|tx| {
            class(tx);
            snapshot_cost(tx, tid, ak, me)
        })?
        else {
            return Ok(None);
        };
        Ok(Some((Load { tid: *tid, ak: ak.clone(), held, snapshot, largest, bodies, leftovers }, stops)))
    }
}

/// Whether this node may write a snapshot of `k` now (`snapshot::may_snapshot`). Where it may not,
/// `k` is owed a weighing (`Trigger::owe`, `quiet` for the quiet rule) that what lets it write
/// wakes (`Trigger::wake`): its minting or delete keys arriving (`Later`: the thing waits in
/// `Indexes::cover_waits`, `replace::wake_covers`) or a role moving above it
/// (`Core::timelines_changed`).
fn owe_unwritable(tx: &mut Tx<'_>, k: &(Tid, Ak), quiet: bool) -> Result<bool> {
    use crate::engine::write::MayWrite;
    let may = super::snapshot::may_snapshot(tx, &k.0, &k.1, k.1.ephemeral(), tx.core.hlc.peek())?;
    if may == MayWrite::Later {
        super::replace::await_cover(tx.core, &k.0);
    }
    if may != MayWrite::Yes {
        tx.core.compaction.owe(k.clone(), quiet);
    }
    Ok(may == MayWrite::Yes)
}

impl Engine {
    /// The compaction trigger (spec/sync.md §7 Trigger), at each step: every aspect due whose
    /// estimate passes `FACTOR` times its last snapshot cost (or asked to be weighed) is weighed,
    /// and where the bodies a snapshot would drop, two at least, cost more than `FACTOR` times
    /// it, or where the aspect has been quiet for `QUIET_MS` (`Trigger::quiet`) and holds an
    /// expired write's leftover a snapshot would drop, this node writes the snapshot if it may
    /// write the aspect (`snapshot`). Returns the
    /// snapshots written, by aspect: an ephemeral one's covered bodies are dropped as it applies
    /// (`retention::memory::drop_covered`), a durable one's by node-sync.
    pub fn compactions(&mut self) -> Result<Vec<(Tid, Ak, CommitId)>> {
        let due = std::mem::take(&mut self.core.compaction.due);
        let forced = std::mem::take(&mut self.core.compaction.forced);
        let quiet = std::mem::take(&mut self.core.compaction.quiet_due);
        let mut out = Vec::new();
        for k in due {
            let (est, last) = self.core.compaction.est.get(&k).map_or((0, 0), |e| (e.held, e.snapshot));
            if !forced.contains(&k) && est <= FACTOR.saturating_mul(last) {
                continue;
            }
            let (tid, ak) = k.clone();
            // an aspect of one body or none has nothing to compact: weighed again at its next write
            if self.core.created(&tid).is_none() || self.core.ix.by_aspect.get(&k).is_none_or(|s| s.len() <= 1) {
                self.core.compaction.est.remove(&k);
                continue;
            }
            // a node that may not write the aspect leaves compaction to one that may, and owes
            // the weighing for when it may (`owe_unwritable`)
            if !self.run(|tx| owe_unwritable(tx, &k, quiet.contains(&k)))? {
                continue;
            }
            let Ok(me) = self.core.writer_for(&tid) else { continue };
            let quiet_owed = self.core.compaction.est.get(&k).is_some_and(|e| e.quiet);
            // counted: tests read how often the trigger weighs and fires per write
            crate::costs::count("compact: aspects weighed", 1);
            let Some((l, stops)) = Load::of(self, &tid, &ak, me)? else {
                self.core.compaction.est.remove(&k);
                continue;
            };
            // cover once quiet: a leftover is the one carrier of an expired write's creations and
            // resets to a node that missed it (hosts deleted the body at its expiry)
            let full = l.bodies >= 2 && l.held > FACTOR.saturating_mul(l.snapshot);
            let fire = full || (quiet.contains(&k) || quiet_owed) && l.leftovers > 0;
            let mut held = l.held;
            if fire {
                match self.snapshot(&tid, &ak) {
                    Ok(Some(c)) => {
                        crate::costs::count("compact: snapshots written", 1);
                        if !full {
                            // counted: tests read how often a quiet aspect is covered
                            crate::costs::count("compact: quiet snapshots", 1);
                        }
                        out.push((tid, ak.clone(), c));
                        held = 0;
                    }
                    Ok(None) | Err(Error::Permission { .. }) => {}
                    Err(e) => return Err(e),
                }
            }
            // an aspect of one body or none weighs again at its next write (O(1)): nothing kept
            if self.core.ix.by_aspect.get(&k).is_none_or(|s| s.len() <= 1) {
                self.core.compaction.est.remove(&k);
            } else {
                self.core.compaction.est.insert(k, Est { held, snapshot: l.snapshot, stops, owed: false, quiet: false });
            }
        }
        Ok(out)
    }

    /// At open: every compactable aspect of more than one body that this node may not write
    /// now is owed a weighing for when it may (`owe_unwritable`). The trigger kept every aspect
    /// it may write within `FACTOR` before; those it may not it could not, and what woke them
    /// went with the estimates. O(the aspects), no body read.
    pub(crate) fn owe_unwritable_held(&mut self) -> Result<()> {
        let aspects: Vec<(Tid, Ak)> = self.core.ix.by_aspect.iter().filter(|(k, s)| compactable(&k.1) && s.len() > 1).map(|(k, _)| k.clone()).collect();
        self.run(|tx| {
            for k in &aspects {
                if tx.core.created(&k.0).is_some() {
                    owe_unwritable(tx, k, false)?;
                }
            }
            Ok(())
        })
    }

    /// Tests: snapshots every ephemeral aspect held here with a body a snapshot may cover, now.
    #[doc(hidden)]
    pub fn compact_memory_now(&mut self) -> Result<Vec<CommitId>> {
        let aspects: Vec<(Tid, Ak)> = self.core.ix.by_aspect.iter().filter(|(k, s)| k.1.ephemeral() && s.iter().any(|(_, c)| self.holds_memory(c))).map(|(k, _)| k.clone()).collect();
        let mut out = Vec::new();
        for (tid, ak) in aspects {
            if self.core.created(&tid).is_none() || !compactable(&ak) {
                continue;
            }
            let Ok(me) = self.core.writer_for(&tid) else { continue };
            let Some((l, _)) = Load::of(self, &tid, &ak, me)? else { continue };
            if l.bodies == 0 {
                continue;
            }
            match self.snapshot(&tid, &ak) {
                Ok(Some(c)) => out.push(c),
                Ok(None) | Err(Error::Permission { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Per compactable aspect held here, its load (tests, diagnostics: at a writer within
    /// `FACTOR` times the snapshot plus one body once the trigger ran).
    pub fn compaction_load(&mut self) -> Result<Vec<Load>> {
        let aspects: Vec<(Tid, Ak)> = self.core.ix.by_aspect.keys().filter(|k| compactable(&k.1)).cloned().collect();
        let mut out = Vec::new();
        for (tid, ak) in aspects {
            if self.core.created(&tid).is_none() {
                continue;
            }
            let Ok(me) = self.core.writer_for(&tid) else { continue };
            if let Some((l, _)) = Load::of(self, &tid, &ak, me)? {
                out.push(l);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_base::Value;

    /// Sets key `k` of thing `t`'s ephemeral `x:m+.0` to `v`.
    fn put(e: &mut Engine, t: Tid, k: &str, v: &str) -> CommitId {
        let mut m = Mutation::new();
        m.op(t, &Ak::new("x:m+.0").unwrap(), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Str(k.into()))], op: osis_crdt::Op::Set(Value::Str(v.into())) }).unwrap();
        e.commit_in_memory(m).unwrap().unwrap()
    }

    fn gap_load(e: &mut Engine) -> Load {
        e.compaction_load().unwrap().into_iter().find(|l| l.ak.as_str() == "x:m+.0").unwrap()
    }

    /// The trigger's step at `e`: (aspects weighed, snapshots written).
    fn step(e: &mut Engine) -> (u64, u64) {
        crate::costs::take();
        e.compactions().unwrap();
        let c = crate::costs::take();
        let get = |k: &str| c.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
        (get("compact: aspects weighed"), get("compact: snapshots written"))
    }

    /// A writer of ephemeral `x:m+.0` with its own session's bodies back after a restart, each
    /// setting key `k` to a new value: `n` bodies, a first snapshot of the first when `snap`,
    /// under history setting `keep` when given. Returns the peer and the packed snapshot (if
    /// any) and bodies, in order, none ingested.
    fn restarted(n: usize, snap: bool, keep: Option<osis_schema::History>) -> (LocalPeer, Option<Vec<u8>>, Vec<Vec<u8>>) {
        let mut lp = LocalPeer::fresh(1, osis_base::WallMs(1_700_000_000_000));
        let p = &mut lp.peers[0];
        let me = p.engine.me();
        let mut m = Mutation::new();
        let t = p.engine.new_thing(&mut m, me);
        if let Some(h) = keep {
            use osis_schema::core_types as ct;
            m.set(t, &ct::RETENTION, &ct::RetentionSetting::of(Ak::new("x:m+.0").unwrap(), h)).unwrap();
        }
        p.commit(m).unwrap();
        let mut s = None;
        if snap {
            put(&mut p.engine, t, "k0", "v");
            let c = p.engine.compact_memory_now().unwrap();
            assert_eq!(c.len(), 1, "the first body covered");
            s = Some(p.engine.package(&c[0]).unwrap().unwrap().bytes);
        }
        let ids: Vec<CommitId> = (0..n).map(|i| put(&mut p.engine, t, "k", &format!("v{i}"))).collect();
        let bodies = ids.iter().map(|c| p.engine.package(c).unwrap().unwrap().bytes).collect();
        p.restart(7).unwrap();
        (lp, s, bodies)
    }

    // spec/sync.md §7 (Trigger): bodies held behind a gap in their session no frontier passes
    // (the author restarted: its first body went with the snapshot that covered it) count for
    // nothing, and writes behind the gap weigh nothing; once the snapshot that reaches the gap
    // arrives, though it adds nothing of its own and no write follows, they count and the writer
    // compacts them, so what it holds stays within `FACTOR` times a snapshot and one body.
    #[test]
    fn bodies_behind_a_gap_count_once_a_snapshot_passes_it_spec_sync_7() {
        let (mut lp, snap, bodies) = restarted(8, true, None);
        let e = &mut lp.peers[0].engine;
        let mut weighed = 0;
        for (i, b) in bodies.iter().enumerate() {
            e.ingest_memory(b, u64::MAX).unwrap();
            let (w, s) = step(e);
            assert_eq!(s, 0, "no frontier passes the gap");
            // the first two weigh (one body is nothing to compact; then the gap is found)
            if i >= 2 {
                weighed += w;
            }
        }
        assert_eq!(weighed, 0, "bodies behind a known gap weigh nothing");
        assert_eq!(gap_load(e).bodies, 0, "nothing counts behind the gap");
        e.ingest_memory(&snap.unwrap(), u64::MAX).unwrap();
        let l = gap_load(e);
        assert!(l.bodies == 8 && l.held > FACTOR * l.snapshot + l.largest, "the eight count now: {l:?}");
        assert_eq!(step(e), (1, 1), "weighed and compacted at the next step");
        let l = gap_load(e);
        assert!(l.held <= FACTOR * l.snapshot + l.largest, "{l:?}");
    }

    // spec/sync.md §7 (Trigger): a gap closed by its missing body is noticed as it arrives: the
    // bodies held behind it count then and are compacted at the next step. With a body missing
    // at every other counter, filling the gaps one by one counts each body once: the trigger
    // weighs about once per snapshot's worth of bodies passed, not at each fill, at n and 10n.
    #[test]
    fn a_gap_filled_by_its_body_counts_what_it_passes_spec_sync_7() {
        let (mut lp, _, bodies) = restarted(3, false, None);
        let e = &mut lp.peers[0].engine;
        for b in &bodies[1..] {
            e.ingest_memory(b, u64::MAX).unwrap();
            e.compactions().unwrap();
        }
        assert_eq!(gap_load(e).bodies, 0, "behind the gap");
        e.ingest_memory(&bodies[0], u64::MAX).unwrap();
        assert_eq!(step(e), (1, 1), "the gap filled: weighed and compacted at the next step");
        for n in [10, 100] {
            let (mut lp, _, bodies) = restarted(2 * n, false, None);
            let e = &mut lp.peers[0].engine;
            for b in bodies.iter().skip(1).step_by(2) {
                e.ingest_memory(b, u64::MAX).unwrap();
                e.compactions().unwrap();
            }
            let (mut weighed, mut written) = (0, 0);
            for b in bodies.iter().step_by(2) {
                e.ingest_memory(b, u64::MAX).unwrap();
                let (w, s) = step(e);
                (weighed, written) = (weighed + w, written + s);
            }
            let l = gap_load(e);
            assert!(l.held <= FACTOR * l.snapshot + l.largest, "n={n}: {l:?}");
            assert!(written >= 1 && weighed <= n as u64 / 2, "n={n}: {weighed} weighings, {written} snapshots over {n} fills");
        }
    }

    // spec/sync.md §7 (Trigger): where the setting keeps live bodies, those that left history
    // behind a gap count once their missing body fills it, as they would had they left after.
    #[test]
    fn out_of_history_bodies_behind_a_gap_count_once_it_fills_spec_sync_7() {
        let (mut lp, _, bodies) = restarted(12, false, Some(osis_schema::History::Keep { until: None, after: Some(2_000) }));
        for b in &bodies[1..] {
            lp.peers[0].engine.ingest_memory(b, u64::MAX).unwrap();
        }
        lp.advance(3_000);
        lp.peers[0].tick().unwrap();
        let e = &mut lp.peers[0].engine;
        e.compactions().unwrap();
        assert_eq!(gap_load(e).bodies, 0, "behind the gap");
        e.ingest_memory(&bodies[0], u64::MAX).unwrap();
        assert_eq!(step(e), (1, 1), "the replaced bodies count once the gap fills");
    }

    // spec/sync.md §7 (Trigger): two writers exchanging bodies and snapshots, with a third
    // writer's session held behind a gap at both (its first body withheld) and growing: the
    // held-back bodies weigh nothing (no snapshot passes the gap), so the two weigh and compact
    // alike with the third writing nothing or five bodies a round, each about once per own
    // write (no snapshot sets the other off), at n and 4n rounds.
    #[test]
    fn two_writers_with_a_gap_held_open_weigh_per_write_spec_sync_7() {
        use osis_base::Role;
        use osis_schema::core_types as ct;
        let run = |rounds: usize, held_back: usize| {
            let mut lp = LocalPeer::fresh(3, osis_base::WallMs(1_700_000_000_000));
            lp.sync_all().unwrap();
            let [a, b, x] = [0, 1, 2].map(|i| lp.peers[i].engine.me());
            let (t, _) = lp.peers[0].engine.create_with_admin(&a).unwrap();
            for w in [b, x] {
                lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
            }
            lp.sync_all().unwrap();
            put(&mut lp.peers[2].engine, t, "x", "withheld");
            let (mut weighed, mut written) = (0u64, 0u64);
            let mut out: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
            for i in 0..rounds {
                lp.advance(10);
                let xs: Vec<Vec<u8>> = (0..held_back)
                    .map(|j| {
                        let c = put(&mut lp.peers[2].engine, t, "x", &format!("v{i}.{j}"));
                        lp.peers[2].engine.package(&c).unwrap().unwrap().bytes
                    })
                    .collect();
                for n in (0..2).filter(|_| i % 4 == 0) {
                    let c = put(&mut lp.peers[n].engine, t, &format!("k{n}"), &format!("v{i}"));
                    out[n].push(lp.peers[n].engine.package(&c).unwrap().unwrap().bytes);
                }
                for (n, p) in lp.peers[..2].iter_mut().enumerate() {
                    for bytes in std::mem::take(&mut out[1 - n]).iter().chain(&xs) {
                        p.engine.ingest_memory(bytes, u64::MAX).unwrap();
                    }
                }
                for (p, o) in lp.peers[..2].iter_mut().zip(&mut out) {
                    crate::costs::take();
                    let snaps = p.engine.compactions().unwrap();
                    let c = crate::costs::take();
                    weighed += c.iter().find(|x| x.0 == "compact: aspects weighed").map_or(0, |x| x.2);
                    written += snaps.len() as u64;
                    for (_, _, s) in snaps {
                        o.push(p.engine.package(&s).unwrap().unwrap().bytes);
                    }
                }
            }
            (weighed, written)
        };
        for rounds in [25, 100] {
            let (quiet, busy) = (run(rounds, 0), run(rounds, 5));
            println!("{rounds} rounds (weighed, written): third writer quiet {quiet:?}, five held-back bodies a round {busy:?}");
            assert!(busy.0 <= quiet.0 + 4 && busy.1 <= quiet.1 + 2, "{rounds} rounds: the held-back bodies weighed: {quiet:?} against {busy:?}");
            assert!(busy.0 <= rounds as u64 / 2 + 4, "{rounds} rounds: {busy:?}");
        }
    }

    // spec/permissions.md §5.2, spec/sync.md §9 (covered; random churn seed 913562400022 shrunk):
    // a snapshot whose writer held a body behind a gap in its session carries the body's writes
    // past its own frontier. A node holding the body judges it covered by the join, as a node
    // that dropped it under a cover that snapshot covers judges by its chain of covers; judged
    // uncovered by the frontier, the body's author placed it again at every pass for the others
    // to delete.
    #[test]
    fn held_memory_body_past_a_snapshot_frontier_judged_by_the_join_spec_permissions_5_2() {
        use osis_base::Role;
        use osis_schema::core_types as ct;
        let mut lp = LocalPeer::fresh(2, osis_base::WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let [a, b] = [0, 1].map(|i| lp.peers[i].engine.me());
        let (t, _) = lp.peers[0].engine.create_with_admin(&a).unwrap();
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
        lp.sync_all().unwrap();
        let ak = Ak::new("x:m+.0").unwrap();
        let w: Vec<CommitId> = ["k1", "k2", "k3"].iter().map(|k| put(&mut lp.peers[0].engine, t, k, "v")).collect();
        // b holds the first and the third: a gap at the second
        for c in [w[0], w[2]] {
            let bytes = lp.peers[0].engine.package(&c).unwrap().unwrap().bytes;
            lp.peers[1].engine.ingest_memory(&bytes, u64::MAX).unwrap();
        }
        let s = lp.peers[1].engine.snapshot(&t, &ak).unwrap().unwrap();
        let bytes = lp.peers[1].engine.package(&s).unwrap().unwrap().bytes;
        lp.peers[0].engine.ingest_memory(&bytes, u64::MAX).unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.covered(&s, &w[2], &t, &ak).unwrap(), Some(true), "its writes are in the snapshot");
        assert_eq!(e.covered(&s, &w[1], &t, &ak).unwrap(), Some(false), "the gap's are not");
    }

    /// A thing whose durable aspect `x:big.0` holds a chunked value of `n` × 64 KiB and whose
    /// ephemeral aspect `x:cur+.0` holds that value's link: (peer, thing, the tree's blobs).
    fn linked(n: usize) -> (LocalPeer, Tid, usize) {
        let mut lp = LocalPeer::fresh(1, osis_base::WallMs(1_700_000_000_000));
        let me = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        let big = Ak::new("x:big.0").unwrap();
        let mut m = Mutation::new();
        m.set(t, &big, &Value::Bytes((0..n * 65536).map(|i| (i * 7 % 251) as u8).collect())).unwrap();
        lp.peers[0].commit(m).unwrap();
        let e = &mut lp.peers[0].engine;
        let link = e.state(&t, &big).unwrap().and_then(|f| f.read()).unwrap();
        assert!(matches!(link, Value::Link(_)), "chunked");
        let tree = e.live_trees(&t).unwrap().blobs.len();
        let mut m = Mutation::new();
        m.set(t, &Ak::new("x:cur+.0").unwrap(), &link).unwrap();
        e.commit_in_memory(m).unwrap().unwrap();
        (lp, t, tree)
    }

    /// What a snapshot of `(t, ak)` is weighed as here (`snapshot_cost`).
    fn cost(lp: &mut LocalPeer, t: Tid, ak: &str) -> usize {
        let ak = Ak::new(ak).unwrap();
        let e = &mut lp.peers[0].engine;
        let me = e.core.writer_for(&t).unwrap();
        e.run(|tx| {
            if ak.ephemeral() {
                tx.set_memory();
            }
            Ok(snapshot_cost(tx, &t, &ak, me)?.unwrap())
        })
        .unwrap()
    }

    // spec/sync.md §7 (Trigger): a snapshot costs its encoded state, a large value its root link
    // alone (it lists none of its tree): durable or ephemeral, the same at n and 10n chunks.
    #[test]
    fn a_snapshot_costs_its_values_roots_alone_spec_sync_7() {
        let mut at = Vec::new();
        for n in [3, 30] {
            let (mut lp, t, tree) = linked(n);
            assert!(tree >= 2 + n / 10, "{n}: the tree has its chunks and a node ({tree})");
            at.push((cost(&mut lp, t, "x:big.0"), cost(&mut lp, t, "x:cur+.0")));
        }
        assert_eq!(at[0], at[1], "the same at 3 and 30 chunks");
    }

    // spec/sync.md §7 (Trigger): a writer whose held bodies of an aspect passed the trigger while
    // it could not write (demoted to reader) compacts them once its write is granted again, with
    // no write of the aspect between, and so after a restart in between. The grant weighs only
    // the aspect owed: another aspect of the thing, weighed while Bob could write, weighs nothing
    // (after the restart it is owed too: an open owes every aspect of a thing it may not write).
    #[test]
    fn writer_compacts_once_it_may_write_again_spec_sync_7() {
        use osis_base::Role;
        use osis_schema::core_types as ct;
        for restart in [false, true] {
            let mut lp = LocalPeer::fresh(2, osis_base::WallMs(1_700_000_000_000));
            lp.sync_all().unwrap();
            let [a, b] = [0, 1].map(|i| lp.peers[i].engine.me());
            let (t, _) = lp.peers[0].engine.create_with_admin(&a).unwrap();
            let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
            lp.peers[0].engine.grant(&t, &b, &edge(Role::Write)).unwrap();
            lp.sync_all().unwrap();
            let (m_ak, n_ak) = (Ak::new("x:m.0").unwrap(), Ak::new("x:n.0").unwrap());
            let set = |lp: &mut LocalPeer, ak: &Ak, k: &str| {
                lp.advance(10);
                let mut m = Mutation::new();
                m.op(t, ak, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Str(k.into()))], op: osis_crdt::Op::Set(Value::Int(1)) }).unwrap();
                lp.peers[1].commit(m).unwrap().unwrap();
            };
            set(&mut lp, &n_ak, "k0");
            set(&mut lp, &n_ak, "k1");
            lp.peers[1].engine.compactions().unwrap();
            for i in 0..8 {
                set(&mut lp, &m_ak, &format!("k{i}"));
            }
            lp.sync_all().unwrap();
            lp.advance(10);
            lp.peers[0].engine.demote(&t, &crate::flows::Demotion { holder: b, new: Some(edge(Role::Read)), retain: None }).unwrap();
            lp.sync_all().unwrap();
            let l = lp.peers[1].engine.compaction_load().unwrap().into_iter().find(|l| l.ak == m_ak).unwrap();
            assert!(l.bodies >= 8 && l.held > FACTOR * l.snapshot + l.largest, "over the trigger: {l:?}");
            let e = &mut lp.peers[1].engine;
            assert!(e.compactions().unwrap().is_empty(), "a reader writes no snapshot");
            assert!(e.compactions().unwrap().is_empty());
            if restart {
                lp.peers[1].restart(3).unwrap();
                assert!(lp.peers[1].engine.compactions().unwrap().is_empty(), "still a reader");
            }
            lp.advance(10);
            lp.peers[0].engine.grant(&t, &b, &edge(Role::Write)).unwrap();
            lp.sync_all().unwrap();
            let e = &mut lp.peers[1].engine;
            crate::costs::take();
            let snaps = e.compactions().unwrap();
            let c = crate::costs::take();
            let weighed = c.iter().find(|x| x.0 == "compact: aspects weighed").map_or(0, |x| x.2);
            assert_eq!(snaps.iter().map(|x| (x.0, x.1.clone())).collect::<Vec<_>>(), vec![(t, m_ak.clone())], "restart {restart}: compacted once it may write");
            assert_eq!(weighed, if restart { 2 } else { 1 }, "restart {restart}: only the owed aspects weighed");
            assert!(e.compactions().unwrap().is_empty(), "restart {restart}: owed once");
        }
    }

    // spec/sync.md §7 (Trigger): a writer whose held bodies passed the trigger while the thing's
    // delete keys were not here (`MayWrite::Later`: a first holder's grant gave the thing secrets
    // of its own, its `keys.0` not yet received) compacts them once the keys arrive, with no write
    // of the aspect between (`replace::wake_covers` wakes the owed weighing).
    #[test]
    fn writer_compacts_once_its_delete_keys_arrive_spec_sync_7() {
        use osis_base::Role;
        use osis_schema::{core_types as ct, Codec};
        let mut lp = LocalPeer::fresh(3, osis_base::WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let [a, b, c] = [0, 1, 2].map(|i| lp.peers[i].engine.me());
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
        // bob writes `t` by a raw edge write: `t` keeps its first admin's secrets
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.op(t, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(b))], op: osis_crdt::Op::Set(edge(Role::Write).to_value()) }).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.sync(0, 1).unwrap();
        let m_ak = Ak::new("x:m.0").unwrap();
        for i in 0..8 {
            lp.advance(10);
            let mut m = Mutation::new();
            m.op(t, &m_ak, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Str(format!("k{i}")))], op: osis_crdt::Op::Set(Value::Int(1)) }).unwrap();
            lp.peers[1].commit(m).unwrap().unwrap();
        }
        // a first holder by the flow gives `t` secrets of its own, its `keys.0` in that commit:
        // bob gets the rest first
        lp.peers[0].engine.grant(&t, &c, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.grant(&t, &b, &edge(Role::Write)).unwrap();
        let keys = Ak::new("keys.0").unwrap();
        let pks = lp.packages(0).unwrap();
        let carries = |id: &CommitId| lp.peers[0].engine.header(id).unwrap().aspects.iter().any(|x| x.tid == t && x.ak == keys);
        let (key_pks, rest): (Vec<_>, Vec<_>) = pks.into_iter().partition(|pk| carries(&pk.id));
        assert!(!key_pks.is_empty());
        for pk in &rest {
            lp.deliver(1, pk).unwrap();
        }
        let e = &mut lp.peers[1].engine;
        assert!(!e.holds_delete_keys(&t).unwrap(), "t's delete keys are not here");
        let l = e.compaction_load().unwrap().into_iter().find(|l| l.ak == m_ak).unwrap();
        assert!(l.bodies >= 8 && l.held > FACTOR * l.snapshot, "over the trigger: {l:?}");
        assert!(e.compactions().unwrap().is_empty(), "no snapshot without the delete keys");
        assert!(e.compactions().unwrap().is_empty());
        for pk in &key_pks {
            lp.deliver(1, pk).unwrap();
        }
        let e = &mut lp.peers[1].engine;
        assert!(e.holds_delete_keys(&t).unwrap());
        let snaps = e.compactions().unwrap();
        assert_eq!(snaps.iter().map(|x| (x.0, x.1.clone())).collect::<Vec<_>>(), vec![(t, m_ak.clone())], "compacted once the keys came");
        assert!(e.compactions().unwrap().is_empty(), "owed once");
    }
}
