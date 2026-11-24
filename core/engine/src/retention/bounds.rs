//! A held body's keep-at-least bound and whether it holds a live write (spec/commits.md §5).

use super::{aspect_index, bounded, held_part, known_part, writes_of};
#[cfg(test)]
use super::oracle;
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::Header;
use osis_crdt::{Fragment, Held, Rows, Winners, Won};
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

/// `Engine::delta_live` in `tx` (`Core::live_bodies`).
pub(crate) fn delta_live(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
    let key = (*c, *tid, ak.clone());
    osis_base::memo::Memo::get_in(tx, |tx| &tx.core.live_bodies, &key, |tx| delta_live_read(tx, &key))
}

/// `delta_live` read anew: an unknown commit counts live (its apply may change nothing here).
fn delta_live_read(tx: &mut Tx<'_>, (c, tid, ak): &(CommitId, Tid, Ak)) -> Result<bool> {
    let Some(ai) = aspect_index(tx.core, c, tid, ak) else { return Ok(true) };
    let r = live(tx, c, ai)?;
    #[cfg(test)]
    assert_eq!(r, oracle::live(tx, c, ai)?, "live streamed vs whole");
    Ok(r)
}

/// Before which wall ms delta `a` of `h` leaves only by purge
/// request or expiry (spec/commits.md §5 Keep bounds; 0: no floor): the later of when it leaves
/// history (`history::Kept::leaves_at`, replaced at wall ms `replaced`, `None`: not replaced; its
/// oldest dead write's `ts` `written`, `written_of`) and the purge-request floor.
pub(crate) fn kept_until(core: &Core, h: &Header, a: &osis_commit::AspectEntry, replaced: Option<u64>, written: Ts) -> u64 {
    super::history::of(core, &a.tid, &a.ak).leaves_at(replaced, written).max(osis_commit::retention::purge_keep_until(h).unwrap_or(0))
}

/// The `ts` of the oldest dead write part `ai` of `c` is dated by, what the floor of its
/// aspect's setting is judged against (spec/commits.md §5 One way): a delta's own `ts` (its writes
/// carry it); a snapshot's, where its own `ts` is not already before the floor, the oldest among
/// the dead writes that date it (`dating_deaths`). Read only where the setting has a floor.
pub(crate) fn written_of(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Ts> {
    let own = h.ts;
    let Some(a) = h.aspects.get(ai) else { return Ok(own) };
    let floor = super::history::of(tx.core, &a.tid, &a.ak).floor();
    if !h.kind.is_compaction() || own < floor || floor == Ts::ZERO {
        return Ok(own);
    }
    let (tid, ak) = (a.tid, a.ak.clone());
    let dead = dating_deaths(tx, h, c, ai, &tid, &ak)?;
    Ok(dead.iter().map(|w| w.stamp.ts).min().unwrap_or(own))
}

/// Whether `s` is a snapshot whose part on `(tid, ak)` this node holds whole (received, not
/// dropped or held as its leftover) and judges valid: one that may stand for the aspect's
/// history (spec/commits.md §5 Purge).
pub(crate) fn valid_snapshot_held(core: &Core, s: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    let Some(m) = core.ix.commits.get(s) else { return false };
    m.view.kind.is_compaction() && m.aspect(tid, ak).is_some_and(|ai| !m.body_gone(ai) && !m.missing(ai) && m.valid_at(ai))
}

/// `Engine::part_keeps` of part `(tid, ak)` of `c` in `tx`: before which wall ms it leaves only
/// by purge or expiry, a replacement dated ahead of the clock included (`at_clock`): from then
/// any node may drop it as covered (spec/commits.md §5 Keep bounds).
pub(crate) fn part_keep(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    tx.core.replaced_reads += 1;
    let b = part_bounds(tx, &h, c, ai)?;
    Ok(at_clock(tx.core, b))
}

/// What history and the purge floor keep of part `(tid, ak)` of `c` (its own aspect's setting at
/// its own replacement, without `at_clock`): what a listing shows of it (spec/commits.md §7
/// Listed parts).
pub(crate) fn body_history_keep(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    tx.core.replaced_reads += 1;
    let r = part_replaced_at(tx, &h, c, ai)?.map(|t| t.wall_ms().0);
    let w = written_of(tx, &h, c, ai)?;
    Ok(h.aspects.get(ai).map_or(0, |a| kept_until(tx.core, &h, a, r, w)))
}

/// Whether part `ai` of `c` is in kept history by its thing's setting alone at wall ms `now`
/// (spec/commits.md §7 Undo): replaced, while in history (`Kept::leaves_at`); live, while kept
/// while live (`live_keep`). Neither the purge floor nor the clock counts, nor whether the body
/// is still held: what undo may take back is the setting's alone.
pub(crate) fn setting_keeps(tx: &mut Tx<'_>, c: &CommitId, ai: usize, now: u64) -> Result<bool> {
    let h = tx.core.ix.commits.get(c).ok_or(Error::UnknownCommit(*c))?.header.clone();
    let Some(a) = h.aspects.get(ai) else { return Ok(false) };
    let until = match part_replaced_at(tx, &h, c, ai)? {
        Some(r) => {
            let w = written_of(tx, &h, c, ai)?;
            super::history::of(tx.core, &a.tid, &a.ak).leaves_at(Some(r.wall_ms().0), w)
        }
        None => live_keep(tx.core, c, ai, a),
    };
    Ok(until > now)
}

/// The keep bound of part `ai` of `c` but for the clock: its own aspect's current setting at its own
/// replacement (`part_replaced_at`, spec/commits.md §5 Dated only where history is kept), and
/// that replacement (wall ms, 0: none) for `at_clock`. A part's date and keep read only its
/// aspect's writes and setting, so no other part of its commit keeps it (a purge-on-replace part
/// goes under its cover whatever its commit's kept parts keep), a covered drop on one aspect
/// moves no other part's bound, and a part on an aspect no setting keeps has none. A part not
/// replaced is kept while live where its aspect's setting says so (`live_keep`).
fn part_bounds(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<(u64, u64)> {
    let Some(a) = h.aspects.get(ai) else { return Ok((0, 0)) };
    let w = written_of(tx, h, c, ai)?;
    // kept for good, live or replaced: when it was replaced decides nothing, so it is not dated
    // (a date reads the aspect's state and held writes, which every write to it moves)
    let live = live_keep(tx.core, c, ai, a);
    if super::history::of(tx.core, &a.tid, &a.ak).forever_bound(w) == Some(live) {
        return Ok((kept_until(tx.core, h, a, None, w).max(live), 0));
    }
    let r = part_replaced_at(tx, h, c, ai)?.map(|t| t.wall_ms().0);
    let k = kept_until(tx.core, h, a, r, w);
    let k = if r.is_none() { k.max(live_keep(tx.core, c, ai, a)) } else { k };
    Ok((k, r.unwrap_or(0)))
}

/// Until when part `ai` of `c` (`a`), not dated as replaced, is kept while live (spec/commits.md
/// §5 Kept while live): its aspect's `history::Kept::live_until` for a held valid delta with
/// values, not a snapshot's or a signal's; 0 for any other. On an aspect some setting keeps
/// history (`bounded`), a part `part_replaced_at` dates nothing of is live; on any other
/// `live_until` is 0 but for fixed retention, whose parts are dated (role) or never out.
pub(crate) fn live_keep(core: &Core, c: &CommitId, ai: usize, a: &osis_commit::AspectEntry) -> u64 {
    let Some(m) = core.ix.commits.get(c) else { return 0 };
    if m.view.kind.is_compaction() || a.ak.signal() || !m.holds(ai) || m.own_gone(ai) || !m.valid_at(ai) {
        return 0;
    }
    super::history::of(core, &a.tid, &a.ak).live_until(m.view.ts)
}

/// A keep bound and replacement (`part_bounds`) at the node's clock: a body replaced after the
/// clock is kept until the clock reaches it (spec/commits.md §5 Keep bounds: a body leaves history
/// no earlier than replaced). Only a dated part has a replacement (`part_replaced_at`): where no
/// setting keeps history for its aspect nothing is dated and it adds no bound.
fn at_clock(core: &Core, (k, last): (u64, u64)) -> u64 {
    // read with a wake at `last`: the bound moves when the clock passes it
    if last > k && core.time.until(Some(last)) < last { last } else { k }
}

/// `part_bounds` of every part of `c`, by aspect index (`Engine::part_keeps`). A memo
/// (`Core::part_bounds`): the clock is read after it, so a bound holds while what it read does.
fn commit_bounds(tx: &mut Tx<'_>, c: &CommitId) -> Result<Arc<Vec<(u64, u64)>>> {
    let h = tx.core.ix.commits.get(c).ok_or(Error::UnknownCommit(*c))?.header.clone();
    tx.core.replaced_reads += 1;
    let mut out = Vec::with_capacity(h.aspects.len());
    for ai in 0..h.aspects.len() {
        out.push(part_bounds(tx, &h, c, ai)?);
    }
    Ok(Arc::new(out))
}

/// The writes that win in part `f` (`Fragment::winners`): one walk, counted
/// (`Core::death_walks`).
pub(super) fn winners_of(tx: &mut Tx<'_>, f: &Fragment) -> Winners {
    tx.core.death_walks += 1;
    f.winners()
}

/// When part `ai` of held commit `c` was replaced, for a relative keep at least (spec/commits.md
/// §5 Bodies and deaths): a function of the held set, judged when asked, never stored, and never
/// of how a part is paged (`deaths` judges it whole). Only its own writes date it, and only
/// where some setting keeps history for its aspect (`bounded`; elsewhere no history is at stake,
/// so a covered body drops at once whatever other aspects keep): a part on another aspect, kept
/// or not, neither dates it nor is dated by it (Fathom: a setting governs its aspect's data). A
/// signal's part is replaced at its own `ts`. Otherwise `dated_replaced_at`.
fn part_replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Option<Ts>> {
    let Some(a) = h.aspects.get(ai) else { return Ok(None) };
    // a signal's body is replaced when written (spec/commits.md §5 Signals)
    if a.ak.signal() {
        return Ok(Some(h.ts));
    }
    if !bounded(tx.core, &a.tid, &a.ak) {
        return Ok(None);
    }
    dated_replaced_at(tx, h, c, ai)
}

/// When part `ai` of `c` was replaced (spec/commits.md §5 Bodies and deaths), a function of the
/// held set: the latest death among the writes it dates in its aspect's held writes
/// (`settle_index`), kept on a dated aspect as the part's history row (`leaving::date_due` rows
/// every part whose date moved at a transaction's end), so a read is the part's row alone.
/// Read from the held writes where the row may lag: on an aspect a running transaction changed
/// before its rows are dated (`leaving::dating_due`).
pub(super) fn dated_replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Option<Ts>> {
    let Some(a) = h.aspects.get(ai) else { return Ok(None) };
    if a.ak.signal() {
        return Ok(Some(h.ts));
    }
    let (tid, ak) = (a.tid, a.ak.clone());
    if !judged(tx.core, c, ai, &tid, &ak) || !bounded(tx.core, &tid, &ak) {
        return Ok(None);
    }
    if super::leaving::dating_due(tx.core, &tid, &ak) {
        return held_date(tx, c, &tid, &ak);
    }
    Ok(tx.core.ix.dated.get(&(*c, tid, ak)).copied())
}

/// Whether part `ai` of `c` on `(tid, ak)` is dated at all: held whole or with its own writes
/// live (a bare leftover has none to keep) and valid.
fn judged(core: &Core, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> bool {
    held_part(core, c, tid, ak) == Some(ai) && core.ix.commits.get(c).is_some_and(|m| !m.own_gone(ai) && m.valid_at(ai))
}

/// When held valid part `(tid, ak)` of `c` was replaced, by the aspect's held writes brought up
/// to date (`settle_index`; spec/crdt.md §4.8 When): a winner of the part is dead when a held
/// valid write supersedes it, and died at the earliest `ts` among those, a write dated by its
/// own stamp whichever body holds it. The part is replaced at the latest of its writes' deaths,
/// a snapshot's leaving out those a held valid snapshot stamped later holds as winners (that
/// one keeps their history); `None`: no write dead. So a cover dropping a body redates nothing
/// in history (notes/engine-retention-dating.md Invariant), and a node holding more bodies
/// dates no later. One row read: the index keeps each body's deaths by date.
pub(super) fn held_date(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Ts>> {
    settle_index(tx, tid, ak)?;
    drop(osis_base::costs::span("replaced at"));
    index(tx, tid, ak, Shred::No)?.date(c)
}

/// When held write `w` of `(tid, ak)` died and the snapshots holding it winning
/// (`osis_crdt::Held::held`), by the aspect's held writes as last settled (`settle_index`).
fn held_write(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, w: &Won) -> Result<Option<osis_crdt::HeldWrite>> {
    index(tx, tid, ak, Shred::No)?.held(w)
}

/// Runs debug check `f` unseen: its reads record nothing, its costs and death walks count none.
#[cfg(debug_assertions)]
pub(super) fn unseen<R>(tx: &mut Tx<'_>, f: impl FnOnce(&mut Tx<'_>) -> R) -> R {
    let walks = tx.core.death_walks;
    let r = osis_base::costs::paused(|| osis_base::memo::unrecorded(|| f(tx)));
    tx.core.death_walks = walks;
    r
}

/// `held_date` by the state: the part's winners the state supersedes (`deaths`), each dated by
/// the held writes (one not held, or held undated: `Error::Corrupt`). The debug check of a row.
#[cfg(debug_assertions)]
pub(super) fn whole_date(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Option<Ts>> {
    let Some(a) = h.aspects.get(ai) else { return Ok(None) };
    let (tid, ak) = (a.tid, a.ak.clone());
    let dead = dating_deaths(tx, h, c, ai, &tid, &ak)?;
    let mut out: Option<Ts> = None;
    for w in &dead {
        let d = held_write(tx, &tid, &ak, w)?.and_then(|x| x.0).ok_or(Error::Corrupt("a dead write no held body supersedes"))?;
        out = out.max(Some(d));
    }
    Ok(out)
}

/// The dead writes that date held valid part `ai` of `c` (`deaths`), a snapshot's leaving out
/// those a held valid snapshot stamped later holds as winners (that one keeps their history).
fn dating_deaths(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<BTreeSet<Won>> {
    let mut dead = deaths(tx, c, ai, tid, ak)?;
    if h.kind.is_compaction() && !dead.is_empty() && bounded(tx.core, tid, ak) {
        settle_index(tx, tid, ak)?;
        let mut kept = BTreeSet::new();
        for w in dead {
            let carried = held_write(tx, tid, ak, &w)?.is_some_and(|x| x.1.iter().any(|(t, x)| *t > h.ts && x != c));
            if !carried {
                kept.insert(w);
            }
        }
        dead = kept;
    }
    Ok(dead)
}

/// How a held valid part is held, which decides the writes its body gives: as a leftover
/// (`Meta::stripped`), and with its own writes gone (`Meta::own_gone`).
pub(crate) type Form = (bool, bool);

/// The form of part `(tid, ak)` of `c` when held and valid (a body the held writes note).
pub(crate) fn form(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<Form> {
    let ai = held_part(core, c, tid, ak)?;
    let m = core.ix.commits.get(c)?;
    m.valid_at(ai).then(|| (m.stripped(ai), m.own_gone(ai)))
}

/// The table of an aspect's unit holding its held writes (`osis_crdt::Held`'s rows in pages,
/// `osis_crdt::PagedRows`): beside its state pages (0), key index (1) and placement (2), in the
/// aspect's class, gone with the aspect. It is there from the aspect's first death
/// (`settle_index`).
const HELD_TABLE: u8 = 3;

/// The pages of `(tid, ak)`'s held writes as `osis_crdt::Rows`: the rows of `HELD_TABLE`.
pub(crate) struct IndexRows<'a, 'b> {
    txn: &'a mut osis_store::Transaction<'b>,
    tid: Tid,
    ak: Ak,
    /// The table, once made.
    table: Option<osis_store::Table>,
    /// A body leaving: what it held goes shredded (its copies of set values, spec/commits.md §5).
    shred: Shred,
}

impl From<osis_crdt::Corrupt> for Error {
    fn from(e: osis_crdt::Corrupt) -> Error {
        Error::Corrupt(e.0)
    }
}

impl Rows for IndexRows<'_, '_> {
    type Err = Error;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.table {
            Some(t) => Ok(self.txn.table_get(t, key)?),
            None => Ok(None),
        }
    }
    fn put(&mut self, key: &[u8], val: &[u8]) -> Result<()> {
        let t = match self.table {
            Some(t) => t,
            None => self.txn.create_table(&self.tid, &self.ak, HELD_TABLE)?,
        };
        self.table = Some(t);
        // counted: what a write costs in held-writes pages (scale tests)
        osis_base::costs::count("held writes: pages written", 1);
        self.txn.table_put(t, key, val.to_vec(), self.shred)?;
        Ok(())
    }
    fn del(&mut self, key: &[u8]) -> Result<()> {
        if let Some(t) = self.table {
            self.txn.table_remove(t, key, self.shred)?;
        }
        Ok(())
    }
    fn scan(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<osis_store::KeyValue>> {
        match self.table {
            Some(t) => Ok(self.txn.table_range(t, from, Some(to), limit)?),
            None => Ok(Vec::new()),
        }
    }
    fn scan_back(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<osis_store::KeyValue>> {
        match self.table {
            Some(t) => Ok(self.txn.table_range_rev(t, from, to, limit)?),
            None => Ok(Vec::new()),
        }
    }
}

/// The held writes of `(tid, ak)` (`osis_crdt::Held`) over the transaction's store.
/// Pages read stay for the rest of the transaction (`Tx::held_pages`), forgotten where the
/// table is not the one they were read from (dropped, or made since).
fn index<'a, 'b>(tx: &'a mut Tx<'b>, tid: &Tid, ak: &Ak, shred: Shred) -> Result<Held<osis_crdt::PagedRows<IndexRows<'a, 'b>, &'a mut osis_crdt::PageCache>>> {
    let table = tx.txn.table(tid, ak, HELD_TABLE)?;
    let (of, cache) = tx.held_pages.entry((*tid, ak.clone())).or_default();
    if *of != table {
        *of = table;
        cache.clear();
    }
    Ok(Held::new(osis_crdt::PagedRows::with_cache(IndexRows { txn: &mut tx.txn, tid: *tid, ak: ak.clone(), table, shred }, PAGE_KEY, cache)))
}

/// The most bytes of a page's key (`osis_crdt::PagedRows`): a table bounds its keys at a quarter
/// of the store's page, 128 B at the smallest (512), less the page tag.
const PAGE_KEY: usize = 120;

/// The tag a body joins the held writes with: its `Form`.
fn tag(f: Form) -> [u8; 2] {
    [u8::from(f.0), u8::from(f.1)]
}

/// What held valid body `x` of `(tid, ak)` gives the held writes in form `f`: its part read
/// whole (a judgment walks it a fixed number of times, `Core::death_walks`).
fn body_writes(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, x: &CommitId, f: Form) -> Result<Option<(osis_crdt::Body, osis_crdt::BodyWrites)>> {
    let Some(xai) = held_part(tx.core, x, tid, ak) else { return Ok(None) };
    let Some((ts, snap)) = tx.core.ix.commits.get(x).map(|m| (m.view.ts, m.header.kind.is_compaction())) else { return Ok(None) };
    let Some(frag) = crate::apply::held_fragment(tx, x, xai)? else { return Ok(None) };
    drop(osis_base::costs::span("deaths: a body"));
    tx.core.death_walks += 1;
    Ok(Some((osis_crdt::Body { c: *x, ts, snap }, osis_crdt::BodyWrites::of(&frag, !f.1))))
}

/// Brings the held writes of value aspect `(tid, ak)` (`osis_crdt::Held`: every write its held
/// valid bodies hold, by position, with when each died and each body's deaths by date; durable
/// rows, so a session reads only the positions a change touches) up to date with what the
/// running transaction changed. What dates a dated aspect's bodies, and what tells an expired
/// write that superseded nothing held (`retention::make_leftover`: removed from the state in
/// place); an aspect holding an expiring part keeps them from then on (`follow`).
///
/// A dated aspect keeps them from its first death, so none kept there means no held write is
/// dead: while no held write supersedes another, every
/// date is none and nothing is kept, so a join that supersedes nothing writes nothing (a thing's
/// role aspects and an aspect only added to cost no row). A join that supersedes a write says so
/// (`Core::died`, from the state's winners it killed or its own it brought dead:
/// `retention::Killed`; while none is superseded every held write wins in the state, since a
/// write the state holds dead is superseded by a live one, which a held body or cover carries).
/// Where the state was rebuilt or the aspect turned dated (`Core::to_date`, or kept with no
/// cursor yet) the held bodies are read to see. Then they are built from every held valid body,
/// once for the aspect: its first death reads its held bodies.
///
/// Kept, they are followed: each commit changed since the last call (the commits index's
/// changes from where it stood, and the parts whose leftover was written) leaves if it is
/// joined in another form than it is held now, or its bytes were rewritten, and joins as it is
/// held: a join reads its own body, a leave none. The bodies whose dates moved are noted for
/// `leaving::date_due` (`Core::dates_moved`).
pub(crate) fn settle_index(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let k = (*tid, ak.clone());
    // a memory transaction changes no durable body, and every row it writes is memory's
    if tx.txn.is_memory() && !ak.ephemeral() {
        return Ok(());
    }
    let now = (tx.core.ix.commits.changes_len(), tx.core.bodies_rewritten.len(), tx.core.died.len(), tx.core.to_date.pushes());
    let from = tx.core.index_settled.get(&k).copied();
    if from == Some(now) {
        return Ok(());
    }
    let built = tx.txn.table(tid, ak, HELD_TABLE)?.is_some();
    if !built {
        tx.core.index_settled.insert(k.clone(), now);
        let died = tx.core.died.contains(&k);
        let unsure = tx.core.to_date.pushed(tid, ak) || super::history::of(tx.core, tid, ak).keeps() && !tx.core.ix.leave_from.contains_key(&k);
        if !died && !unsure {
            return Ok(());
        }
        let mut fresh = built_fresh(tx, tid, ak)?;
        // nothing dead: nothing to keep
        if !fresh.any_dead()? {
            return Ok(());
        }
        let moved = fresh.take_moved();
        index(tx, tid, ak, Shred::No)?.rows.fill(&fresh.rows.0)?;
        tx.core.dates_moved.extend(moved.into_iter().map(|x| (*tid, ak.clone(), x)));
        tx.core.index_settled.insert(k, now);
        return Ok(());
    }
    let (commits, rewritten): (BTreeSet<CommitId>, BTreeSet<CommitId>) = {
        let (log, re, ..) = from.unwrap_or((0, 0, 0, 0));
        let re: BTreeSet<CommitId> = tx.core.bodies_rewritten.get(re..).unwrap_or_default().iter().filter(|x| x.0 == *tid && x.1 == *ak).map(|x| x.2).collect();
        let mut all = tx.core.ix.commits.changed_from(log, tid, ak);
        all.extend(re.iter().copied());
        (all, re)
    };
    let mut left = false;
    for c in commits {
        let is = form(tx.core, &c, tid, ak);
        let was = index(tx, tid, ak, Shred::No)?.joined(&c)?;
        if was.as_deref() == is.map(tag).as_ref().map(|t| t.as_slice()) && !rewritten.contains(&c) {
            continue;
        }
        let mut moved = BTreeSet::new();
        if was.is_some() {
            // its `ts` and kind are not read: a leaving body is named by its commit
            let b = osis_crdt::Body { c, ts: Ts::ZERO, snap: false };
            let mut ix = index(tx, tid, ak, Shred::Yes)?;
            ix.leave(&b)?;
            moved.extend(ix.take_moved());
            let revived = ix.take_revived();
            tx.core.revivals += u64::from(revived);
            left = true;
        }
        let joining = match is {
            Some(f) => body_writes(tx, tid, ak, &c, f)?.map(|(b, w)| (f, b, w)),
            None => None,
        };
        if let Some((f, b, w)) = joining {
            let mut ix = index(tx, tid, ak, Shred::No)?;
            ix.join(&b, &w, &tag(f))?;
            moved.extend(ix.take_moved());
        }
        tx.core.dates_moved.extend(moved.into_iter().map(|x| (*tid, ak.clone(), x)));
    }
    // the last body gone: nothing is kept, so an aspect holding no valid body costs no row
    if left && index(tx, tid, ak, Shred::No)?.empty()? {
        return drop_index(tx, tid, ak);
    }
    tx.core.index_settled.insert(k, now);
    Ok(())
}

/// The held writes of `(tid, ak)` built in memory from every held valid body, dated: a build
/// reads no row.
fn built_fresh(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Held<osis_crdt::MemRows>> {
    let _s = osis_base::costs::span("held writes");
    let noted: Vec<(CommitId, Form)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter_map(|x| Some((x.1, form(tx.core, &x.1, tid, ak)?))).collect();
    let mut fresh = Held::new(osis_crdt::MemRows::default());
    for (c, f) in noted {
        if let Some((b, w)) = body_writes(tx, tid, ak, &c, f)? {
            fresh.place(&b, &w, &tag(f))?;
        }
    }
    fresh.date_every()?;
    Ok(fresh)
}

/// The row of an aspect whose held writes are kept though none is dead (`follow`): after every
/// position's and body's rows (`osis_crdt::Held` keys start 0 or 1).
const FOLLOWED: &[u8] = &[2];

/// An expiring part of `(tid, ak)` is held: its held writes are kept from now on, built from the
/// held bodies where none are (its first expiring part: O(the held bodies) once), so its expiry
/// tells whether a write of it superseded one still held (`retention::make_leftover`). Kept until
/// its last body leaves.
pub(crate) fn follow(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if ak.signal() || tx.txn.is_memory() && !ak.ephemeral() || followed(tx, tid, ak)? {
        return Ok(());
    }
    settle_index(tx, tid, ak)?;
    if followed(tx, tid, ak)? {
        return Ok(());
    }
    let mut fresh = built_fresh(tx, tid, ak)?;
    fresh.rows.0.insert(FOLLOWED.to_vec(), Vec::new());
    let moved = fresh.take_moved();
    index(tx, tid, ak, Shred::No)?.rows.fill(&fresh.rows.0)?;
    tx.core.dates_moved.extend(moved.into_iter().map(|x| (*tid, ak.clone(), x)));
    let now = (tx.core.ix.commits.changes_len(), tx.core.bodies_rewritten.len(), tx.core.died.len(), tx.core.to_date.pushes());
    tx.core.index_settled.insert((*tid, ak.clone()), now);
    Ok(())
}

/// Whether the held writes of `(tid, ak)` are kept (`settle_index` follows them).
pub(crate) fn followed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<bool> {
    Ok(tx.txn.table(tid, ak, HELD_TABLE)?.is_some())
}

/// Forgets the held writes of `(tid, ak)` (it is dated no more, its rows were forgotten, or
/// its last body left): the table, shredded.
pub(crate) fn drop_index(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    tx.txn.drop_table(tid, ak, HELD_TABLE)?;
    tx.held_pages.remove(&(*tid, ak.clone()));
    tx.core.index_settled.remove(&(*tid, ak.clone()));
    Ok(())
}

/// Debug builds: held writes built from nothing (`index_exact`), with each placed body's date.
#[cfg(debug_assertions)]
pub(super) struct Built {
    pub(super) rows: osis_crdt::MemRows,
    dates: std::collections::BTreeMap<CommitId, Ts>,
    /// `Held::any_dead`.
    any_dead: bool,
}

#[cfg(debug_assertions)]
impl Built {
    /// `Held::date` of body `c` (`None`: not placed, or nothing it dates is dead).
    pub(super) fn date(&self, c: &CommitId) -> Option<Ts> {
        self.dates.get(c).copied()
    }
}

/// Debug builds: the held writes `index_exact` built, by what they are built of (each placed
/// body, its writes and form; a 128-bit hash of their `Debug`), shared by the process's engines:
/// the nodes holding one set of bodies (the order harness's orders of a held set, a synced
/// world's peers) build it once, each still compared row for row. Cleared whole when it would
/// pass `BUILT_BYTES` of rows: at 0 every check builds anew; with no bound a process keeps every
/// set it ever checked (a rotation run's 100 worlds: about 160 MB, none read again).
#[cfg(debug_assertions)]
static BUILT: std::sync::Mutex<Option<BuiltSets>> = std::sync::Mutex::new(None);

/// `BUILT`'s contents: the sets by key, and their rows' bytes.
#[cfg(debug_assertions)]
#[derive(Default)]
struct BuiltSets {
    bytes: usize,
    sets: std::collections::HashMap<u128, Arc<Built>>,
}

/// `BUILT`'s bound: a few worlds' sets per thread at once (an order seed's are about 2 MB).
#[cfg(debug_assertions)]
const BUILT_BYTES: usize = 64 << 20;

/// Debug builds: the kept held writes of `(tid, ak)` are, row for row, those built from its
/// held valid bodies at once, each write dated by the rows (`Held::place`, `Held::date_every`):
/// so no join or leave was missed, every death and date moved with them, and the deaths kept
/// are those the rows date; none kept on a dated aspect, no held write is dead. Gives the held
/// writes built from nothing (`BUILT`).
#[cfg(debug_assertions)]
pub(super) fn index_exact(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, when: &str) -> Result<Arc<Built>> {
    use std::fmt::Write;
    use std::hash::{Hash, Hasher};
    let bodies: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let mut placed = Vec::new();
    let mut key = format!("{tid:?} {ak:?}");
    for c in bodies {
        if let Some(f) = form(tx.core, &c, tid, ak)
            && let Some((b, w)) = body_writes(tx, tid, ak, &c, f)?
        {
            let _ = write!(key, " {b:?} {w:?} {f:?}");
            placed.push((b, w, tag(f)));
        }
    }
    let key = {
        let (mut a, mut b) = (std::collections::hash_map::DefaultHasher::new(), std::collections::hash_map::DefaultHasher::new());
        b.write_u8(1);
        key.hash(&mut a);
        key.hash(&mut b);
        u128::from(a.finish()) << 64 | u128::from(b.finish())
    };
    let cached = BUILT.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|m| m.sets.get(&key).cloned());
    let fresh = match cached {
        Some(f) => f,
        None => {
            let mut held = Held::new(osis_crdt::MemRows::default());
            for (b, w, t) in &placed {
                held.place(b, w, t)?;
            }
            held.date_every()?;
            let mut dates = std::collections::BTreeMap::new();
            for (b, ..) in &placed {
                if let Some(t) = held.date(&b.c)? {
                    dates.insert(b.c, t);
                }
            }
            let any_dead = held.any_dead()?;
            let f = Arc::new(Built { rows: held.rows, dates, any_dead });
            let bytes: usize = f.rows.0.iter().map(|(k, v)| k.len() + v.len()).sum();
            let mut g = BUILT.lock().unwrap_or_else(|e| e.into_inner());
            let m = g.get_or_insert_default();
            if m.bytes + bytes > BUILT_BYTES {
                *m = BuiltSets::default();
            }
            m.bytes += bytes;
            m.sets.insert(key, f.clone());
            f
        }
    };
    if tx.txn.table(tid, ak, HELD_TABLE)?.is_none() {
        assert!(!bounded(tx.core, tid, ak) || !fresh.any_dead, "{when}: dated {tid:?} {ak:?} keeps no held writes, yet a held write is dead");
        return Ok(fresh);
    }
    let kept: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = index(tx, tid, ak, Shred::No)?.rows.scan(&[], FOLLOWED, usize::MAX)?.into_iter().collect();
    let diff: Vec<String> = kept.keys().chain(fresh.rows.0.keys()).filter(|k| kept.get(*k) != fresh.rows.0.get(*k)).take(4).map(|k| format!("{:?}: kept {:?}, fresh {:?}", osis_base::hex::encode(k), kept.get(k).map(|v| osis_base::hex::encode(v)), fresh.rows.0.get(k).map(|v| osis_base::hex::encode(v)))).collect();
    assert!(diff.is_empty(), "{when}: the held writes of {tid:?} {ak:?} differ from those of its held bodies: {diff:?}");
    Ok(fresh)
}

/// The writes of held part `ai` of `c` the state supersedes (spec/crdt.md §4.8): the part's
/// winners that do not win once it joins, whole, a copy of the state at its positions
/// (`Tx::state_part_at`: O(part), whatever the state's size).
fn deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<BTreeSet<Won>> {
    let Some(f) = crate::apply::held_fragment(tx, c, ai)? else { return Ok(Default::default()) };
    let Some(mut st) = tx.state_part_at(tid, ak, &f)? else { return Ok(Default::default()) };
    let mine = winners_of(tx, &f);
    st.join(f);
    let joined = winners_of(tx, &st);
    Ok(mine.minus(&joined))
}

/// `deaths` of `c`'s part on `(tid, ak)`, and the oracle's (`oracle::deaths`: the part joined
/// into the whole state), for `tests_paged`.
#[cfg(test)]
pub(crate) fn deaths_and_whole(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<(BTreeSet<Won>, BTreeSet<Won>)>> {
    let Some(ai) = held_part(tx.core, c, tid, ak) else { return Ok(None) };
    Ok(Some((deaths(tx, c, ai, tid, ak)?, oracle::deaths(tx, c, ai, tid, ak)?)))
}

/// The writes joins on an aspect superseded (spec/crdt.md §4.8), by dot, for listing
/// (`mark_killed`). Noted join by join (a whole delta, each of its pieces, a paged reset's
/// skeleton and each page): the reaches together are the whole join's.
#[derive(Debug, Default)]
pub(crate) struct Killed {
    pub dots: BTreeSet<osis_crdt::Dot>,
}

impl Killed {
    /// Notes the writes the join of `d` into `st` superseded: `before` (`Killed::before`) against
    /// `st` after the join, at the same records of each key (`Fragment::reach_after`: a record
    /// the join took out of `d`'s reach is no death).
    pub(crate) fn note(&mut self, before: &KillBefore, st: &Fragment, d: &Fragment) {
        let reach = st.reach_after(d, &before.reach);
        self.dots.extend(before.winners.minus(&reach.winners()).into_iter().map(|w| w.stamp.dot));
    }
    /// What `note` compares with: the winners `st ⊔ d` may supersede (of `st` at `d`'s reach,
    /// and of `d`), and that reach.
    pub(crate) fn before(st: &Fragment, d: &Fragment) -> KillBefore {
        let reach = st.reach(d);
        let mut winners = reach.winners();
        winners.extend(d.winners());
        KillBefore { reach, winners }
    }
}

/// `Killed::before`.
pub(crate) struct KillBefore {
    reach: Fragment,
    winners: Winners,
}

/// A join on `(tid, ak)` superseded `dead`: listeners are told of the commits it may have
/// replaced (the dying writes' own commits, and the aspect's snapshots, which may carry them).
/// Their dates follow from the held set (`leaving::date_due`).
pub(crate) fn mark_killed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, dead: &Killed) {
    if dead.dots.is_empty() {
        return;
    }
    // the aspect's held writes are kept from its first death (`settle_index`)
    if bounded(tx.core, tid, ak) {
        tx.core.died.push((*tid, ak.clone()));
    }
    let core = &*tx.core;
    let mut on: BTreeSet<CommitId> = dead.dots.iter().filter_map(|d| core.commit_of(tid, ak, d)).collect();
    on.extend(core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1));
    crate::engine::listing::note_killed(tx, tid, ak, &on);
}

/// The state of `(tid, ak)` was rebuilt (a validity flip, an un-merge, a drop): every held
/// body's date is judged again (`leaving::date_due`), as writes may have left the held set.
pub(crate) fn mark_bounded(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) {
    if bounded(tx.core, tid, ak) {
        tx.core.to_date.push(*tid, ak.clone(), false);
    }
}

/// `Engine::delta_live` of delta `ai` of `c`, judged against the state in
/// `tx`: a function of the commits applied (the join's), so alike at nodes that applied the
/// same ones.
pub(super) fn live(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    if h.kind.is_compaction() {
        return snapshot_live(tx, &h, c, ai);
    }
    let Some(a) = h.aspects.get(ai) else { return Ok(false) };
    let own = writes_of(&h, c, ai);
    let owns = |st: &Fragment| st.holds_owned_write(&|src, lo, hi| own.iter().any(|o| o.owns_range(src, lo, hi)));
    // per piece of the delta, the state at its positions (O(piece), whatever the state's size;
    // all of it when none is held)
    // the stream stops at the first piece holding a live write: a part with one costs the
    // pages up to it, not every page
    let mut live = false;
    let held = match crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
        live = tx.state_part_at(&a.tid, &a.ak, &f)?.as_ref().is_some_and(owns);
        if live { Err(Error::Misuse("live: stream stopped")) } else { Ok(()) }
    }) {
        Ok(held) => held.is_some(),
        Err(_) if live => true,
        Err(e) => return Err(e),
    };
    if !held {
        live = tx.state(&a.tid, &a.ak)?.is_some_and(owns);
    }
    Ok(live)
}

/// Whether a compaction snapshot carries a write still live in this node's state (`delta_live`;
/// live writes as for deltas, `Fragment::live_writes`: no element or entry tombstone): held, a
/// write it carries (by dot) is there, judged a piece of it at a time against the state's part
/// it meets. Not held (dropped or never received), which writes it carried are not known here: it
/// is live while the state holds a write stamped at or before its `ts` (the header's `ts` bounds
/// what it carried) or one without a `ts` (an element identity whose record carries none): an
/// over-approximation, so its delete at peers waits for a carrier (spec/sync-compaction.md §1).
pub(super) fn snapshot_live(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(a) = h.aspects.get(ai) else { return Ok(false) };
    // by dot: records without a `ts` count too
    let valid = crate::apply::copies::snapshot_valid(tx.core, c, &a.tid, &a.ak);
    let mut live = false;
    let held = crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
        let carried: BTreeSet<osis_crdt::Dot> = f.live_writes().into_iter().map(|(d, _)| d).collect();
        if !live && !carried.is_empty() {
            // a valid snapshot is joined in the state, so a dot it shares with the state sits
            // at a position it holds; an invalid one's may sit elsewhere (one delta stamp
            // covers many positions)
            let st = if valid { tx.state_part_at(&a.tid, &a.ak, &f)? } else { tx.state_at(&a.tid, &a.ak, &f)? };
            live = st.is_some_and(|st| st.live_writes().into_iter().any(|(d, _)| carried.contains(&d)));
        }
        Ok(())
    })?;
    if live || held.is_some() {
        return Ok(live);
    }
    let Some(st) = tx.state(&a.tid, &a.ak)? else { return Ok(false) };
    Ok(st.live_writes().iter().any(|(_, t)| t.is_none_or(|t| t <= h.ts)))
}

impl Engine {
    /// Keep-at-least bound (wall ms, 0: none) of each part of known commit `c`, by aspect index
    /// (`part_keep`): a commit's judgment costs O(parts) death reads.
    pub fn part_keeps(&mut self, c: &CommitId) -> Result<Vec<u64>> {
        let b = osis_base::memo::Memo::get_in(self, |e| &e.core.part_bounds, c, |e| e.read(|tx| commit_bounds(tx, c)))?;
        Ok(b.iter().map(|x| at_clock(&self.core, *x)).collect())
    }

    /// Whether aspect `a` of `h` is a permanent delta (`history::permanent`).
    pub fn permanent(&self, h: &Header, a: &osis_commit::AspectEntry) -> bool {
        super::history::permanent(&self.core, h, a)
    }

    /// From when any node may drop held part `(tid, ak)` of `c` under a held valid writer's
    /// cover or its author's own whole replaces (spec/commits.md §5 Out of history, spec/sync.md
    /// §7): its keep-at-least bound on this node's clock (`part_keep`; a local drop changes only
    /// this node's reads, which follow its clock; deleting it at peers waits `MAX_DRIFT` more,
    /// `Dropped::peer_delete_from`). Out of history nothing promises to keep it, so the cover's writer
    /// need not hold the purge right.
    pub fn drop_from(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.read(|tx| part_keep(tx, &c, &tid, &ak))
    }

    /// When part `ak` of `c` was replaced, for a relative keep at least (`part_replaced_at`;
    /// `None`: no relative bound on its aspect, or no write of it dead).
    pub fn replaced_at(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Ts>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.read(|tx| {
            let (ai, h) = known_part(tx.core, &c, &tid, &ak)?;
            tx.core.replaced_reads += 1;
            part_replaced_at(tx, &h, &c, ai)
        })
    }

    /// Whether a write of `c`'s delta on `(tid, ak)` is still in this node's state (a dot it owns
    /// survives there; unknown counts as live): what only a blob of `c` can carry (spec/sync.md
    /// §6, §7). A delta without one needs no carrier before it leaves a sync ID (spec/sync-compaction.md §1);
    /// one with one goes only after its carrier (spec/commits.md §5). Writes the state does not
    /// hold count dead: superseded, purged or expired ones, and those of deltas invalid here or
    /// undone (stripped from the state; live again once a validity flip or a redo puts them
    /// back). Any write counts: resets (a tombstone's, for its remover) and gone writes
    /// too. A memo (`Core::live_bodies`): a hit runs no transaction.
    pub fn delta_live(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        let key = (*c, *tid, ak.clone());
        osis_base::memo::Memo::get_in(self, |e| &e.core.live_bodies, &key, |e| e.run(|tx| delta_live_read(tx, &key)))
    }

    /// The lowest `ts` among the writes the held body of aspect `ak` of `c` carries (`None`: not
    /// held, or none stamped). Tests: the order harness bounds which invalid writes may have
    /// killed a snapshot's carried write.
    #[doc(hidden)]
    pub fn body_min_ts(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Ts>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.read(|tx| {
            let Some(ai) = aspect_index(tx.core, &c, &tid, &ak) else { return Ok(None) };
            let mut min = None;
            crate::apply::each_held_piece(tx, &c, ai, &mut |_, f| {
                min = f.writes().into_iter().filter_map(|(_, t)| t).chain(min).min();
                Ok(())
            })?;
            Ok(min)
        })
    }

    /// Whether `c` is known with an aspect `(tid, ak)` whose body is neither dropped nor held as
    /// its leftover (`Meta::body_gone`): true for a missing part too (`Engine::aspect_dump` shows
    /// which).
    pub fn body_not_dropped(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let Some(m) = self.core.ix.commits.get(c) else { return false };
        m.aspect(tid, ak).is_some_and(|ai| !m.body_gone(ai))
    }

    /// Whether this node keeps held part `(tid, ak)` of `c` under cover `s` though `s` covers it
    /// (`retention::own_kept_under`, spec/sync-compaction.md §1 own bodies).
    pub fn own_kept_under(&mut self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
        self.read(|tx| super::own_kept_under(tx, &s, &c, &tid, &ak))
    }

    /// Whether `c`'s part on `(tid, ak)` drops as covered (compaction, spec/commits.md §5;
    /// `retention::drops_as_covered`).
    pub fn droppable_if_covered(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let Some(m) = self.core.ix.commits.get(c) else { return false };
        m.aspect(tid, ak).is_some_and(|ai| super::drops_as_covered(m, ai, self.now().0))
    }

    /// The snapshots that covered `c`'s part on `(tid, ak)` when it dropped, and those that
    /// covered such a coverer dropped in turn (`Dropped::covered_by`).
    pub fn coverers_of(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
        let Some(ai) = self.core.ix.commits.get(c).and_then(|m| m.aspect(tid, ak)) else { return Vec::new() };
        super::coverers(&self.core, c, ai)
    }
}

