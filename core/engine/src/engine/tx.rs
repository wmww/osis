//! One transaction with the engine's in-memory state (`Tx`): its classes and steps, and its
//! reads and writes of states, commit records and local rows.

use super::{Core, Hold, Meta, Step, blobs, decode_commit_record, index, large, pages, records, refs, state};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, WallMs};
use osis_commit::CommitBlob;
use osis_crdt::Fragment;
use osis_crypto::CryptoRngCore;
use osis_store::{AspectUnit, Shred, Transaction};
use std::collections::BTreeSet;
use std::sync::Arc;

/// One transaction with the engine's in-memory state.
pub struct Tx<'a> {
    pub txn: Transaction<'a>,
    /// Blob ciphertexts, in the node's one store (`blobs::Cipher`).
    pub blobs: blobs::Cipher<'a>,
    pub core: &'a mut Core,
    pub rng: &'a mut dyn CryptoRngCore,
    /// What a bounded read may still hold of the states it loads (`Engine::get_within`,
    /// `pages::charge`); `None` otherwise.
    pub(crate) bound: pages::Bound,
    /// Per aspect, the held-writes pages this transaction read (`retention::bounds::index`,
    /// `osis_crdt::PageCache`), with the table they were read from; emptied by a rollback.
    pub(crate) held_pages: std::collections::BTreeMap<(Tid, Ak), (Option<osis_store::Table>, osis_crdt::PageCache)>,
    /// Things whose keysets written in this transaction carry KEM keys up to the role given
    /// (spec/crypto.md §3, Published KEM keys, judged at the transaction's end: "or is granted it
    /// in the same transaction"): a grant's holder, a mint admin of a thing minted after it, a
    /// minted thing whose setting the transaction enables a signal in (`rotation::kem`).
    pub(crate) publishing: Vec<(Tid, osis_base::Role)>,
}

impl Tx<'_> {
    /// Makes this a memory transaction: every new row in the store's memory overlay, the
    /// change counter `memory_generation`.
    pub fn set_memory(&mut self) {
        self.txn.set_memory(true);
        self.core.memory_tx = true;
    }

    /// Runs `f` as work on data of class `memory`: rows it creates for a
    /// memory commit or aspect inside a durable transaction go to memory, and it neither steps
    /// `generation` nor marks node-sync's changes. A memory transaction stays memory.
    pub fn in_class<T>(&mut self, memory: bool, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let was = self.core.memory_tx;
        let on = was || memory;
        self.txn.set_memory(on);
        self.core.memory_tx = on;
        let r = f(self);
        self.txn.set_memory(was);
        self.core.memory_tx = was;
        r
    }

    /// Runs `f` as one step: applied fully or not at all. On error every change it made to the
    /// store and the in-memory state is undone (`Transaction::savepoint`, `Core::mark`) and the
    /// error returned, so a caller that goes on continues from exactly the state before it.
    pub(crate) fn step<T>(&mut self, site: Step, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        let m = self.core.mark();
        let sp = self.txn.savepoint();
        let held = self.blobs.mark();
        #[cfg(test)]
        let r = match self.core.step_fault.as_mut().filter(|x| x.site == site) {
            Some(x) if x.skip > 0 => {
                x.skip -= 1;
                f(self)
            }
            Some(x) if x.after => f(self).and(Err(Error::BadInput("step fault (tests)"))),
            Some(_) => Err(Error::BadInput("step fault (tests)")),
            None => f(self),
        };
        #[cfg(not(test))]
        let r = {
            let _ = site;
            f(self)
        };
        match r {
            Ok(v) => {
                self.txn.release(sp)?;
                Ok(v)
            }
            Err(e) => {
                self.txn.rollback_to(sp);
                self.held_pages.clear();
                self.blobs.rollback_to(held);
                self.core.forget_reach_since(m.reached);
                let walked = m.walked;
                self.core.rollback_to(m);
                crate::apply::reach::rolled_back(self.core, walked);
                Err(e)
            }
        }
    }

    /// Whether commit `c` is a memory commit.
    pub fn is_memory_commit(&self, c: &CommitId) -> bool {
        self.core.ix.commits.get(c).is_some_and(|m| m.view.memory)
    }

    /// Writes the local record `records::aspect_key(prefix, tid, ak)`: memory for a memory
    /// aspect (as the store routes the aspect's own rows), whichever transaction writes it.
    pub(crate) fn put_aspect_local(&mut self, prefix: &[u8], tid: &Tid, ak: &Ak, val: &[u8]) -> Result<()> {
        let memory = ak.ephemeral();
        self.in_class(memory, |tx| Ok(tx.txn.put_local(&records::aspect_key(prefix, tid, ak), val, Shred::No)?))
    }

    /// Sets a retention timer of commit `c`'s part `ai` at `t`: memory for a memory commit.
    pub(crate) fn put_timer(&mut self, t: u64, c: &CommitId, ai: usize, kind: u8) -> Result<()> {
        let memory = self.is_memory_commit(c);
        self.core.timer_floor = self.core.timer_floor.min(t);
        self.in_class(memory, |tx| {
            tx.txn.put_local(&records::timer_key(t, c, ai), &[kind], Shred::No)?;
            Ok(tx.txn.put_local(&records::timer_of_key(t, c, ai), &[], Shred::No)?)
        })
    }

    /// Removes timer `t` of commit `c`'s part `ai`.
    pub(crate) fn remove_timer(&mut self, t: u64, c: &CommitId, ai: usize) -> Result<()> {
        self.txn.remove_local(&records::timer_key(t, c, ai), Shred::No)?;
        self.txn.remove_local(&records::timer_of_key(t, c, ai), Shred::No)?;
        Ok(())
    }

    /// Removes every timer of commit `c` (`ai`: of that part alone), found by part
    /// (`records::TIMER_OF`): O(the commit's timers).
    pub(crate) fn remove_timers_of(&mut self, c: &CommitId, ai: Option<usize>) -> Result<()> {
        let found = self.scan_rows(&[records::TIMER_OF, &c.0[..]].concat(), |k, _| {
            let mut r = records::Rd::new(k);
            Ok((r.u32()? as usize, r.u64()?))
        })?;
        for (x, t) in found.into_iter().filter(|(x, _)| ai.is_none_or(|ai| ai == *x)) {
            self.remove_timer(t, c, x)?;
        }
        Ok(())
    }

    /// The stored state row of `(tid, ak)` (`state::stored` reads it), empty where none is.
    fn stored_state(&mut self, tid: &Tid, ak: &Ak) -> Result<Vec<u8>> {
        Ok(self.txn.get_aspect(tid, ak)?.map(|u| u.state).unwrap_or_default())
    }

    /// The AKs of `t` with a state stored (an aspect unit), in key order.
    pub(crate) fn state_aks(&mut self, t: &Tid) -> Result<Vec<Ak>> {
        Ok(self.txn.aspects_of(t)?)
    }

    /// Loads the state of `(tid, ak)` into the cache: a paged state lazily (its skeleton; pages
    /// as `ensure_*` and `load` need them), a state stored as its body from that body's part in
    /// its commit record. The one reader of stored states.
    pub fn load_lazy(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        let k = (*tid, ak.clone());
        self.txn.noted_aspect(tid, ak);
        if self.core.states.contains_key(&k) {
            return Ok(());
        }
        let b = self.stored_state(tid, ak)?;
        let mut bound = self.bound.take();
        let f = match state::stored(&b)? {
            state::Stored::Empty => None,
            state::Stored::Whole(b) => Some(pages::charge(&mut bound, b.len(), || state::decode(b))?),
            state::Stored::Paged(b) => {
                let mut idx = None;
                let f = pages::charge(&mut bound, b.len(), || {
                    let (f, i) = pages::open(b, &self.core.key_salt)?;
                    idx = Some(i);
                    Ok(f)
                })?;
                self.core.pages.extend(idx.map(|i| (k.clone(), i)));
                Some(f)
            }
            state::Stored::Body(c) => {
                // its parts on the aspect, joined: one, or its pieces (spec/wire.md §4 Pieces)
                let ais = self.core.ix.commits.get(&c).map(|m| m.aspect_parts(tid, ak)).filter(|r| !r.is_empty()).ok_or(Error::Corrupt("state body"))?;
                let len = self.get_commit(&c)?.map(|r| ais.clone().filter_map(|ai| r.part(ai).map(|p| p.delta.len())).sum()).unwrap_or(0);
                Some(pages::charge(&mut bound, len, || self.stored_body(&c, ais)?.ok_or(Error::Corrupt("state body")))?)
            }
        };
        self.bound = bound;
        self.core.states.insert(k, f);
        Ok(())
    }

    /// The fragments of parts `ais` of commit `id` its record holds, joined (`apply::stored_fragment`):
    /// what a state stored as that body reads. `None` where one is not held.
    fn stored_body(&mut self, id: &CommitId, ais: std::ops::Range<usize>) -> Result<Option<Fragment>> {
        let mut out: Option<Fragment> = None;
        for ai in ais {
            let Some(f) = crate::apply::stored_fragment(self, id, ai)? else { return Ok(None) };
            match &mut out {
                Some(o) => {
                    o.join(f);
                }
                None => out = Some(f),
            }
        }
        Ok(out)
    }

    /// Before parts `ais` of commit `id` leave its record: each state stored as one of them
    /// (`state::Stored::Body`) is read into the cache and noted written, so this transaction reads
    /// it as it was and `settle_states` stores it again (by then it is rewritten: a valid body's
    /// drop rebuilds its state, shredded).
    pub(crate) fn pin_states(&mut self, id: &CommitId, ais: &[usize]) -> Result<()> {
        let Some(h) = self.core.ix.commits.get(id).map(|m| m.view.clone()) else { return Ok(()) };
        for ai in ais {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let k = (a.tid, a.ak.clone());
            let b = self.stored_state(&a.tid, &a.ak)?;
            if matches!(state::stored(&b)?, state::Stored::Body(c) if c == *id) {
                self.load_lazy(&a.tid, &a.ak)?;
                self.core.wrote(k);
            }
        }
        Ok(())
    }

    /// Transaction end: the placement of each paged sequence of a state written here that a
    /// write could not follow, or a read found missing or damaged, is laid out anew
    /// (`pages::unplaced`): the writer pays for it, and a read never writes.
    pub(crate) fn settle_placements(&mut self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for k in self.core.written.clone() {
            if !seen.insert(k.clone()) {
                continue;
            }
            let Some(ps) = self.core.pages.get(&k).map(pages::unplaced).filter(|p| !p.is_empty()) else { continue };
            let (tid, ak) = (&k.0, &k.1);
            self.with_pages(tid, ak, |txn, idx, f| ps.iter().try_for_each(|p| pages::rebuild_placement(txn, tid, ak, idx, f, p)))?;
        }
        Ok(())
    }

    /// Transaction end: each unpaged state written here is stored as a body equal to it, held
    /// whole and valid (`state::Stored::Body`): the one it names already, else the aspect's
    /// newest; else whole. One rule for every writer (joins, rebuilds, drops, purges); equality
    /// makes the reference exact whatever normalised the state.
    pub(crate) fn settle_states(&mut self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for k in self.core.written.clone() {
            if !seen.insert(k.clone()) || self.core.pages.contains_key(&k) {
                continue;
            }
            let Some(Some(st)) = self.core.states.get(&k) else { continue };
            let (tid, ak) = (&k.0, &k.1);
            let st = st.clone();
            let b = self.stored_state(tid, ak)?;
            let now = match state::stored(&b)? {
                state::Stored::Body(c) => Some(c),
                _ => None,
            };
            // the body it names already, then the newest held one
            let newest = self.core.ix.by_aspect.get(&k).and_then(|s| s.iter().next_back()).map(|x| x.1);
            let mut same = None;
            for c in now.into_iter().chain(newest.filter(|c| Some(*c) != now)) {
                // every part of it on the aspect held whole and valid (one, or its pieces)
                let Some(ais) = self.core.ix.commits.get(&c).map(|m| m.aspect_parts(tid, ak)).filter(|r| !r.is_empty() && self.core.ix.commits.get(&c).is_some_and(|m| r.clone().all(|ai| m.valid_at(ai) && m.holds(ai) && !m.stripped(ai)))) else { continue };
                if self.stored_body(&c, ais)?.is_some_and(|f| f == st) {
                    same = Some(c);
                    break;
                }
            }
            match same {
                Some(c) if now != Some(c) => self.txn.put_aspect(tid, ak, &AspectUnit { state: state::body(&c) }, Shred::No)?,
                None if now.is_some() => self.write_state(tid, ak, Some(st), Shred::No)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Whether the state of `(tid, ak)` is paged with some page not loaded.
    fn held_in_part(&self, tid: &Tid, ak: &Ak) -> bool {
        self.core.pages.get(&(*tid, ak.clone())).is_some_and(|i| !i.whole())
    }

    /// Runs `g` on the cached state of `(tid, ak)` (taken out of the cache meanwhile) and its page
    /// index; nothing for an unpaged state.
    fn with_pages<T>(&mut self, tid: &Tid, ak: &Ak, g: impl FnOnce(&mut Transaction<'_>, &mut pages::StatePages, &mut Fragment) -> Result<T>) -> Result<Option<T>> {
        let k = (*tid, ak.clone());
        let Some(idx) = self.core.pages.get_mut(&k) else { return Ok(None) };
        let Some(mut f) = self.core.states.get_mut(&k).and_then(Option::take) else { return Ok(None) };
        idx.bound = self.bound.take();
        let r = g(&mut self.txn, idx, &mut f);
        self.bound = idx.bound.take();
        self.core.states.insert(k, Some(f));
        r.map(Some)
    }

    /// Runs read `f` of `(tid, ak)` holding at most `max` bytes of the state as it loads it
    /// (`pages::charge`), then leaves the cache about as it found it: a state it loaded goes (as at
    /// a restart), one held in part before loses its loaded pages (`pages::evict`, which keeps a
    /// paged sequence's). So a read holds what it loads only while it runs.
    pub(crate) fn reading<T>(&mut self, tid: &Tid, ak: &Ak, max: Option<usize>, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let k = (*tid, ak.clone());
        let cached = self.core.states.contains_key(&k);
        let whole = !self.held_in_part(tid, ak);
        self.bound = max.map(pages::Budget::new);
        let r = f(self);
        self.bound = None;
        if !cached {
            self.core.states.remove(&k);
            self.core.pages.remove(&k);
        } else if !whole {
            self.evict_pages(tid, ak);
        }
        r
    }

    /// Loads the whole state of `(tid, ak)` into the cache.
    pub fn load(&mut self, tid: &Tid, ak: &Ak) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if self.held_in_part(tid, ak) {
            // counted: scale tests read which operations hold a paged state whole
            drop(osis_base::costs::span("paged state loaded whole"));
            self.with_pages(tid, ak, |txn, idx, f| pages::load_all(txn, tid, ak, idx, f))?;
        }
        Ok(())
    }

    /// Loads what reads at `paths` (op path segments) read: each position and all below it
    /// (`pages::ensure_path`).
    pub fn ensure_paths(&mut self, tid: &Tid, ak: &Ak, paths: &[Vec<osis_crdt::PathSeg>]) -> Result<()> {
        self.ensure_at(tid, ak, paths.iter().map(|p| (p.as_slice(), true)))
    }

    /// Loads what ops at `paths` (positions, and whether below each) read and write
    /// (`pages::ensure_path`).
    fn ensure_at<'p>(&mut self, tid: &Tid, ak: &Ak, paths: impl IntoIterator<Item = (&'p [osis_crdt::PathSeg], bool)>) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if !self.held_in_part(tid, ak) {
            return Ok(());
        }
        let ok = self.with_pages(tid, ak, |txn, idx, f| {
            for (p, below) in paths {
                if !pages::ensure_path(txn, tid, ak, idx, f, p, below)? {
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        if ok == Some(false) {
            self.load(tid, ak)?;
        }
        Ok(())
    }

    /// Loads what `ops` on `(tid, ak)` read: the `paths` they address (`pages::op_paths`), else
    /// (ops by index into paged sequences, `edits`) the pages they attach to through the stored
    /// placements (`pages::attach_ops`; `new`: the first element the ops would create), else the
    /// whole state. Whether they attached (`run_attached`).
    pub(crate) fn load_for_ops(&mut self, tid: &Tid, ak: &Ak, paths: Option<Vec<pages::OpPath>>, ops: &[osis_crdt::PathOp], edits: &[Option<large::ListEdit>], new: &osis_crdt::Dot) -> Result<bool> {
        if let Some(paths) = paths {
            self.ensure_at(tid, ak, paths.iter().map(|p| (p.path.as_slice(), p.below)))?;
            return Ok(false);
        }
        self.load_lazy(tid, ak)?;
        if self.held_in_part(tid, ak) && self.with_pages(tid, ak, |txn, idx, f| pages::attach_ops(txn, tid, ak, idx, f, ops, edits, new))? == Some(true) {
            return Ok(true);
        }
        self.load(tid, ak)?;
        Ok(false)
    }

    /// `run` on the state of `(tid, ak)` as loaded; if the ops `attached` (`load_for_ops`), run
    /// again while it missed rows, chunks or pages (what it missed loaded, `pages::absorb`) until
    /// the runs' work passes about one whole pass, then on the whole state.
    pub(crate) fn run_attached<R>(&mut self, tid: &Tid, ak: &Ak, attached: bool, run: impl Fn(&Tx<'_>) -> R) -> Result<R> {
        let mut out = run(self);
        if !attached {
            return Ok(out);
        }
        let mut work = 0;
        loop {
            match self.with_pages(tid, ak, |txn, idx, f| pages::absorb(txn, tid, ak, idx, f, &mut work))?.flatten() {
                Some(false) => break,
                Some(true) => out = run(self),
                None => {
                    self.load(tid, ak)?;
                    out = run(self);
                    break;
                }
            }
        }
        Ok(out)
    }

    /// The visible elements `r` (by index, clamped) of the sequence at `path` (op path segments):
    /// a paged one through its placement (`pages::seq_range`), loading only the pages holding
    /// them; else, or where the placement is missing or damaged (laid out anew by the next
    /// transaction writing the state, `settle_placements`), from the whole sequence. `None` if
    /// absent or not a sequence.
    pub fn read_range(&mut self, tid: &Tid, ak: &Ak, path: &[osis_crdt::PathSeg], r: std::ops::Range<usize>) -> Result<Option<osis_base::Value>> {
        self.load_lazy(tid, ak)?;
        if self.held_in_part(tid, ak)
            // an empty sequence reads whole (its presence)
            && let Some(pages::Ranged::Read(p, dots, total)) = self.with_pages(tid, ak, |txn, idx, f| pages::seq_range(txn, tid, ak, idx, f, path, r.clone()))?
            && total > 0
        {
            match self.cached(tid, ak).and_then(|f| f.at_steps(&p)).and_then(|s| s.read_elems(&dots)) {
                Some(v) => return Ok(Some(v)),
                // a placement naming what its pages lack
                None => {
                    if let Some(idx) = self.core.pages.get_mut(&(*tid, ak.clone())) {
                        pages::damaged(idx, &p);
                    }
                }
            }
        }
        self.ensure_paths(tid, ak, &[path.to_vec()])?;
        Ok(self.cached(tid, ak).and_then(|f| f.at(path)).filter(Fragment::present).and_then(|s| s.read_elems(&s.visible_range(r)?)))
    }

    /// Loads what joining a delta with this touch reads and rewrites (`pages::ensure_touch`;
    /// `None`: everything).
    pub fn ensure_touch(&mut self, tid: &Tid, ak: &Ak, touch: &pages::Touch) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if !self.held_in_part(tid, ak) {
            return Ok(());
        }
        if let Some(t) = touch
            && self.with_pages(tid, ak, |txn, idx, f| pages::ensure_touch(txn, tid, ak, idx, f, t))? == Some(true)
        {
            return Ok(());
        }
        self.load(tid, ak)
    }

    /// A joined state `st` of `(tid, ak)` as it is cached: `None` exactly when the whole state
    /// is empty, as a rebuild leaves it. A paged state whose loaded part is empty loads every
    /// page first: a page not loaded may hold elements below a record the skeleton drops (one
    /// holding only paged content, `PageSet::path`), and an emptied first page stays (rare: an
    /// un-merge emptying all that is loaded).
    pub fn kept(&mut self, tid: &Tid, ak: &Ak, mut st: osis_crdt::Fragment) -> Result<Option<osis_crdt::Fragment>> {
        if st.is_empty()
            && let Some(idx) = self.core.pages.get_mut(&(*tid, ak.clone()))
        {
            pages::load_all(&mut self.txn, tid, ak, idx, &mut st)?;
        }
        Ok((!st.is_empty()).then_some(st))
    }

    /// Drops the loaded pages of the cached state of `(tid, ak)`, keeping its skeleton
    /// (`pages::evict`).
    pub fn evict_pages(&mut self, tid: &Tid, ak: &Ak) {
        let k = (*tid, ak.clone());
        if let (Some(idx), Some(Some(f))) = (self.core.pages.get_mut(&k), self.core.states.get_mut(&k)) {
            pages::evict(idx, f);
        }
    }

    /// Joins `delta` into the paged state of `(tid, ak)` a page at a time where it may reset a
    /// paged collection or change its encoding (`pages::join_reset`); `None`: not paged, or it
    /// does not fit (join whole, nothing noted in `dead`). The state is noted written.
    pub(crate) fn join_reset(&mut self, tid: &Tid, ak: &Ak, delta: &osis_crdt::Fragment, dead: Option<&mut crate::retention::Killed>) -> Result<Option<osis_crdt::Changes>> {
        let k = (*tid, ak.clone());
        // an index derives from the whole state (`derive`): joined whole
        if !self.core.pages.contains_key(&k) || derives(ak) {
            return Ok(None);
        }
        // noted first: a failure midway evicts what it changed
        self.core.touch();
        self.core.wrote(k.clone());
        let (Some(idx), Some(Some(f))) = (self.core.pages.get_mut(&k), self.core.states.get(&k)) else { return Ok(None) };
        let mut moved = refs::Delta::default();
        match pages::join_reset(&mut self.txn, tid, ak, idx, f, delta, &mut moved, dead)? {
            pages::Reset::Whole => {
                let _s = osis_base::costs::span("reset: whole");
                Ok(None)
            }
            pages::Reset::Paged { skeleton, unit, changes } => {
                let _s = osis_base::costs::span("reset: by pages");
                self.txn.put_aspect(tid, ak, &AspectUnit { state: unit }, Shred::No)?;
                self.core.states.insert(k, Some(skeleton));
                refs::note(self, tid, ak, moved)?;
                Ok(Some(changes))
            }
            pages::Reset::Laid { state, changes } => {
                let _s = osis_base::costs::span("reset: laid out");
                self.set_state(tid, ak, state, Shred::No)?;
                Ok(Some(changes))
            }
        }
    }

    /// The cached state as loaded so far (after `load_lazy` and `ensure_*`).
    pub fn cached(&self, tid: &Tid, ak: &Ak) -> Option<&Fragment> {
        self.core.states.get(&(*tid, ak.clone())).and_then(Option::as_ref)
    }

    /// The part of the state of `(tid, ak)` a join of `f` meets: a paged state's skeleton and
    /// the pages holding `f`'s dots (`pages::touch_of`; all of them where `f` may reset a paged
    /// collection), dropped from the cache again (`evict_pages`), so reading a delta against
    /// the state a piece at a time holds about one page of it. `None`: the state is empty.
    pub fn state_at(&mut self, tid: &Tid, ak: &Ak, f: &Fragment) -> Result<Option<Fragment>> {
        self.load_touched(tid, ak, f)?;
        drop(osis_base::costs::span("state copied whole"));
        let out = self.cached(tid, ak).cloned();
        self.evict_pages(tid, ak);
        Ok(out)
    }

    /// The state of `(tid, ak)` at `f`'s positions (`Fragment::part_at`: what a join of `f` meets,
    /// the resets on its paths included), loading only the pages `f` touches: O(f), not a copy of
    /// the state.
    pub fn state_part_at(&mut self, tid: &Tid, ak: &Ak, f: &Fragment) -> Result<Option<Fragment>> {
        self.load_touched(tid, ak, f)?;
        let out = self.cached(tid, ak).map(|s| s.part_at(f));
        self.evict_pages(tid, ak);
        Ok(out)
    }

    /// Loads the state of `(tid, ak)` with the pages a join of `f` meets (`pages::touch_of`).
    fn load_touched(&mut self, tid: &Tid, ak: &Ak, f: &Fragment) -> Result<()> {
        self.load_lazy(tid, ak)?;
        let touch = pages::touch_of(f, self.core.pages.get(&(*tid, ak.clone())));
        self.ensure_touch(tid, ak, &touch)
    }

    /// The pieces of the state of `(tid, ak)` as a read sees each, within the running read's
    /// bound (`reading`): an unpaged or wholly loaded state is one piece, a paged one its skeleton,
    /// then its pages one at a time read from the store, never joined into the cache
    /// (`osis_crdt::each_piece`; with `keys` each reads as the whole does there, and a collection
    /// paged inside another's elements reads whole, one piece). `each` returns whether to stop.
    pub(crate) fn each_piece(&mut self, tid: &Tid, ak: &Ak, keys: bool, each: &mut dyn FnMut(&Fragment) -> Result<bool>) -> Result<()> {
        self.load_lazy(tid, ak)?;
        if self.held_in_part(tid, ak) {
            let k = (*tid, ak.clone());
            if let (Some(idx), Some(Some(f))) = (self.core.pages.get(&k), self.core.states.get(&k)) {
                let skeleton = f.reduced(idx.paths());
                let mut err = None;
                let mut w = pages::StoredPages::new(&mut self.txn, tid, ak, idx, self.bound)?;
                let r = osis_crdt::each_piece(osis_crdt::Paged { skeleton: &skeleton, paths: idx.paths(), pages: &mut w, gone: &|_| false }, keys, &mut |f| {
                    each(f).unwrap_or_else(|e| {
                        err = Some(e);
                        true
                    })
                });
                if let Some(e) = err.or_else(|| w.take_err()) {
                    return Err(e);
                }
                if r?.is_some() {
                    return Ok(());
                }
            }
        }
        if let Some(f) = self.state(tid, ak)? {
            each(f)?;
        }
        Ok(())
    }

    /// Whether the state of `(tid, ak)` is present (`Fragment::present`), holding at most `max`
    /// of it (`reading`): its pieces up to the first present one (`each_piece`; a state is
    /// present iff a write in it survives, and each piece holds what prunes its writes).
    pub fn present_within(&mut self, tid: &Tid, ak: &Ak, max: Option<usize>) -> Result<bool> {
        self.reading(tid, ak, max, |tx| {
            let mut present = false;
            tx.each_piece(tid, ak, false, &mut |f| {
                present = f.present();
                Ok(present)
            })?;
            Ok(present)
        })
    }

    /// The whole state of `(tid, ak)`.
    pub fn state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<&Fragment>> {
        self.load(tid, ak)?;
        Ok(self.cached(tid, ak))
    }

    /// Writes a whole state; `f` is the whole state. The reference index follows it whole
    /// (`refs::resync`).
    pub fn set_state(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, shred: Shred) -> Result<()> {
        refs::resync(self, tid, ak, f.as_ref())?;
        self.write_state(tid, ak, f, shred)
    }

    /// `set_state` for a join, whose caller keeps the reference index (`refs::Delta::reach`).
    fn write_state(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, shred: Shred) -> Result<()> {
        self.core.touch();
        self.core.wrote((*tid, ak.clone()));
        let paged = matches!(state::stored(&self.stored_state(tid, ak)?)?, state::Stored::Paged(_));
        let (state, idx) = pages::write_full(&mut self.txn, tid, ak, f.as_ref(), paged, &self.core.key_salt)?;
        match idx {
            Some(idx) => self.core.pages.insert((*tid, ak.clone()), idx),
            None => self.core.pages.remove(&(*tid, ak.clone())),
        };
        // an aspect has a unit while it has a state (`state_aks`)
        match f {
            Some(_) => self.txn.put_aspect(tid, ak, &AspectUnit { state }, shred)?,
            None => self.txn.remove_aspect(tid, ak, shred)?,
        }
        self.derive(tid, ak, f.as_ref());
        self.core.states.insert((*tid, ak.clone()), f);
        Ok(())
    }

    /// Keeps the index derived from states at the state `f` of `(tid, ak)`, whatever wrote it:
    /// `Indexes::sync_recorded`, `Indexes::steps`.
    fn derive(&mut self, tid: &Tid, ak: &Ak, f: Option<&Fragment>) {
        if derives(ak) {
            let before = self.core.ix.sync_recorded_ids.get(tid).cloned().unwrap_or_default();
            let after = f.map(crate::sync::recorded_ids).unwrap_or_default();
            match after.is_empty() {
                true => self.core.ix.sync_recorded_ids.remove(tid),
                false => self.core.ix.sync_recorded_ids.insert(*tid, after.clone()),
            };
            for s in before.difference(&after) {
                self.core.ix.sync_recorders.remove(s, tid);
            }
            for s in after.difference(&before) {
                self.core.ix.sync_recorders.insert(*s, *tid);
            }
            match f {
                Some(_) => self.core.ix.sync_recorded.insert(*tid),
                None => self.core.ix.sync_recorded.remove(tid),
            };
            self.core.steps_recorded(tid, f);
        }
    }

    /// Writes a state a join changed: `touch` (`pages::touch_of` the delta) says what it
    /// changed. A paged state rewrites only those pages (and its skeleton if needed); anything
    /// else is written whole (the pages not loaded joined in first). The caller has noted the
    /// state as written (`Core::written`).
    pub fn set_state_touched(&mut self, tid: &Tid, ak: &Ak, f: Option<Fragment>, touch: &pages::Touch, shred: Shred) -> Result<()> {
        let k = (*tid, ak.clone());
        let mut f = f;
        // an index derives from the whole state (`derive`), never the pages loaded
        if derives(ak)
            && let (Some(st), Some(idx)) = (&mut f, self.core.pages.get_mut(&k))
        {
            pages::load_all(&mut self.txn, tid, ak, idx, st)?;
        }
        if let (Some(st), Some(idx), Some(touch)) = (&f, self.core.pages.get_mut(&k), touch)
            && let Some(unit_state) = pages::write_touched(&mut self.txn, idx, tid, ak, st, touch, shred)?
        {
            if let Some(s) = unit_state {
                self.txn.put_aspect(tid, ak, &AspectUnit { state: s }, shred)?;
            }
            self.derive(tid, ak, f.as_ref());
            self.core.states.insert(k, f);
            return Ok(());
        }
        if let (Some(st), Some(idx)) = (&mut f, self.core.pages.get_mut(&k)) {
            pages::load_all(&mut self.txn, tid, ak, idx, st)?;
        }
        self.write_state(tid, ak, f, shred)
    }

    /// `m` as `id`'s meta, its stored record rewritten under it (the blob unchanged).
    pub(crate) fn put_meta_record(&mut self, id: &CommitId, m: Meta) -> Result<()> {
        if let Some(blob) = self.get_commit(id)? {
            self.put_commit(id, &blob, &m, Shred::No, None)?;
        }
        self.core.put_meta(*id, m);
        Ok(())
    }

    /// Writes a commit record (`index::record_head`: received, origin, dropped parts and what
    /// they keep; then its blob), and for a role commit its `node/perm` row (`edges`: what the caller already
    /// read of `blob` with `perm_parts_of`, else decoded here).
    pub(crate) fn put_commit(&mut self, id: &CommitId, blob: &CommitBlob, meta: &Meta, shred: Shred, edges: Option<&crate::apply::validity::PermParts>) -> Result<()> {
        // the bodies leaving the record: held whole as the index has it, absent from `blob`
        self.core.note_kept(id, meta);
        let leaving: Vec<usize> = self.core.ix.commits.get(id).map(|m| (0..m.view.aspects.len()).filter(|ai| m.holds(*ai) && !m.stripped(*ai) && blob.part(*ai).is_none()).collect()).unwrap_or_default();
        self.pin_states(id, &leaving)?;
        for ai in &leaving {
            crate::apply::remove_page_index(self, id, Some(*ai))?;
        }
        // a blob made again from what the record carries is made a last time first
        crate::sync::bodies::unseal_record(self, id, Some(blob))?;
        let v = [index::record_head(meta), blob.encode()].concat();
        self.txn.put_local(&records::commit_key(id), &v, shred)?;
        crate::sync_ids::opened::prune(self, id, meta)?;
        if meta.header.kind.is_role() {
            // perm's reading of it, persisted beside the record (an open decodes no body)
            match edges {
                Some(p) => index::put_perm(self, id, p, shred)?,
                None => {
                    let p = crate::apply::perm_parts_of(self, id, &meta.header, blob)?;
                    index::put_perm(self, id, &p, shred)?;
                }
            }
        }
        // likewise what an addendum says (`validity::note_addenda` read it from the body)
        if meta.view.aspects.iter().any(|a| osis_schema::core_types::is_addenda(a.ak.as_str())) {
            let p = crate::apply::validity::AddendaParts::from_index(self.core, id, &meta.view.aspects);
            index::put_addenda(self, id, &p, shred)?;
        }
        Ok(())
    }

    /// Removes a commit record (shredded) with what the index keeps beside it.
    pub fn remove_commit(&mut self, id: &CommitId) -> Result<()> {
        crate::sync::bodies::unseal_record(self, id, None)?;
        self.txn.remove_local(&records::commit_key(id), Shred::Yes)?;
        crate::apply::remove_page_index(self, id, None)?;
        crate::sync_ids::opened::forget(self, id)?;
        index::remove_perm(self, id)?;
        index::remove_addenda(self, id)
    }

    /// The blob of the stored record of commit `id`, decoded once per write of the record
    /// (`Core::decoded`).
    pub fn get_commit(&mut self, id: &CommitId) -> Result<Option<Arc<CommitBlob>>> {
        let key = records::commit_key(id);
        self.txn.noted_local(&key);
        let at = self.txn.local_stamp(&key);
        let txn = &mut self.txn;
        if let Some(b) = self.core.decoded.record(id, at, || osis_base::costs::paused(|| txn.get_local(&key)))? {
            return Ok(Some(b));
        }
        drop(osis_base::costs::span("commit read"));
        let Some(v) = self.txn.get_local(&key)? else { return Ok(None) };
        let b = Arc::new(decode_commit_record(&v)?.1);
        self.core.decoded.keep_record(*id, at, b.clone(), &v);
        Ok(Some(b))
    }

    /// `get_commit` for the bytes of the parts `keep` selects alone, read at those parts' holds
    /// in the index (`Meta::hold`) rather than at the record's row: a part's bytes are fixed by
    /// the commit's ID, and the record carries exactly the parts held as their bodies, so a reader
    /// of some parts moves with those parts alone, not with another part of the commit arriving or
    /// dropping. Mid-write (a hold set before its record is written, or after) the two disagree:
    /// the reader then reads the row too, so the write moves it whatever order it comes in.
    pub(crate) fn commit_for_parts(&mut self, id: &CommitId, keep: &dyn Fn(usize) -> bool) -> Result<Option<Arc<CommitBlob>>> {
        let Some(m) = self.core.ix.commits.get(id) else { return self.get_commit(id) };
        let bodies: Vec<(usize, bool)> = (0..m.parts()).filter(|ai| keep(*ai)).map(|ai| (ai, matches!(m.hold(ai), Some(Hold::Body { .. })))).collect();
        let blob = osis_base::memo::unrecorded(|| self.get_commit(id))?;
        if bodies.iter().any(|(ai, body)| *body != blob.as_ref().is_some_and(|b| b.part(*ai).is_some())) {
            self.txn.noted_local(&records::commit_key(id));
        }
        Ok(blob)
    }

    /// The change stamp of commit `id`'s record (`Transaction::local_stamp`): what `Core::decoded`
    /// keeps its decodes at.
    pub(crate) fn commit_stamp(&self, id: &CommitId) -> u64 {
        self.txn.local_stamp(&records::commit_key(id))
    }

    /// Every stored pending or parked copy, a page at a time.
    pub(crate) fn each_pending(&mut self, mut f: impl FnMut(CommitId, osis_store::Pending)) -> Result<()> {
        let mut after: Option<CommitId> = None;
        loop {
            let page = self.txn.pending(after.as_ref(), SCAN_PAGE)?;
            let n = page.len();
            for (id, p) in page {
                after = Some(id);
                f(id, p);
            }
            if n < SCAN_PAGE {
                return Ok(());
            }
        }
    }

    /// Removes, shredded, every local record under `prefix` whose key past it `pred` takes.
    pub(crate) fn remove_scanned(&mut self, prefix: &[u8], pred: impl Fn(&[u8]) -> Result<bool>) -> Result<()> {
        let mut gone = Vec::new();
        self.scan(prefix, |k, _| {
            if pred(k)? {
                gone.push([prefix, k].concat());
            }
            Ok(())
        })?;
        for k in gone {
            self.txn.remove_local(&k, Shred::Yes)?;
        }
        Ok(())
    }

    /// Scans local records under `prefix` (keys returned without it).
    pub fn scan(&mut self, prefix: &[u8], mut f: impl FnMut(&[u8], Vec<u8>) -> Result<()>) -> Result<()> {
        let mut from: Vec<u8> = Vec::new();
        loop {
            let page = self.txn.scan_local(prefix, &from, SCAN_PAGE)?;
            let n = page.len();
            for (k, v) in page {
                let tail = k.get(prefix.len()..).unwrap_or_default();
                from = [tail, &[0]].concat();
                f(tail, v)?;
            }
            if n < SCAN_PAGE {
                return Ok(());
            }
        }
    }

    /// `scan`, each row (key, value) made a `T` by `f`, in key order.
    pub(crate) fn scan_rows<T>(&mut self, prefix: &[u8], mut f: impl FnMut(&[u8], Vec<u8>) -> Result<T>) -> Result<Vec<T>> {
        let mut out = Vec::new();
        self.scan(prefix, |k, v| {
            out.push(f(k, v)?);
            Ok(())
        })?;
        Ok(out)
    }

    /// The keys under `prefix`, each `N` bytes made a `T` by `of`; a key of another length is a
    /// corrupt `what` row.
    pub(crate) fn scan_keys<const N: usize, T>(&mut self, prefix: &[u8], what: &'static str, of: impl Fn([u8; N]) -> T) -> Result<Vec<T>> {
        self.scan_rows(prefix, |k, _| Ok(of(k.try_into().map_err(|_| Error::Corrupt(what))?)))
    }

    pub fn now(&self) -> WallMs {
        self.core.now()
    }
}

/// Rows read per store call by the scans.
const SCAN_PAGE: usize = 256;

/// Calls `f` on every row of table `t` from `start` up to `end` (exclusive), a page of rows
/// per store call.
pub(crate) fn scan_table(txn: &mut Transaction<'_>, t: osis_store::Table, start: &[u8], end: Option<&[u8]>, mut f: impl FnMut(Vec<u8>, Vec<u8>) -> Result<()>) -> Result<()> {
    let mut from = start.to_vec();
    loop {
        let rows = txn.table_range(t, &from, end, SCAN_PAGE)?;
        let n = rows.len();
        for (k, v) in rows {
            from = [k.as_slice(), &[0]].concat();
            f(k, v)?;
        }
        if n < SCAN_PAGE {
            return Ok(());
        }
    }
}

/// Removes every row of table `t` from `start` up to `end` (exclusive).
pub(crate) fn clear_table(txn: &mut Transaction<'_>, t: osis_store::Table, start: &[u8], end: &[u8], shred: Shred) -> Result<()> {
    loop {
        let rows = txn.table_range(t, start, Some(end), SCAN_PAGE)?;
        if rows.is_empty() {
            return Ok(());
        }
        for (k, _) in rows {
            txn.table_remove(t, &k, shred)?;
        }
    }
}

/// Whether an index derives from the state of aspect `ak` (`Tx::derive`): `sync.0`'s recorded
/// sync IDs, read from the whole state.
fn derives(ak: &Ak) -> bool {
    ak.as_str() == "sync.0"
}
