//! Suspect lists out and in (spec/permissions.md §4 Suspect, Suspect list; spec/sync-compaction.md
//! §1 Repair; spec/wire.md §11.2 Suspect).
//!
//! Out: per S, this node's flagged, not dormant aspects of things S carries (the engine's
//! `suspect(t, ak)` per aspect, grouped by its `carrying(t)`), most recently flagged first, each
//! with its state digest taken as it goes. Sent to each member's peer at its join and to every
//! member's peer when S's list moves, once S's first sync here ended (`Store::first_synced`: a
//! node mid first sync digests a partial state, so every writer would repair it for nothing).
//! An empty list, or one going empty, sends nothing: a repair is idempotent.
//!
//! In: a list from a peer is judged only for its reporter, the account it proved holding read or
//! above on S's actor (`Engine::reader_account`); a peer proving none is answered Ok and not
//! acted on. Account, not node: an account adds nodes at will, so per node one account could ask
//! as many repairs per state as it has nodes; a snapshot written for one of its nodes reaches the
//! others under S anyway. Before S's first sync here ended, the latest message per (connection,
//! S) waits, its entries this node may repair, judged once it ends (the sender sends again only
//! when its flags move). Each entry: `Engine::repair_suspect` with the digest of the state this node last wrote
//! a snapshot from for that reporter (row `I/s/ reporter thing ak`), and the row follows: written
//! with a snapshot, dropped when the entry is the same state or not judged, so it is kept only
//! while it can spare a repair.
//!
//! Work follows change: one `Effects` key per flagged aspect (new ones from `suspect_feed`), one
//! per S whose first sync is awaited; a list goes out only when S's list moved or a member
//! joined.
//!
//! Bounds: a followed key per flagged aspect, and its place in the lists of the sync IDs carrying
//! it (both go with the flag); the members per S (gone at `Left` or close); one message's entries
//! waiting per (connection, S), only aspects this node may snapshot (gone at `Left`, close or the
//! first sync's end); a row per (reporter account, aspect), replaced by a later
//! state. A flood of lists repairs at most once per state per reporter.

use super::{Here, Net};
use crate::types::{ConnId, Result};
use osis_base::memo::{Effects, Feed};
use osis_base::{Ak, SyncId, Tid};
use osis_engine::retention::suspect::Repaired;
use osis_proto::{Msg, SuspectEntry};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

const ROWS: &[u8] = b"I/s/";

type Aspect = (Tid, Ak);

/// A list waiting for S's first sync here to end: its reporter and entries.
type Waiting = (Tid, BTreeMap<Aspect, [u8; 16]>);

/// A flagged aspect as the lists see it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Flag {
    /// Its flag went: let go.
    Gone,
    /// Flagged, not listed: dormant, or its thing's record unknown.
    Quiet,
    /// Listed under these sync IDs, flagged at `at`.
    Listed { at: u64, under: BTreeSet<SyncId> },
}

#[derive(Clone)]
pub(super) struct Suspects {
    feed: Option<Feed<Aspect>>,
    flags: Effects<Aspect, Flag>,
    /// Per S, the listed aspects and when each was flagged.
    lists: BTreeMap<SyncId, BTreeMap<Aspect, u64>>,
    /// Sync IDs with a list or entries waiting, followed for their first sync's end.
    synced: Effects<SyncId, bool>,
    first: BTreeSet<SyncId>,
    members: BTreeMap<SyncId, BTreeSet<ConnId>>,
    /// Lists owed to a member's peer: at its join, or S's list moved.
    owed: BTreeSet<(ConnId, SyncId)>,
    /// Entries received before S's first sync here ended: the reporter and its entries.
    waiting: BTreeMap<(ConnId, SyncId), Waiting>,
}

impl Default for Suspects {
    fn default() -> Self {
        Suspects { feed: None, flags: Effects::new("inbox: suspect flags"), lists: BTreeMap::new(), synced: Effects::new("inbox: first synced"), first: BTreeSet::new(), members: BTreeMap::new(), owed: BTreeSet::new(), waiting: BTreeMap::new() }
    }
}

/// The key of the row naming the state last snapshotted for `reporter`.
fn row(reporter: &Tid, t: &Tid, ak: &Ak) -> Vec<u8> {
    [ROWS, reporter.as_bytes(), t.as_bytes(), ak.as_str().as_bytes()].concat()
}

/// Bytes a message's frame and fields take besides its entries, and an entry's beyond its AK:
/// generous, so a chunk never passes `MAX_MESSAGE`.
const FRAME: usize = 256;
const ENTRY: usize = 15 + 16 + 16;

/// `entries` cut into messages of at most `max` bytes each, in order.
pub(crate) fn chunks(entries: Vec<SuspectEntry>, max: usize) -> Vec<Vec<SuspectEntry>> {
    let mut out: Vec<Vec<SuspectEntry>> = Vec::new();
    let mut size = FRAME;
    let mut cur: Vec<SuspectEntry> = Vec::new();
    for e in entries {
        let n = ENTRY + e.ak.as_str().len();
        if !cur.is_empty() && size + n > max {
            out.push(std::mem::take(&mut cur));
            size = FRAME;
        }
        size += n;
        cur.push(e);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// S's list in sending order: the most recently flagged first.
fn ordered(list: &BTreeMap<Aspect, u64>) -> Vec<&Aspect> {
    let mut v: Vec<(&Aspect, u64)> = list.iter().map(|(k, at)| (k, *at)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    v.into_iter().map(|(k, _)| k).collect()
}

impl Suspects {
    /// Follows every flag held now; new ones come by the feed.
    pub(super) fn start(&mut self, h: &mut Here<'_>) {
        self.feed = Some(h.engine.suspect_feed());
        for k in h.engine.suspect_keys() {
            self.flags.want(k);
        }
    }

    pub(super) fn joined(&mut self, conn: ConnId, s: SyncId) {
        self.members.entry(s).or_default().insert(conn);
        self.owed.insert((conn, s));
    }

    pub(super) fn left(&mut self, conn: ConnId, s: &SyncId) {
        if let Some(m) = self.members.get_mut(s) {
            m.remove(&conn);
            if m.is_empty() {
                self.members.remove(s);
            }
        }
        self.owed.remove(&(conn, *s));
        self.waiting.remove(&(conn, *s));
    }

    pub(super) fn closed(&mut self, conn: ConnId) {
        for m in self.members.values_mut() {
            m.remove(&conn);
        }
        self.members.retain(|_, m| !m.is_empty());
        self.owed.retain(|(c, _)| *c != conn);
        self.waiting.retain(|(c, _), _| *c != conn);
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>, net: &mut impl Net) -> Result<bool> {
        if let Some(f) = self.feed.as_mut() {
            for k in f.added() {
                self.flags.want(k);
            }
        }
        let mut moved = BTreeSet::new();
        for k in self.flags.due() {
            let engine = &mut *h.engine;
            let Some((was, now)) = self.flags.try_settle(&k, || flag(engine, &k))? else { continue };
            if let Some(Flag::Listed { under, .. }) = &was {
                for s in under {
                    if let Some(l) = self.lists.get_mut(s) {
                        l.remove(&k);
                        if l.is_empty() {
                            self.lists.remove(s);
                        }
                    }
                    moved.insert(*s);
                }
            }
            match &now {
                Flag::Listed { at, under } => {
                    for s in under {
                        self.lists.entry(*s).or_default().insert(k.clone(), *at);
                        moved.insert(*s);
                    }
                }
                Flag::Gone => self.flags.unwant(&k),
                Flag::Quiet => {}
            }
        }
        for s in &moved {
            self.synced.want(*s);
            for c in self.members.get(s).into_iter().flatten() {
                self.owed.insert((*c, *s));
            }
        }
        let mut acted = false;
        for s in self.synced.due() {
            let store = &*h.store;
            let Some((_, done)) = self.synced.try_settle(&s, || store.first_synced(&s))? else { continue };
            if !done {
                self.first.remove(&s);
                continue;
            }
            self.first.insert(s);
            for c in self.members.get(&s).into_iter().flatten() {
                self.owed.insert((*c, s));
            }
            let ready: Vec<(ConnId, SyncId)> = self.waiting.keys().filter(|(_, x)| *x == s).copied().collect();
            if !ready.is_empty() {
                moved.insert(s);
            }
            for k in ready {
                if let Some((reporter, entries)) = self.waiting.remove(&k) {
                    for ((t, ak), d) in entries {
                        acted |= judge(h, &s, &reporter, &t, &ak, &d)?;
                    }
                }
            }
        }
        // a S neither listed nor awaited is followed no more
        let idle: Vec<SyncId> = moved.into_iter().filter(|s| !self.lists.contains_key(s) && !self.waiting.keys().any(|(_, x)| x == s)).collect();
        for s in idle {
            self.synced.unwant(&s);
            self.first.remove(&s);
        }
        for (conn, s) in std::mem::take(&mut self.owed) {
            if !self.first.contains(&s) || !self.members.get(&s).is_some_and(|m| m.contains(&conn)) {
                continue;
            }
            let Some(list) = self.lists.get(&s) else { continue };
            let mut entries = Vec::new();
            for (t, ak) in ordered(list) {
                if let Some(digest) = h.engine.state_digest(t, ak)? {
                    entries.push(SuspectEntry { thing: *t, ak: ak.clone(), digest });
                }
            }
            for chunk in chunks(entries, osis_base::format::MAX_MESSAGE) {
                osis_base::costs::count("inbox: suspect sent", 1);
                net.request(conn, Msg::Suspect { id: 0, sync_id: s, entries: chunk });
                acted = true;
            }
        }
        Ok(acted)
    }

    /// A Suspect message from `conn` (answered Ok by the caller whatever is judged,
    /// spec/wire.md §11.2).
    pub(super) fn received(&mut self, h: &mut Here<'_>, net: &impl Net, conn: ConnId, s: SyncId, entries: Vec<SuspectEntry>) -> Result<()> {
        let Some(reporter) = h.engine.reader_account(&s, &net.actors(conn))? else { return Ok(()) };
        if !h.store.first_synced(&s)? {
            // the latest message waits, its entries this node may repair (what it holds of them
            // is judged once the first sync ended)
            let mut keep = BTreeMap::new();
            for e in entries {
                if h.engine.may_repair(&s, &e.thing, &e.ak)? {
                    keep.insert((e.thing, e.ak), e.digest);
                }
            }
            if keep.is_empty() {
                self.waiting.remove(&(conn, s));
            } else {
                self.waiting.insert((conn, s), (reporter, keep));
                self.synced.want(s);
            }
            return Ok(());
        }
        for e in entries {
            judge(h, &s, &reporter, &e.thing, &e.ak, &e.digest)?;
        }
        Ok(())
    }
}

/// `k`'s flag as the lists see it.
fn flag(engine: &mut osis_engine::Engine, k: &Aspect) -> Result<Flag> {
    let Some((at, why)) = engine.suspect(&k.0, &k.1) else { return Ok(Flag::Gone) };
    if why == 0 || !engine.record_known(&k.0) {
        return Ok(Flag::Quiet);
    }
    Ok(Flag::Listed { at, under: engine.carrying(&k.0)? })
}

/// Judges one entry for `reporter`, keeping the row of the state last snapshotted for it.
/// Whether a snapshot was written.
fn judge(h: &mut Here<'_>, s: &SyncId, reporter: &Tid, t: &Tid, ak: &Ak, theirs: &[u8; 16]) -> Result<bool> {
    let key = row(reporter, t, ak);
    let wrote = h.store.with_tx(|x| x.get_local(&key))?.and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok());
    match h.engine.repair_suspect(s, t, ak, theirs, reporter, wrote)? {
        Repaired::Wrote { from, .. } => {
            osis_base::costs::count("inbox: suspect repaired", 1);
            h.store.with_tx(|x| x.put_local(&key, &from, Shred::No))?;
            Ok(true)
        }
        Repaired::Already => Ok(false),
        Repaired::Same | Repaired::Skipped => {
            if wrote.is_some() {
                h.store.with_tx(|x| x.remove_local(&key, Shred::No).map(drop))?;
            }
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: u8, ak: &str) -> SuspectEntry {
        SuspectEntry { thing: Tid::from_bytes([i; 15]), ak: Ak::new(ak).unwrap(), digest: [i; 16] }
    }

    // spec/wire.md §11.2 (Suspect): as many entries as fit `MAX_MESSAGE` per message, in order.
    #[test]
    fn a_list_is_cut_to_fit_a_message_spec_wire_11_2() {
        let es: Vec<SuspectEntry> = (0..10).map(|i| entry(i, "t:reg.0")).collect();
        let per = ENTRY + "t:reg.0".len();
        let cut = chunks(es.clone(), FRAME + 3 * per);
        assert_eq!(cut.iter().map(Vec::len).collect::<Vec<_>>(), vec![3, 3, 3, 1]);
        assert_eq!(cut.concat(), es, "in order");
        assert!(chunks(Vec::new(), FRAME + per).is_empty(), "an empty list sends nothing");
        for c in chunks(es, osis_base::format::MAX_MESSAGE) {
            let m = Msg::Suspect { id: 1, sync_id: SyncId([1; 16]), entries: c };
            assert!(m.encode().len() <= osis_base::format::MAX_MESSAGE);
        }
    }

    // spec/permissions.md §4 (Suspect list): the most recently flagged first.
    #[test]
    fn a_list_goes_most_recently_flagged_first_spec_permissions_4() {
        let a = |i: u8| (Tid::from_bytes([i; 15]), Ak::new("t:reg.0").unwrap());
        let list: BTreeMap<Aspect, u64> = [(a(1), 5), (a(2), 9), (a(3), 7)].into_iter().collect();
        assert_eq!(ordered(&list), vec![&a(2), &a(3), &a(1)]);
    }
}
