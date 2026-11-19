//! Suspect lists out and in (spec/permissions.md §4 Suspect, Suspect list; spec/sync-compaction.md
//! §1 Repair; spec/wire.md §11.2 Suspect).
//!
//! Out: per S, this node's flagged, not dormant aspects of things S carries and S's actor may read
//! (the engine's `suspect(t, ak)` per aspect, grouped by `carrying(t)` filtered by
//! `suspect_under`; under no S while a source's stream shows under S a body the flag names: it
//! is fetched, its state not yet what it reports), most recently flagged first, each with its state digest taken as it goes.
//! Sent to each reader source's peer at its join and to every one when S's list moves, where the
//! peer proves an account that may read S (the class is the peer's word; a store source keeps S
//! unread: it learns nothing of S's closure from us), once S's first sync here ended (`Store::first_synced`: a
//! node mid first sync digests a partial state, so every writer would repair it for nothing).
//! An empty list, or one going empty, sends nothing: a repair is idempotent.
//!
//! In: a list from a peer is judged only for its reporter, the account it proved holding read or
//! above on S's actor (`Engine::reader_account`); a peer proving none is answered Ok and not
//! acted on. Account, not node: an account adds nodes at will, so per node one account could ask
//! as many repairs per state as it has nodes; a snapshot written for one of its nodes reaches the
//! others under S anyway. Before S's first sync here ended, the latest message per (connection,
//! S) waits, its entries this node may repair, judged once it ends (the sender sends again only
//! when its flags move). An aspect named twice in a message is judged once. Each entry: `Engine::repair_suspect` with the digest of the state this node last wrote
//! a snapshot from for that reporter (row `I/s/ reporter thing ak`), written with a snapshot and
//! dropped only once stale (`judge`), so no sequence of lists gets a second snapshot of one
//! state for one reporter.
//!
//! Work follows change: one `Effects` key per flagged aspect (new ones from `suspect_feed`), one
//! per S whose first sync is awaited; a list goes out only when S's list moved or a member
//! joined.
//!
//! Bounds: a followed key per flagged aspect, and its place in the lists of the sync IDs carrying
//! it (both go with the flag); the members per S (gone at `Left` or close); one message's entries
//! waiting per (connection, S), only aspects this node may snapshot (gone at `Left`, close or the
//! first sync's end); a followed key per S listed or with entries waiting (gone with the last of
//! them, `let_go`); a row per (reporter account, aspect) repaired, replaced by a later state,
//! dropped when an entry shows it stale; a row of a thing gone stays until then (issues/storage-owners.md,
//! item 10). A flood of lists repairs at most once per state per reporter,
//! and an entry judged again costs a lookup (`Engine::state_digest` is a memo per aspect).

use super::{Here, Net};
use crate::types::{ConnId, Result, SourceClass};
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
    /// Entries received before S's first sync here ended, per (S, connection): the reporter and
    /// its entries.
    waiting: BTreeMap<(SyncId, ConnId), Waiting>,
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

    /// S joined `conn`'s shared set: a reader source is owed S's list. A store source keeps S
    /// unread: it learns no tid, AK or digest of S's closure, and could repair nothing.
    pub(super) fn joined(&mut self, conn: ConnId, s: SyncId, net: &impl Net) {
        if !net.member(conn, &s).is_some_and(|m| m.class == SourceClass::Reader) {
            return self.left(conn, &s);
        }
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
        if self.waiting.remove(&(*s, conn)).is_some() {
            self.let_go(s);
        }
    }

    pub(super) fn closed(&mut self, conn: ConnId) {
        for m in self.members.values_mut() {
            m.remove(&conn);
        }
        self.members.retain(|_, m| !m.is_empty());
        self.owed.retain(|(c, _)| *c != conn);
        let gone: Vec<SyncId> = self.waiting.keys().filter(|(_, c)| *c == conn).map(|(s, _)| *s).collect();
        for s in &gone {
            self.waiting.remove(&(*s, conn));
            self.let_go(s);
        }
    }

    /// S neither listed nor awaited is followed no more.
    fn let_go(&mut self, s: &SyncId) {
        if !self.lists.contains_key(s) && self.waiting.range((*s, ConnId(0))..=(*s, ConnId(u64::MAX))).next().is_none() {
            self.synced.unwant(s);
            self.first.remove(s);
        }
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
            let Some((was, now)) = self.flags.try_settle(&k, || flag(engine, &*net, &k))? else { continue };
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
            let ready: Vec<(SyncId, ConnId)> = self.waiting.range((s, ConnId(0))..=(s, ConnId(u64::MAX))).map(|(k, _)| *k).collect();
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
        for s in &moved {
            self.let_go(s);
        }
        for (conn, s) in std::mem::take(&mut self.owed) {
            if !self.first.contains(&s) || !self.members.get(&s).is_some_and(|m| m.contains(&conn)) {
                continue;
            }
            let Some(list) = self.lists.get(&s) else { continue };
            // the peer's class is its word: the list goes only where its proof shows it may read
            // S, the judgement a list received is held to
            let actors = crate::opens::counted(h.engine, &net.named(conn));
            if h.engine.reader_account(&s, &actors)?.is_none() {
                continue;
            }
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
        let actors = crate::opens::counted(h.engine, &net.named(conn));
        let Some(reporter) = h.engine.reader_account(&s, &actors)? else { return Ok(()) };
        // an aspect named twice is one entry (the last), judged once
        let entries: BTreeMap<Aspect, [u8; 16]> = entries.into_iter().map(|e| ((e.thing, e.ak), e.digest)).collect();
        if !h.store.first_synced(&s)? {
            // the latest message waits, its entries this node may repair (what it holds of them
            // is judged once the first sync ended)
            let mut keep = BTreeMap::new();
            for ((t, ak), d) in entries {
                if h.engine.may_repair(&s, &t, &ak)? {
                    keep.insert((t, ak), d);
                }
            }
            if keep.is_empty() {
                if self.waiting.remove(&(s, conn)).is_some() {
                    self.let_go(&s);
                }
            } else {
                self.waiting.insert((s, conn), (reporter, keep));
                self.synced.want(s);
            }
            return Ok(());
        }
        for ((t, ak), d) in entries {
            judge(h, &s, &reporter, &t, &ak, &d)?;
        }
        Ok(())
    }
}

/// `k`'s flag as the lists see it: listed under each S that may name it, unless a source's
/// stream shows a body its flag names present under S (the node fetches it there, so its state
/// is not yet the one it would report; spec/permissions.md §4 Suspect list).
fn flag(engine: &mut osis_engine::Engine, net: &impl Net, k: &Aspect) -> Result<Flag> {
    let Some((at, why)) = engine.suspect(&k.0, &k.1) else { return Ok(Flag::Gone) };
    if why == 0 || !engine.record_known(&k.0) {
        return Ok(Flag::Quiet);
    }
    let mut blobs = Vec::new();
    for c in engine.suspect_bodies(&k.0, &k.1) {
        blobs.extend(engine.commit_blobs(&c)?.iter().copied());
    }
    let mut under = BTreeSet::new();
    for s in engine.carrying(&k.0)? {
        if engine.suspect_under(&s, &k.0)? && !blobs.iter().any(|b| net.shown(&s, b)) {
            under.insert(s);
        }
    }
    Ok(if under.is_empty() { Flag::Quiet } else { Flag::Listed { at, under } })
}

/// Judges one entry for `reporter`, keeping the row of the state last snapshotted for it.
/// Whether a snapshot was written. The row goes only once it is stale (this node's state moved
/// off it, seen as the reporter's digest matching a state other than the row's): dropped on an
/// entry not judged or a matching one, a reporter could alternate the true digest (or a sync ID
/// not carrying the thing) with a false one and have a snapshot written per pair.
fn judge(h: &mut Here<'_>, s: &SyncId, reporter: &Tid, t: &Tid, ak: &Ak, theirs: &[u8; 16]) -> Result<bool> {
    let key = row(reporter, t, ak);
    let wrote = h.store.with_tx(|x| x.get_local(&key))?.and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok());
    let done = h.engine.repair_suspect(s, t, ak, theirs, reporter, wrote)?;
    match row_after(wrote, theirs, &done) {
        Row::Put(from) => h.store.with_tx(|x| x.put_local(&key, &from, Shred::No))?,
        Row::Drop => h.store.with_tx(|x| x.remove_local(&key, Shred::No).map(drop))?,
        Row::Keep => {}
    }
    let wrote_one = matches!(done, Repaired::Wrote { .. });
    if wrote_one {
        osis_base::costs::count("inbox: suspect repaired", 1);
    }
    Ok(wrote_one)
}

/// What becomes of a reporter's row after an entry was judged.
#[derive(Debug, PartialEq, Eq)]
enum Row {
    Put([u8; 16]),
    Drop,
    Keep,
}

/// The row after `done`, `wrote` the row before, `theirs` the entry's digest (`judge`).
fn row_after(wrote: Option<[u8; 16]>, theirs: &[u8; 16], done: &Repaired) -> Row {
    match done {
        Repaired::Wrote { from, .. } => Row::Put(*from),
        // this node's state is `theirs` and the row names another: stale
        Repaired::Same if wrote.is_some_and(|w| w != *theirs) => Row::Drop,
        Repaired::Already | Repaired::Same | Repaired::Skipped => Row::Keep,
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

    // spec/sync-compaction.md §1 (Repair: unless it already wrote one from that same state for
    // that reporter): the row of the state last snapshotted stays through every entry that does
    // not show it stale, so a reporter alternating the true digest, a sync ID not carrying the
    // thing, and a false digest gets one snapshot per state; a matching digest of a state the row
    // does not name drops it.
    #[test]
    fn a_reporter_cannot_alternate_its_way_to_a_second_snapshot_spec_sync_compaction_1() {
        let (own, other) = ([1; 16], [2; 16]);
        assert_eq!(row_after(None, &other, &Repaired::Wrote { commit: osis_base::CommitId([0; 32]), from: own }), Row::Put(own));
        assert_eq!(row_after(Some(own), &own, &Repaired::Same), Row::Keep, "the true digest keeps it");
        assert_eq!(row_after(Some(own), &other, &Repaired::Skipped), Row::Keep, "an entry not judged keeps it");
        assert_eq!(row_after(Some(own), &other, &Repaired::Already), Row::Keep);
        assert_eq!(row_after(Some(other), &own, &Repaired::Same), Row::Drop, "stale: this node moved to the reporter's state");
        assert_eq!(row_after(None, &own, &Repaired::Same), Row::Keep);
    }

    /// A `Net` of members alone.
    #[derive(Default)]
    struct Members(BTreeMap<(ConnId, SyncId), SourceClass>);

    impl Net for Members {
        fn named(&self, _: ConnId) -> osis_store::Named {
            osis_store::Named::default()
        }
        fn member(&self, conn: ConnId, s: &SyncId) -> Option<crate::opens::Member> {
            self.0.get(&(conn, *s)).map(|class| crate::opens::Member { class: *class, own: crate::types::SourceClass::Reader, by: crate::types::Credential::SyncKey, until: None, departed: false })
        }
        fn member_at(&self, _: crate::store::Source, _: &SyncId) -> Option<crate::opens::Member> {
            None
        }
        fn conn_of(&self, _: crate::store::Source) -> Option<ConnId> {
            None
        }
        fn head(&self, _: crate::store::Source, _: &SyncId) -> Option<osis_blob::StepId> {
            None
        }
        fn present(&self, _: crate::store::Source, _: &SyncId, _: &osis_base::BlobId) -> bool {
            false
        }
        fn shown(&self, _: &SyncId, _: &osis_base::BlobId) -> bool {
            false
        }
        fn filter_generation(&self, _: ConnId) -> u64 {
            0
        }
        fn shows_deposit_key(&self, _: ConnId, _: &SyncId, _: &[u8; 32]) -> bool {
            false
        }
        fn source(&self, conn: ConnId) -> crate::store::Source {
            crate::store::Source::Conn(conn)
        }
        fn request(&mut self, _: ConnId, _: Msg) -> Option<crate::session::RequestId> {
            None
        }
        fn answer(&mut self, _: ConnId, _: crate::session::RequestId, _: Msg) {}
    }

    // spec/permissions.md §4 (Suspect list), spec/requirements.md Confidentiality: a list goes
    // to a reader source of S only; a peer keeping S unread (a store source) learns no tid, AK
    // or digest of S's closure. One that opened S as a reader and then as a store source is owed
    // nothing more.
    #[test]
    fn a_list_goes_to_reader_sources_alone_spec_permissions_4() {
        let s = SyncId([1; 16]);
        let (reader, store) = (ConnId(1), ConnId(2));
        let mut net = Members::default();
        net.0.insert((reader, s), SourceClass::Reader);
        net.0.insert((store, s), SourceClass::Store);
        let mut x = Suspects::default();
        x.joined(reader, s, &net);
        x.joined(store, s, &net);
        assert_eq!(x.members.get(&s).cloned().unwrap_or_default(), [reader].into());
        assert_eq!(x.owed, [(reader, s)].into());
        net.0.insert((reader, s), SourceClass::Store);
        x.joined(reader, s, &net);
        assert!(x.members.is_empty() && x.owed.is_empty());
    }

    // spec/sync-compaction.md §1 (Repair: a list received mid first sync waits for its end):
    // a waiting list that leaves before the first sync ended (its member left, its connection
    // closed, a later list naming nothing this node may repair) takes S's first-sync follow with
    // it, at n and 10n sync IDs.
    #[test]
    fn a_waiting_list_gone_early_follows_nothing_spec_sync_compaction_1() {
        for n in [3u8, 30] {
            let mut x = Suspects::default();
            let (a, b) = (ConnId(1), ConnId(2));
            let ids: Vec<SyncId> = (0..n).map(|i| SyncId([i; 16])).collect();
            let entries: BTreeMap<Aspect, [u8; 16]> = [((Tid::from_bytes([1; 15]), Ak::new("t:reg.0").unwrap()), [1; 16])].into();
            for s in &ids {
                for c in [a, b] {
                    x.waiting.insert((*s, c), (Tid::from_bytes([9; 15]), entries.clone()));
                }
                x.synced.want(*s);
                x.first.insert(*s);
            }
            for s in &ids {
                x.left(a, s);
                assert!(x.synced.wants(s), "another list still waits");
            }
            x.closed(b);
            assert!(ids.iter().all(|s| !x.synced.wants(s)) && x.first.is_empty() && x.waiting.is_empty());
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
