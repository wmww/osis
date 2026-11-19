//! Suspect lists out and in (spec/permissions.md §4 Suspect, Suspect list; spec/sync-compaction.md
//! §1 Repair; spec/wire.md §11.2 Suspect).
//!
//! Out: per S, this node's flagged, not dormant aspects of things S carries and S's actor may read
//! (the engine's `suspect(t, ak)` per aspect, grouped by `carrying(t)` filtered by
//! `suspect_under`; under no S while a source's stream shows under S a body the flag names: it
//! is fetched, its state not yet what it reports), most recently flagged first, each with its state digest taken as it goes.
//! Owed to each reader member's peer as read owes its acts (notes/sync-read.md, Owed acts): per
//! (record, S), named by no connection, owed at the member's open and to every one when S's list
//! moves, once S's first sync here ended (`Store::first_synced`: a node mid first sync digests a
//! partial state, so every writer would repair it for nothing); it goes on the record's
//! connection once its digests agree there (spec/sync-opens.md §3 Agreement), where the peer
//! proves an account that may read S (the class is the peer's word; a store source keeps S
//! unread: it learns nothing of S's closure from us), and is done once every message of it is
//! answered Ok; refused, or unanswered as its connection ends, it goes again on the next. A
//! reconnect moves nothing owed nothing. An empty list, or one going empty, is owed nowhere: a
//! repair is idempotent.
//!
//! In: a list from a peer is judged only for its reporter, the account it proved holding read or
//! above on S's actor (`Engine::reader_account`); a peer proving none is answered Ok and not
//! acted on. Account, not node: an account adds nodes at will, so per node one account could ask
//! as many repairs per state as it has nodes; a snapshot written for one of its nodes reaches the
//! others under S anyway. Before S's first sync here ended, the latest message per (connection,
//! S) waits (a message received is the connection's), its entries this node may repair, judged once it ends (the sender sends again only
//! when its flags move). An aspect named twice in a message is judged once. Each entry: `Engine::repair_suspect` with the digest of the state this node last wrote
//! a snapshot from for that reporter (row `I/s/ reporter thing ak`), written with a snapshot and
//! dropped only once stale (`judge`), so no sequence of lists gets a second snapshot of one
//! state for one reporter.
//!
//! Work follows change: one `Effects` key per flagged aspect (new ones from `suspect_feed`), one
//! per S whose first sync is awaited, one per record owed a list (where it goes, `Owed::on`); a
//! list goes out only when S's list moved, a member opened, or a record owed one is connected.
//!
//! Bounds: a followed key per flagged aspect, and its place in the lists of the sync IDs carrying
//! it (both go with the flag); the reader members per S, by record (gone with the member or the
//! record); a list owed per (record, S) with a list, so the members of S with a list; the
//! messages out per connection (gone with their answer or the connection); one message's entries
//! waiting per (connection, S), only aspects this node may snapshot (gone at `Left`, close or the
//! first sync's end); a followed key per S listed or with entries waiting (gone with the last of
//! them, `let_go`); a row per (reporter account, aspect) repaired, replaced by a later state,
//! dropped when an entry shows it stale; a row of a thing gone stays until then (issues/storage-owners.md,
//! item 10). A flood of lists repairs at most once per state per reporter,
//! and an entry judged again costs a lookup (`Engine::state_digest` is a memo per aspect).

use super::{Here, Net};
use crate::session::RequestId;
use crate::store::Source;
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
    /// Per S, its reader members by record.
    members: BTreeMap<SyncId, BTreeSet<Source>>,
    /// The lists owed to each record (`Owed`).
    owed: Owed,
    /// Entries received before S's first sync here ended, per (S, connection): the reporter and
    /// its entries.
    waiting: BTreeMap<(SyncId, ConnId), Waiting>,
}

impl Default for Suspects {
    fn default() -> Self {
        Suspects { feed: None, flags: Effects::new("inbox: suspect flags"), lists: BTreeMap::new(), synced: Effects::new("inbox: first synced"), first: BTreeSet::new(), members: BTreeMap::new(), owed: Owed::default(), waiting: BTreeMap::new() }
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

    /// Member S of the record at `src` opened (or opened again as `class`): a reader is owed S's
    /// list. A store source keeps S unread: it learns no tid, AK or digest of S's closure, and
    /// could repair nothing.
    pub(super) fn joined(&mut self, src: Source, s: SyncId, class: Option<SourceClass>) {
        if class != Some(SourceClass::Reader) {
            return self.left(src, &s);
        }
        self.members.entry(s).or_default().insert(src);
        if self.listed(&s) {
            self.owed.add(src, s);
        }
    }

    /// Member S of the record at `src` closed: nothing of S is owed there.
    pub(super) fn left(&mut self, src: Source, s: &SyncId) {
        if let Some(m) = self.members.get_mut(s) {
            m.remove(&src);
            if m.is_empty() {
                self.members.remove(s);
            }
        }
        self.owed.remove(src, s);
    }

    /// Record `src` went: nothing is owed there.
    pub(super) fn record_gone(&mut self, src: Source) {
        let ids: Vec<SyncId> = self.members.iter().filter(|(_, m)| m.contains(&src)).map(|(s, _)| *s).collect();
        for s in ids {
            self.left(src, &s);
        }
    }

    /// A list received on `conn` waits no more once its member closed there.
    pub(super) fn closed_on(&mut self, conn: ConnId, s: &SyncId) {
        if self.waiting.remove(&(*s, conn)).is_some() {
            self.let_go(s);
        }
    }

    /// `conn` ended: what it carried unanswered goes on the record's next connection; the lists
    /// received on it wait no more.
    pub(super) fn closed(&mut self, conn: ConnId) {
        self.owed.closed(conn);
        let gone: Vec<SyncId> = self.waiting.keys().filter(|(_, c)| *c == conn).map(|(s, _)| *s).collect();
        for s in &gone {
            self.waiting.remove(&(*s, conn));
            self.let_go(s);
        }
    }

    /// A reply to one of this module's Suspect messages: whether it was one. Ok takes it.
    pub(super) fn answered(&mut self, conn: ConnId, id: RequestId, m: &Msg) -> bool {
        self.owed.answered(conn, id, matches!(m, Msg::Ok { .. }))
    }

    /// Whether S has a list to send now: a non-empty one, past S's first sync here.
    fn listed(&self, s: &SyncId) -> bool {
        self.first.contains(s) && self.lists.get(s).is_some_and(|l| !l.is_empty())
    }

    /// S's list moved (or came to be sendable): owed again at every reader member, or nowhere.
    fn list_moved(&mut self, s: &SyncId) {
        let listed = self.listed(s);
        for src in self.members.get(s).into_iter().flatten() {
            if listed {
                self.owed.add(*src, *s);
            } else {
                self.owed.remove(*src, s);
            }
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
            self.list_moved(s);
        }
        let mut acted = false;
        for s in self.synced.due() {
            let store = &*h.store;
            let Some((_, done)) = self.synced.try_settle(&s, || store.first_synced(&s))? else { continue };
            if !done {
                self.first.remove(&s);
                self.list_moved(&s);
                continue;
            }
            self.first.insert(s);
            self.list_moved(&s);
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
        let (engine, lists) = (&mut *h.engine, &self.lists);
        acted |= self.owed.deliver(net, &mut |net, conn, s| {
            let Some(list) = lists.get(s) else { return Ok(None) };
            // the peer's class is its word: the list goes only where its proof shows it may read
            // S, the judgement a list received is held to
            let actors = crate::opens::counted(engine, &net.named(conn));
            if engine.reader_account(s, &actors)?.is_none() {
                return Ok(None);
            }
            let mut entries = Vec::new();
            for (t, ak) in ordered(list) {
                if let Some(digest) = engine.state_digest(t, ak)? {
                    entries.push(SuspectEntry { thing: *t, ak: ak.clone(), digest });
                }
            }
            Ok(Some(chunks(entries, osis_base::format::MAX_MESSAGE)))
        })?;
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

/// Where a list owed to a record stands: waiting for the record's agreed connection, or sent on
/// one with these messages not yet answered Ok (a refused one stays: it goes on the next).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Owe {
    Waiting,
    Sent(ConnId, BTreeSet<RequestId>),
}

/// The lists owed per (record, S) (notes/sync-read.md, Owed acts, the same shape): named by no
/// connection; one goes on the record's connection once its digests agree there and is done
/// (dropped) once each message of it is answered Ok.
#[derive(Clone)]
pub(super) struct Owed {
    by: BTreeMap<Source, BTreeMap<SyncId, Owe>>,
    /// Per connection, the messages out and the list each carries.
    out: BTreeMap<ConnId, BTreeMap<RequestId, (Source, SyncId)>>,
    /// Per record owed a list, its connection once agreed (`Net::agreed_on`): a take, a release
    /// or an agreement moving makes it due.
    on: Effects<Source, Option<ConnId>>,
    /// Records owed a list anew since the last delivery.
    touched: BTreeSet<Source>,
}

impl Default for Owed {
    fn default() -> Self {
        Owed { by: BTreeMap::new(), out: BTreeMap::new(), on: Effects::new("inbox: suspect owed"), touched: BTreeSet::new() }
    }
}

/// S's list as messages for the peer on a connection, or none to send there now.
type Lists<'a, N> = dyn FnMut(&N, ConnId, &SyncId) -> Result<Option<Vec<Vec<SuspectEntry>>>> + 'a;

impl Owed {
    /// S's list as it stands now is owed at `src`.
    pub(super) fn add(&mut self, src: Source, s: SyncId) {
        self.by.entry(src).or_default().insert(s, Owe::Waiting);
        self.on.want(src);
        self.touched.insert(src);
    }

    /// Nothing of S is owed at `src`.
    pub(super) fn remove(&mut self, src: Source, s: &SyncId) {
        let Some(m) = self.by.get_mut(&src) else { return };
        m.remove(s);
        if m.is_empty() {
            self.by.remove(&src);
            self.on.unwant(&src);
            self.touched.remove(&src);
        }
    }

    /// The answer to message `id` on `conn`: whether it was one of these. Ok (`taken`) and the
    /// list's last: done. Refused: it stays sent there, and goes again on the next connection.
    pub(super) fn answered(&mut self, conn: ConnId, id: RequestId, taken: bool) -> bool {
        let Some(out) = self.out.get_mut(&conn) else { return false };
        let Some(&(src, s)) = out.get(&id) else { return false };
        if !taken {
            return true;
        }
        out.remove(&id);
        if let Some(Owe::Sent(c, ids)) = self.by.get_mut(&src).and_then(|m| m.get_mut(&s))
            && *c == conn
        {
            ids.remove(&id);
            if ids.is_empty() {
                self.remove(src, &s);
            }
        }
        true
    }

    /// `conn` ended: what it carried and was not taken goes on the record's next connection.
    pub(super) fn closed(&mut self, conn: ConnId) {
        for (_, (src, s)) in self.out.remove(&conn).unwrap_or_default() {
            if let Some(st) = self.by.get_mut(&src).and_then(|m| m.get_mut(&s))
                && matches!(st, Owe::Sent(c, _) if *c == conn)
            {
                *st = Owe::Waiting;
            }
        }
    }

    /// Sends what is owed at each record owed a list anew or whose connection moved, on that
    /// connection once its digests agreed (`list` gives S's messages for it, or none now).
    pub(super) fn deliver<N: Net>(&mut self, net: &mut N, list: &mut Lists<'_, N>) -> Result<bool> {
        let mut due: BTreeSet<Source> = std::mem::take(&mut self.touched);
        due.extend(self.on.due());
        let mut acted = false;
        for src in due {
            if !self.by.contains_key(&src) {
                continue;
            }
            let mut on = None;
            self.on.settle(&src, || {
                on = net.agreed_on(src);
                on
            });
            let Some(conn) = on else { continue };
            let todo: Vec<SyncId> = self.by.get(&src).into_iter().flatten().filter(|(_, st)| !matches!(st, Owe::Sent(c, _) if *c == conn)).map(|(s, _)| *s).collect();
            for s in todo {
                let Some(messages) = list(net, conn, &s)? else { continue };
                let mut ids = BTreeSet::new();
                for chunk in messages {
                    osis_base::costs::count("inbox: suspect sent", 1);
                    if let Some(id) = net.request(conn, Msg::Suspect { id: 0, sync_id: s, entries: chunk }) {
                        ids.insert(id);
                        self.out.entry(conn).or_default().insert(id, (src, s));
                    }
                    acted = true;
                }
                if ids.is_empty() {
                    self.remove(src, &s);
                } else if let Some(st) = self.by.get_mut(&src).and_then(|m| m.get_mut(&s)) {
                    *st = Owe::Sent(conn, ids);
                }
            }
        }
        Ok(acted)
    }

    /// Tests: the lists owed and not done, per record.
    #[cfg(test)]
    fn pending(&self, src: Source) -> usize {
        self.by.get(&src).map_or(0, BTreeMap::len)
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

    /// A `Net` of records: the connection holding each, whether its digests agreed there, and
    /// the messages sent.
    #[derive(Default)]
    struct Records {
        on: osis_base::memo::Stamped<Source, ConnId>,
        agreed: osis_base::memo::Stamped<Source, ConnId>,
        next: RequestId,
        sent: Vec<(ConnId, RequestId, SyncId)>,
    }

    impl Records {
        /// `conn` takes `src`'s record; its digests agree there at once when `agreed`.
        fn take(&mut self, src: Source, conn: ConnId, agreed: bool) {
            self.on.insert(src, conn);
            if agreed {
                self.agreed.insert(src, conn);
            } else if self.agreed.contains_key(&src) {
                self.agreed.remove(&src);
            }
        }

        fn agree(&mut self, src: Source) {
            if let Some(c) = self.on.get(&src).copied() {
                self.agreed.insert(src, c);
            }
        }

        fn release(&mut self, src: Source) {
            self.on.remove(&src);
            if self.agreed.contains_key(&src) {
                self.agreed.remove(&src);
            }
        }
    }

    impl Net for Records {
        fn named(&self, _: ConnId) -> osis_store::Named {
            osis_store::Named::default()
        }
        fn member(&self, _: ConnId, _: &SyncId) -> Option<crate::opens::Member> {
            None
        }
        fn member_at(&self, _: Source, _: &SyncId) -> Option<crate::opens::Member> {
            None
        }
        fn conn_of(&self, src: Source) -> Option<ConnId> {
            self.on.get(&src).copied()
        }
        fn agreed_on(&self, src: Source) -> Option<ConnId> {
            self.agreed.get(&src).copied()
        }
        fn members(&self, _: ConnId) -> Vec<(SyncId, SourceClass)> {
            Vec::new()
        }
        fn head(&self, _: Source, _: &SyncId) -> Option<osis_blob::StepId> {
            None
        }
        fn present(&self, _: Source, _: &SyncId, _: &osis_base::BlobId) -> bool {
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
        fn source(&self, conn: ConnId) -> Source {
            Source::Conn(conn)
        }
        fn request(&mut self, conn: ConnId, m: Msg) -> Option<RequestId> {
            let Msg::Suspect { sync_id, .. } = m else { return None };
            self.next += 1;
            self.sent.push((conn, self.next, sync_id));
            Some(self.next)
        }
        fn answer(&mut self, _: ConnId, _: RequestId, _: Msg) {}
    }

    const S: SyncId = SyncId([1; 16]);

    /// Suspects with S's first sync ended and a list of one aspect under S.
    fn listing() -> Suspects {
        let mut x = Suspects::default();
        x.first.insert(S);
        x.lists.insert(S, [((Tid::from_bytes([1; 15]), Ak::new("t:reg.0").unwrap()), 1)].into());
        x
    }

    /// Delivers what is owed: each list one message. What was sent this time.
    fn deliver(x: &mut Suspects, net: &mut Records) -> Vec<(ConnId, RequestId, SyncId)> {
        let n = net.sent.len();
        x.owed.deliver(net, &mut |_, _, _| Ok(Some(vec![vec![entry(1, "t:reg.0")]]))).unwrap();
        net.sent[n..].to_vec()
    }

    // spec/permissions.md §4 (Suspect list), spec/requirements.md Confidentiality: a list goes
    // to a reader source of S only; a peer keeping S unread (a store source) learns no tid, AK
    // or digest of S's closure. One that opened S as a reader and then as a store source is owed
    // nothing more.
    #[test]
    fn a_list_goes_to_reader_sources_alone_spec_permissions_4() {
        let (reader, store) = (Source::Record([1; 16]), Source::Record([2; 16]));
        let mut x = listing();
        x.joined(reader, S, Some(SourceClass::Reader));
        x.joined(store, S, Some(SourceClass::Store));
        assert_eq!(x.members.get(&S).cloned().unwrap_or_default(), [reader].into());
        assert_eq!((x.owed.pending(reader), x.owed.pending(store)), (1, 0));
        x.joined(reader, S, Some(SourceClass::Store));
        assert!(x.members.is_empty() && x.owed.pending(reader) == 0);
    }

    // spec/permissions.md §4 (Suspect list), spec/sync-opens.md §3 (Agreement: nothing of S
    // before the digests agree): a list is owed per record, named by no connection. It goes on
    // the record's connection only once its digests agreed there; one unanswered as its
    // connection ends goes on the next; one answered Ok is done, sent at no later reconnect
    // until S's list moves; one refused goes again on the next connection.
    #[test]
    fn a_list_owed_goes_once_agreed_until_taken_spec_permissions_4() {
        let r = Source::Record([1; 16]);
        let mut net = Records::default();
        let mut x = listing();
        x.joined(r, S, Some(SourceClass::Reader));
        assert!(deliver(&mut x, &mut net).is_empty(), "no connection");
        net.take(r, ConnId(1), false);
        assert!(deliver(&mut x, &mut net).is_empty(), "taken, the digests not agreed: nothing goes");
        net.agree(r);
        assert_eq!(deliver(&mut x, &mut net).len(), 1, "agreed: it goes");
        // the connection ends unanswered: owed on the next
        x.closed(ConnId(1));
        net.release(r);
        assert!(deliver(&mut x, &mut net).is_empty());
        net.take(r, ConnId(2), true);
        let sent = deliver(&mut x, &mut net);
        assert_eq!(sent.len(), 1, "carried out on the next connection");
        assert!(x.answered(ConnId(2), sent[0].1, &Msg::Ok { id: 0 }));
        assert_eq!(x.owed.pending(r), 0, "taken: done");
        x.closed(ConnId(2));
        net.release(r);
        net.take(r, ConnId(3), true);
        assert!(deliver(&mut x, &mut net).is_empty(), "taken: not sent again at a reconnect");
        // S's list moves: owed again; refused, it goes again on the next connection
        x.list_moved(&S);
        let sent = deliver(&mut x, &mut net);
        assert_eq!(sent.len(), 1, "a list moving is owed again");
        assert!(x.answered(ConnId(3), sent[0].1, &Msg::Error { id: 0, code: osis_proto::Code::RATE_LIMITED }));
        assert_eq!(x.owed.pending(r), 1, "refused: still owed");
        assert!(deliver(&mut x, &mut net).is_empty(), "not again on the connection that refused it");
        x.closed(ConnId(3));
        net.release(r);
        net.take(r, ConnId(4), true);
        assert_eq!(deliver(&mut x, &mut net).len(), 1, "refused: sent again on the next connection");
    }

    // spec/sync.md §2 (work in proportion to change), spec/permissions.md §4 (Suspect list): what
    // is owed is bounded by the reader members of sync IDs with a list: a peer that never answers
    // holds one list per such member and adds none as it reconnects; a record with members but
    // no list owes nothing, so its reconnect sends and walks nothing.
    #[test]
    fn a_peer_never_answering_holds_one_list_per_member_spec_permissions_4() {
        let (r, quiet) = (Source::Record([1; 16]), Source::Record([2; 16]));
        let mut net = Records::default();
        let mut x = listing();
        x.joined(r, S, Some(SourceClass::Reader));
        for i in 2..40u8 {
            x.joined(quiet, SyncId([i; 16]), Some(SourceClass::Reader));
        }
        assert_eq!(x.owed.pending(quiet), 0, "no list: nothing owed");
        for c in 1..20 {
            net.take(r, ConnId(c), true);
            net.take(quiet, ConnId(100 + c), true);
            assert_eq!(deliver(&mut x, &mut net).len(), 1);
            x.closed(ConnId(c));
            x.closed(ConnId(100 + c));
            net.release(r);
            net.release(quiet);
            assert_eq!(x.owed.pending(r), 1);
            assert!(x.owed.out.is_empty(), "requests out go with their connection");
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
