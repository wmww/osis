//! What each source's stream showed (spec/sync-judgement.md §3 `known`), with what else a source
//! told on its stream: its head per sync ID, full, and the refusals it sent (spec/sync-streams.md
//! §4 Full, Refused).
//!
//! A refusal stands only while its ground does: it goes when the entry is offered again to that
//! source (`Op::Lift`, from serving), when the source's stream shows the entry present, with
//! every refusal of S there when the head its stream names moves, and with the entry
//! (`store::entries::remove`; `settle` for memory rows). `full` is a fact of the connection it
//! was told on (spec/sync-streams.md §4 Full), kept under `Source::Conn` whatever the source: it
//! ends with `full` false, S leaving the connection, or the connection.
//!
//! All of it is the source's rows (`store::source`, tags `PRESENT HEAD KEPT FULL REFUSED`), one
//! mechanism whatever the source: a peer's record keeps its word durably, in the record, written
//! by the transaction that applies what showed it (`write`) and lost with the record (a lost
//! record is a first contact); a connection keeps its rows in the memory part, gone with it. What
//! holds only while an ephemeral entry does (they have no log position and are lost at a restart
//! without an event) is in the memory part whatever the source: presence under `Source::Conn`,
//! a refusal under the source that sent it. The store stamps every row, so a memo or `Effects`
//! reading it is moved by exactly the source, sync ID and entry that changed.
//!
//! A read the store fails answers as if nothing were shown, which only ever holds back an act
//! (nothing is judged held elsewhere, left or registered on it); the one read whose absence
//! would act, the presence a listing replaces, fails the step instead (`list`).

use crate::store::Source;
use crate::store::Store;
use crate::store::rows::tag::{FULL, HEAD, KEPT, PRESENT, REFUSED};
use crate::store::source::{self, home, parts};
use crate::types::ConnId;
use osis_base::memo::{Feed, Stamps};
use osis_base::{BlobId, SyncId};
use osis_blob::StepId;
use osis_proto::Code;
use osis_store::Transaction;
use std::collections::{BTreeMap, BTreeSet};

/// A change of what a source showed of S.
#[derive(Clone, Debug)]
pub(super) enum Op {
    Add(SyncId, BlobId),
    Remove(SyncId, BlobId),
    Head(SyncId, StepId),
    /// The source joined S keeping it unread (a store source, spec/sync-opens.md §4) or not.
    Kept(SyncId, bool),
    /// Told on a connection (under `Source::Conn` only).
    Full(SyncId, bool),
    Refused(SyncId, BlobId, Code),
    /// The source's refusal of one entry of S, or of every entry of S, ends: offered to it again.
    Lift(SyncId, Option<BlobId>),
    /// Everything shown of S goes.
    Forget(SyncId),
}

/// Writes `op` into `src`'s rows in `t`'s part.
pub(super) fn write(t: &mut Transaction<'_>, src: Source, op: &Op) -> Result<(), osis_store::Error> {
    let lift_all = |t: &mut Transaction<'_>, s: &SyncId| -> Result<(), osis_store::Error> {
        for (k, _) in source::rows(t, src, REFUSED, s, usize::MAX)? {
            source::remove(t, src, REFUSED, s, &k)?;
        }
        Ok(())
    };
    match op {
        Op::Add(s, b) => {
            source::remove(t, src, REFUSED, s, &b.0)?;
            source::put(t, src, PRESENT, s, &b.0, Vec::new())
        }
        Op::Remove(s, b) => source::remove(t, src, PRESENT, s, &b.0).map(drop),
        // the same head named again writes nothing: what read it does not move as a stream
        // rejoins
        Op::Head(s, h) => match source::get(t, src, HEAD, s, b"")? {
            Some(v) if v == h.0 => Ok(()),
            old => {
                if old.is_some() {
                    lift_all(t, s)?;
                }
                source::put(t, src, HEAD, s, b"", h.0.to_vec())
            }
        },
        Op::Kept(s, k) => match source::get(t, src, KEPT, s, b"")? {
            Some(v) if v == [*k as u8] => Ok(()),
            _ => source::put(t, src, KEPT, s, b"", vec![*k as u8]),
        },
        Op::Full(s, true) => match source::get(t, src, FULL, s, b"")? {
            Some(_) => Ok(()),
            None => source::put(t, src, FULL, s, b"", Vec::new()),
        },
        Op::Full(s, false) => source::remove(t, src, FULL, s, b"").map(drop),
        Op::Refused(s, b, c) => source::put(t, src, REFUSED, s, &b.0, c.0.to_be_bytes().to_vec()),
        Op::Lift(s, Some(b)) => source::remove(t, src, REFUSED, s, &b.0).map(drop),
        Op::Lift(s, None) => lift_all(t, s),
        Op::Forget(s) => {
            lift_all(t, s)?;
            for (k, _) in source::rows(t, src, PRESENT, s, usize::MAX)? {
                source::remove(t, src, PRESENT, s, &k)?;
            }
            for tag in [KEPT, HEAD, FULL] {
                source::remove(t, src, tag, s, b"")?;
            }
            Ok(())
        }
    }
}

/// What a record's durable `op` ends of its memory rows (its refusals of ephemeral entries end
/// as its durable ones do; `moved`: an `Op::Head` naming a head other than the one stored).
pub(super) fn memory_lift(op: &Op, moved: bool) -> Option<Op> {
    match op {
        Op::Add(s, b) | Op::Lift(s, Some(b)) => Some(Op::Lift(*s, Some(*b))),
        Op::Lift(s, None) | Op::Forget(s) => Some(Op::Lift(*s, None)),
        Op::Head(s, _) if moved => Some(Op::Lift(*s, None)),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct Known {
    store: Store,
    /// The store's entries changed: a memory refusal of an entry no longer held goes (`settle`).
    entries: Feed<(SyncId, BlobId)>,
    /// `in_hand` per (S, blob).
    stamps: Stamps,
    /// Entries a message in hand shows present and owes a body of, per (S, blob) the number of
    /// such messages: shown, not recorded until the message applies (`shown`).
    in_hand: BTreeMap<(SyncId, BlobId), usize>,
    /// Every presence row written (shown present or removed, any source): `feed` readers take
    /// each (read, judging what a source showed of a commit).
    log: Stamps,
}

/// A presence row as `Known::feed` names it.
pub type Row = (Source, SyncId, BlobId);

impl Known {
    pub(super) fn new(store: Store) -> Known {
        let entries = store.entry_feed();
        Known { store, entries, stamps: Stamps::named("streams: known in hand"), in_hand: BTreeMap::new(), log: Stamps::named("streams: known rows") }
    }

    /// Tests only (world copies): the copy's store.
    pub(super) fn set_store(&mut self, store: Store) {
        self.entries = store.entry_feed();
        self.store = store;
    }

    /// `f` over a read of `memory`'s part; a store failure answers the default.
    fn read<T: Default>(&self, memory: bool, f: impl FnOnce(&mut Transaction<'_>) -> Result<T, osis_store::Error>) -> T {
        self.store.with_read_in(memory, f).unwrap_or_default()
    }

    /// `op` of `src` was applied: a presence row goes to the feed.
    pub(super) fn logged(&self, src: Source, op: &Op) {
        if let Op::Add(s, b) | Op::Remove(s, b) = op {
            self.log.wrote_added(&(src, *s, *b), true, true);
        }
    }

    /// A cursor over the presence rows written from now on.
    pub fn feed(&self) -> osis_base::memo::Feed<Row> {
        self.log.feed()
    }

    /// Writes `ops` into the memory part, each under its source (a connection's, and what holds
    /// only while an ephemeral entry does; a record's durable rows go through `write` in the
    /// transaction applying what showed them), then logs them.
    pub(super) fn remember(&mut self, ops: &[(Source, Op)]) -> crate::types::Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        self.store.with_tx_in(true, |t| ops.iter().try_for_each(|(src, op)| write(t, *src, op)))?;
        for (src, op) in ops {
            self.logged(*src, op);
        }
        Ok(())
    }

    /// The memory refusals of entries that left this node go (spec/sync-streams.md §4 Refused:
    /// kept per entry held; a record's rows go with the entry, `store::entries::remove`).
    /// O(the entries changed).
    pub(super) fn settle(&mut self) -> crate::types::Result<()> {
        for (s, b) in self.entries.added() {
            let srcs = self.store.with_read_in(true, |t| source::with_row(t, &s, REFUSED, &b.0, usize::MAX))?;
            if !srcs.is_empty() && self.store.entry(&s, &b)?.is_none() {
                self.store.with_tx_in(true, |t| srcs.iter().try_for_each(|src| source::remove(t, *src, REFUSED, &s, &b.0).map(drop)))?;
            }
        }
        Ok(())
    }

    /// Everything a connection's source showed goes with it (its ephemeral entries and what a
    /// peer with no record showed): the rows under the tags `Known` keeps.
    pub fn forget_source(&mut self, src: Source) -> crate::types::Result<()> {
        self.store.with_tx_in(true, |t| source::forget_tags(t, src, |x| [PRESENT, HEAD, KEPT, FULL, REFUSED].contains(&x)))
    }

    /// Whether `src`'s stream showed `b` present under S.
    pub fn knows(&self, src: Source, s: &SyncId, b: &BlobId) -> bool {
        self.read(home(src), |t| Ok(source::get(t, src, PRESENT, s, &b.0)?.is_some()))
    }

    /// A message in hand showing `b` present under S, owing its body, was held (`true`) or
    /// applied or dropped (`false`).
    pub(super) fn hand(&mut self, s: &SyncId, b: &BlobId, held: bool) {
        let k = (*s, *b);
        let was = self.in_hand.get(&k).copied().unwrap_or(0);
        let n = if held { was + 1 } else { was.saturating_sub(1) };
        if n == 0 {
            self.in_hand.remove(&k);
        } else {
            self.in_hand.insert(k, n);
        }
        if (was == 0) != (n == 0) {
            self.stamps.wrote(&k, true);
        }
    }

    /// Whether some source shows `b` present under S: `present`, or a message in hand showing it
    /// whose body is owed (a body taken for it is opened before the message applies).
    pub fn shown(&self, s: &SyncId, b: &BlobId) -> bool {
        self.stamps.read(&(*s, *b));
        self.present(s, b) || self.in_hand.contains_key(&(*s, *b))
    }

    /// Whether any source's stream showed `b` present under S.
    pub fn present(&self, s: &SyncId, b: &BlobId) -> bool {
        [true, false].into_iter().any(|m| self.read(m, |t| source::any_row(t, s, PRESENT, &b.0)))
    }

    /// Every presence row, of every source (a start judges what each shows; O(rows)).
    pub fn rows_all(&self) -> Result<Vec<Row>, osis_store::Error> {
        let mut out = Vec::new();
        for m in [true, false] {
            let rows = self.store.with_read_in(m, |t| source::tag_rows(t, PRESENT)).map_err(|e| e.into_store("streams: known"))?;
            out.extend(rows.into_iter().filter_map(|(src, s, k)| Some((src, s, BlobId(k.try_into().ok()?)))));
        }
        Ok(out)
    }

    /// The sources whose stream showed `b` present under S.
    pub fn shown_at(&self, s: &SyncId, b: &BlobId) -> BTreeSet<Source> {
        [true, false].into_iter().flat_map(|m| self.read(m, |t| source::with_row(t, s, PRESENT, &b.0, usize::MAX))).collect()
    }

    /// What `src`'s stream showed present under S, or the store's failure: a listing replacing
    /// presence reads it, and a list read as empty would keep presence the listing proved gone.
    pub fn list(&self, src: Source, s: &SyncId) -> Result<Vec<BlobId>, osis_store::Error> {
        let rows = self.store.with_read_in(home(src), |t| source::rows(t, src, PRESENT, s, usize::MAX)).map_err(|e| e.into_store("streams: known"))?;
        Ok(rows.into_iter().filter_map(|(k, _)| Some(BlobId(k.try_into().ok()?))).collect())
    }

    /// The source's step for S: the head its stream last named.
    pub fn head(&self, src: Source, s: &SyncId) -> Option<StepId> {
        self.read(home(src), |t| Ok(source::get(t, src, HEAD, s, b"")?.and_then(|v| Some(StepId(v.try_into().ok()?)))))
    }

    /// Whether the source keeps S unread, as it last joined S (`Op::Kept`): kept with what its
    /// stream showed, so it reads alike while the source is away and after a restart.
    pub fn kept(&self, src: Source, s: &SyncId) -> bool {
        self.read(home(src), |t| Ok(source::get(t, src, KEPT, s, b"")? == Some(vec![1])))
    }

    /// Whether the peer on `conn` told on it that it is full for S.
    pub fn full(&self, conn: ConnId, s: &SyncId) -> bool {
        let src = Source::Conn(conn);
        self.read(home(src), |t| Ok(source::get(t, src, FULL, s, b"")?.is_some()))
    }

    /// Whether a refusal the source sent of some entry of S stands (spec/sync-streams.md §4
    /// Refused): status names it among those that do not take S.
    pub fn refusing(&self, src: Source, s: &SyncId) -> bool {
        parts(src).iter().any(|m| self.read(*m, |t| Ok(!source::rows(t, src, REFUSED, s, 1)?.is_empty())))
    }

    /// The code of the source's standing refusal of entry `b` of S.
    pub fn refusal(&self, src: Source, s: &SyncId, b: &BlobId) -> Option<Code> {
        parts(src).iter().find_map(|m| self.read(*m, |t| Ok(source::get(t, src, REFUSED, s, &b.0)?.and_then(|v| Some(Code(u64::from_be_bytes(v.try_into().ok()?)))))))
    }
}
