//! What read owes each source (spec/sync-judgement.md §3 Deletes, §4): the acts its
//! judgements hold toward it (`Act::toward`), keyed by (S, commit, act) under the source's record,
//! never by connection. A judgement reads the record's facts alone (what its stream showed, its
//! head and class, its membership of S), so a reconnect moves none; an act goes on the record's
//! connection once its digests agree (`Ground::connected`), and again on the next one while it
//! is not done: a request once taken (a Delete answered 0; refused, it goes on the next
//! connection), anything else once carried out (a deposit,
//! a logging again; a Fetch, whose answer is streams', goes on each connection while the body
//! is still missing there). One owed only while the source is full (`Act::needs_full`) goes only
//! on a connection the source told so. A restart judges every body again.
//!
//! Bound: an act is owed exactly while some judgement's value holds it (added and removed with
//! the value), so the acts per source are what its `known` rows and S's must-hold bodies give,
//! as `RECORD_BUDGET` bounds them; a peer that never answers holds its acts at `Sent` and adds
//! none. Requests out per connection go with the connection (`closed`).

use super::judge::Act;
use crate::session::RequestId;
use crate::store::Source;
use crate::types::ConnId;
use osis_base::memo::Effects;
use osis_base::{CommitId, SyncId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One act owed: under S, for a body (`Some`) or a piece, freed link or certificate blob.
pub(crate) type Key = (SyncId, Option<CommitId>, Act);

/// Where an owed act stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Waiting,
    /// Carried out on this connection, its answer not in.
    Sent(ConnId),
    Done,
}

/// The connection a source's acts go on, and the sync IDs of its acts owed only while full that
/// the source told it is full for there.
pub(crate) type On = (Option<ConnId>, Arc<BTreeSet<SyncId>>);

#[derive(Clone)]
pub(crate) struct Owed {
    pub by: BTreeMap<Source, BTreeMap<Key, State>>,
    /// Per connection, the requests out and the act each answers.
    out: BTreeMap<ConnId, BTreeMap<RequestId, (Source, Key)>>,
    /// Per source owed something, where its acts go (`On`): a take, a release, an agreement or a
    /// `full` moving makes it due.
    pub on: Effects<Source, On>,
    /// Sources owed a new act since the last `due`.
    touched: BTreeSet<Source>,
}

impl Default for Owed {
    fn default() -> Self {
        Owed { by: BTreeMap::new(), out: BTreeMap::new(), on: Effects::new("read: owed"), touched: BTreeSet::new() }
    }
}

impl Owed {
    /// A judgement came to hold act `k` toward its source.
    pub fn add(&mut self, k: Key) {
        let Some(at) = k.2.toward() else { return };
        self.by.entry(at).or_default().entry(k).or_insert(State::Waiting);
        self.on.want(at);
        self.touched.insert(at);
    }

    /// No judgement holds act `k` any more.
    pub fn remove(&mut self, k: &Key) {
        let Some(at) = k.2.toward() else { return };
        let Some(m) = self.by.get_mut(&at) else { return };
        m.remove(k);
        if m.is_empty() {
            self.by.remove(&at);
            self.on.unwant(&at);
            self.touched.remove(&at);
        }
    }

    /// Every act owed under S goes (S no longer read here).
    pub fn forget(&mut self, s: &SyncId) {
        let keys: Vec<Key> = self.by.values().flat_map(|m| m.keys().filter(|k| k.0 == *s).cloned()).collect();
        for k in keys {
            self.remove(&k);
        }
    }

    /// The sources whose acts may go now: owed a new one, or where they go moved.
    pub fn due(&mut self) -> Vec<Source> {
        let mut out: BTreeSet<Source> = std::mem::take(&mut self.touched);
        out.extend(self.on.due());
        out.into_iter().collect()
    }

    /// The sync IDs of `at`'s acts owed only while full and not done.
    pub fn full_wanted(&self, at: &Source) -> Vec<SyncId> {
        let mut out: Vec<SyncId> = self.by.get(at).into_iter().flatten().filter(|(k, st)| **st != State::Done && k.2.needs_full()).map(|(k, _)| k.0).collect();
        out.dedup();
        out
    }

    /// Request `id` on `conn` carrying act `k` toward `at` is out.
    pub fn sent(&mut self, conn: ConnId, id: RequestId, at: Source, k: Key) {
        self.out.entry(conn).or_default().insert(id, (at, k));
    }

    /// The answer to request `id` on `conn` came: its act is done once `taken`; refused (for now
    /// or for good), it stays owed and goes again on the record's next connection, as before
    /// it was answered.
    pub fn answered(&mut self, conn: ConnId, id: RequestId, taken: bool) {
        let Some((at, k)) = self.out.get_mut(&conn).and_then(|m| m.remove(&id)) else { return };
        if let Some(st) = self.by.get_mut(&at).and_then(|m| m.get_mut(&k))
            && taken
        {
            *st = State::Done;
        }
    }

    /// `conn` ended: what it carried and was not answered goes on the record's next connection.
    pub fn closed(&mut self, conn: ConnId) {
        self.out.remove(&conn);
    }

    /// Tests: the acts owed, not done.
    pub fn pending(&self) -> usize {
        self.by.values().flat_map(|m| m.values()).filter(|st| **st != State::Done).count()
    }
}
