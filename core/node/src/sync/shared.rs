//! The shared set of a connection (issues/net-shared-set.md): the rule: a node shares sync ID L with
//! a connected peer exactly while, on what it holds now, the peer may hold L. Each side sends a
//! filter of beacons of what it may share, tests its own beacons against the peer's filter and
//! offers the hits; a hit opens L only with the tag or J proving it.
//!
//! Invariants the design rests on (each a tier-1 test in tests/it/shared.rs):
//! - A beacon is equal on both sides, so a filter entry only finds a pair; a Hit is keyed by its
//!   sender's side and the connection (`osis_crypto::kdf::beacon_hit`): reflected to its sender or
//!   carried to another connection it shows nothing.
//! - An untagged 0 opens nothing for the tester; the tag is computed only with the credential.
//! - J counts the actors a connection proved (`Proven::all`).
//! - `pending` (changed_at past `acked_pos`) is tested at every arrival and every own change, and
//!   `acked_pos` passes only what is acknowledged and tested with no Offer unanswered: two nodes
//!   gaining one credential at once cannot both miss it.
//! - A filter connection ends with the rule: re-judged at every change of what a node holds.
//!
//! As built, a connection starts with a whole filter and tests everything: base generations and
//! the digest come with durable S (step 7). A filter goes only to a peer that proved a known actor,
//! so where only one side knows the other (a link's redeemer) that side's filter is the only one;
//! a connection without a record uses its own pair key.

use super::{Action, ConnId, SyncEngine};
use super::credentials::Credential;
use super::proofs::Proven;
use super::records::ConnRecord;
use crate::error::Result;
use osis_base::LabelId;
use osis_crypto::kdf::{Side, beacon, beacon_hit, beacon_reply};
use osis_proto::filter::{BEACON_P, Page, beacon_value, decode_gcs, filter_width, pages};
use osis_proto::msg::{MAX_SHARED_ITEMS, OfferItem};
use osis_proto::{Code, Command, Message, ServingInput};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Entries a peer's filter may hold, the sum of its pages. Resource bound: 0 no filter is
/// accepted (nothing opens), infinity a known actor's filter is this node's memory.
pub const MAX_FILTER_ENTRIES: usize = 1 << 22;
/// A page's body, Golomb-coded bytes: well inside `MAX_MESSAGE` and the request window. A page
/// past it is split. Performance switch: 0 is not a page; infinity a filter in one message.
pub const PAGE_BYTES: usize = 256 * 1024;

/// Credential classes as a member records them (`Member::proved`).
const READ: u8 = 0;
const STATIC: u8 = 1;
/// An open by J with no credential.
const JUDGED: u8 = 2;

/// One credential of one L as this connection sees it.
#[derive(Clone)]
struct Cred {
    label: LabelId,
    class: u8,
    value: [u8; 32],
    beacon: [u8; 32],
}

/// One item of an Offer this side sent.
enum AskedItem {
    Hit(Cred),
    ByRole(LabelId),
}

/// What a request of this side waits for.
enum Asked {
    Beacons { pos: u64, last: bool },
    /// Items in order.
    Offer(Vec<AskedItem>),
    Lost,
}

/// The peer's filter as received.
struct PeerFilter {
    generation: u64,
    f: u8,
    /// Sorted.
    values: Vec<u64>,
    /// Entries of the whole filter, and how many additions came since.
    whole: usize,
    added: usize,
}

/// A generation of the peer's arriving in pages.
struct Pages {
    generation: u64,
    base: Option<u64>,
    f: u8,
    next_lo: u64,
    values: Vec<u64>,
}

/// One member of S (issues/net-shared-set.md, Opens).
struct Member {
    class: u8,
    /// The credential's match value, for an open by a credential (none for JUDGED).
    value: Option<[u8; 32]>,
}

/// The shared set state of one connection with a record.
pub(crate) struct Shared {
    r: [u8; 32],
    by_listener: bool,
    key: [u8; 32],
    dialer: [u8; 32],
    listener: [u8; 32],
    next_id: u32,
    /// `ack`, `tested` and Offers unanswered (`ConnRecord`), and `acked_pos`, for this connection.
    pending: ConnRecord,
    acked_pos: u64,
    test_due: bool,
    /// Whole filter's entries and additions since, generations.
    sent_gen: u64,
    in_flight: bool,
    /// The last generation was refused: a whole filter goes again (`again`) at this time (raw
    /// ms), `resync_ms` after, as a refused Pull does (`stream_refused`).
    retry_at: Option<u64>,
    again: bool,
    whole_n: usize,
    added: usize,
    f: u8,
    sent_pos: u64,
    peer: Option<PeerFilter>,
    pages: Option<Pages>,
    members: BTreeMap<LabelId, Member>,
    /// Hits already offered and answered (a refused one is not sent again until re-marked).
    offered: BTreeSet<[u8; 32]>,
    /// Sync IDs a ByRole was sent for (none again until re-marked).
    by_role: BTreeSet<LabelId>,
    asked: BTreeMap<u32, Asked>,
    /// This connection's Hit table (the peer's Hit → credential), built at the first Hit, dropped
    /// when what this node holds changes.
    table: Option<HashMap<[u8; 32], Cred>>,
    /// The peer refused this connection a filter (it knows no actor proved here).
    refused: bool,
    /// Sync IDs this side tested a key actor's static entry of against the peer's filter and
    /// found absent: a link's sharer refused it (`static_entry_refused`).
    static_missing: BTreeSet<LabelId>,
    /// The peer proved an actor known here now: this side sends a filter (issues/net-shared-set.md, Words).
    filter_out: bool,
}

/// Ids this module draws: never one the session's own requests use (top bit set).
const ID_BASE: u32 = osis_proto::msg::NODE_IDS;
/// The id of a dialer's `NoRecord` (`Records::send_resume`).
pub(super) const NO_RECORD_ID: u32 = ID_BASE;

impl Shared {
    fn bare(by_listener: bool) -> Shared {
        Shared {
            r: [0; 32],
            by_listener,
            key: [0; 32],
            dialer: [0; 32],
            listener: [0; 32],
            next_id: 0,
            pending: ConnRecord::new([0; 16], 0),
            acked_pos: 0,
            test_due: false,
            sent_gen: 0,
            in_flight: false,
            retry_at: None,
            again: false,
            whole_n: 0,
            added: 0,
            f: BEACON_P as u8,
            sent_pos: 0,
            peer: None,
            pages: None,
            members: BTreeMap::new(),
            offered: BTreeSet::new(),
            by_role: BTreeSet::new(),
            asked: BTreeMap::new(),
            table: None,
            refused: false,
            static_missing: BTreeSet::new(),
            filter_out: false,
        }
    }

    /// Whether L is a member here.
    pub(crate) fn has(&self, l: &LabelId) -> bool {
        self.members.contains_key(l)
    }

    /// Whether S is empty here.
    pub(crate) fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    fn side(&self, by_listener: bool) -> Side<'_> {
        (by_listener, &self.key, &self.dialer, &self.listener)
    }
    fn next(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        ID_BASE | (self.next_id & (ID_BASE - 1))
    }
}

impl SyncEngine {
    /// Whether L is a member of `conn`'s shared set.
    pub(crate) fn shared_member(&self, conn: ConnId, l: &LabelId) -> bool {
        self.records.shared.get(&conn).is_some_and(|s| s.members.contains_key(l))
    }

    /// Sync IDs open on `conn` by its shared set (tests).
    pub fn shared_members(&self, conn: ConnId) -> BTreeSet<LabelId> {
        self.records.shared.get(&conn).map(|s| s.members.keys().copied().collect()).unwrap_or_default()
    }

    /// Puts `l` in served session `conn`'s shared set directly (tests whose subject is what a
    /// member gets, not how one is found).
    #[doc(hidden)]
    pub fn shared_admit(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let s = self.records.shared.entry(conn).or_insert_with(|| Shared::bare(!self.conns.contains_key(&conn)));
        s.members.insert(l, Member { class: JUDGED, value: None });
        self.shared_open(conn, l, JUDGED, None, out)
    }

    /// Whether what `conn` can open is known: its shared set saw the peer's filter or a refusal
    /// and nothing it asked is unanswered, or it never starts (a host, a peer with no proofs yet
    /// counts as still finding).
    pub(crate) fn shared_settled(&self, conn: ConnId) -> bool {
        self.records.shared.get(&conn).is_some_and(|s| (s.peer.is_some() || s.refused) && !s.test_due && !s.in_flight && s.pending.offers_unanswered == 0)
    }

    /// The listener answered this dialer's `NoRecord` with a refusal: it knows no actor this
    /// connection proved, so a link key it will not list stays refused (`static_entry_refused`).
    fn shared_peer_refused(&mut self, conn: ConnId) {
        let hinted: Vec<LabelId> = self.state.hints.iter().filter(|(_, h)| h.via.is_some()).map(|(l, _)| *l).collect();
        if let Some(s) = self.records.shared.get_mut(&conn) {
            s.static_missing.extend(hinted);
            s.refused = true;
        }
    }

    /// Whether a connection's peer showed a filter without this node's static entry of `l`: the
    /// sharer of a link does not list its key (spec/sync.md §5).
    pub(crate) fn shared_static_missing(&self, l: &LabelId) -> bool {
        self.records.shared.values().any(|s| s.static_missing.contains(l) && !s.members.contains_key(l))
    }

    /// The shared set of `conn` starts, whichever side dialed, under the record's `r` or, with no
    /// record, the connection's own pair key (spec/sync.md §10): a filter goes out only if the
    /// peer proved a known actor (issues/net-shared-set.md, Words).
    pub(super) fn shared_begin(&mut self, conn: ConnId, r: Option<[u8; 32]>, out: &mut Vec<Action>) -> Result<()> {
        if self.records.shared.contains_key(&conn) {
            return Ok(());
        }
        let (binding, by_listener) = match self.conns.get(&conn) {
            Some(c) => (c.session.binding(), false),
            None => (self.served_binding(conn), true),
        };
        let Some((dialer, listener, key)) = binding else { return Ok(()) };
        let r = r.unwrap_or_else(|| *osis_crypto::kdf::pair_key(&dialer, &listener).expose());
        let filter_out = self.shared_known(conn);
        let s = Shared { r, key, dialer, listener, filter_out, ..Shared::bare(by_listener) };
        self.records.shared.insert(conn, s);
        self.shared_send_generation(conn, out)
    }

    /// Every connection re-judged after a change of what this node holds, and the additions and
    /// tests it makes due (issues/net-shared-set.md, Opens and Testing).
    pub(super) fn shared_changed(&mut self, out: &mut Vec<Action>) -> Result<()> {
        if !std::mem::take(&mut self.shared_dirty) {
            return Ok(());
        }
        let conns: Vec<ConnId> = self.records.shared.keys().copied().collect();
        for conn in conns {
            let Some(s) = self.records.shared.get_mut(&conn) else { continue };
            s.table = None;
            s.test_due = true;
            self.shared_rejudge(conn, out)?;
            self.shared_send_generation(conn, out)?;
            self.shared_test(conn, out)?;
        }
        Ok(())
    }

    /// Whether this side's actors for `conn` are still known here: only key actors counted, read
    /// now, never from the proof exchange's time (spec/sync.md §10).
    fn shared_known(&self, conn: ConnId) -> bool {
        self.connection_proven(conn).is_some_and(|p| !super::records::counted_actors(&self.engine, p).is_empty())
    }

    /// `conn`'s credentials admissible now (issues/net-shared-set.md, Admissible), of the `only`
    /// labels when given. A label J judges departed has none: a departure the peer's actors are
    /// covered past is not recognised yet (a rotation covering it reopens by a later credential).
    fn shared_creds(&mut self, conn: ConnId, only: Option<&BTreeSet<LabelId>>) -> Result<Vec<Cred>> {
        let Some(r) = self.records.shared.get(&conn).map(|s| s.r) else { return Ok(Vec::new()) };
        let Some(actors) = self.connection_proven(conn).map(Proven::all) else { return Ok(Vec::new()) };
        let things = self.things();
        let labels: Vec<LabelId> = things.keys().filter(|l| only.is_none_or(|o| o.contains(l))).copied().collect();
        let creds = self.credentials(&labels)?;
        let mut judge = self.engine.core.judge(actors);
        let mut out = Vec::new();
        for (l, cs) in creds {
            let Some(t) = things.get(&l) else { continue };
            let j = judge.of(t);
                if j == super::credentials::Judgment::Departed {
                continue;
            }
            for c in cs {
                let class = match c {
                    Credential::ReadSecret(_) => READ,
                    Credential::StaticEntry(_) => STATIC,
                    // a peer that cannot read's own entries, not tested by a reader (step 9)
                    Credential::SyncKey(_) | Credential::DepositKey(_) => continue,
                };
                let value = c.match_value();
                out.push(Cred { label: l, class, value, beacon: beacon(&value, &l.0, &r) });
            }
        }
        Ok(out)
    }

    /// The labels changed past `pos` and the highest position among them.
    fn shared_changes_after(&mut self, pos: u64) -> Result<(BTreeSet<LabelId>, u64)> {
        let rows = self.engine.run(|tx| Ok(tx.txn.changed_after(pos, usize::MAX)?))?;
        let top = rows.last().map_or(pos, |(p, _)| *p);
        Ok((rows.into_iter().map(|(_, l)| l).collect(), top))
    }

    fn shared_send_generation(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        if !s.filter_out || s.in_flight || s.retry_at.is_some() {
            return Ok(());
        }
        // a whole filter, also after a refused generation (`shared_retry`)
        let first = s.sent_gen == 0 || s.again;
        let after = if first { 0 } else { s.sent_pos };
        let (labels, top) = self.shared_changes_after(after)?;
        if !first && labels.is_empty() {
            return Ok(());
        }
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        let (f, whole_n, added) = (s.f, s.whole_n, s.added);
        let mut creds = if first { self.shared_creds(conn, None)? } else { self.shared_creds(conn, Some(&labels))? };
        // a whole filter when its additions pass the entries in the last one (issues/net-shared-set.md, Staleness)
        let whole = first || added + creds.len() > whole_n;
        if whole && !first {
            creds = self.shared_creds(conn, None)?;
        }
        let n = creds.len();
        let width = if whole { filter_width(n) } else { f };
        let mut values: Vec<u64> = creds.iter().map(|c| beacon_value(&c.beacon, width)).collect();
        values.sort_unstable();
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let base = (!whole).then_some(s.sent_gen);
        s.sent_gen += 1;
        let generation = s.sent_gen;
        s.again = false;
        if whole {
            s.whole_n = n;
            s.added = 0;
            s.f = width;
        } else {
            s.added += n;
        }
        s.in_flight = true;
        s.sent_pos = top;
        let mut msgs = Vec::new();
        for Page { lo, hi, gcs, more } in pages(&values, width, PAGE_BYTES) {
            let id = s.next();
            s.asked.insert(id, Asked::Beacons { pos: top, last: !more });
            msgs.push(Message::Beacons { id, generation, base, f: width, lo, hi, gcs, more });
        }
        self.stats.beacons_sent += n as u64;
        self.stats.filters_sent += 1;
        for m in msgs {
            self.shared_send(conn, m, out)?;
        }
        Ok(())
    }

    /// Sends again the filters whose last generation was refused, once their time came.
    pub(super) fn shared_retry(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
        let due: Vec<ConnId> = self.records.shared.iter().filter(|(_, s)| s.retry_at.is_some_and(|t| t <= now)).map(|(c, _)| *c).collect();
        for conn in due {
            if let Some(s) = self.records.shared.get_mut(&conn) {
                s.retry_at = None;
            }
            self.shared_send_generation(conn, out)?;
        }
        Ok(())
    }

    /// When a refused filter goes again (`next_wake`).
    pub(super) fn shared_wake(&self) -> Option<u64> {
        self.records.shared.values().filter_map(|s| s.retry_at).min()
    }

    pub(super) fn shared_send(&mut self, conn: ConnId, m: Message, out: &mut Vec<Action>) -> Result<()> {
        if self.conns.contains_key(&conn) {
            self.command(conn, Command::Peer(Box::new(m)), out)
        } else {
            self.serve(conn, ServingInput::Peer(Box::new(m)), out)
        }
    }

    /// A shared-set message from `conn`'s peer. A connection with no shared set answers refused
    /// (a request) or ignores it (an answer).
    pub(super) fn shared_message(&mut self, conn: ConnId, m: Message, out: &mut Vec<Action>) -> Result<()> {
        if !self.records.shared.contains_key(&conn) {
            if matches!(m, Message::NoRecord { .. }) && self.served_has(conn) && self.shared_known(conn) {
                self.shared_begin(conn, None, out)?;
                return self.shared_message(conn, m, out);
            }
            if m.is_request() {
                self.shared_send(conn, Message::Error { id: m.id(), code: Code::NOT_ADMITTED }, out)?;
            } else if matches!(m, Message::Error { id: NO_RECORD_ID, code: Code::NOT_ADMITTED }) {
                self.shared_peer_refused(conn);
            }
            return Ok(());
        }
        match m {
            Message::NoRecord { id } => self.shared_send(conn, Message::Shared { id, codes: vec![(Code::OK, None, None)] }, out),
            Message::Beacons { id, generation, base, f, lo, hi, gcs, more } => self.shared_beacons(conn, id, (generation, base, f, lo, hi), &gcs, more, out),
            Message::Offer { id, items } => self.shared_offer(conn, id, items, out),
            Message::Lost { id, items } => self.shared_lost(conn, id, items, out),
            Message::Shared { id, .. } if id == NO_RECORD_ID => Ok(()),
            Message::Error { id: NO_RECORD_ID, code: Code::NOT_ADMITTED } => {
                self.shared_peer_refused(conn);
                Ok(())
            }
            Message::Shared { id, codes } => self.shared_reply(conn, id, codes, out),
            // an Error answers what it names as a refusal would (a request refused whole)
            Message::Error { id, code } => {
                let code = if code == Code::OK { Code::REFUSED } else { code };
                self.shared_reply(conn, id, vec![(code, None, None)], out)
            }
            _ => Ok(()),
        }
    }

    /// Closes a connection whose peer broke a filter rule (spec/wire.md §11.2: Error 2 and close).
    fn shared_kill(&mut self, conn: ConnId, id: u32, what: &str, out: &mut Vec<Action>) -> Result<()> {
        self.diag(format!("closing peer: {what}"));
        self.shared_send(conn, Message::Error { id, code: Code::MALFORMED }, out)?;
        out.push(Action::Close { conn });
        self.lost(conn);
        self.end_served(conn, out);
        Ok(())
    }

    fn shared_beacons(&mut self, conn: ConnId, id: u32, (generation, base, f, lo, hi): (u64, Option<u64>, u8, u64, u64), gcs: &[u8], more: bool, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        // a whole filter replaces, additions build on the one held: a base not held is answered 13
        if base.is_some() && s.peer.as_ref().map(|p| p.generation) != base {
            s.pages = None;
            return self.shared_send(conn, Message::Shared { id, codes: vec![(Code::UNKNOWN_LABEL, None, None)] }, out);
        }
        let space = if f >= 64 { None } else { Some(1u64 << f) };
        let ordered = lo < hi && space.is_none_or(|e| hi <= e);
        let continues = s.pages.as_ref().is_some_and(|p| p.generation == generation && p.f == f && p.base == base && p.next_lo == lo);
        let starts = lo == 0;
        if !ordered || !(continues || starts) {
            return self.shared_kill(conn, id, "filter page out of order", out);
        }
        let Ok(values) = decode_gcs(gcs, lo, hi) else {
            return self.shared_kill(conn, id, "filter page does not decode", out);
        };
        let held = if continues { s.pages.as_ref().map_or(0, |p| p.values.len()) } else { 0 };
        if held + values.len() > MAX_FILTER_ENTRIES {
            return self.shared_kill(conn, id, "filter too large", out);
        }
        if !continues {
            s.pages = Some(Pages { generation, base, f, next_lo: lo, values: Vec::new() });
        }
        let Some(p) = s.pages.as_mut() else { return Ok(()) };
        p.values.extend(values);
        p.next_lo = hi;
        if more {
            return self.shared_send(conn, Message::Shared { id, codes: vec![(Code::OK, None, None)] }, out);
        }
        let Some(p) = s.pages.take() else { return Ok(()) };
        if space.is_some_and(|e| p.next_lo != e) {
            return self.shared_kill(conn, id, "filter does not reach the end of the space", out);
        }
        let fin = match (p.base, s.peer.take()) {
            (None, _) if f == filter_width(p.values.len()) => {
                let n = p.values.len();
                let mut values = p.values;
                values.sort_unstable();
                Some(PeerFilter { generation, f, whole: n, added: 0, values })
            }
            (Some(_), Some(mut held)) if f == held.f && held.added + p.values.len() <= held.whole => {
                held.added += p.values.len();
                held.values.extend(p.values);
                held.values.sort_unstable();
                held.generation = generation;
                Some(held)
            }
            _ => None,
        };
        let Some(fin) = fin else {
            return self.shared_kill(conn, id, "filter width or density", out);
        };
        s.peer = Some(fin);
        s.test_due = true;
        self.stats.filters_received += 1;
        self.shared_send(conn, Message::Shared { id, codes: vec![(Code::OK, None, None)] }, out)?;
        self.shared_test(conn, out)
    }

    /// Tests the pending set against the peer's filter (issues/net-shared-set.md, Testing), when
    /// due, after a filter, and with no Offer of this side unanswered.
    fn shared_test(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        if !s.test_due || s.peer.is_none() || s.pending.offers_unanswered > 0 {
            return Ok(());
        }
        let acked = s.acked_pos;
        let (labels, top) = self.shared_changes_after(acked)?;
        let creds = self.shared_creds(conn, Some(&labels))?;
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        s.test_due = false;
        s.pending.tested = s.pending.tested.max(top);
        let side = (s.by_listener, &s.key, &s.dialer, &s.listener);
        let Some(peer) = &s.peer else { return Ok(()) };
        let mut items = Vec::new();
        let mut asked = Vec::new();
        let mut more = false;
        for c in creds {
            if s.members.contains_key(&c.label) {
                continue;
            }
            if peer.values.binary_search(&beacon_value(&c.beacon, peer.f)).is_err() {
                if c.class == STATIC {
                    s.static_missing.insert(c.label);
                }
                continue;
            }
            s.static_missing.remove(&c.label);
            let hit = beacon_hit(&c.value, &c.label.0, &c.beacon, side);
            if s.offered.contains(&hit) {
                continue;
            }
            if items.len() == MAX_SHARED_ITEMS {
                more = true;
                break;
            }
            s.offered.insert(hit);
            items.push(OfferItem::Hit(hit));
            asked.push(AskedItem::Hit(c));
        }
        s.test_due = more;
        if items.is_empty() {
            return self.shared_roles(conn, out);
        }
        self.stats.hits_sent += items.len() as u64;
        self.shared_send_offer(conn, items, asked, out)
    }

    fn shared_send_offer(&mut self, conn: ConnId, items: Vec<OfferItem>, asked: Vec<AskedItem>, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let id = s.next();
        s.asked.insert(id, Asked::Offer(asked));
        s.pending.offers_unanswered += 1;
        self.shared_send(conn, Message::Offer { id, items }, out)
    }

    /// ByRole items once the Hits were answered: for L not open that J judges the peer holds
    /// (issues/net-shared-set.md, Offer). Then the pending position may rise.
    fn shared_roles(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let Some(actors) = self.connection_proven(conn).map(Proven::all) else { return Ok(()) };
        let things = self.things();
        let mut judge = self.engine.core.judge(actors);
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        let wanted: Vec<LabelId> = things.iter().filter(|(l, t)| !s.members.contains_key(l) && !s.by_role.contains(l) && judge.of(t) == super::credentials::Judgment::Holder).map(|(l, _)| *l).take(MAX_SHARED_ITEMS).collect();
        if !wanted.is_empty() {
            let set: BTreeSet<LabelId> = wanted.iter().copied().collect();
            let creds = self.shared_creds(conn, Some(&set))?;
            let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
            let side = (s.by_listener, &s.key, &s.dialer, &s.listener);
            let mut items = Vec::new();
            let mut asked = Vec::new();
            for l in wanted {
                let hits: Vec<[u8; 32]> = creds.iter().filter(|c| c.label == l).take(osis_proto::msg::MAX_BYROLE_HITS).map(|c| beacon_hit(&c.value, &c.label.0, &c.beacon, side)).collect();
                if hits.is_empty() {
                    continue;
                }
                s.by_role.insert(l);
                items.push(OfferItem::ByRole(l, hits));
                asked.push(AskedItem::ByRole(l));
            }
            if !items.is_empty() {
                self.stats.by_role_sent += items.len() as u64;
                return self.shared_send_offer(conn, items, asked, out);
            }
        }
        self.shared_rise(conn)
    }

    /// `acked_pos` rises to `min(ack, tested)` once no Offer is unanswered and no test is due.
    fn shared_rise(&mut self, conn: ConnId) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        if !s.test_due
            && let Some(pos) = s.pending.rise_to()
        {
            s.acked_pos = s.acked_pos.max(pos);
        }
        Ok(())
    }

    fn shared_table(&mut self, conn: ConnId) -> Result<()> {
        if self.records.shared.get(&conn).is_none_or(|s| s.table.is_some()) {
            return Ok(());
        }
        let creds = self.shared_creds(conn, None)?;
        self.stats.tables_built += 1;
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let peer_side = (!s.by_listener, &s.key, &s.dialer, &s.listener);
        let table = creds.into_iter().map(|c| (beacon_hit(&c.value, &c.label.0, &c.beacon, peer_side), c)).collect();
        s.table = Some(table);
        Ok(())
    }

    /// Whether a proven key actor of `conn` is the key actor of static entry `value` on `l`.
    fn shared_static_proved(&self, conn: ConnId, l: &LabelId, value: &[u8; 32]) -> bool {
        let Some(p) = self.connection_proven(conn) else { return false };
        p.key_actors.iter().any(|t| match self.engine.core.created(t) {
            Some(osis_base::CreationRecord::KeyActor { public_key, .. }) => osis_crypto::VerifyingKey::from_slice(public_key).is_ok_and(|pk| osis_crypto::static_entry(l, &pk) == *value),
            _ => false,
        })
    }

    fn shared_offer(&mut self, conn: ConnId, id: u32, items: Vec<OfferItem>, out: &mut Vec<Action>) -> Result<()> {
        self.shared_table(conn)?;
        let things = self.things();
        let Some(actors) = self.connection_proven(conn).map(Proven::all) else { return Ok(()) };
        let served = self.served_labels();
        let mut judge = self.engine.core.judge(actors);
        let mut codes = Vec::with_capacity(items.len());
        let mut opens: Vec<(LabelId, u8, Option<[u8; 32]>)> = Vec::new();
        let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
        for item in items {
            let answer = match item {
                OfferItem::Hit(hit) => match s.table.as_ref().and_then(|t| t.get(&hit)) {
                    Some(c) if c.class != STATIC || self.shared_static_proved(conn, &c.label, &c.value) => {
                        let tag = beacon_reply(&c.value, &c.label.0, &c.beacon, s.side(s.by_listener));
                        opens.push((c.label, c.class, Some(c.value)));
                        // a key actor's node learns the read secret from the head's box for it
                        let grant = (c.class == STATIC).then(|| served.get(&c.label).and_then(|x| x.grant(&c.value))).flatten().map(Box::new);
                        (Code::OK, Some(tag), grant)
                    }
                    _ => (Code::NOT_ADMITTED, None, None),
                },
                OfferItem::ByRole(l, hits) => {
                    let listed = hits.iter().filter_map(|h| s.table.as_ref().and_then(|t| t.get(h))).find(|c| c.label == l && (c.class != STATIC || self.shared_static_proved(conn, &c.label, &c.value)));
                    let holder = things.get(&l).is_some_and(|t| judge.of(t) == super::credentials::Judgment::Holder);
                    if holder || listed.is_some() {
                        opens.push((l, listed.map_or(JUDGED, |c| c.class), listed.map(|c| c.value)));
                        (Code::OK, None, None)
                    } else {
                        (Code::NOT_ADMITTED, None, None)
                    }
                }
            };
            codes.push(answer);
        }
        drop(judge);
        // the answer first: the tester opens on reading it, so a Pull joining L after it finds L
        // open there (stream.rs)
        self.shared_send(conn, Message::Shared { id, codes }, out)?;
        for (l, class, value) in opens {
            self.shared_open(conn, l, class, value, out)?;
        }
        Ok(())
    }

    /// L joins `conn`'s S on this side, and this side's stream of the peer.
    fn shared_open(&mut self, conn: ConnId, l: LabelId, class: u8, value: Option<[u8; 32]>, out: &mut Vec<Action>) -> Result<()> {
        // the first sync ID shared here: what this node holds of labels synced with no host is
        // placed for its readers from now on (`serves_readers`)
        self.local_dirty |= self.records.shared.values().all(Shared::is_empty);
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        s.members.insert(l, Member { class, value });
        self.stream_join(conn, l, out)?;
        self.stream_source_gained(conn, &l, out)
    }

    /// L leaves S on this side (a Lost, a judgment): nothing more is served or pulled for it and
    /// the member is pending again for this connection (issues/net-shared-set.md, Re-marking).
    fn shared_close(&mut self, conn: ConnId, l: &LabelId) -> Result<()> {
        let at = self.engine.run(|tx| Ok(tx.txn.changed_at(l)?))?.unwrap_or(0);
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        s.members.remove(l);
        s.by_role.remove(l);
        s.offered.clear();
        s.pending.remark(at);
        s.acked_pos = s.acked_pos.min(at.saturating_sub(1));
        s.test_due = true;
        self.stream_leave(conn, l)
    }

    /// Re-judges every member: holders stay; a credential open stays while that credential is
    /// admissible; anything else closes with a `Lost`. A connection whose actors are unknown here
    /// now keeps what the rule keeps, but sends no more beacons and loses its record.
    fn shared_rejudge(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        if !self.records.shared.contains_key(&conn) {
            return Ok(());
        }
        let known = self.shared_known(conn);
        if !known {
            // a record is honoured only while its actors are known here (spec/sync.md §10)
            self.records.unbind(conn);
        }
        let Some(actors) = self.connection_proven(conn).map(Proven::all) else { return Ok(()) };
        let creds = self.shared_creds(conn, None)?;
        let things = self.things();
        let mut judge = self.engine.core.judge(actors);
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        s.filter_out = known;
        let gone: Vec<LabelId> = s
            .members
            .iter()
            .filter(|(l, m)| {
                if !things.contains_key(*l) {
                    return true;
                }
                let holder = things.get(*l).is_some_and(|t| judge.of(t) == super::credentials::Judgment::Holder);
                let cred = m.value.is_some_and(|v| m.class != JUDGED && creds.iter().any(|c| c.label == **l && c.value == v));
                !holder && !cred
            })
            .map(|(l, _)| *l)
            .collect();
        if gone.is_empty() {
            return Ok(());
        }
        for l in &gone {
            self.shared_close(conn, l)?;
        }
        for batch in gone.chunks(MAX_SHARED_ITEMS) {
            let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
            let id = s.next();
            s.asked.insert(id, Asked::Lost);
            let items = batch.iter().map(|l| (*l, None)).collect();
            self.shared_send(conn, Message::Lost { id, items }, out)?;
        }
        Ok(())
    }

    fn shared_lost(&mut self, conn: ConnId, id: u32, items: Vec<(LabelId, Option<Vec<u8>>)>, out: &mut Vec<Action>) -> Result<()> {
        // only a member of S is closed: a sync ID the peer does not share with this node changes
        // nothing and costs no test (idempotent)
        let n = items.len();
        for (l, _) in items {
            if self.shared_member(conn, &l) {
                self.shared_close(conn, &l)?;
            }
        }
        self.shared_send(conn, Message::Shared { id, codes: vec![(Code::OK, None, None); n] }, out)?;
        self.shared_test(conn, out)
    }

    fn shared_reply(&mut self, conn: ConnId, id: u32, codes: Vec<osis_proto::msg::SharedCode>, out: &mut Vec<Action>) -> Result<()> {
        let retry_at = self.raw_now().saturating_add(self.cfg.resync_ms);
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let Some(asked) = s.asked.remove(&id) else { return Ok(()) };
        match asked {
            Asked::Lost => Ok(()),
            Asked::Beacons { pos, last, .. } => {
                let code = codes.first().map_or(Code::REFUSED, |c| c.0);
                if !last {
                    return Ok(());
                }
                s.in_flight = false;
                if code == Code::OK {
                    s.pending.ack = s.pending.ack.max(pos);
                } else {
                    // refused (base unknown, an Error): a whole filter goes again after
                    // `resync_ms`, as a refused Pull does (one rule for refused node requests)
                    s.whole_n = 0;
                    s.added = 0;
                    s.again = true;
                    s.retry_at = Some(retry_at);
                }
                self.shared_send_generation(conn, out)?;
                self.shared_rise(conn)
            }
            Asked::Offer(items) => {
                s.pending.offers_unanswered = s.pending.offers_unanswered.saturating_sub(1);
                for (item, (code, tag, grant)) in items.into_iter().zip(codes) {
                    if code != Code::OK {
                        continue;
                    }
                    match item {
                        // a ByRole's sender judged the peer a holder: no proof but J, still so now
                        AskedItem::ByRole(l) => {
                            let things = self.things();
                            let actors = self.connection_proven(conn).map(Proven::all).unwrap_or_default();
                            if things.get(&l).is_some_and(|t| self.engine.core.judge(actors).of(t) == super::credentials::Judgment::Holder) {
                                self.shared_open(conn, l, JUDGED, None, out)?;
                            }
                        }
                        AskedItem::Hit(c) => {
                            let Some(s) = self.records.shared.get(&conn) else { return Ok(()) };
                            let expect = beacon_reply(&c.value, &c.label.0, &c.beacon, s.side(!s.by_listener));
                            if tag != Some(expect) {
                                continue;
                            }
                            // a static entry's grant gives the read secret, or opens nothing
                            let granted = match &grant {
                                Some(g) if c.class == STATIC => self.granted(c.label, &c.value, g)?,
                                _ => true,
                            };
                            // still admissible when the answer came?
                            let set: BTreeSet<LabelId> = [c.label].into();
                            let now = self.shared_creds(conn, Some(&set))?;
                            if granted && now.iter().any(|x| x.value == c.value) {
                                self.shared_open(conn, c.label, c.class, Some(c.value), out)?;
                            } else if !self.shared_member(conn, &c.label) {
                                // this tester's credential is gone (issues/net-shared-set.md, Divergence)
                                self.shared_lost_send(conn, c.label, out)?;
                            }
                        }
                    }
                }
                match self.records.shared.get(&conn) {
                    Some(s) if s.pending.offers_unanswered > 0 => Ok(()),
                    Some(s) if s.test_due => self.shared_test(conn, out),
                    Some(_) => self.shared_roles(conn, out),
                    None => Ok(()),
                }
            }
        }
    }

    fn shared_lost_send(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let Some(s) = self.records.shared.get_mut(&conn) else { return Ok(()) };
        let id = s.next();
        s.asked.insert(id, Asked::Lost);
        self.shared_send(conn, Message::Lost { id, items: vec![(l, None)] }, out)
    }
}
