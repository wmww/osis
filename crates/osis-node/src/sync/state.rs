//! The sync engine's durable state, in the engine's local records under `y/` (one write batch
//! per `SyncEngine::handle`): label entries this node knows (wrap, stamp, what the blob is),
//! presence per server, cursors and heads per (server, label), blob keys of commit blobs,
//! certificates and heartbeats placed, blobs a server tombstoned, label hints from inbox blobs,
//! inbox deliveries to re-send, stranded heartbeat times, direct commits for the app.

use crate::engine::{Engine, Tx};
use crate::engine::records::{Rd, Wr};
use crate::error::{Error, Result};
use osis_core::{BlobId, CommitId, LabelId, Tid};
use osis_crypto::{Secret32, Signature, WRAP_LEN};
use osis_label::{Address, Step};
use osis_proto::Cursor;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// A server, by its static key (its address key).
pub type ServerKey = [u8; 32];

const ENTRY: &[u8] = b"y/e";
const PRESENT: &[u8] = b"y/p";
const CURSOR: &[u8] = b"y/c";
const HEAD: &[u8] = b"y/h";
const BLOB: &[u8] = b"y/b";
const CERT: &[u8] = b"y/k";
const BEAT: &[u8] = b"y/t";
const GONE: &[u8] = b"y/g";
const HINT: &[u8] = b"y/i";
const TIMED: &[u8] = b"y/d";
const CARRIER: &[u8] = b"y/s";
const REACH: &[u8] = b"y/r";
const TOMB: &[u8] = b"y/x";
const OUTBOX: &[u8] = b"y/o";
/// Things forgotten whose inbox blobs this node has not checked yet (`SyncEngine::forget_inbox`).
const FORGET: &[u8] = b"y/f";
/// Replaced labels this admin is done with (`SyncEngine::retire_at`).
const RETIRED: &[u8] = b"y/q";
/// Inbox deliveries re-sent after `INBOX_LIFETIME` while unanswered (`SyncEngine::resend_inbox`).
const SENT_INBOX: &[u8] = b"y/v";
/// When a stranded heartbeat last went under a label.
const STRANDED: &[u8] = b"y/u";
/// Commits for a node over a direct connection, until the app takes them (`take_direct`).
const DIRECT: &[u8] = b"y/j";
/// Per-group `/reach` policy set by the app (1 publish, 0 exclude; `SyncEngine::set_reach_policy`).
const REACH_POLICY: &[u8] = b"y/n";
/// Persons marked as contacts (`SyncEngine::set_contact`).
const CONTACT: &[u8] = b"y/a";
/// Groups whose co-readers are dialed whatever the `/reach` policy (`SyncEngine::dial_group`).
const DIAL: &[u8] = b"y/l";

/// What an entry's blob is, as far as this node could open it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Not opened: a chunk, tree node or page (filler wrap), a blob under an epoch not held, or
    /// a blob not fetched yet.
    Unknown,
    /// A commit blob holding these parts.
    Commit { commit: CommitId, parts: Vec<(usize, usize)> },
    /// An inbox blob this node opened, with the commit it carried (`None`: opened by an older
    /// build).
    Inbox(Option<CommitId>),
    /// Unwraps under a held secret but is no valid commit blob (spec/versioning.md §2: bad
    /// input): never retried, never judged.
    Bad,
    /// A commit this build cannot interpret, held parked (spec/versioning.md §2): relayed,
    /// never judged.
    Parked(CommitId),
}

/// A label entry as this node knows it (spec/sync.md §4).
#[derive(Clone, Debug)]
pub struct Entry {
    pub wrap: [u8; WRAP_LEN],
    pub stamp: Option<Signature>,
    /// Placed by this node as a certificate blob (spec/sync.md §3).
    pub cert: bool,
    pub kind: Kind,
}

/// A commit blob this node holds the key of (received, or sealed here).
#[derive(Clone)]
pub struct BlobRec {
    pub commit: CommitId,
    pub parts: Vec<(usize, usize)>,
    pub key: Secret32,
    /// A certificate encryption (never shared with another label).
    pub cert: bool,
}

/// An inbox blob to deposit at a server, kept until the server answers (spec/sync.md §3).
#[derive(Clone, Debug)]
pub struct OutRec {
    pub label: LabelId,
    pub server: Address,
    pub owner: Tid,
    pub blob: Vec<u8>,
}

/// A membership commit delivered by inbox to `member` (spec/sync.md §3): re-sealed and sent
/// again once `INBOX_LIFETIME` passed since `at` (corrected wall ms) unless the member acted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentInbox {
    pub member: Tid,
    pub commit: CommitId,
    pub things: Vec<Tid>,
    /// Only the `/members` parts went (a removal).
    pub edge_only: bool,
    pub at: u64,
    /// Re-sends so far.
    pub tries: u32,
}

/// A label learned from an inbox blob before its `/label` is held, or followed by a held key
/// actor's static entry (`via`: a recovery card's home label, a link's label).
#[derive(Clone, Debug)]
pub struct Hint {
    pub thing: Tid,
    pub servers: Vec<Address>,
    /// The key actor whose static entry may open it; no other key actor's is presented.
    pub via: Option<Tid>,
}

#[derive(Default)]
pub struct State {
    pub entries: BTreeMap<(LabelId, BlobId), Entry>,
    pub present: BTreeSet<(ServerKey, LabelId, BlobId)>,
    /// Present entries the server holds deposited (no stamp there; spec/sync.md §5): a writer
    /// promotes them at that server, whatever stamp this node knows.
    pub deposited: BTreeSet<(ServerKey, LabelId, BlobId)>,
    pub cursors: BTreeMap<(ServerKey, LabelId), Cursor>,
    pub heads: BTreeMap<(ServerKey, LabelId), Step>,
    pub blobs: BTreeMap<BlobId, BlobRec>,
    pub by_commit: BTreeMap<CommitId, BTreeSet<BlobId>>,
    pub certs: BTreeSet<(LabelId, CommitId)>,
    pub beats: BTreeMap<LabelId, u64>,
    pub gone: BTreeSet<(ServerKey, LabelId, BlobId)>,
    pub hints: BTreeMap<LabelId, Hint>,
    /// Timed deletes sent (spec/sync.md §5).
    pub timed: BTreeSet<(ServerKey, LabelId, BlobId)>,
    /// The snapshots carrying a body's live writes once it was dropped, one per aspect at most
    /// (spec/sync.md §7).
    pub carriers: BTreeMap<CommitId, Vec<CommitId>>,
    /// This node's dialable transport secret (spec/sync.md §10).
    pub reach_secret: Option<Secret32>,
    /// The label logs member-peer sessions see (in memory).
    pub feed: super::serve::Feed,
    /// Entries this node dropped, by when (corrected wall ms): refused from peers for
    /// `TOMBSTONE_LIFETIME` (spec/sync.md §5), so a peer cannot replay a deleted body.
    pub tombs: BTreeMap<(LabelId, BlobId), u64>,
    /// Inbox blobs not yet answered by their server, by (server, blob).
    pub outbox: BTreeMap<(ServerKey, BlobId), OutRec>,
    /// Corrected wall ms of the running `handle` (tombstone times).
    pub now: u64,
    /// Things forgotten whose opened inbox blobs are not yet checked (`y/f`).
    pub forget: BTreeSet<Tid>,
    /// Replaced labels this admin no longer syncs (`y/q`, spec/sync.md §2).
    pub retired: BTreeSet<LabelId>,
    /// When this admin first saw each replaced label it still syncs (corrected wall ms, `y/q`
    /// with a time): retired after `MEMBERSHIP_KEEP` whatever its servers say.
    pub replaced_seen: BTreeMap<LabelId, u64>,
    /// Inbox deliveries by (member, commit), until the member acts or the re-sends run out.
    pub sent_inbox: BTreeMap<(Tid, CommitId), SentInbox>,
    /// When a stranded heartbeat last went under each label (corrected wall ms).
    pub stranded: BTreeMap<LabelId, u64>,
    /// Commits for nodes over a direct connection (pairing), until the app takes them.
    pub direct: BTreeMap<Tid, Vec<CommitId>>,
    /// `/reach` policy per group the app set (`y/n`).
    pub reach_policy: BTreeMap<Tid, bool>,
    /// Persons marked as contacts (`y/a`).
    pub contacts: BTreeSet<Tid>,
    /// Groups whose co-readers are dialed though this node's `/reach` stays out (`y/l`).
    pub dial: BTreeSet<Tid>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

fn key(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    for p in parts {
        k.extend_from_slice(p);
    }
    k
}

fn encode_parts(w: Wr, parts: &[(usize, usize)]) -> Wr {
    let mut w = w.u32(parts.len() as u32);
    for (a, d) in parts {
        w = w.u32(*a as u32).u32(*d as u32);
    }
    w
}

fn decode_parts(r: &mut Rd<'_>) -> Result<Vec<(usize, usize)>> {
    let n = r.u32()?;
    let mut v = Vec::new();
    for _ in 0..n {
        v.push((r.u32()? as usize, r.u32()? as usize));
    }
    Ok(v)
}

fn encode_entry(e: &Entry) -> Vec<u8> {
    let mut w = Wr::new().raw(&e.wrap).u8(u8::from(e.cert));
    w = match &e.stamp {
        Some(s) => w.u8(1).raw(&s.0),
        None => w.u8(0),
    };
    match &e.kind {
        Kind::Unknown => w.u8(0),
        Kind::Commit { commit, parts } => encode_parts(w.u8(1).raw(&commit.0), parts),
        Kind::Inbox(None) => w.u8(2),
        Kind::Inbox(Some(c)) => w.u8(5).raw(&c.0),
        Kind::Bad => w.u8(3),
        Kind::Parked(c) => w.u8(4).raw(&c.0),
    }
    .take()
}

fn decode_entry(b: &[u8]) -> Result<Entry> {
    let mut r = Rd::new(b);
    let wrap = r.arr()?;
    let cert = r.u8()? == 1;
    let stamp = match r.u8()? {
        1 => Some(Signature(r.arr()?)),
        _ => None,
    };
    let kind = match r.u8()? {
        1 => {
            let commit = CommitId(r.arr()?);
            Kind::Commit { commit, parts: decode_parts(&mut r)? }
        }
        2 => Kind::Inbox(None),
        5 => Kind::Inbox(Some(CommitId(r.arr()?))),
        3 => Kind::Bad,
        4 => Kind::Parked(CommitId(r.arr()?)),
        _ => Kind::Unknown,
    };
    Ok(Entry { wrap, stamp, cert, kind })
}

impl State {
    /// Loads every record.
    pub fn load(engine: &mut Engine) -> Result<State> {
        let recs = engine.run(|tx| {
            let mut v = Vec::new();
            tx.scan(b"y/", |k, val| {
                v.push((k.to_vec(), val));
                Ok(())
            })?;
            Ok(v)
        })?;
        let mut s = State::default();
        for (k, v) in recs {
            let (p, rest) = k.split_at_checked(1).ok_or(Error::Corrupt("sync record"))?;
            let mut r = Rd::new(rest);
            match p {
                b"e" => {
                    let l = LabelId(r.arr()?);
                    s.entries.insert((l, BlobId(r.arr()?)), decode_entry(&v)?);
                }
                b"p" => {
                    let k = (r.arr()?, LabelId(r.arr()?), BlobId(r.arr()?));
                    if v.first() == Some(&1) {
                        s.deposited.insert(k);
                    }
                    s.present.insert(k);
                }
                b"c" => {
                    let k = (r.arr()?, LabelId(r.arr()?));
                    let mut c = Rd::new(&v);
                    s.cursors.insert(k, Cursor { log_id: c.arr()?, seq: c.u64()? });
                }
                b"h" => {
                    let k = (r.arr()?, LabelId(r.arr()?));
                    s.heads.insert(k, Step::parse(&v).map_err(|_| Error::Corrupt("head step"))?);
                }
                b"b" => {
                    let id = BlobId(r.arr()?);
                    let mut x = Rd::new(&v);
                    let commit = CommitId(x.arr()?);
                    let key = Secret32::from_bytes(x.arr()?);
                    let cert = x.u8()? == 1;
                    let parts = decode_parts(&mut x)?;
                    s.by_commit.entry(commit).or_default().insert(id);
                    s.blobs.insert(id, BlobRec { commit, parts, key, cert });
                }
                b"k" => {
                    s.certs.insert((LabelId(r.arr()?), CommitId(r.arr()?)));
                }
                b"t" => {
                    s.beats.insert(LabelId(r.arr()?), Rd::new(&v).u64()?);
                }
                b"g" => {
                    s.gone.insert((r.arr()?, LabelId(r.arr()?), BlobId(r.arr()?)));
                }
                b"s" => {
                    let body = CommitId(r.arr()?);
                    let mut x = Rd::new(&v);
                    let mut list = Vec::new();
                    while !x.is_empty() {
                        list.push(CommitId(x.arr()?));
                    }
                    s.carriers.insert(body, list);
                }
                b"x" => {
                    s.tombs.insert((LabelId(r.arr()?), BlobId(r.arr()?)), Rd::new(&v).u64()?);
                }
                b"r" => s.reach_secret = Some(Secret32::from_bytes(Rd::new(&v).arr()?)),
                b"o" => {
                    let k = (r.arr()?, BlobId(r.arr()?));
                    let mut x = Rd::new(&v);
                    let label = LabelId(x.arr()?);
                    let url = String::from_utf8(x.bytes()?.to_vec()).map_err(|_| Error::Corrupt("outbox"))?;
                    let server = Address { url, key: x.arr()? };
                    let owner = x.tid()?;
                    let blob = x.bytes()?.to_vec();
                    s.outbox.insert(k, OutRec { label, server, owner, blob });
                }
                b"q" => {
                    let l = LabelId(r.arr()?);
                    if v.is_empty() {
                        s.retired.insert(l);
                    } else {
                        s.replaced_seen.insert(l, Rd::new(&v).u64()?);
                    }
                }
                b"f" => {
                    s.forget.insert(r.tid()?);
                }
                // a record that does not decode is a delivery not re-sent: never a failed load
                b"v" => {
                    if let Ok(x) = decode_sent(&v) {
                        s.sent_inbox.insert((x.member, x.commit), x);
                    }
                }
                b"u" => {
                    s.stranded.insert(LabelId(r.arr()?), Rd::new(&v).u64()?);
                }
                b"j" => {
                    let to = r.tid()?;
                    let mut x = Rd::new(&v);
                    let mut list = Vec::new();
                    while !x.is_empty() {
                        list.push(CommitId(x.arr()?));
                    }
                    s.direct.insert(to, list);
                }
                b"n" => {
                    s.reach_policy.insert(r.tid()?, v.first() == Some(&1));
                }
                b"a" => {
                    s.contacts.insert(r.tid()?);
                }
                b"l" => {
                    s.dial.insert(r.tid()?);
                }
                b"d" => {
                    s.timed.insert((r.arr()?, LabelId(r.arr()?), BlobId(r.arr()?)));
                }
                b"i" => {
                    let l = LabelId(r.arr()?);
                    let mut x = Rd::new(&v);
                    let thing = x.tid()?;
                    let n = x.u32()?;
                    let mut servers = Vec::new();
                    for _ in 0..n {
                        let url = String::from_utf8(x.bytes()?.to_vec()).map_err(|_| Error::Corrupt("hint"))?;
                        servers.push(Address { url, key: x.arr()? });
                    }
                    let via = if x.is_empty() { None } else { Some(x.tid()?) };
                    s.hints.insert(l, Hint { thing, servers, via });
                }
                _ => {}
            }
        }
        Ok(s)
    }

    /// Writes the records changed since the last flush in one transaction (wraps and blob keys
    /// shredded on removal).
    pub fn flush(&mut self, engine: &mut Engine) -> Result<()> {
        if self.writes.is_empty() {
            return Ok(());
        }
        let writes = std::mem::take(&mut self.writes);
        let r = engine.run(|tx| {
            for (k, v) in writes.clone() {
                match v {
                    // a replaced wrap or key leaves no copy behind
                    Some(v) => tx.txn.put_local(&k, &v, if k.starts_with(ENTRY) || k.starts_with(BLOB) || k.starts_with(REACH) { Shred::Yes } else { Shred::No })?,
                    None => {
                        tx.txn.remove_local(&k, Shred::Yes)?;
                    }
                }
            }
            Ok(())
        });
        // the in-memory state already holds them: kept for the next flush, so what is durable
        // never lags behind what this node acted on
        if r.is_err() {
            for (k, v) in writes {
                self.writes.entry(k).or_insert(v);
            }
        }
        r
    }

    fn put(&mut self, k: Vec<u8>, v: Vec<u8>) {
        self.writes.insert(k, Some(v));
    }

    fn del(&mut self, k: Vec<u8>) {
        self.writes.insert(k, None);
    }

    pub fn set_entry(&mut self, l: LabelId, b: BlobId, e: Entry) {
        self.put(key(ENTRY, &[&l.0, &b.0]), encode_entry(&e));
        self.entries.insert((l, b), e);
        self.feed.added(l, b);
    }

    pub fn remove_entry(&mut self, l: LabelId, b: BlobId) {
        if self.entries.remove(&(l, b)).is_some() {
            self.del(key(ENTRY, &[&l.0, &b.0]));
            self.feed.deleted(l, b);
            self.put(key(TOMB, &[&l.0, &b.0]), Wr::new().u64(self.now).take());
            self.tombs.insert((l, b), self.now);
        }
    }

    /// Forgets an entry that never counted (junk a server announced): no tombstone.
    pub fn drop_entry(&mut self, l: LabelId, b: BlobId) {
        if self.entries.remove(&(l, b)).is_some() {
            self.del(key(ENTRY, &[&l.0, &b.0]));
            self.feed.deleted(l, b);
        }
    }

    /// Forgets tombstones past their lifetime.
    pub fn expire_tombs(&mut self, now: u64) {
        let old: Vec<(LabelId, BlobId)> = self.tombs.iter().filter(|(_, t)| t.saturating_add(osis_core::format::TOMBSTONE_LIFETIME_MS) <= now).map(|(k, _)| *k).collect();
        for (l, b) in old {
            self.tombs.remove(&(l, b));
            self.del(key(TOMB, &[&l.0, &b.0]));
        }
    }

    pub fn set_reach_secret(&mut self, s: Secret32) {
        self.put(REACH.to_vec(), s.expose().to_vec());
        self.reach_secret = Some(s);
    }

    pub fn set_present(&mut self, s: ServerKey, l: LabelId, b: BlobId, on: bool) {
        let k = key(PRESENT, &[&s, &l.0, &b.0]);
        if on {
            if self.present.insert((s, l, b)) {
                self.put(k, Vec::new());
            }
        } else if self.present.remove(&(s, l, b)) {
            self.deposited.remove(&(s, l, b));
            self.del(k);
        }
    }

    /// Marks a present entry deposited at a server, or not (stamped there).
    pub fn set_deposited(&mut self, s: ServerKey, l: LabelId, b: BlobId, on: bool) {
        if !self.present.contains(&(s, l, b)) {
            return;
        }
        let changed = if on { self.deposited.insert((s, l, b)) } else { self.deposited.remove(&(s, l, b)) };
        if changed {
            self.put(key(PRESENT, &[&s, &l.0, &b.0]), if on { vec![1] } else { Vec::new() });
        }
    }

    pub fn is_present(&self, s: &ServerKey, l: &LabelId, b: &BlobId) -> bool {
        self.present.contains(&(*s, *l, *b))
    }

    /// Whether any server holds the entry.
    pub fn present_anywhere(&self, l: &LabelId, b: &BlobId) -> bool {
        self.present.iter().any(|(_, x, y)| x == l && y == b)
    }

    /// Entry IDs known present at a server for a label.
    pub fn present_at(&self, s: &ServerKey, l: &LabelId) -> Vec<BlobId> {
        self.present.iter().filter(|(x, y, _)| x == s && y == l).map(|(_, _, b)| *b).collect()
    }

    pub fn set_cursor(&mut self, s: ServerKey, l: LabelId, c: Option<Cursor>) {
        let k = key(CURSOR, &[&s, &l.0]);
        match c {
            Some(c) => {
                self.put(k, Wr::new().raw(&c.log_id).u64(c.seq).take());
                self.cursors.insert((s, l), c);
            }
            None => {
                self.del(k);
                self.cursors.remove(&(s, l));
            }
        }
    }

    pub fn set_head(&mut self, s: ServerKey, l: LabelId, step: &Step) {
        self.put(key(HEAD, &[&s, &l.0]), step.to_bytes());
        self.heads.insert((s, l), step.clone());
    }

    pub fn add_blob(&mut self, id: BlobId, rec: BlobRec) {
        let v = encode_parts(Wr::new().raw(&rec.commit.0).raw(rec.key.expose()).u8(u8::from(rec.cert)), &rec.parts).take();
        self.put(key(BLOB, &[&id.0]), v);
        self.by_commit.entry(rec.commit).or_default().insert(id);
        self.blobs.insert(id, rec);
    }

    pub fn remove_blob(&mut self, id: &BlobId) {
        if let Some(r) = self.blobs.remove(id) {
            if let Some(s) = self.by_commit.get_mut(&r.commit) {
                s.remove(id);
                if s.is_empty() {
                    self.by_commit.remove(&r.commit);
                }
            }
            self.del(key(BLOB, &[&id.0]));
        }
    }

    /// Sets (or clears, `None`) a group's `/reach` policy.
    pub fn set_reach_policy(&mut self, g: Tid, publish: Option<bool>) {
        match publish {
            Some(p) => {
                self.put(key(REACH_POLICY, &[g.as_bytes()]), vec![u8::from(p)]);
                self.reach_policy.insert(g, p);
            }
            None => {
                self.del(key(REACH_POLICY, &[g.as_bytes()]));
                self.reach_policy.remove(&g);
            }
        }
    }

    pub fn set_contact(&mut self, person: Tid, contact: bool) {
        if contact {
            self.put(key(CONTACT, &[person.as_bytes()]), Vec::new());
            self.contacts.insert(person);
        } else {
            self.del(key(CONTACT, &[person.as_bytes()]));
            self.contacts.remove(&person);
        }
    }

    pub fn set_dial(&mut self, g: Tid) {
        if self.dial.insert(g) {
            self.put(key(DIAL, &[g.as_bytes()]), Vec::new());
        }
    }

    pub fn retire(&mut self, l: LabelId) {
        self.replaced_seen.remove(&l);
        if self.retired.insert(l) {
            self.put(key(RETIRED, &[&l.0]), Vec::new());
        }
    }

    /// When a replaced label was first seen (recorded now if not yet).
    pub fn replaced_seen(&mut self, l: LabelId, now: u64) -> u64 {
        if let Some(t) = self.replaced_seen.get(&l) {
            return *t;
        }
        self.replaced_seen.insert(l, now);
        self.put(key(RETIRED, &[&l.0]), Wr::new().u64(now).take());
        now
    }

    /// Records an inbox delivery, or a re-send of one (counted).
    pub fn note_sent(&mut self, member: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool, at: u64) {
        let x = match self.sent_inbox.get(&(member, commit)) {
            Some(old) => SentInbox { at, tries: old.tries.saturating_add(1), ..old.clone() },
            None => SentInbox { member, commit, things, edge_only, at, tries: 0 },
        };
        self.put(key(SENT_INBOX, &[member.as_bytes(), &commit.0]), encode_sent(&x));
        self.sent_inbox.insert((member, commit), x);
    }

    pub fn remove_sent(&mut self, member: &Tid, commit: &CommitId) {
        if self.sent_inbox.remove(&(*member, *commit)).is_some() {
            self.del(key(SENT_INBOX, &[member.as_bytes(), &commit.0]));
        }
    }

    pub fn set_stranded(&mut self, l: LabelId, t: u64) {
        self.put(key(STRANDED, &[&l.0]), Wr::new().u64(t).take());
        self.stranded.insert(l, t);
    }

    /// Adds commits for node `to` (direct connection).
    pub fn add_direct(&mut self, to: Tid, commits: &[CommitId]) {
        let list = self.direct.entry(to).or_default();
        for c in commits {
            if !list.contains(c) {
                list.push(*c);
            }
        }
        let v: Vec<u8> = list.iter().flat_map(|c| c.0).collect();
        self.put(key(DIRECT, &[to.as_bytes()]), v);
    }

    /// Takes the commits for `to` (every node when `None`).
    pub fn take_direct(&mut self, to: Option<&Tid>) -> Vec<(Tid, Vec<CommitId>)> {
        let tids: Vec<Tid> = self.direct.keys().filter(|t| to.is_none_or(|x| x == *t)).copied().collect();
        let mut out = Vec::new();
        for t in tids {
            if let Some(list) = self.direct.remove(&t) {
                self.del(key(DIRECT, &[t.as_bytes()]));
                out.push((t, list));
            }
        }
        out
    }

    pub fn add_cert(&mut self, l: LabelId, c: CommitId) {
        if self.certs.insert((l, c)) {
            self.put(key(CERT, &[&l.0, &c.0]), Vec::new());
        }
    }

    pub fn set_beat(&mut self, l: LabelId, t: u64) {
        self.put(key(BEAT, &[&l.0]), Wr::new().u64(t).take());
        self.beats.insert(l, t);
    }

    pub fn set_gone(&mut self, s: ServerKey, l: LabelId, b: BlobId) {
        if self.gone.insert((s, l, b)) {
            self.put(key(GONE, &[&s, &l.0, &b.0]), Vec::new());
        }
    }

    pub fn is_gone(&self, l: &LabelId, b: &BlobId) -> bool {
        self.gone.iter().any(|(_, x, y)| x == l && y == b)
    }

    /// Adds a carrier of `body` (a snapshot of one of its aspects).
    pub fn set_carrier(&mut self, body: CommitId, snapshot: CommitId) {
        let list = self.carriers.entry(body).or_default();
        if !list.contains(&snapshot) {
            list.push(snapshot);
        }
        let v: Vec<u8> = list.iter().flat_map(|c| c.0).collect();
        self.put(key(CARRIER, &[&body.0]), v);
    }

    pub fn set_timed(&mut self, s: ServerKey, l: LabelId, b: BlobId) {
        if self.timed.insert((s, l, b)) {
            self.put(key(TIMED, &[&s, &l.0, &b.0]), Vec::new());
        }
    }

    pub fn add_out(&mut self, o: OutRec) {
        let id = osis_label::blob_id(&o.blob);
        let v = Wr::new().raw(&o.label.0).bytes(o.server.url.as_bytes()).raw(&o.server.key).raw(o.owner.as_bytes()).bytes(&o.blob).take();
        self.put(key(OUTBOX, &[&o.server.key, &id.0]), v);
        self.outbox.insert((o.server.key, id), o);
    }

    pub fn remove_out(&mut self, s: &ServerKey, b: &BlobId) {
        if self.outbox.remove(&(*s, *b)).is_some() {
            self.del(key(OUTBOX, &[s, &b.0]));
        }
    }

    /// Records a hint; a hint naming no key actor keeps the one an earlier hint followed for (an
    /// inbox payload naming a followed label must not stall the follow).
    pub fn add_hint(&mut self, l: LabelId, mut h: Hint) {
        if h.via.is_none() {
            h.via = self.hints.get(&l).and_then(|x| x.via);
        }
        let mut w = Wr::new().raw(h.thing.as_bytes()).u32(h.servers.len() as u32);
        for a in &h.servers {
            w = w.bytes(a.url.as_bytes()).raw(&a.key);
        }
        if let Some(v) = &h.via {
            w = w.raw(v.as_bytes());
        }
        self.put(key(HINT, &[&l.0]), w.take());
        self.hints.insert(l, h);
    }

    /// The inbox blobs of `t` are checked.
    pub fn forget_done(&mut self, t: &Tid) {
        if self.forget.remove(t) {
            self.del(key(FORGET, &[t.as_bytes()]));
        }
    }

    pub fn remove_hint(&mut self, l: &LabelId) {
        if self.hints.remove(l).is_some() {
            self.del(key(HINT, &[&l.0]));
        }
    }

    /// The blob this node holds for exactly these parts of a commit (not a certificate
    /// encryption), if any.
    pub fn blob_for(&self, c: &CommitId, parts: &[(usize, usize)], skip: impl Fn(&BlobId) -> bool) -> Option<BlobId> {
        self.by_commit.get(c)?.iter().find(|b| !skip(b) && self.blobs.get(b).is_some_and(|r| !r.cert && r.parts == parts)).copied()
    }
}


/// Removes, shredded, the sync records of what the engine forgets (inside its transaction,
/// `retention::forget`): everything about `labels`, the blob records of `commits` and of blobs
/// holding forgotten `parts`, carriers and certificates of `commits`, hints naming `things`; adds
/// `things` to the inbox work list. Returns the blobs among those dropped and `extra` that no
/// kept entry or blob record names (their ciphertexts may go).
pub(crate) fn forget_records(tx: &mut Tx<'_>, labels: &BTreeSet<LabelId>, things: &BTreeSet<Tid>, commits: &BTreeSet<CommitId>, parts: &BTreeMap<CommitId, BTreeSet<usize>>, extra: BTreeSet<BlobId>) -> Result<BTreeSet<BlobId>> {
    let mut recs = Vec::new();
    tx.scan(b"y/", |k, v| {
        recs.push((k.to_vec(), v));
        Ok(())
    })?;
    let mut drop: Vec<Vec<u8>> = Vec::new();
    let mut freed = extra;
    let mut kept: BTreeSet<BlobId> = BTreeSet::new();
    let lab = |b: &[u8]| -> Result<bool> { Ok(labels.contains(&LabelId(Rd::new(b).arr()?))) };
    for (k, v) in recs {
        let (p, rest) = k.split_at_checked(1).ok_or(Error::Corrupt("sync record"))?;
        let gone = match p {
            b"e" | b"x" => {
                let mut r = Rd::new(rest);
                let l = LabelId(r.arr()?);
                let b = BlobId(r.arr()?);
                let gone = labels.contains(&l);
                if p == b"e" {
                    if gone {
                        freed.insert(b);
                    } else {
                        kept.insert(b);
                    }
                }
                gone
            }
            b"p" | b"c" | b"h" | b"g" | b"d" => lab(rest.get(32..).unwrap_or_default())?,
            b"t" => lab(rest)?,
            b"k" => {
                let mut r = Rd::new(rest);
                let l = LabelId(r.arr()?);
                labels.contains(&l) || commits.contains(&CommitId(r.arr()?))
            }
            b"b" => {
                let b = BlobId(Rd::new(rest).arr()?);
                let mut x = Rd::new(&v);
                let c = CommitId(x.arr()?);
                let _key: [u8; 32] = x.arr()?;
                let _cert = x.u8()?;
                let ps = decode_parts(&mut x)?;
                let gone = commits.contains(&c) || parts.get(&c).is_some_and(|s| ps.iter().any(|(ai, _)| s.contains(ai)));
                if gone {
                    freed.insert(b);
                } else {
                    kept.insert(b);
                }
                gone
            }
            b"s" => commits.contains(&CommitId(Rd::new(rest).arr()?)),
            b"o" => lab(&v)?,
            b"u" => lab(rest)?,
            b"v" => decode_sent(&v).is_ok_and(|x| commits.contains(&x.commit) || things.contains(&x.member)),
            b"i" => lab(rest)? || things.contains(&Rd::new(&v).tid()?),
            _ => false,
        };
        if gone {
            drop.push([b"y/".as_slice(), &k].concat());
        }
    }
    for k in drop {
        tx.txn.remove_local(&k, Shred::Yes)?;
    }
    for t in things {
        tx.txn.put_local(&key(FORGET, &[t.as_bytes()]), &[], Shred::No)?;
    }
    Ok(freed.difference(&kept).copied().collect())
}

fn encode_sent(x: &SentInbox) -> Vec<u8> {
    let mut w = Wr::new().raw(x.member.as_bytes()).raw(&x.commit.0).u8(u8::from(x.edge_only)).u64(x.at).u32(x.tries).u32(x.things.len() as u32);
    for t in &x.things {
        w = w.raw(t.as_bytes());
    }
    w.take()
}

fn decode_sent(v: &[u8]) -> Result<SentInbox> {
    let mut r = Rd::new(v);
    let member = r.tid()?;
    let commit = CommitId(r.arr()?);
    let edge_only = r.u8()? == 1;
    let at = r.u64()?;
    let tries = r.u32()?;
    let n = r.u32()?;
    let mut things = Vec::new();
    for _ in 0..n {
        things.push(r.tid()?);
    }
    Ok(SentInbox { member, commit, things, edge_only, at, tries })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec/sync.md §3 (re-sends are the sender's policy): an inbox delivery record that does not
    // decode is skipped, never a failed load of the sync state.
    #[test]
    fn corrupt_delivery_record_skipped_spec_sync_3() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 961, osis_core::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        e.run(|tx| {
            tx.txn.put_local(b"y/vjunk", b"not a record", Shred::No)?;
            Ok(())
        })
        .unwrap();
        let s = State::load(e).unwrap();
        assert!(s.sent_inbox.is_empty());
    }

    // spec/sync.md §5: a followed label keeps the key actor it follows for when an inbox
    // payload names the same label first (its static entry is still tried).
    #[test]
    fn inbox_hint_keeps_followed_key_actor_spec_sync_5() {
        let mut s = State::default();
        let (l, t, k) = (LabelId([1; 16]), Tid::from_bytes([2; 15]), Tid::from_bytes([3; 15]));
        s.add_hint(l, Hint { thing: t, servers: Vec::new(), via: Some(k) });
        s.add_hint(l, Hint { thing: t, servers: Vec::new(), via: None });
        assert_eq!(s.hints.get(&l).and_then(|h| h.via), Some(k));
    }
}
