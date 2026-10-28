//! The sync engine's durable state, in the engine's local records under `y/` (one write batch
//! per `SyncEngine::handle`): label entries this node knows (wrap, stamp, what the blob is),
//! presence per server, cursors and heads per (server, label), blob keys of commit blobs,
//! certificates and heartbeats placed, blobs a server tombstoned, label hints from inbox blobs,
//! inbox deliveries to re-send, stranded heartbeat times, direct commits for the app.

use crate::engine::{Engine, Tx};
use crate::engine::records::{Rd, Wr};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, LabelId, Tid};
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
/// The sharer node a followed link names, by K (`SyncEngine::follow_link_peer`).
const LINK_PEER: &[u8] = b"y/l";

/// A followed link's sharer node (spec/permissions.md §9): dialed at the link's `peer://`
/// addresses for K's labels and the target's, nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkPeer {
    pub target: Tid,
    pub peers: Vec<Address>,
}

/// What an entry's blob is, as far as this node could open it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Not opened: a chunk, tree node or page (filler wrap), a blob under an epoch not held, or
    /// a blob not fetched yet.
    Unknown,
    /// A commit blob holding these parts, with its prefix salt (a delete-key signature is made
    /// for it, spec/crypto.md §7).
    Commit { commit: CommitId, parts: Vec<(usize, usize)>, salt: [u8; 16] },
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

/// A deposit (an inbox blob, a non-writer's membership write) sealed, wrapped and signed, kept
/// until its server answers (spec/sync.md §3, §5).
#[derive(Clone, Debug)]
pub struct OutRec {
    pub label: LabelId,
    pub server: Address,
    pub blob: Vec<u8>,
    pub wrap: [u8; WRAP_LEN],
    pub sig: Signature,
}

/// A membership commit delivered by inbox to `member` (spec/sync.md §3): re-sealed and sent
/// again once `INBOX_LIFETIME` passed since `at` (corrected wall ms) unless the member acted;
/// `at` 0: not sent yet (`SyncEngine::send_inbox`).
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

/// What changed under a label since its passes last looked (`SyncEngine::spread_touches`): a
/// commit's entries, or a blob that is no commit entry (a chunk, an inbox or parked blob).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Touch {
    Commit(CommitId),
    Blob(BlobId),
}

impl Kind {
    /// The index tag of a kind other than `Commit` (`State::by_kind`).
    pub fn tag(&self) -> Option<u8> {
        match self {
            Kind::Unknown => Some(0),
            Kind::Commit { .. } => None,
            Kind::Inbox(_) => Some(2),
            Kind::Bad => Some(3),
            Kind::Parked(_) => Some(4),
        }
    }
}

#[derive(Default)]
pub struct State {
    pub entries: BTreeMap<(LabelId, BlobId), Entry>,
    /// Indexes over `entries`, kept by the setters (`index`): commit entries by (label,
    /// commit), other kinds by (label, `Kind::tag`), certificate copies, labels naming a blob.
    pub by_label_commit: BTreeMap<(LabelId, CommitId), BTreeSet<BlobId>>,
    pub by_kind: BTreeSet<(LabelId, u8, BlobId)>,
    pub cert_entries: BTreeSet<(LabelId, BlobId)>,
    pub blob_labels: BTreeSet<(BlobId, LabelId)>,
    /// `present` and `gone` by (label, blob, server).
    present_by: BTreeSet<(LabelId, BlobId, ServerKey)>,
    gone_by: BTreeSet<(LabelId, BlobId, ServerKey)>,
    /// Entries, presence and certificates changed since the passes last looked, by label; and
    /// commits whose carriers changed (any label). In memory.
    pub touched: BTreeSet<(LabelId, Touch)>,
    pub touched_commits: BTreeSet<CommitId>,
    /// Commits whose blob records were added since `SyncEngine::forget_dropped` last looked (a
    /// dropped body's blob that came back).
    pub new_blobs: BTreeSet<CommitId>,
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
    /// Sharer nodes of followed links by K (`y/l`).
    pub link_peers: BTreeMap<Tid, LinkPeer>,
    /// Bumped by every change of entries, presence or the outbox (`SyncEngine::placed` caches
    /// by it; in memory).
    pub version: u64,
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
        Kind::Commit { commit, parts, salt } => encode_parts(w.u8(6).raw(&commit.0).raw(salt), parts),
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
        6 => {
            let commit = CommitId(r.arr()?);
            let salt = r.arr()?;
            Kind::Commit { commit, parts: decode_parts(&mut r)?, salt }
        }
        // a commit entry stored before entries kept their blob's salt: opened again
        1 => Kind::Unknown,
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
                // a queued deposit that does not decode (an older format) is not sent and goes:
                // never a failed load
                b"o" => match decode_out(rest, &v) {
                    Ok((k, o)) => {
                        s.outbox.insert(k, o);
                    }
                    Err(_) => s.del([b"y/".as_slice(), &k].concat()),
                },
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
                    let k = r.tid()?;
                    let mut x = Rd::new(&v);
                    let target = x.tid()?;
                    let n = x.u32()?;
                    let mut peers = Vec::new();
                    for _ in 0..n {
                        let url = String::from_utf8(x.bytes()?.to_vec()).map_err(|_| Error::Corrupt("link peer"))?;
                        peers.push(Address { url, key: x.arr()? });
                    }
                    s.link_peers.insert(k, LinkPeer { target, peers });
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
        let all: Vec<((LabelId, BlobId), Entry)> = s.entries.iter().map(|(k, e)| (*k, e.clone())).collect();
        for ((l, b), e) in all {
            s.index(l, b, &e, true);
        }
        for (sv, l, b) in s.present.clone() {
            s.present_by.insert((l, b, sv));
        }
        for (sv, l, b) in s.gone.clone() {
            s.gone_by.insert((l, b, sv));
        }
        Ok(s)
    }

    /// Adds (or removes) an entry to (from) the indexes over `entries`.
    fn index(&mut self, l: LabelId, b: BlobId, e: &Entry, add: bool) {
        fn set<T: Ord>(s: &mut BTreeSet<T>, x: T, add: bool) {
            if add {
                s.insert(x);
            } else {
                s.remove(&x);
            }
        }
        match (&e.kind, e.kind.tag()) {
            (Kind::Commit { commit, .. }, _) => {
                let k = (l, *commit);
                if add {
                    self.by_label_commit.entry(k).or_default().insert(b);
                } else if let Some(x) = self.by_label_commit.get_mut(&k) {
                    x.remove(&b);
                    if x.is_empty() {
                        self.by_label_commit.remove(&k);
                    }
                }
            }
            (_, Some(t)) => set(&mut self.by_kind, (l, t, b), add),
            _ => {}
        }
        if e.cert {
            set(&mut self.cert_entries, (l, b), add);
        }
        set(&mut self.blob_labels, (b, l), add);
    }

    /// Notes that what is known of entry `b` under `l` changed (its passes judge it again).
    fn touch(&mut self, l: LabelId, b: BlobId) {
        let t = match self.entries.get(&(l, b)).map(|e| &e.kind) {
            Some(Kind::Commit { commit, .. }) => Touch::Commit(*commit),
            _ => Touch::Blob(b),
        };
        self.touched.insert((l, t));
    }

    /// The commit entries under `l` of commit `c`.
    pub fn entries_of<'a>(&'a self, l: &LabelId, c: &CommitId) -> impl Iterator<Item = (BlobId, &'a Entry)> + 'a {
        let l = *l;
        self.by_label_commit.get(&(l, *c)).into_iter().flatten().filter_map(move |b| self.entries.get(&(l, *b)).map(|e| (*b, e)))
    }

    /// The entries under `l` of a kind other than `Commit` (`Kind::tag`).
    pub fn of_kind(&self, l: &LabelId, tag: u8) -> Vec<BlobId> {
        self.by_kind.range((*l, tag, BlobId([0; 32]))..=(*l, tag, BlobId([0xff; 32]))).map(|(_, _, b)| *b).collect()
    }

    /// Whether any label has an entry of blob `b`.
    pub fn named(&self, b: &BlobId) -> bool {
        self.blob_labels.range((*b, LabelId([0; 16]))..=(*b, LabelId([0xff; 16]))).next().is_some()
    }

    /// The labels with an entry of blob `b`.
    pub fn labels_of(&self, b: &BlobId) -> Vec<LabelId> {
        self.blob_labels.range((*b, LabelId([0; 16]))..=(*b, LabelId([0xff; 16]))).map(|(_, l)| *l).collect()
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
        self.touch(l, b);
        if let Some(old) = self.entries.get(&(l, b)).cloned() {
            self.index(l, b, &old, false);
        }
        self.index(l, b, &e, true);
        self.entries.insert((l, b), e);
        self.touch(l, b);
        self.feed.added(l, b);
        self.version += 1;
    }

    pub fn remove_entry(&mut self, l: LabelId, b: BlobId) {
        self.touch(l, b);
        if let Some(e) = self.entries.remove(&(l, b)) {
            self.index(l, b, &e, false);
            self.version += 1;
            self.del(key(ENTRY, &[&l.0, &b.0]));
            self.feed.deleted(l, b);
            self.put(key(TOMB, &[&l.0, &b.0]), Wr::new().u64(self.now).take());
            self.tombs.insert((l, b), self.now);
        }
    }

    /// Forgets an entry that never counted (junk a server announced): no tombstone.
    pub fn drop_entry(&mut self, l: LabelId, b: BlobId) {
        self.touch(l, b);
        if let Some(e) = self.entries.remove(&(l, b)) {
            self.index(l, b, &e, false);
            self.version += 1;
            self.del(key(ENTRY, &[&l.0, &b.0]));
            self.feed.deleted(l, b);
        }
    }

    /// Forgets tombstones past their lifetime.
    pub fn expire_tombs(&mut self, now: u64) {
        let old: Vec<(LabelId, BlobId)> = self.tombs.iter().filter(|(_, t)| t.saturating_add(osis_base::format::TOMBSTONE_LIFETIME_MS) <= now).map(|(k, _)| *k).collect();
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
                self.present_by.insert((l, b, s));
                self.touch(l, b);
                self.version += 1;
                self.put(k, Vec::new());
            }
        } else if self.present.remove(&(s, l, b)) {
            self.present_by.remove(&(l, b, s));
            self.touch(l, b);
            self.version += 1;
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
            self.touch(l, b);
            self.put(key(PRESENT, &[&s, &l.0, &b.0]), if on { vec![1] } else { Vec::new() });
        }
    }

    pub fn is_present(&self, s: &ServerKey, l: &LabelId, b: &BlobId) -> bool {
        self.present.contains(&(*s, *l, *b))
    }

    /// Whether any server holds the entry.
    pub fn present_anywhere(&self, l: &LabelId, b: &BlobId) -> bool {
        self.present_by.range((*l, *b, [0; 32])..=(*l, *b, [0xff; 32])).next().is_some()
    }

    /// Entry IDs known present at a server for a label.
    pub fn present_at(&self, s: &ServerKey, l: &LabelId) -> Vec<BlobId> {
        self.present.range((*s, *l, BlobId([0; 32]))..=(*s, *l, BlobId([0xff; 32]))).map(|(_, _, b)| *b).collect()
    }

    /// Entries deposited at a server under a label.
    pub fn deposited_at(&self, s: &ServerKey, l: &LabelId) -> Vec<BlobId> {
        self.deposited.range((*s, *l, BlobId([0; 32]))..=(*s, *l, BlobId([0xff; 32]))).map(|(_, _, b)| *b).collect()
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
        self.new_blobs.insert(rec.commit);
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

    /// Records the sharer node a followed link names (its K, target and `peer://` addresses).
    pub fn set_link_peer(&mut self, k: Tid, lp: LinkPeer) {
        let mut w = Wr::new().raw(lp.target.as_bytes()).u32(lp.peers.len() as u32);
        for a in &lp.peers {
            w = w.bytes(a.url.as_bytes()).raw(&a.key);
        }
        self.put(key(LINK_PEER, &[k.as_bytes()]), w.take());
        self.link_peers.insert(k, lp);
    }

    pub fn remove_link_peer(&mut self, k: &Tid) {
        if self.link_peers.remove(k).is_some() {
            self.del(key(LINK_PEER, &[k.as_bytes()]));
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
            // the first send of a delivery queued unsent (`at` 0) is no re-send
            Some(old) if old.at == 0 => SentInbox { at, ..old.clone() },
            Some(old) => SentInbox { at, tries: old.tries.saturating_add(1), ..old.clone() },
            None => SentInbox { member, commit, things, edge_only, at, tries: 0 },
        };
        self.put(key(SENT_INBOX, &[member.as_bytes(), &commit.0]), encode_sent(&x));
        self.sent_inbox.insert((member, commit), x);
    }

    /// Records an inbox delivery not sent yet (`at` 0; `SyncEngine::send_inbox` seals and sends
    /// it once its commit is placed), unless one is recorded already.
    pub fn note_unsent(&mut self, member: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool) {
        if self.sent_inbox.contains_key(&(member, commit)) {
            return;
        }
        let x = SentInbox { member, commit, things, edge_only, at: 0, tries: 0 };
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
            self.touched.insert((l, Touch::Commit(c)));
            self.put(key(CERT, &[&l.0, &c.0]), Vec::new());
        }
    }

    pub fn set_beat(&mut self, l: LabelId, t: u64) {
        self.put(key(BEAT, &[&l.0]), Wr::new().u64(t).take());
        self.beats.insert(l, t);
    }

    pub fn set_gone(&mut self, s: ServerKey, l: LabelId, b: BlobId) {
        if self.gone.insert((s, l, b)) {
            self.gone_by.insert((l, b, s));
            self.touch(l, b);
            self.put(key(GONE, &[&s, &l.0, &b.0]), Vec::new());
        }
    }

    pub fn is_gone(&self, l: &LabelId, b: &BlobId) -> bool {
        self.gone_by.range((*l, *b, [0; 32])..=(*l, *b, [0xff; 32])).next().is_some()
    }

    /// Adds a carrier of `body` (a snapshot of one of its aspects).
    pub fn set_carrier(&mut self, body: CommitId, snapshot: CommitId) {
        self.touched_commits.insert(body);
        let list = self.carriers.entry(body).or_default();
        if !list.contains(&snapshot) {
            list.push(snapshot);
        }
        let v: Vec<u8> = list.iter().flat_map(|c| c.0).collect();
        self.put(key(CARRIER, &[&body.0]), v);
    }

    pub fn set_timed(&mut self, s: ServerKey, l: LabelId, b: BlobId) {
        if self.timed.insert((s, l, b)) {
            self.touch(l, b);
            self.put(key(TIMED, &[&s, &l.0, &b.0]), Vec::new());
        }
    }

    pub fn add_out(&mut self, o: OutRec) {
        let id = osis_label::blob_id(&o.blob);
        let v = Wr::new().raw(&o.label.0).bytes(o.server.url.as_bytes()).raw(&o.server.key).raw(&o.wrap).raw(&o.sig.0).bytes(&o.blob).take();
        self.put(key(OUTBOX, &[&o.server.key, &id.0]), v);
        self.outbox.insert((o.server.key, id), o);
        self.version += 1;
    }

    pub fn remove_out(&mut self, s: &ServerKey, b: &BlobId) {
        if self.outbox.remove(&(*s, *b)).is_some() {
            self.version += 1;
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
fn forget_records(tx: &mut Tx<'_>, labels: &BTreeSet<LabelId>, things: &BTreeSet<Tid>, commits: &BTreeSet<CommitId>, parts: &BTreeMap<CommitId, BTreeSet<usize>>, extra: BTreeSet<BlobId>) -> Result<BTreeSet<BlobId>> {
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
            // a queued deposit is sealed and signed already: forgetting does not recall it
            b"o" => false,
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

/// `State::note_unsent` inside a flow's transaction (the commit's own): a crash before
/// `SyncEngine::carry_out` loses no inbox delivery.
fn note_unsent_tx(tx: &mut Tx<'_>, member: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool) -> Result<()> {
    let k = key(SENT_INBOX, &[member.as_bytes(), &commit.0]);
    if tx.txn.get_local(&k)?.is_none() {
        let x = SentInbox { member, commit, things, edge_only, at: 0, tries: 0 };
        tx.txn.put_local(&k, &encode_sent(&x), Shred::No)?;
    }
    Ok(())
}

fn decode_out(k: &[u8], v: &[u8]) -> Result<((ServerKey, BlobId), OutRec)> {
    let mut r = Rd::new(k);
    let key = (r.arr()?, BlobId(r.arr()?));
    let mut x = Rd::new(v);
    let label = LabelId(x.arr()?);
    let url = String::from_utf8(x.bytes()?.to_vec()).map_err(|_| Error::Corrupt("outbox"))?;
    let server = Address { url, key: x.arr()? };
    let wrap = x.arr()?;
    let sig = Signature(x.arr()?);
    let blob = x.bytes()?.to_vec();
    if !x.is_empty() {
        return Err(Error::Corrupt("outbox"));
    }
    Ok((key, OutRec { label, server, blob, wrap, sig }))
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

/// The records engine transactions touch (`Engine::set_sync_records`).
pub(crate) struct Records;

impl crate::engine::SyncRecords for Records {
    fn note_unsent(&self, tx: &mut Tx<'_>, member: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool) -> Result<()> {
        note_unsent_tx(tx, member, commit, things, edge_only)
    }

    fn forget(&self, tx: &mut Tx<'_>, labels: &BTreeSet<LabelId>, things: &BTreeSet<Tid>, commits: &BTreeSet<CommitId>, parts: &BTreeMap<CommitId, BTreeSet<usize>>, extra: BTreeSet<BlobId>) -> Result<BTreeSet<BlobId>> {
        forget_records(tx, labels, things, commits, parts, extra)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec: none (local store format): a commit entry keeps its blob's salt (tag 6) and round
    // trips; one stored before (tag 1, no salt) loads as not opened, never a failed load.
    #[test]
    fn commit_entry_salt_and_older_layout() {
        let e = Entry { wrap: [3; WRAP_LEN], stamp: None, cert: false, kind: Kind::Commit { commit: CommitId([1; 32]), parts: vec![(0, 1)], salt: [9; 16] } };
        let back = decode_entry(&encode_entry(&e)).unwrap();
        assert!(matches!(back.kind, Kind::Commit { salt, .. } if salt == [9; 16]));
        let old = encode_parts(Wr::new().raw(&[3; WRAP_LEN]).u8(0).u8(0).u8(1).raw(&[1; 32]), &[(0, 1)]).take();
        assert!(matches!(decode_entry(&old).unwrap().kind, Kind::Unknown));
    }

    // spec/sync.md §3 (re-sends are the sender's policy): an inbox delivery record that does not
    // decode is skipped, never a failed load of the sync state.
    #[test]
    fn corrupt_delivery_record_skipped_spec_sync_3() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 961, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        e.run(|tx| {
            tx.txn.put_local(b"y/vjunk", b"not a record", Shred::No)?;
            Ok(())
        })
        .unwrap();
        let s = State::load(e).unwrap();
        assert!(s.sent_inbox.is_empty());
    }

    // spec/sync.md §5: a queued deposit record that does not decode (an older format) is
    // skipped, never a failed load of the sync state.
    #[test]
    fn corrupt_outbox_record_skipped_spec_sync_5() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 962, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let k = key(OUTBOX, &[&[7u8; 32], &[8u8; 32]]);
        e.run(|tx| {
            tx.txn.put_local(&k, b"short", Shred::No)?;
            Ok(())
        })
        .unwrap();
        let mut s = State::load(e).unwrap();
        assert!(s.outbox.is_empty());
        s.flush(e).unwrap();
        let left = e.run(|tx| Ok(tx.txn.scan_local(OUTBOX, &[], 8)?)).unwrap();
        assert!(left.is_empty(), "the undecodable record is deleted");
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
