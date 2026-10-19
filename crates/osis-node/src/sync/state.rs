//! The sync engine's durable state, in the engine's local records under `y/` (one write batch
//! per `SyncEngine::handle`): label entries this node knows (wrap, stamp, what the blob is),
//! presence per server, cursors and heads per (server, label), blob keys of commit blobs,
//! certificates and heartbeats placed, blobs a server tombstoned, label hints from inbox blobs.

use crate::engine::Engine;
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
const INBOX_ONLY: &[u8] = b"y/n";
const CARRIER: &[u8] = b"y/s";
const REACH: &[u8] = b"y/r";

/// What an entry's blob is, as far as this node could open it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Not opened: a chunk, tree node or page (filler wrap), a blob under an epoch not held, or
    /// a blob not fetched yet.
    Unknown,
    /// A commit blob holding these parts.
    Commit { commit: CommitId, parts: Vec<(usize, usize)> },
    /// An inbox blob this node opened.
    Inbox,
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

/// A label learned from an inbox blob before its `/label` is held.
#[derive(Clone, Debug)]
pub struct Hint {
    pub thing: Tid,
    pub servers: Vec<Address>,
}

#[derive(Default)]
pub struct State {
    pub entries: BTreeMap<(LabelId, BlobId), Entry>,
    pub present: BTreeSet<(ServerKey, LabelId, BlobId)>,
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
    /// Commits that travel by inbox only (re-seals): never placed under a label.
    pub inbox_only: BTreeSet<CommitId>,
    /// The snapshot carrying a body's live writes once it was dropped (spec/sync.md §7).
    pub carriers: BTreeMap<CommitId, CommitId>,
    /// This node's dialable transport secret (spec/sync.md §10).
    pub reach_secret: Option<Secret32>,
    /// The label logs member-peer sessions see (in memory).
    pub feed: super::serve::Feed,
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
        Kind::Inbox => w.u8(2),
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
        2 => Kind::Inbox,
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
                    s.present.insert((r.arr()?, LabelId(r.arr()?), BlobId(r.arr()?)));
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
                    s.carriers.insert(CommitId(r.arr()?), CommitId(Rd::new(&v).arr()?));
                }
                b"r" => s.reach_secret = Some(Secret32::from_bytes(Rd::new(&v).arr()?)),
                b"n" => {
                    s.inbox_only.insert(CommitId(r.arr()?));
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
                    s.hints.insert(l, Hint { thing, servers });
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
        engine.run(|tx| {
            for (k, v) in writes {
                match v {
                    // a replaced wrap or key leaves no copy behind
                    Some(v) => tx.txn.put_local(&k, &v, if k.starts_with(ENTRY) || k.starts_with(BLOB) || k.starts_with(REACH) { Shred::Yes } else { Shred::No })?,
                    None => {
                        tx.txn.remove_local(&k, Shred::Yes)?;
                    }
                }
            }
            Ok(())
        })
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
            self.del(k);
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

    pub fn set_carrier(&mut self, body: CommitId, snapshot: CommitId) {
        self.put(key(CARRIER, &[&body.0]), snapshot.0.to_vec());
        self.carriers.insert(body, snapshot);
    }

    pub fn set_inbox_only(&mut self, c: CommitId) {
        if self.inbox_only.insert(c) {
            self.put(key(INBOX_ONLY, &[&c.0]), Vec::new());
        }
    }

    pub fn set_timed(&mut self, s: ServerKey, l: LabelId, b: BlobId) {
        if self.timed.insert((s, l, b)) {
            self.put(key(TIMED, &[&s, &l.0, &b.0]), Vec::new());
        }
    }

    pub fn add_hint(&mut self, l: LabelId, h: Hint) {
        let mut w = Wr::new().raw(h.thing.as_bytes()).u32(h.servers.len() as u32);
        for a in &h.servers {
            w = w.bytes(a.url.as_bytes()).raw(&a.key);
        }
        self.put(key(HINT, &[&l.0]), w.take());
        self.hints.insert(l, h);
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

