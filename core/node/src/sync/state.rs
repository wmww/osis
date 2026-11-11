//! The sync engine's durable state, in the engine's local records under `y/` (one write batch
//! per `SyncEngine::handle`): label entries this node knows (wrap, stamp, what the blob is),
//! presence per host, cursors and heads per (host, label), blob keys of commit blobs,
//! certificates placed, blobs a host tombstoned, label hints from inbox blobs, inbox
//! deliveries to re-send, direct commits for the app, flows'
//! deliveries owed (`y/y`).

use crate::engine::{Engine, Tx};
use crate::engine::records::{Rd, Wr};
use crate::error::{Error, Result};
use crate::flows::Delivery;
use osis_base::{BlobId, CommitId, LabelId, Tid};
use osis_crypto::{Secret32, Signature, WRAP_LEN};
use osis_label::{Address, Step};
use osis_proto::Cursor;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// A host, by its static key (its address key).
pub type HostKey = [u8; 32];

const ENTRY: &[u8] = b"y/e";
const PRESENT: &[u8] = b"y/p";
const CURSOR: &[u8] = b"y/c";
/// A (host, label) whose first sync has not ended (`fill`).
const FILLING: &[u8] = b"y/4";
const HEAD: &[u8] = b"y/h";
const BLOB: &[u8] = b"y/b";
const CERT: &[u8] = b"y/k";
/// Thing lists placed: label, rotation, thing (`State::listed`).
const LISTED: &[u8] = b"y/L";
const GONE: &[u8] = b"y/g";
const DOUBT: &[u8] = b"y/3";
const HINT: &[u8] = b"y/i";
const CARRIER: &[u8] = b"y/s";
const REACH: &[u8] = b"y/r";
/// Which run of hosting this is (`HostConfig::store_id`), while the node hosts.
const HOST_STORE: &[u8] = b"y/z";
const TOMB: &[u8] = b"y/x";
const OUTBOX: &[u8] = b"y/o";
/// Things forgotten whose inbox blobs this node has not checked yet (`SyncEngine::forget_inbox`).
const FORGET: &[u8] = b"y/f";
/// Replaced labels this admin is done with (`SyncEngine::retire_at`).
const RETIRED: &[u8] = b"y/q";
/// Inbox deliveries re-sent after `INBOX_LIFETIME` while unanswered (`SyncEngine::resend_inbox`).
const SENT_INBOX: &[u8] = b"y/v";
/// Commits for a node over a direct connection, until the app takes them (`take_direct`).
const DIRECT: &[u8] = b"y/j";
/// Persons marked as contacts (`SyncEngine::set_contact`).
const CONTACT: &[u8] = b"y/a";
/// The sharer node a followed link names, by K (`SyncEngine::follow_link_peer`).
const LINK_PEER: &[u8] = b"y/l";
/// Commits of invite requests the user declined (`SyncEngine::decline_invite`).
const DECLINED: &[u8] = b"y/m";
/// Groups handed off to another node (`SyncEngine::set_handed_off`).
const HANDED_OFF: &[u8] = b"y/w";
/// Labels a pass finished at once, or that this node made (`note_passed`).
const PASSED: &[u8] = b"y/B";
/// A flow's delivery (not an inbox blob) not carried out yet, by the hash of its encoding
/// (`owe_tx`, `SyncEngine::take_done`).
const OWED: &[u8] = b"y/y";
/// Own entries a co-reader source reported holding (`State::applied`).
const APPLIED: &[u8] = b"y/A";

/// A followed link's sharer node (spec/permissions.md §7): dialed at the link's `peer://`
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
    /// A commit blob: the parts this node opened and the aspects every section of it lists
    /// (sealed ones included: its prefix groups and delete signatures follow them, spec/wire.md
    /// §5).
    Commit { commit: CommitId, parts: Vec<usize>, ais: Vec<usize> },
    /// A commit this node opened and could not judge: nothing of it is kept but the record of what
    /// it awaits (the actor or thing named by the wait), to fetch it again when that arrives
    /// (notes/expiry-creation-design.md §3).
    Awaits { commit: CommitId, thing: Tid },
    /// An inbox blob this node opened, with the commit it carried (`None`: opened by an older
    /// build).
    Inbox(Option<CommitId>),
    /// An opened inbox blob not admitted (spec/sync.md §3, invite requests): its commit is not
    /// applied and nothing it names is followed until the user accepts or it is admitted.
    Request(CommitId),
    /// Unwraps under a held secret but is no valid commit blob (spec/versioning.md §2: bad
    /// input): never retried, never judged.
    Bad,
    /// A commit this build cannot interpret, held parked (spec/versioning.md §2): relayed,
    /// never judged.
    Parked(CommitId),
    /// A list blob of rotation `rotation`'s thing lists (spec/sync.md §3): `held` once the engine
    /// holds them (`Engine::hold_lists`), else it awaits the rotation and is held again once that
    /// is here.
    List { rotation: CommitId, held: bool },
    /// A record blob (spec/wire.md §3): the raw creation records it carries, by tid, ascending.
    Records(Vec<Tid>),
}

/// A node log event waiting for the flush that writes its effect.
#[derive(Clone, Copy, Debug)]
enum LogWrite {
    Added(LabelId, BlobId),
    Deleted(LabelId, BlobId, u64),
    Head(LabelId, [u8; 32]),
}

/// A tombstone (`State::tombs`): when (wall ms) and what the entry was.
#[derive(Clone, Debug)]
pub struct Tomb {
    pub at: u64,
    pub wrap: [u8; WRAP_LEN],
    pub cert: bool,
    pub salt: Option<[u8; 16]>,
    pub kind: Kind,
}

/// A label entry as this node knows it (spec/sync.md §4).
#[derive(Clone, Debug)]
pub struct Entry {
    pub wrap: [u8; WRAP_LEN],
    pub stamp: Option<Signature>,
    /// Placed by this node as a certificate blob (spec/sync.md §3).
    pub cert: bool,
    /// The blob's prefix salt, once its bytes were here (spec/sync.md §6 Tombstones): a
    /// delete-key signature is made for it (spec/crypto.md §7), so it outlives the bytes.
    pub salt: Option<[u8; 16]>,
    pub kind: Kind,
    /// An ephemeral blob (its prefix class, spec/sync.md §9): the entry and everything recorded
    /// about it (presence, blob record, tombstone) live in memory only, never in the sync
    /// records, and go with a restart.
    pub memory: bool,
}

impl Entry {
    /// Its wrap went with a dropped body's bytes (`SyncEngine::forget_blob`).
    pub fn shredded(&self) -> bool {
        self.wrap == [0; WRAP_LEN]
    }

    /// Not opened, though it opens under one of `secrets` (a shredded one: the fetch brings
    /// its wrap back).
    pub fn unopened(&self, b: &BlobId, secrets: &[Secret32]) -> bool {
        self.kind == Kind::Unknown && (self.shredded() || osis_label::unwrap_any(secrets, b, &self.wrap).is_some())
    }
}

/// A commit blob this node holds the key of (received, or sealed here).
#[derive(Clone)]
pub struct BlobRec {
    pub commit: CommitId,
    /// The parts this node opened.
    pub parts: Vec<usize>,
    /// The aspects every section lists (`Kind::Commit`).
    pub ais: Vec<usize>,
    pub key: Secret32,
    /// A certificate encryption (never shared with another label).
    pub cert: bool,
    /// A memory commit's blob (`Entry::memory`): the record lives in memory only.
    pub memory: bool,
}

/// A body under a label: (label, commit, its parts by aspect index, sorted).
pub type DeletedBody = (LabelId, CommitId, Vec<usize>);

/// Where a queued deposit goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dest {
    /// A host of its label, until that host takes it.
    Host(Address),
    /// The nodes of inbox actor `0` (an inbox listing no host): a Deposit item to a connected
    /// node judged a holder of the inbox (spec/sync.md §10 Shared set), until one takes it.
    Nodes(Tid),
}

/// The outbox key of `Dest::Nodes`: no host has it (an Ed25519 key of all zeros).
pub const INBOX_NODES: HostKey = [0; 32];

impl Dest {
    /// Its outbox key.
    pub fn key(&self) -> HostKey {
        match self {
            Dest::Host(a) => a.key,
            Dest::Nodes(_) => INBOX_NODES,
        }
    }
}

/// A deposit (an inbox blob, a non-writer's role write) sealed, wrapped and signed, kept
/// until where it goes takes it (spec/sync.md §3, §5, §10).
#[derive(Clone, Debug)]
pub struct OutRec {
    pub label: LabelId,
    pub to: Dest,
    pub blob: Vec<u8>,
    pub wrap: [u8; WRAP_LEN],
    pub sig: Signature,
    /// The inbox delivery (`State::sent_inbox` key) this blob is a seal of: dropped when that
    /// delivery is forgotten or sealed again.
    pub delivery: Option<(Tid, CommitId)>,
}

/// A role commit delivered by inbox to `holder` (spec/sync.md §3): re-sealed and sent
/// again once `INBOX_LIFETIME` passed since `at` (wall ms) unless the holder acted;
/// `at` 0: not sent yet (`SyncEngine::send_inbox`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentInbox {
    pub holder: Tid,
    pub commit: CommitId,
    pub things: Vec<Tid>,
    /// Only the `roles.0` parts went (a removal).
    pub edge_only: bool,
    pub at: u64,
    /// Re-sends so far.
    pub tries: u32,
}

impl SentInbox {
    /// Not sealed and queued yet (a queued seal counts in the outbox until taken).
    pub fn unsent(&self) -> bool {
        self.at == 0
    }
}

/// A label learned from an inbox blob before its `label.0` is held, or followed by a held key
/// actor's static entry (`via`: a link's label).
#[derive(Clone, Debug)]
pub struct Hint {
    pub thing: Tid,
    /// The label's index (its role keys derive from it, spec/sync.md §2).
    pub index: u64,
    pub hosts: Vec<Address>,
    /// The key actor whose static entry may open it; no other key actor's is presented.
    pub via: Option<Tid>,
    /// The inbox entry it came from (`SyncEngine::vet_inbox_hints`): a hint with no `via` goes
    /// with that entry, at its expiry, or when its commit is judged invalid.
    pub inbox: Option<InboxSource>,
}

/// An opened inbox entry a hint came from, with the inbox blob's prefix expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboxSource {
    pub label: LabelId,
    pub blob: BlobId,
    pub until: u64,
}

/// What changed under a label since its passes last looked (`SyncEngine::spread_touches`): a
/// commit's entries, or a blob that is no commit entry (a chunk, an inbox or parked blob).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Touch {
    Commit(CommitId),
    Blob(BlobId),
}

impl Kind {
    pub const TAG_UNKNOWN: u8 = 0;
    pub const TAG_INBOX: u8 = 2;
    pub const TAG_BAD: u8 = 3;
    pub const TAG_PARKED: u8 = 4;
    pub const TAG_REQUEST: u8 = 5;
    pub const TAG_AWAITS: u8 = 6;
    pub const TAG_LIST: u8 = 7;
    pub const TAG_LIST_AWAITS: u8 = 8;
    pub const TAG_RECORDS: u8 = 9;

    /// The index tag of a kind other than `Commit` (`State::by_kind`).
    pub fn tag(&self) -> Option<u8> {
        match self {
            Kind::Unknown => Some(Kind::TAG_UNKNOWN),
            Kind::Commit { .. } => None,
            Kind::Awaits { .. } => Some(Kind::TAG_AWAITS),
            Kind::Inbox(_) => Some(Kind::TAG_INBOX),
            Kind::Bad => Some(Kind::TAG_BAD),
            Kind::Parked(_) => Some(Kind::TAG_PARKED),
            Kind::Request(_) => Some(Kind::TAG_REQUEST),
            Kind::List { held: true, .. } => Some(Kind::TAG_LIST),
            Kind::List { held: false, .. } => Some(Kind::TAG_LIST_AWAITS),
            Kind::Records(_) => Some(Kind::TAG_RECORDS),
        }
    }
}

/// A dropped body's carriers (`State::carriers`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carriers {
    pub by: Vec<CommitId>,
    /// Wall ms of the last change.
    pub at: u64,
    /// Of a memory commit (`State::memory_commits` when set): never stored, kept for a memory
    /// tombstone's lifetime.
    pub memory: bool,
}

#[derive(Clone, Default)]
pub struct State {
    pub entries: BTreeMap<(LabelId, BlobId), Entry>,
    /// Indexes over `entries`, kept by the setters (`index`): commit entries by (label,
    /// commit), other kinds by (label, `Kind::tag`), certificate copies, labels naming a blob.
    pub by_label_commit: BTreeMap<(LabelId, CommitId), BTreeSet<BlobId>>,
    /// Inbox entries with a stamp, by the commit they carry.
    pub stamped_inbox: BTreeSet<(LabelId, CommitId, BlobId)>,
    pub commit_labels: BTreeSet<(CommitId, LabelId)>,
    pub by_kind: BTreeSet<(LabelId, u8, BlobId)>,
    pub by_tag: BTreeSet<(u8, LabelId, BlobId)>,
    pub cert_entries: BTreeSet<(LabelId, BlobId)>,
    pub blob_labels: BTreeSet<(BlobId, LabelId)>,
    /// `present` and `gone` by (label, blob, host).
    present_by: BTreeSet<(LabelId, BlobId, HostKey)>,
    gone_by: BTreeSet<(LabelId, BlobId, HostKey)>,
    /// Entries, presence and certificates changed since the passes last looked, by label; and
    /// commits whose carriers changed (any label). In memory.
    pub touched: BTreeSet<(LabelId, Touch)>,
    pub touched_commits: BTreeSet<CommitId>,
    /// Commits whose blob records were added since `SyncEngine::forget_dropped` last looked (a
    /// dropped body's blob that came back).
    pub new_blobs: BTreeSet<CommitId>,
    pub present: BTreeSet<(HostKey, LabelId, BlobId)>,
    /// Present entries the host holds deposited (no stamp there; spec/sync.md §5): a writer
    /// promotes them at that host, whatever stamp this node knows.
    pub deposited: BTreeSet<(HostKey, LabelId, BlobId)>,
    /// Own entries a co-reader source (`SyncEngine::pass_source`) reported holding: its
    /// Applied position at or past where the node log first held them (spec/sync.md §5
    /// Placed). Recorded only for commits `placed` waits on (`SyncEngine::note_applied`), kept
    /// only while it waits.
    pub applied: BTreeSet<(LabelId, BlobId, Tid)>,
    pub cursors: BTreeMap<(HostKey, LabelId), Cursor>,
    /// `FILLING`.
    pub filling: BTreeSet<(HostKey, LabelId)>,
    pub heads: BTreeMap<(HostKey, LabelId), Step>,
    pub blobs: BTreeMap<BlobId, BlobRec>,
    pub by_commit: BTreeMap<CommitId, BTreeSet<BlobId>>,
    /// How many inbox or request entries carry each commit.
    pub inbox_commits: BTreeMap<CommitId, usize>,
    /// How many held entries carry each commit (notes/node-sync.md, Unjudged input): label
    /// entries naming it (`Commit`, `Parked`, `Awaits`), inbox entries carrying it as their
    /// commit (`Inbox`, `Request`) or in their author's chain (`inbox_chain`), and stranded
    /// reports (`reported`).
    pub carried: BTreeMap<CommitId, usize>,
    /// Commits whose last carrying entry left, not swept yet (`SyncEngine::sweep_pending`).
    pub uncarried: BTreeSet<CommitId>,
    /// The chain commits each opened inbox entry carries, in memory: noted when its payload is
    /// ingested (every inbox entry is retried at a start, which notes them again).
    pub inbox_chain: BTreeMap<(LabelId, BlobId), Vec<CommitId>>,
    /// The keys commits the newest stranded report on a label carries for each holder it names
    /// (spec/permissions.md §4), in memory: a report has no entry to carry them, and is the only
    /// route of a node connected to a writer. One per (label, holder), dropped at the next report
    /// once the holder is no current holder of a label synced (`SyncEngine::stranded_report`).
    pub reported: BTreeMap<(LabelId, Tid), Vec<CommitId>>,
    /// Entries a wake reopened (`Kind::Unknown` again) and the commit each was awaiting for: its
    /// reading-only secrets stay until the entry is judged again or leaves (`SyncEngine::sweep_unchecked`).
    pub awaits_reopened: BTreeMap<(LabelId, BlobId), CommitId>,
    /// Commits whose last `Kind::Awaits` entry changed kind or left, not told the engine yet.
    pub awaits_left: Vec<CommitId>,
    /// `Kind::Awaits` entries by what they await and by commit.
    pub by_awaited: BTreeMap<Tid, BTreeSet<(LabelId, BlobId)>>,
    pub awaits_by_commit: BTreeMap<CommitId, BTreeSet<(LabelId, BlobId)>>,
    pub certs: BTreeSet<(LabelId, CommitId)>,
    /// The thing lists this node placed under a label: (label, rotation, thing).
    pub listed: BTreeSet<(LabelId, CommitId, Tid)>,
    /// Blob IDs of no use at a host, by when (wall ms): uploads it refused as
    /// tombstoned, and entries it holds under a wrap not opening to the blob's key (a stamped
    /// entry's wrap never changes there, spec/sync.md §5). Forgotten after `TOMBSTONE_LIFETIME`,
    /// when the host's tombstone is gone too; not while the host still holds the entry.
    pub gone: BTreeMap<(HostKey, LabelId, BlobId), u64>,
    /// The wraps behind those of `gone` that opened under no read secret when heard, while the host
    /// holds the entry: possibly under an epoch not held yet (`SyncEngine::recheck_doubts`).
    pub doubts: BTreeMap<(HostKey, LabelId, BlobId), [u8; WRAP_LEN]>,
    /// `SyncEngine::secrets_count` when `doubts` were last checked. In memory.
    pub doubts_at: usize,
    pub hints: BTreeMap<LabelId, Hint>,
    /// The snapshots carrying a body's live writes once it was dropped, one per aspect at most
    /// (spec/sync.md §7), with when they were last set (`sweep_carriers`).
    pub carriers: BTreeMap<CommitId, Carriers>,
    /// This node's dialable transport secret (spec/sync.md §10).
    pub reach_secret: Option<Secret32>,
    /// Which run of hosting this is, while it hosts (`HostConfig::store_id`).
    pub host_store: Option<[u8; 32]>,
    /// The node log's memory part: memory entries' events, which the durable log never holds.
    pub mem_log: super::stream::MemLog,
    /// Entries this node dropped (`remove_entry`): refused from peers for `TOMBSTONE_LIFETIME`
    /// (spec/sync.md §5), so a peer cannot replay a deleted body, with what the entry was: a host
    /// reporting it within that time (one an upload reached, its answer lost or late) gets it
    /// recorded again as present there without a fetch, so the pass judges it there as any
    /// (`SyncEngine::host_holds`).
    pub tombs: BTreeMap<(LabelId, BlobId), Tomb>,
    /// Bodies (commit and delta set) whose entry (not a certificate copy) left a label by a
    /// delete, by when (`remove_entry`): such a body (or one it is a purge rewrite of,
    /// `body_deleted`) is not placed there again while its live writes are carried (spec/sync.md
    /// §6). In memory, from `tombs` at load where the blob's record is known;
    /// forgotten with the tombstone (`TOMBSTONE_LIFETIME`, minor consequence: at 0 a right
    /// holder whose bounds are dated later re-uploads it every pass until its own bound, at
    /// infinity memory grows with deletions; live writes are carried either way).
    pub deleted: BTreeMap<DeletedBody, u64>,
    /// Commits to look at for forgetting (`forget_own_covered`): one's last part dropped, entry
    /// gone or tombstone expired.
    pub forget_due: BTreeSet<CommitId>,
    /// Commits with a row in `deleted`, and how many.
    pub deleted_commits: BTreeMap<CommitId, usize>,
    /// Inbox blobs not yet answered by their host, by (host, blob).
    pub outbox: BTreeMap<(HostKey, LabelId, BlobId), OutRec>,
    /// Wall ms of the running `handle` (tombstone times).
    pub now: u64,
    /// Things forgotten whose opened inbox blobs are not yet checked (`y/f`).
    pub forget: BTreeSet<Tid>,
    /// Replaced labels this admin no longer syncs (`y/q`, spec/sync.md §2).
    pub retired: crate::engine::memo::StampedSet<LabelId>,
    /// When this admin first saw each replaced label it still syncs (wall ms, `y/q`
    /// with a time): retired after `ROLE_KEEP` whatever its hosts say.
    pub replaced_seen: BTreeMap<LabelId, u64>,
    /// Inbox deliveries by (holder, commit), until the holder acts or the re-sends run out.
    pub sent_inbox: BTreeMap<(Tid, CommitId), SentInbox>,
    /// Commits for nodes over a direct connection (pairing), until the app takes them.
    pub direct: BTreeMap<Tid, Vec<CommitId>>,
    /// Groups handed off to another node (`y/w`).
    pub handed_off: crate::engine::memo::StampedSet<Tid>,
    /// Labels with no first download outstanding: a pass finished once, or this node made them
    /// (`y/B`). History `complete` reads it, so it outlives the run.
    pub passed: BTreeSet<LabelId>,
    /// Persons marked as contacts (`y/a`).
    pub contacts: BTreeSet<Tid>,
    /// Commits of declined invite requests (`y/m`).
    pub declined: BTreeSet<CommitId>,
    /// Sharer nodes of followed links by K (`y/l`).
    pub link_peers: BTreeMap<Tid, LinkPeer>,
    /// Flows' deliveries owed at load (`y/y`), by key (`owed_key`): taken at start.
    pub owed: BTreeMap<[u8; 32], Delivery>,
    /// Bumped by every change of entries, presence or the outbox (`SyncEngine::placed` caches
    /// by it; in memory).
    pub version: u64,
    /// Entries and hosts' copies gone so far, in memory (`InboxCopied`).
    pub losses: u64,
    /// Memory-class entries (`Entry::memory`) and the memory commits they are of: nothing
    /// recorded about them is written (`put`, `del` skip them).
    pub memory_entries: BTreeSet<(LabelId, BlobId)>,
    pub memory_commits: BTreeSet<CommitId>,
    /// What each memory entry held from another node is charged against its label's node cap
    /// (`SyncConfig::ephemeral_bytes`; `Engine::memory_charge`, at least its bytes) and the sum
    /// per label; the same for entries whose commit waits unverified (the pending share).
    pub memory_charge: BTreeMap<(LabelId, BlobId), u64>,
    pub memory_bytes: BTreeMap<LabelId, u64>,
    /// Encoded size of each memory entry's blob while held here (tests, diagnostics).
    pub memory_sizes: BTreeMap<(LabelId, BlobId), usize>,
    /// Memory entries judged or placed while their body was in the label's closure here: only
    /// those are deleted for leaving it (`pass/delete`, spec/sync.md §9).
    pub memory_in_closure: BTreeSet<(LabelId, BlobId)>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Node log events of those writes, in order: they go in the same transaction.
    log: Vec<LogWrite>,
    /// The head last logged per label, so an unchanged head costs no transaction.
    logged_heads: BTreeMap<LabelId, [u8; 32]>,
    /// Whether the next flush sweeps old deletion events from the node log.
    pub log_sweep_due: bool,
    /// A hint came or went (`SyncEngine::stamp_changes`).
    pub hints_moved: bool,
}

fn key(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    for p in parts {
        k.extend_from_slice(p);
    }
    k
}

fn encode_ais(w: Wr, ais: &[usize]) -> Wr {
    let mut w = w.u32(ais.len() as u32);
    for a in ais {
        w = w.u32(*a as u32);
    }
    w
}

fn decode_ais(r: &mut Rd<'_>) -> Result<Vec<usize>> {
    let n = r.u32()?;
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(r.u32()? as usize);
    }
    Ok(v)
}

/// Whether a blob record has a section this node did not open (an aspect listed by no opened
/// part).
pub fn sealed(ais: &[usize], parts: &[usize]) -> bool {
    ais.iter().any(|a| !parts.contains(a))
}

fn encode_addrs(w: Wr, addrs: &[Address]) -> Wr {
    let mut w = w.u32(addrs.len() as u32);
    for a in addrs {
        w = w.bytes(a.url.as_bytes()).raw(&a.key);
    }
    w
}

fn decode_addrs(r: &mut Rd<'_>, what: &'static str) -> Result<Vec<Address>> {
    let n = r.u32()?;
    let mut v = Vec::new();
    for _ in 0..n {
        let url = String::from_utf8(r.bytes()?.to_vec()).map_err(|_| Error::Corrupt(what))?;
        v.push(Address { url, key: r.arr()? });
    }
    Ok(v)
}

fn encode_commits(list: &[CommitId]) -> Vec<u8> {
    list.iter().flat_map(|c| c.0).collect()
}

fn decode_commits(v: &[u8]) -> Result<Vec<CommitId>> {
    let mut x = Rd::new(v);
    let mut list = Vec::new();
    while !x.is_empty() {
        list.push(CommitId(x.arr()?));
    }
    Ok(list)
}

fn encode_entry(e: &Entry) -> Vec<u8> {
    let mut w = Wr::new().raw(&e.wrap).u8(u8::from(e.cert));
    w = match &e.stamp {
        Some(s) => w.u8(1).raw(&s.0),
        None => w.u8(0),
    };
    encode_kind(encode_salt(w, &e.salt), &e.kind).take()
}

fn encode_kind(w: Wr, kind: &Kind) -> Wr {
    match kind {
        Kind::Unknown => w.u8(0),
        Kind::Commit { commit, parts, ais } => encode_ais(encode_ais(w.u8(6).raw(&commit.0), parts), ais),
        Kind::Inbox(None) => w.u8(2),
        Kind::Inbox(Some(c)) => w.u8(5).raw(&c.0),
        Kind::Bad => w.u8(3),
        Kind::Parked(c) => w.u8(4).raw(&c.0),
        Kind::Request(c) => w.u8(7).raw(&c.0),
        Kind::Awaits { commit, thing } => w.u8(8).raw(&commit.0).raw(thing.as_bytes()),
        Kind::List { rotation, held } => w.u8(9).raw(&rotation.0).u8(u8::from(*held)),
        Kind::Records(ts) => {
            let mut w = w.u8(10).u32(ts.len() as u32);
            for t in ts {
                w = w.raw(t.as_bytes());
            }
            w
        }
    }
}

fn decode_entry(b: &[u8]) -> Result<Entry> {
    let mut r = Rd::new(b);
    let wrap = r.arr()?;
    let cert = r.u8()? == 1;
    let stamp = match r.u8()? {
        1 => Some(Signature(r.arr()?)),
        _ => None,
    };
    let salt = decode_salt(&mut r)?;
    Ok(Entry { wrap, stamp, cert, salt, kind: decode_kind(&mut r)?, memory: false })
}

fn encode_salt(w: Wr, salt: &Option<[u8; 16]>) -> Wr {
    match salt {
        Some(s) => w.u8(1).raw(s),
        None => w.u8(0),
    }
}

fn decode_salt(r: &mut Rd) -> Result<Option<[u8; 16]>> {
    Ok(match r.u8()? {
        1 => Some(r.arr()?),
        _ => None,
    })
}

fn decode_kind(r: &mut Rd) -> Result<Kind> {
    Ok(match r.u8()? {
        6 => {
            let commit = CommitId(r.arr()?);
            let parts = decode_ais(r)?;
            Kind::Commit { commit, parts, ais: decode_ais(r)? }
        }
        0 => Kind::Unknown,
        2 => Kind::Inbox(None),
        5 => Kind::Inbox(Some(CommitId(r.arr()?))),
        3 => Kind::Bad,
        4 => Kind::Parked(CommitId(r.arr()?)),
        7 => Kind::Request(CommitId(r.arr()?)),
        8 => Kind::Awaits { commit: CommitId(r.arr()?), thing: Tid::from_bytes(r.arr()?) },
        9 => Kind::List { rotation: CommitId(r.arr()?), held: r.u8()? == 1 },
        10 => {
            let n = r.u32()?;
            let mut ts = Vec::new();
            for _ in 0..n {
                ts.push(Tid::from_bytes(r.arr()?));
            }
            Kind::Records(ts)
        }
        _ => return Err(Error::Corrupt("sync entry kind")),
    })
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
        let logged_heads = engine.run(|tx| Ok(tx.txn.log_heads()?))?.into_iter().collect();
        let mut s = State { logged_heads, ..State::default() };
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
                b"A" => {
                    s.applied.insert((LabelId(r.arr()?), BlobId(r.arr()?), r.tid()?));
                }
                b"4" => {
                    let k: (HostKey, LabelId) = (r.arr()?, LabelId(r.arr()?));
                    s.filling.insert(k);
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
                    let parts = decode_ais(&mut x)?;
                    let ais = decode_ais(&mut x)?;
                    s.by_commit.entry(commit).or_default().insert(id);
                    s.blobs.insert(id, BlobRec { commit, parts, ais, key, cert, memory: false });
                }
                b"k" => {
                    s.certs.insert((LabelId(r.arr()?), CommitId(r.arr()?)));
                }
                b"L" => {
                    s.listed.insert((LabelId(r.arr()?), CommitId(r.arr()?), Tid::from_bytes(r.arr()?)));
                }
                b"g" => {
                    s.gone.insert((r.arr()?, LabelId(r.arr()?), BlobId(r.arr()?)), Rd::new(&v).u64()?);
                }
                b"3" => {
                    s.doubts.insert((r.arr()?, LabelId(r.arr()?), BlobId(r.arr()?)), Rd::new(&v).arr()?);
                }
                b"s" => {
                    let at = Rd::new(&v).u64()?;
                    s.carriers.insert(CommitId(r.arr()?), Carriers { by: decode_commits(v.get(8..).unwrap_or_default())?, at, memory: false });
                }
                b"x" => {
                    let k = (LabelId(r.arr()?), BlobId(r.arr()?));
                    let mut x = Rd::new(&v);
                    let at = x.u64()?;
                    let wrap = x.arr()?;
                    let cert = x.u8()? == 1;
                    let salt = decode_salt(&mut x)?;
                    s.tombs.insert(k, Tomb { at, wrap, cert, salt, kind: decode_kind(&mut x)? });
                }
                b"r" => s.reach_secret = Some(Secret32::from_bytes(Rd::new(&v).arr()?)),
                b"z" => s.host_store = Some(Rd::new(&v).arr()?),
                b"o" => {
                    // not rebuildable: a record that does not decode fails the load, named
                    let (k, o) = decode_out(rest, &v).map_err(|_| Error::Corrupt("sync outbox record"))?;
                    s.outbox.insert(k, o);
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
                        s.sent_inbox.insert((x.holder, x.commit), x);
                    }
                }
                b"j" => {
                    s.direct.insert(r.tid()?, decode_commits(&v)?);
                }
                b"w" => {
                    s.handed_off.insert(r.tid()?);
                }
                b"B" => {
                    s.passed.insert(LabelId(r.arr()?));
                }
                // one that does not decode is skipped, never a failed load
                b"y" => {
                    if let Ok(d) = decode_owed(&v) {
                        s.owed.insert(r.arr()?, d);
                    }
                }
                b"a" => {
                    s.contacts.insert(r.tid()?);
                }
                b"m" => {
                    s.declined.insert(CommitId(r.arr()?));
                }
                b"l" => {
                    let k = r.tid()?;
                    let mut x = Rd::new(&v);
                    let target = x.tid()?;
                    let peers = decode_addrs(&mut x, "link peer")?;
                    s.link_peers.insert(k, LinkPeer { target, peers });
                }
                b"i" => {
                    let l = LabelId(r.arr()?);
                    let mut x = Rd::new(&v);
                    let thing = x.tid()?;
                    let index = x.u64()?;
                    let hosts = decode_addrs(&mut x, "hint")?;
                    let flags = x.u8()?;
                    let via = if flags & 1 != 0 { Some(x.tid()?) } else { None };
                    let inbox = if flags & 2 != 0 { Some(InboxSource { label: LabelId(x.arr()?), blob: BlobId(x.arr()?), until: x.u64()? }) } else { None };
                    s.hints.insert(l, Hint { thing, index, hosts, via, inbox });
                }
                _ => {}
            }
        }
        let entries = std::mem::take(&mut s.entries);
        for ((l, b), e) in &entries {
            s.index(*l, *b, e, true);
        }
        s.entries = entries;
        s.present_by = s.present.iter().map(|(host, l, b)| (*l, *b, *host)).collect();
        s.gone_by = s.gone.keys().map(|(host, l, b)| (*l, *b, *host)).collect();
        s.deleted = s.tombs.iter().filter_map(|(k, t)| match &t.kind {
            Kind::Commit { commit, parts, .. } if !t.cert => Some(((k.0, *commit, parts.clone()), t.at.saturating_add(osis_base::format::TOMBSTONE_LIFETIME_MS))),
            _ => None,
        }).collect();
        for (_, c, _) in s.deleted.keys() {
            *s.deleted_commits.entry(*c).or_default() += 1;
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
                    self.commit_labels.insert((*commit, l));
                } else if let Some(x) = self.by_label_commit.get_mut(&k) {
                    x.remove(&b);
                    if x.is_empty() {
                        self.by_label_commit.remove(&k);
                        self.commit_labels.remove(&(*commit, l));
                        self.forget_due.insert(*commit);
                    }
                }
            }
            (_, Some(t)) => {
                set(&mut self.by_kind, (l, t, b), add);
                set(&mut self.by_tag, (t, l, b), add);
            }
            _ => {}
        }
        if let Kind::Awaits { commit, thing } = &e.kind {
            fn by<K: Ord>(m: &mut BTreeMap<K, BTreeSet<(LabelId, BlobId)>>, k: K, v: (LabelId, BlobId), add: bool) {
                if add {
                    m.entry(k).or_default().insert(v);
                } else if let Some(s) = m.get_mut(&k) {
                    s.remove(&v);
                    if s.is_empty() {
                        m.remove(&k);
                    }
                }
            }
            by(&mut self.by_awaited, *thing, (l, b), add);
            by(&mut self.awaits_by_commit, *commit, (l, b), add);
            if !add && !self.awaits_by_commit.contains_key(commit) {
                self.awaits_left.push(*commit);
            }
        }
        // judged again or gone: the reopened entry stops holding its commit's reading-only secrets
        if add && !matches!(e.kind, Kind::Unknown) {
            self.awaits_reopened.remove(&(l, b));
        }
        if let Kind::Inbox(Some(c)) | Kind::Request(c) = &e.kind {
            let n = self.inbox_commits.entry(*c).or_default();
            *n = if add { n.saturating_add(1) } else { n.saturating_sub(1) };
            if *n == 0 {
                self.inbox_commits.remove(c);
            }
        }
        if let (Kind::Inbox(Some(c)), Some(_)) = (&e.kind, &e.stamp) {
            set(&mut self.stamped_inbox, (l, *c, b), add);
        }
        if let Kind::Commit { commit: c, .. } | Kind::Parked(c) | Kind::Awaits { commit: c, .. } | Kind::Inbox(Some(c)) | Kind::Request(c) = &e.kind {
            self.carry(*c, add);
        }
        if e.cert {
            set(&mut self.cert_entries, (l, b), add);
        }
        set(&mut self.blob_labels, (b, l), add);
    }

    /// One more (or one fewer) entry carries commit `c`; the last gone, it is swept.
    fn carry(&mut self, c: CommitId, add: bool) {
        let n = self.carried.entry(c).or_default();
        *n = if add { n.saturating_add(1) } else { n.saturating_sub(1) };
        if *n == 0 {
            self.carried.remove(&c);
            self.uncarried.insert(c);
        }
    }

    /// Inbox entry `b` under `l` carries `chain` (its author's chain commits).
    pub(crate) fn note_chain(&mut self, l: LabelId, b: BlobId, chain: Vec<CommitId>) {
        if !self.entries.get(&(l, b)).is_some_and(|e| matches!(e.kind, Kind::Inbox(_))) {
            return;
        }
        for c in self.inbox_chain.remove(&(l, b)).unwrap_or_default() {
            self.carry(c, false);
        }
        for c in &chain {
            self.carry(*c, true);
        }
        self.inbox_chain.insert((l, b), chain);
    }

    /// The newest stranded report on `l` naming `holder` carries `keys` (`reported`); none
    /// drops the slot.
    pub(crate) fn note_report(&mut self, l: LabelId, holder: Tid, keys: Vec<CommitId>) {
        for c in &keys {
            self.carry(*c, true);
        }
        let old = if keys.is_empty() { self.reported.remove(&(l, holder)) } else { self.reported.insert((l, holder), keys) };
        for c in old.unwrap_or_default() {
            self.carry(c, false);
        }
    }

    /// Notes that what is known of entry `b` under `l` changed (its passes judge it again).
    pub(crate) fn touch(&mut self, l: LabelId, b: BlobId) {
        let t = match self.entries.get(&(l, b)).map(|e| &e.kind) {
            Some(Kind::Commit { commit, .. }) => Touch::Commit(*commit),
            _ => Touch::Blob(b),
        };
        self.touched.insert((l, t));
    }

    /// The entries under `l`.
    pub fn label_entries(&self, l: &LabelId) -> impl Iterator<Item = (BlobId, &Entry)> + '_ {
        self.entries.range((*l, BlobId([0; 32]))..=(*l, BlobId([0xff; 32]))).map(|((_, b), e)| (*b, e))
    }

    /// The commits with an entry under `l`.
    pub fn label_commits(&self, l: &LabelId) -> impl Iterator<Item = CommitId> + '_ {
        self.by_label_commit.range((*l, CommitId([0; 32]))..=(*l, CommitId([0xff; 32]))).map(|((_, c), _)| *c)
    }

    /// The commit entries under `l` of commit `c`.
    pub fn entries_of<'a>(&'a self, l: &LabelId, c: &CommitId) -> impl Iterator<Item = (BlobId, &'a Entry)> + 'a {
        let l = *l;
        self.by_label_commit.get(&(l, *c)).into_iter().flatten().filter_map(move |b| self.entries.get(&(l, *b)).map(|e| (*b, e)))
    }

    /// Whether an inbox entry under `l` other than `b` carrying commit `c` has a stamp.
    pub fn stamped_inbox_other(&self, l: &LabelId, c: &CommitId, b: &BlobId) -> bool {
        self.stamped_inbox.range((*l, *c, BlobId([0; 32]))..=(*l, *c, BlobId([0xff; 32]))).any(|x| x.2 != *b)
    }

    /// The entries under `l` of a kind other than `Commit` (`Kind::tag`).
    pub fn of_kind(&self, l: &LabelId, tag: u8) -> Vec<BlobId> {
        self.by_kind.range((*l, tag, BlobId([0; 32]))..=(*l, tag, BlobId([0xff; 32]))).map(|(_, _, b)| *b).collect()
    }

    /// The entries of `Kind::tag` `tag` over every label.
    pub fn of_tag(&self, tag: u8) -> Vec<(LabelId, BlobId)> {
        self.by_tag.range((tag, LabelId([0; 16]), BlobId([0; 32]))..=(tag, LabelId([0xff; 16]), BlobId([0xff; 32]))).map(|(_, l, b)| (*l, *b)).collect()
    }

    /// The labels with an entry of commit `c`.
    pub fn labels_of_commit(&self, c: &CommitId) -> Vec<LabelId> {
        self.commit_labels.range((*c, LabelId([0; 16]))..=(*c, LabelId([0xff; 16]))).map(|(_, l)| *l).collect()
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
        self.flush_storing(engine, Vec::new())
    }

    /// `flush`, with `blobs` stored in the same transaction: a node log `Added` is written when
    /// an entry becomes servable here, its row and its bytes both held, in the transaction that
    /// completes the pair. So a queued `Added` of an entry whose bytes are not here is dropped
    /// (the arrival logs it), and a blob newly stored logs every entry that names it.
    pub fn flush_storing(&mut self, engine: &mut Engine, blobs: Vec<(BlobId, Vec<u8>)>) -> Result<()> {
        if self.writes.is_empty() && self.log.is_empty() && !self.log_sweep_due && blobs.is_empty() {
            return Ok(());
        }
        let writes = std::mem::take(&mut self.writes);
        let log = std::mem::take(&mut self.log);
        let (sweep, now) = (self.log_sweep_due, self.now);
        let r = engine.run(|tx| {
            for (k, v) in writes.clone() {
                match v {
                    // a replaced wrap or key leaves no copy behind
                    Some(v) => tx.txn.put_local(&k, &v, if k.starts_with(ENTRY) || k.starts_with(DOUBT) || k.starts_with(BLOB) || k.starts_with(REACH) { Shred::Yes } else { Shred::No })?,
                    None => {
                        tx.txn.remove_local(&k, Shred::Yes)?;
                    }
                }
            }
            let stored = tx.store_blobs(blobs)?;
            let mut logged = BTreeSet::new();
            for e in &log {
                match *e {
                    LogWrite::Added(l, b) => {
                        if tx.txn.read_blob(&b, 0, 0)?.is_some() {
                            tx.txn.log_added(l, b)?;
                            logged.insert((l, b));
                        }
                    }
                    LogWrite::Deleted(l, b, at) => drop(tx.txn.log_deleted(l, b, at)?),
                    LogWrite::Head(l, head) => drop(tx.txn.log_head(l, &head)?),
                }
            }
            for b in &stored {
                for l in self.labels_of(b) {
                    if !self.is_memory(&l, b) && !logged.contains(&(l, *b)) {
                        tx.txn.log_added(l, *b)?;
                    }
                }
            }
            Ok((sweep && tx.txn.log_sweep(now)?, !stored.is_empty()))
        });
        // the in-memory state already holds them: kept for the next flush, so what is durable
        // never lags behind what this node acted on
        match r {
            Ok((more, stored)) => {
                self.log_sweep_due = more;
                if stored {
                    engine.blobs_stored();
                }
                Ok(())
            }
            Err(e) => {
                for (k, v) in writes {
                    self.writes.entry(k).or_insert(v);
                }
                self.log.splice(0..0, log);
                Err(e)
            }
        }
    }

    /// Logs `head` as `l`'s head where it moved: derived from group data, so a head a crash
    /// kept from the log is logged by the next comparison.
    pub fn note_head(&mut self, l: LabelId, head: [u8; 32]) {
        if self.logged_heads.get(&l) != Some(&head) {
            self.logged_heads.insert(l, head);
            self.log.push(LogWrite::Head(l, head));
        }
    }

    fn put(&mut self, k: Vec<u8>, v: Vec<u8>) {
        self.writes.insert(k, Some(v));
    }

    fn del(&mut self, k: Vec<u8>) {
        self.writes.insert(k, None);
    }

    /// `put` of a record about entry `b` of `l`: nothing for a memory entry.
    fn put_of(&mut self, l: &LabelId, b: &BlobId, k: Vec<u8>, v: Vec<u8>) {
        if !self.memory_entries.contains(&(*l, *b)) {
            self.put(k, v);
        }
    }

    fn del_of(&mut self, l: &LabelId, b: &BlobId, k: Vec<u8>) {
        if !self.memory_entries.contains(&(*l, *b)) {
            self.del(k);
        }
    }

    /// Whether entry `b` of `l` is a memory entry.
    pub fn is_memory(&self, l: &LabelId, b: &BlobId) -> bool {
        self.memory_entries.contains(&(*l, *b))
    }

    /// Notes the encoded size of memory entry `b` of `l`'s blob.
    pub fn note_memory_size(&mut self, l: LabelId, b: BlobId, size: usize) {
        if self.memory_entries.contains(&(l, b)) {
            self.memory_sizes.insert((l, b), size);
        }
    }

    pub fn set_entry(&mut self, l: LabelId, b: BlobId, e: Entry) {
        self.set_entry_fed(l, b, e, true);
    }

    /// `set_entry` without announcing the entry to the streams this node serves (node log,
    /// `mem_log`): a tombstoned entry recorded again only to delete it where a host still
    /// holds it.
    pub fn set_entry_quiet(&mut self, l: LabelId, b: BlobId, e: Entry) {
        self.set_entry_fed(l, b, e, false);
    }

    fn set_entry_fed(&mut self, l: LabelId, b: BlobId, e: Entry, fed: bool) {
        debug_assert!(self.entries.get(&(l, b)).is_none_or(|o| o.memory == e.memory), "an entry changes class");
        // what a peer is sent: a change of only what this node knows of the blob is no event;
        // `flush_storing` keeps this one only if the bytes are here
        let changed = self.entries.get(&(l, b)).is_none_or(|o| o.wrap != e.wrap || o.stamp != e.stamp);
        if fed && !e.memory && changed {
            self.log.push(LogWrite::Added(l, b));
        }
        if fed && e.memory && changed {
            self.mem_log.added(l, b, self.now);
        }
        if e.memory {
            self.memory_entries.insert((l, b));
            if let Kind::Commit { commit, .. } = &e.kind {
                self.memory_commits.insert(*commit);
            }
        } else {
            self.put(key(ENTRY, &[&l.0, &b.0]), encode_entry(&e));
        }
        self.touch(l, b);
        if let Some(old) = self.entries.get(&(l, b)).cloned() {
            self.index(l, b, &old, false);
        }
        self.index(l, b, &e, true);
        self.entries.insert((l, b), e);
        self.touch(l, b);
        self.version += 1;
    }

    /// Charges memory entry `b` of `l` (held from another node) `n` against the label's cap
    /// (replacing any earlier charge), or releases it (`None`).
    pub fn charge_memory(&mut self, l: LabelId, b: BlobId, n: Option<u64>) {
        let old = self.memory_charge.remove(&(l, b)).unwrap_or(0);
        let total = self.memory_bytes.entry(l).or_default();
        *total = total.saturating_sub(old).saturating_add(n.unwrap_or(0));
        if let Some(n) = n {
            self.memory_charge.insert((l, b), n);
        }
        if *total == 0 {
            self.memory_bytes.remove(&l);
        }
    }

    /// Whether a body of commit `c` sharing a delta with `parts` (sorted) left `l` by a delete
    /// (`deleted`): bodies of one commit hold disjoint delta sets, so this is that body or a
    /// purge rewrite of it.
    /// Whether a delete took a blob of `c` holding exactly `parts` from `l` (spec/sync.md §6): a
    /// deleted blob holding more (a rewrite replaced it for a dropped part) was another body.
    pub fn body_deleted(&self, l: LabelId, c: CommitId, parts: &[usize]) -> bool {
        self.deleted.range((l, c, Vec::new())..).take_while(|((x, y, _), _)| *x == l && *y == c).any(|((_, _, p), _)| p == parts)
    }

    /// Forgets an entry, tombstoned (`tombs`).
    pub fn remove_entry(&mut self, l: LabelId, b: BlobId) {
        if let Some(Entry { cert: false, kind: Kind::Commit { commit, parts, .. }, memory, .. }) = self.entries.get(&(l, b)) {
            let life = if *memory { osis_base::format::MAX_DRIFT_MS } else { osis_base::format::TOMBSTONE_LIFETIME_MS };
            if self.deleted.insert((l, *commit, parts.clone()), self.now.saturating_add(life)).is_none() {
                *self.deleted_commits.entry(*commit).or_default() += 1;
            }
        }
        let e = self.entries.get(&(l, b)).cloned();
        let (true, Some(e)) = (self.drop_entry(l, b), e) else { return };
        // the class mark stays with the tombstone (`expire_tombs`)
        if e.memory {
            self.memory_entries.insert((l, b));
        }
        let tomb = Tomb { at: self.now, wrap: e.wrap, cert: e.cert, salt: e.salt, kind: e.kind };
        let v = encode_kind(encode_salt(Wr::new().u64(tomb.at).raw(&tomb.wrap).u8(u8::from(tomb.cert)), &tomb.salt), &tomb.kind).take();
        self.put_of(&l, &b, key(TOMB, &[&l.0, &b.0]), v);
        self.tombs.insert((l, b), tomb);
    }

    /// Forgets an entry that never counted (junk a host announced, an expired one): no
    /// tombstone. Whether there was one.
    pub fn drop_entry(&mut self, l: LabelId, b: BlobId) -> bool {
        self.awaits_reopened.remove(&(l, b));
        self.touch(l, b);
        let Some(e) = self.entries.remove(&(l, b)) else { return false };
        self.index(l, b, &e, false);
        let applied: Vec<Tid> = self.applied.range((l, b, Tid::from_bytes([0; 15]))..=(l, b, Tid::from_bytes([0xff; 15]))).map(|x| x.2).collect();
        for t in applied {
            self.applied.remove(&(l, b, t));
            self.del_of(&l, &b, key(APPLIED, &[&l.0, &b.0, t.as_bytes()]));
        }
        for c in self.inbox_chain.remove(&(l, b)).unwrap_or_default() {
            self.carry(c, false);
        }
        self.version += 1;
        self.losses += 1;
        if e.memory {
            self.memory_entries.remove(&(l, b));
            self.memory_in_closure.remove(&(l, b));
            self.charge_memory(l, b, None);
            self.memory_sizes.remove(&(l, b));
            // the class marks go last: `drop_entry` of a memory entry writes nothing
            if let Kind::Commit { commit, .. } = &e.kind
                && self.commit_labels.range((*commit, LabelId([0; 16]))..=(*commit, LabelId([0xff; 16]))).next().is_none()
            {
                self.memory_commits.remove(commit);
            }
        } else {
            self.del(key(ENTRY, &[&l.0, &b.0]));
            self.log.push(LogWrite::Deleted(l, b, self.now));
        }
        if e.memory {
            self.mem_log.deleted(l, b, self.now);
        }
        true
    }

    /// Forgets every record of an entry announced without its bytes that turned out ephemeral
    /// (its blob's prefix class, spec/sync.md §9): it is recorded again as a memory entry (no
    /// tombstone).
    pub fn forget_class(&mut self, l: LabelId, b: BlobId) {
        let hosts: Vec<HostKey> = self.present_by.range((l, b, [0u8; 32])..).take_while(|(x, y, _)| *x == l && *y == b).map(|(_, _, s)| *s).collect();
        for s in hosts {
            self.set_present(s, l, b, false);
        }
        self.drop_entry(l, b);
    }

    /// Forgets tombstones, and hosts' tombstoned answers, past their lifetime.
    pub fn expire_tombs(&mut self, now: u64) {
        // a memory entry's tombstone lasts `MAX_DRIFT`, as a host's does (spec/sync.md §5)
        let life = |memory: bool| if memory { osis_base::format::MAX_DRIFT_MS } else { osis_base::format::TOMBSTONE_LIFETIME_MS };
        let old: Vec<(HostKey, LabelId, BlobId)> = self.gone.iter().filter(|((s, l, b), t)| t.saturating_add(life(self.memory_entries.contains(&(*l, *b)))) <= now && !self.is_present(s, l, b)).map(|(k, _)| *k).collect();
        for (s, l, b) in old {
            self.gone.remove(&(s, l, b));
            self.gone_by.remove(&(l, b, s));
            self.touch(l, b);
            self.del_of(&l, &b, key(GONE, &[&s, &l.0, &b.0]));
        }
        let old: Vec<(LabelId, BlobId)> = self.tombs.iter().filter(|((l, b), t)| t.at.saturating_add(life(self.memory_entries.contains(&(*l, *b)))) <= now).map(|(k, _)| *k).collect();
        for (l, b) in old {
            self.del_of(&l, &b, key(TOMB, &[&l.0, &b.0]));
            self.tombs.remove(&(l, b));
            // an entry recorded again (`SyncEngine::host_holds`) keeps its class
            if !self.entries.contains_key(&(l, b)) {
                self.memory_entries.remove(&(l, b));
            }
        }
        let due: Vec<(DeletedBody, u64)> = self.deleted.iter().filter(|(_, until)| **until <= now).map(|(k, v)| (k.clone(), *v)).collect();
        for ((l, c, parts), _) in due {
            self.deleted.remove(&(l, c, parts));
            if let Some(n) = self.deleted_commits.get_mut(&c) {
                *n -= 1;
                if *n == 0 {
                    self.deleted_commits.remove(&c);
                }
            }
            self.forget_due.insert(c);
        }
    }

    pub fn set_reach_secret(&mut self, s: Secret32) {
        self.put(REACH.to_vec(), s.expose().to_vec());
        self.reach_secret = Some(s);
    }

    pub fn set_host_store(&mut self, s: Option<[u8; 32]>) {
        match &s {
            Some(s) => self.put(HOST_STORE.to_vec(), s.to_vec()),
            None => self.del(HOST_STORE.to_vec()),
        }
        self.host_store = s;
    }

    pub fn set_present(&mut self, s: HostKey, l: LabelId, b: BlobId, on: bool) {
        let k = key(PRESENT, &[&s, &l.0, &b.0]);
        if on {
            if self.present.insert((s, l, b)) {
                self.present_by.insert((l, b, s));
                self.touch(l, b);
                self.version += 1;
                self.put_of(&l, &b, k, Vec::new());
            }
        } else if self.present.remove(&(s, l, b)) {
            self.present_by.remove(&(l, b, s));
            self.touch(l, b);
            self.version += 1;
            self.losses += 1;
            self.deposited.remove(&(s, l, b));
            self.del_of(&l, &b, k);
            self.drop_doubt(s, l, b);
        }
    }

    /// Marks a present entry deposited at a host, or not (stamped there).
    pub fn set_deposited(&mut self, s: HostKey, l: LabelId, b: BlobId, on: bool) {
        if !self.present.contains(&(s, l, b)) {
            return;
        }
        let changed = if on { self.deposited.insert((s, l, b)) } else { self.deposited.remove(&(s, l, b)) };
        if changed {
            self.touch(l, b);
            self.put_of(&l, &b, key(PRESENT, &[&s, &l.0, &b.0]), if on { vec![1] } else { Vec::new() });
        }
    }

    /// Records that `source` reported holding own entry `b` of `l` (`applied`).
    pub fn set_applied(&mut self, l: LabelId, b: BlobId, source: Tid) {
        if self.applied.insert((l, b, source)) {
            self.version += 1;
            self.put_of(&l, &b, key(APPLIED, &[&l.0, &b.0, source.as_bytes()]), Vec::new());
        }
    }

    /// The co-reader sources that reported holding the entry (`applied`).
    pub fn applied_by<'a>(&'a self, l: &LabelId, b: &BlobId) -> impl Iterator<Item = Tid> + 'a {
        self.applied.range((*l, *b, Tid::from_bytes([0; 15]))..=(*l, *b, Tid::from_bytes([0xff; 15]))).map(|x| x.2)
    }

    pub fn is_present(&self, s: &HostKey, l: &LabelId, b: &BlobId) -> bool {
        self.present.contains(&(*s, *l, *b))
    }

    /// Whether any host holds the entry.
    pub fn present_anywhere(&self, l: &LabelId, b: &BlobId) -> bool {
        self.present_by.range((*l, *b, [0; 32])..=(*l, *b, [0xff; 32])).next().is_some()
    }

    /// Whether some host holds the entry under a wrap of use.
    pub fn held_anywhere(&self, l: &LabelId, b: &BlobId) -> bool {
        self.hosts_of(l, b).iter().any(|s| !self.is_gone_at(s, l, b))
    }

    /// Whether the host holds the entry under a wrap of use (`gone`).
    pub fn holds_at(&self, s: &HostKey, l: &LabelId, b: &BlobId) -> bool {
        self.is_present(s, l, b) && !self.is_gone_at(s, l, b)
    }

    /// The hosts holding the entry.
    pub fn hosts_of(&self, l: &LabelId, b: &BlobId) -> Vec<HostKey> {
        self.present_by.range((*l, *b, [0; 32])..=(*l, *b, [0xff; 32])).map(|(_, _, s)| *s).collect()
    }

    /// Entry IDs known present at a host for a label.
    pub fn present_at(&self, s: &HostKey, l: &LabelId) -> Vec<BlobId> {
        self.present.range((*s, *l, BlobId([0; 32]))..=(*s, *l, BlobId([0xff; 32]))).map(|(_, _, b)| *b).collect()
    }

    /// Entries deposited at a host under a label.
    pub fn deposited_at(&self, s: &HostKey, l: &LabelId) -> Vec<BlobId> {
        self.deposited.range((*s, *l, BlobId([0; 32]))..=(*s, *l, BlobId([0xff; 32]))).map(|(_, _, b)| *b).collect()
    }

    pub fn set_cursor(&mut self, s: HostKey, l: LabelId, c: Option<Cursor>) {
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

    pub fn set_filling(&mut self, s: HostKey, l: LabelId, on: bool) {
        let k = key(FILLING, &[&s, &l.0]);
        if on {
            if self.filling.insert((s, l)) {
                self.put(k, Vec::new());
            }
        } else if self.filling.remove(&(s, l)) {
            self.del(k);
        }
    }

    pub fn set_head(&mut self, s: HostKey, l: LabelId, step: &Step) {
        self.put(key(HEAD, &[&s, &l.0]), step.to_bytes());
        self.heads.insert((s, l), step.clone());
    }

    pub fn add_blob(&mut self, id: BlobId, rec: BlobRec) {
        if !rec.memory {
            let v = encode_ais(encode_ais(Wr::new().raw(&rec.commit.0).raw(rec.key.expose()).u8(u8::from(rec.cert)), &rec.parts), &rec.ais).take();
            self.put(key(BLOB, &[&id.0]), v);
        }
        self.by_commit.entry(rec.commit).or_default().insert(id);
        self.new_blobs.insert(rec.commit);
        self.blobs.insert(id, rec);
    }

    /// More parts of blob `id` opened (a section under a secret learned since): the record and
    /// every entry of it now list them; `copy`: it proved a per-label copy (`OpenedBlob::copy`).
    pub fn note_opened(&mut self, id: &BlobId, parts: &[usize], copy: bool) {
        let Some(mut rec) = self.blobs.remove(id) else { return };
        if let Some(s) = self.by_commit.get_mut(&rec.commit) {
            s.remove(id);
        }
        rec.parts = parts.to_vec();
        rec.cert |= copy;
        self.add_blob(*id, rec);
        let ls: Vec<LabelId> = self.labels_of(id);
        for l in ls {
            if let Some(mut e) = self.entries.get(&(l, *id)).cloned()
                && let Kind::Commit { parts: p, .. } = &mut e.kind
            {
                *p = parts.to_vec();
                self.set_entry(l, *id, e);
            }
        }
    }

    pub fn remove_blob(&mut self, id: &BlobId) {
        if let Some(r) = self.blobs.remove(id) {
            if let Some(s) = self.by_commit.get_mut(&r.commit) {
                s.remove(id);
                if s.is_empty() {
                    self.by_commit.remove(&r.commit);
                    self.forget_due.insert(r.commit);
                }
            }
            if !r.memory {
                self.del(key(BLOB, &[&id.0]));
            }
        }
    }

    /// A pass of `l` finished, or this node made it (`passed`).
    pub fn note_passed(&mut self, l: LabelId) {
        if self.passed.insert(l) {
            self.put(key(PASSED, &[&l.0]), Vec::new());
        }
    }

    /// This node no longer holds `l`.
    pub fn forget_passed(&mut self, l: &LabelId) {
        if self.passed.remove(l) {
            self.del(key(PASSED, &[&l.0]));
        }
    }

    /// Marks (or unmarks) a group as handed off.
    pub fn set_handed_off(&mut self, g: Tid, on: bool) {
        if on {
            self.put(key(HANDED_OFF, &[g.as_bytes()]), Vec::new());
            self.handed_off.insert(g);
        } else {
            self.del(key(HANDED_OFF, &[g.as_bytes()]));
            self.handed_off.remove(&g);
        }
    }

    pub fn decline(&mut self, c: CommitId) {
        self.put(key(DECLINED, &[&c.0]), Vec::new());
        self.declined.insert(c);
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
        let w = encode_addrs(Wr::new().raw(lp.target.as_bytes()), &lp.peers);
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
    pub fn note_sent(&mut self, holder: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool, at: u64) {
        let x = match self.sent_inbox.get(&(holder, commit)) {
            // the first send of a delivery queued unsent (`at` 0) is no re-send
            Some(old) if old.at == 0 => SentInbox { at, ..old.clone() },
            Some(old) => SentInbox { at, tries: old.tries.saturating_add(1), ..old.clone() },
            None => SentInbox { holder, commit, things, edge_only, at, tries: 0 },
        };
        self.put(key(SENT_INBOX, &[holder.as_bytes(), &commit.0]), encode_sent(&x));
        self.sent_inbox.insert((holder, commit), x);
    }

    /// Records an inbox delivery not sent yet (`at` 0; `SyncEngine::send_inbox` seals and sends
    /// it at its next step), unless one is recorded already.
    pub fn note_unsent(&mut self, holder: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool) {
        if self.sent_inbox.contains_key(&(holder, commit)) {
            return;
        }
        let x = SentInbox { holder, commit, things, edge_only, at: 0, tries: 0 };
        self.put(key(SENT_INBOX, &[holder.as_bytes(), &commit.0]), encode_sent(&x));
        self.sent_inbox.insert((holder, commit), x);
    }

    pub fn remove_sent(&mut self, holder: &Tid, commit: &CommitId) {
        if self.sent_inbox.remove(&(*holder, *commit)).is_some() {
            self.del(key(SENT_INBOX, &[holder.as_bytes(), &commit.0]));
        }
    }

    /// Adds commits for node `to` (direct connection).
    pub fn add_direct(&mut self, to: Tid, commits: &[CommitId]) {
        let list = self.direct.entry(to).or_default();
        for c in commits {
            if !list.contains(c) {
                list.push(*c);
            }
        }
        let v = encode_commits(list);
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

    /// Drops the record of an owed delivery carried out (`owed_key`).
    pub fn settle_owed(&mut self, k: [u8; 32]) {
        self.owed.remove(&k);
        self.del(key(OWED, &[&k]));
    }

    pub fn add_cert(&mut self, l: LabelId, c: CommitId) {
        if self.certs.insert((l, c)) {
            self.touched.insert((l, Touch::Commit(c)));
            self.put(key(CERT, &[&l.0, &c.0]), Vec::new());
        }
    }

    pub fn add_listed(&mut self, l: LabelId, r: CommitId, t: Tid) {
        if self.listed.insert((l, r, t)) {
            self.put(key(LISTED, &[&l.0, &r.0, t.as_bytes()]), Vec::new());
        }
    }

    pub fn set_gone(&mut self, s: HostKey, l: LabelId, b: BlobId) {
        if !self.gone.contains_key(&(s, l, b)) {
            self.losses += 1;
            self.gone.insert((s, l, b), self.now);
            self.gone_by.insert((l, b, s));
            self.touch(l, b);
            self.version += 1;
            self.put_of(&l, &b, key(GONE, &[&s, &l.0, &b.0]), Wr::new().u64(self.now).take());
        }
    }

    /// `set_gone` for a wrap that opened under no read secret held.
    pub fn set_doubtful(&mut self, s: HostKey, l: LabelId, b: BlobId, wrap: [u8; WRAP_LEN]) {
        self.set_gone(s, l, b);
        self.doubts.insert((s, l, b), wrap);
        self.put_of(&l, &b, key(DOUBT, &[&s, &l.0, &b.0]), wrap.to_vec());
    }

    pub fn drop_doubt(&mut self, s: HostKey, l: LabelId, b: BlobId) {
        if self.doubts.remove(&(s, l, b)).is_some() {
            self.del_of(&l, &b, key(DOUBT, &[&s, &l.0, &b.0]));
        }
    }

    /// The host's entry is of use after all.
    pub fn clear_gone(&mut self, s: HostKey, l: LabelId, b: BlobId) {
        self.drop_doubt(s, l, b);
        if self.gone.remove(&(s, l, b)).is_some() {
            self.gone_by.remove(&(l, b, s));
            self.touch(l, b);
            self.version += 1;
            self.del_of(&l, &b, key(GONE, &[&s, &l.0, &b.0]));
        }
    }

    pub fn is_gone_at(&self, s: &HostKey, l: &LabelId, b: &BlobId) -> bool {
        self.gone.contains_key(&(*s, *l, *b))
    }

    pub fn is_gone(&self, l: &LabelId, b: &BlobId) -> bool {
        self.gone_by.range((*l, *b, [0; 32])..=(*l, *b, [0xff; 32])).next().is_some()
    }

    /// Adds a carrier of `body` (a snapshot of one of its aspects).
    pub fn set_carrier(&mut self, body: CommitId, snapshot: CommitId) {
        self.touched_commits.insert(body);
        let now = self.now;
        let memory = self.memory_commits.contains(&body);
        let c = self.carriers.entry(body).or_insert(Carriers { by: Vec::new(), at: now, memory });
        if !c.by.contains(&snapshot) {
            c.by.push(snapshot);
        }
        c.at = now;
        if !c.memory {
            let v = [Wr::new().u64(now).take(), encode_commits(&c.by)].concat();
            self.put(key(CARRIER, &[&body.0]), v);
        }
    }

    /// Forgets the carriers no body needs any more (spec/sync.md §7: they decide whether a
    /// dropped body's entry may go): kept for a body with an entry under some label or deleted
    /// from one within `TOMBSTONE_LIFETIME`, for one set within that time (an entry of the body
    /// may still be learned), and for every carrier those reach (`carrier_of` follows dropped
    /// carriers to theirs). One the sweep forgot costs at most a fresh covering snapshot when an
    /// entry of its body turns up later (`snapshot_first`). The wait is `TOMBSTONE_LIFETIME`:
    /// past it an entry comes back only by a stale relay or bundle; at 0 a body dropped before
    /// its entries are learned would cost that snapshot, at infinity carriers stay for good.
    pub fn sweep_carriers(&mut self, now: u64) {
        let life = |memory: bool| if memory { osis_base::format::MAX_DRIFT_MS } else { osis_base::format::TOMBSTONE_LIFETIME_MS };
        let mut keep: BTreeSet<CommitId> = self.by_label_commit.keys().map(|(_, c)| *c).chain(self.deleted.keys().map(|(_, c, _)| *c)).collect();
        keep.extend(self.carriers.iter().filter(|(_, c)| c.at.saturating_add(life(c.memory)) > now).map(|(b, _)| *b));
        let mut todo: Vec<CommitId> = keep.iter().copied().collect();
        while let Some(b) = todo.pop() {
            for c in self.carriers.get(&b).map(|c| c.by.clone()).unwrap_or_default() {
                if keep.insert(c) {
                    todo.push(c);
                }
            }
        }
        let gone: Vec<CommitId> = self.carriers.keys().filter(|b| !keep.contains(b)).copied().collect();
        for b in gone {
            if self.carriers.remove(&b).is_some_and(|c| !c.memory) {
                self.del(key(CARRIER, &[&b.0]));
            }
        }
    }

    /// Whether a delete of a body of `c` is within its tombstone, under any label.
    pub fn deleted_commit(&self, c: &CommitId) -> bool {
        self.deleted_commits.contains_key(c)
    }

    /// Forgets commit `c`'s carrier row (it is forgotten: it carries nothing and nothing names
    /// it again).
    pub fn forget_carrier(&mut self, c: &CommitId) {
        if self.carriers.remove(c).is_some_and(|x| !x.memory) {
            self.del(key(CARRIER, &[&c.0]));
        }
    }

    /// Forgets the certificate placements of commits `held` says this node holds no part of
    /// any more: nothing is left to place again (`add_cert` keeps a deleted copy from coming back).
    pub fn sweep_certs(&mut self, held: impl Fn(&CommitId) -> bool) {
        let gone: Vec<(LabelId, CommitId)> = self.certs.iter().filter(|(_, c)| !held(c)).copied().collect();
        for (l, c) in gone {
            self.certs.remove(&(l, c));
            self.del(key(CERT, &[&l.0, &c.0]));
        }
    }

    pub fn add_out(&mut self, o: OutRec) {
        let id = osis_label::blob_id(&o.blob);
        let w = Wr::new().raw(&o.label.0);
        let mut w = match &o.to {
            Dest::Host(a) => w.u8(0).bytes(a.url.as_bytes()).raw(&a.key),
            Dest::Nodes(t) => w.u8(1).raw(t.as_bytes()),
        };
        w = w.raw(&o.wrap).raw(&o.sig.0).bytes(&o.blob);
        if let Some((m, c)) = &o.delivery {
            w = w.raw(m.as_bytes()).raw(&c.0);
        }
        let v = w.take();
        let k = o.to.key();
        self.put(key(OUTBOX, &[&k, &o.label.0, &id.0]), v);
        self.outbox.insert((k, o.label, id), o);
        self.version += 1;
    }

    pub fn remove_out(&mut self, s: &HostKey, l: &LabelId, b: &BlobId) {
        if self.outbox.remove(&(*s, *l, *b)).is_some() {
            self.version += 1;
            self.del(key(OUTBOX, &[s, &l.0, &b.0]));
        }
    }

    /// Records a hint; a hint naming no key actor keeps the one an earlier hint followed for (an
    /// inbox payload naming a followed label must not stall the follow).
    pub fn add_hint(&mut self, l: LabelId, mut h: Hint) {
        if h.via.is_none() {
            h.via = self.hints.get(&l).and_then(|x| x.via);
        }
        let flags = u8::from(h.via.is_some()) | u8::from(h.inbox.is_some()) << 1;
        let mut w = encode_addrs(Wr::new().raw(h.thing.as_bytes()).u64(h.index), &h.hosts).u8(flags);
        if let Some(v) = &h.via {
            w = w.raw(v.as_bytes());
        }
        if let Some(i) = &h.inbox {
            w = w.raw(&i.label.0).raw(&i.blob.0).u64(i.until);
        }
        self.put(key(HINT, &[&l.0]), w.take());
        self.hints.insert(l, h);
        self.hints_moved = true;
    }

    /// The inbox blobs of `t` are checked.
    pub fn forget_done(&mut self, t: &Tid) {
        if self.forget.remove(t) {
            self.del(key(FORGET, &[t.as_bytes()]));
        }
    }

    pub fn remove_hint(&mut self, l: &LabelId) {
        if self.hints.remove(l).is_some() {
            self.hints_moved = true;
            self.del(key(HINT, &[&l.0]));
        }
    }

    /// The blob this node holds for exactly these parts of a commit (not a certificate
    /// encryption), if any.
    pub fn blob_for(&self, c: &CommitId, needed: &[usize], held: &[usize], skip: impl Fn(&BlobId) -> bool) -> Option<BlobId> {
        self.by_commit.get(c)?.iter().filter(|b| !skip(b)).filter_map(|b| self.blobs.get(b).filter(|r| !r.cert && needed.iter().all(|p| r.parts.contains(p)) && r.parts.iter().all(|p| held.contains(p))).map(|r| (r.parts.len(), *b))).max().map(|x| x.1)
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
            b"p" | b"c" | b"h" | b"g" | b"3" | b"d" => lab(rest.get(32..).unwrap_or_default())?,
            b"t" | b"A" => lab(rest)?,
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
                let ps = decode_ais(&mut x)?;
                let gone = commits.contains(&c) || parts.get(&c).is_some_and(|s| ps.iter().any(|ai| s.contains(ai)));
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
            b"v" => decode_sent(&v).is_ok_and(|x| commits.contains(&x.commit) || things.contains(&x.holder)),
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
    // no deletion events: this node stopped holding them, nobody deleted them
    for l in labels {
        tx.txn.log_forget(*l)?;
        tx.txn.changed_forget(l)?;
    }
    for t in things {
        tx.txn.put_local(&key(FORGET, &[t.as_bytes()]), &[], Shred::No)?;
    }
    Ok(freed.difference(&kept).copied().collect())
}

fn encode_sent(x: &SentInbox) -> Vec<u8> {
    let mut w = Wr::new().raw(x.holder.as_bytes()).raw(&x.commit.0).u8(u8::from(x.edge_only)).u64(x.at).u32(x.tries).u32(x.things.len() as u32);
    for t in &x.things {
        w = w.raw(t.as_bytes());
    }
    w.take()
}

/// `State::note_unsent` inside a flow's transaction (the commit's own): a crash before
/// `SyncEngine::carry_out` loses no inbox delivery.
fn note_unsent_tx(tx: &mut Tx<'_>, holder: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool) -> Result<()> {
    let k = key(SENT_INBOX, &[holder.as_bytes(), &commit.0]);
    if tx.txn.get_local(&k)?.is_none() {
        let x = SentInbox { holder, commit, things, edge_only, at: 0, tries: 0 };
        tx.txn.put_local(&k, &encode_sent(&x), Shred::No)?;
    }
    Ok(())
}

/// The encoding of a flow's delivery, `None` for an inbox blob (its record is `y/v`).
fn encode_owed(d: &Delivery) -> Option<Vec<u8>> {
    fn commits(w: Wr, cs: &[CommitId]) -> Wr {
        cs.iter().fold(w.u32(cs.len() as u32), |w, c| w.raw(&c.0))
    }
    let w = match d {
        Delivery::Inbox { .. } => return None,
        Delivery::Direct { to, commits: cs } => commits(Wr::new().u8(1).raw(to.as_bytes()), cs),
        Delivery::First { commits: cs, under } => under.iter().fold(commits(Wr::new().u8(2), cs).u32(under.len() as u32), |w, t| w.raw(t.as_bytes())),
        Delivery::Certificate { commits: cs, under } => commits(Wr::new().u8(3), cs).raw(under.as_bytes()),
        Delivery::Deposit { commit, under } => Wr::new().u8(4).raw(&commit.0).raw(under.as_bytes()),
        Delivery::Removal { commit, under } => Wr::new().u8(5).raw(&commit.0).raw(under.as_bytes()),
    };
    Some(w.take())
}

fn decode_owed(v: &[u8]) -> Result<Delivery> {
    fn commits(r: &mut Rd<'_>) -> Result<Vec<CommitId>> {
        (0..r.u32()?).map(|_| Ok(CommitId(r.arr()?))).collect()
    }
    let mut r = Rd::new(v);
    let d = match r.u8()? {
        1 => {
            let to = r.tid()?;
            Delivery::Direct { to, commits: commits(&mut r)? }
        }
        2 => {
            let cs = commits(&mut r)?;
            let under = (0..r.u32()?).map(|_| r.tid()).collect::<Result<_>>()?;
            Delivery::First { commits: cs, under }
        }
        3 => {
            let cs = commits(&mut r)?;
            Delivery::Certificate { commits: cs, under: r.tid()? }
        }
        4 => Delivery::Deposit { commit: CommitId(r.arr()?), under: r.tid()? },
        5 => Delivery::Removal { commit: CommitId(r.arr()?), under: r.tid()? },
        _ => return Err(Error::Corrupt("owed delivery")),
    };
    if !r.is_empty() {
        return Err(Error::Corrupt("owed delivery"));
    }
    Ok(d)
}

/// The key of an owed delivery's record (`y/y`): the hash of its encoding, so the transaction
/// that owes it and `SyncEngine::take_done` name the same record; `None` for an inbox blob.
pub(crate) fn owed_key(d: &Delivery) -> Option<[u8; 32]> {
    encode_owed(d).map(|v| osis_base::hash::hash(&v))
}

/// Records (`owed`) or drops a flow's delivery in the transaction that owes it
/// (`SyncRecords::owe`).
fn owe_tx(tx: &mut Tx<'_>, d: &Delivery, owed: bool) -> Result<()> {
    let Some(v) = encode_owed(d) else { return Ok(()) };
    let k = key(OWED, &[&osis_base::hash::hash(&v)]);
    if owed {
        tx.txn.put_local(&k, &v, Shred::No)?;
    } else {
        tx.txn.remove_local(&k, Shred::No)?;
    }
    Ok(())
}

fn decode_out(k: &[u8], v: &[u8]) -> Result<((HostKey, LabelId, BlobId), OutRec)> {
    let mut r = Rd::new(k);
    let key = (r.arr()?, LabelId(r.arr()?), BlobId(r.arr()?));
    let mut x = Rd::new(v);
    let label = LabelId(x.arr()?);
    if !r.is_empty() || label != key.1 {
        return Err(Error::Corrupt("outbox"));
    }
    let to = match x.u8()? {
        0 => {
            let url = String::from_utf8(x.bytes()?.to_vec()).map_err(|_| Error::Corrupt("outbox"))?;
            Dest::Host(Address { url, key: x.arr()? })
        }
        1 => Dest::Nodes(x.tid()?),
        _ => return Err(Error::Corrupt("outbox")),
    };
    if to.key() != key.0 {
        return Err(Error::Corrupt("outbox"));
    }
    let wrap = x.arr()?;
    let sig = Signature(x.arr()?);
    let blob = x.bytes()?.to_vec();
    let delivery = if x.is_empty() { None } else { Some((x.tid()?, CommitId(x.arr()?))) };
    if !x.is_empty() {
        return Err(Error::Corrupt("outbox"));
    }
    Ok((key, OutRec { label, to, blob, wrap, sig, delivery }))
}

fn decode_sent(v: &[u8]) -> Result<SentInbox> {
    let mut r = Rd::new(v);
    let holder = r.tid()?;
    let commit = CommitId(r.arr()?);
    let edge_only = r.u8()? == 1;
    let at = r.u64()?;
    let tries = r.u32()?;
    let n = r.u32()?;
    let mut things = Vec::new();
    for _ in 0..n {
        things.push(r.tid()?);
    }
    Ok(SentInbox { holder, commit, things, edge_only, at, tries })
}

/// The records engine transactions touch (`Engine::set_sync_records`).
pub(crate) struct Records;

impl crate::engine::SyncRecords for Records {
    fn note_unsent(&self, tx: &mut Tx<'_>, holder: Tid, commit: CommitId, things: Vec<Tid>, edge_only: bool) -> Result<()> {
        note_unsent_tx(tx, holder, commit, things, edge_only)
    }

    fn owe(&self, tx: &mut Tx<'_>, d: &Delivery, owed: bool) -> Result<()> {
        owe_tx(tx, d, owed)
    }

    fn forget(&self, tx: &mut Tx<'_>, labels: &BTreeSet<LabelId>, things: &BTreeSet<Tid>, commits: &BTreeSet<CommitId>, parts: &BTreeMap<CommitId, BTreeSet<usize>>, extra: BTreeSet<BlobId>) -> Result<BTreeSet<BlobId>> {
        forget_records(tx, labels, things, commits, parts, extra)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec/sync.md §9: a memory entry dropped without a tombstone leaves no class mark (its
    // records would otherwise be kept for good, one per entry)
    #[test]
    fn memory_entry_dropped_leaves_no_mark() {
        let mut s = State::default();
        let (l, b) = (LabelId([1; 16]), BlobId([2; 32]));
        s.set_entry(l, b, Entry { wrap: [0; WRAP_LEN], stamp: None, cert: false, salt: None, kind: Kind::Unknown, memory: true });
        assert!(s.is_memory(&l, &b));
        s.drop_entry(l, b);
        assert!(!s.is_memory(&l, &b));
    }

    // spec: none (local store format): an entry keeps its blob's salt and round trips.
    #[test]
    fn entry_salt_round_trips() {
        let e = Entry { wrap: [3; WRAP_LEN], stamp: None, cert: false, salt: Some([9; 16]), kind: Kind::Commit { commit: CommitId([1; 32]), parts: vec![0], ais: vec![0, 2] }, memory: false };
        let back = decode_entry(&encode_entry(&e)).unwrap();
        assert!(back.salt == Some([9; 16]) && matches!(&back.kind, Kind::Commit { ais, .. } if *ais == vec![0, 2]));
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

    // spec: none (local store format): a queued deposit record that does not decode fails the
    // load with a named error, never a panic or a silent drop.
    #[test]
    fn corrupt_outbox_record_fails_load() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 962, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let k = key(OUTBOX, &[&[7u8; 32], &[8u8; 32]]);
        e.run(|tx| {
            tx.txn.put_local(&k, b"short", Shred::No)?;
            Ok(())
        })
        .unwrap();
        assert!(matches!(State::load(e), Err(Error::Corrupt("sync outbox record"))));
    }

    // spec: none (engine/sync seam): node-sync's records stay installed across a reload (a
    // forget reloads; a flow or forget after it still writes and drops sync records).
    #[test]
    fn sync_records_survive_reload() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 963, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        e.set_sync_records(&Records);
        e.reload().unwrap();
        assert!(e.core.sync_records.is_some());
        e.rebuild_index().unwrap();
        assert!(e.core.sync_records.is_some());
    }

    // spec: none (local store format): a hint with its key actor and inbox source round trips.
    #[test]
    fn hint_round_trips() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 964, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let mut s = State::default();
        let src = InboxSource { label: LabelId([4; 16]), blob: BlobId([5; 32]), until: 77 };
        let addr = Address { url: "quic://s".into(), key: [6; 32] };
        s.add_hint(LabelId([1; 16]), Hint { thing: Tid::from_bytes([2; 15]), index: 3, hosts: vec![addr], via: Some(Tid::from_bytes([3; 15])), inbox: Some(src) });
        s.add_hint(LabelId([2; 16]), Hint { thing: Tid::from_bytes([2; 15]), index: 0, hosts: Vec::new(), via: None, inbox: None });
        s.flush(e).unwrap();
        let back = State::load(e).unwrap();
        let h = back.hints.get(&LabelId([1; 16])).unwrap();
        assert_eq!((h.index, h.via, h.inbox, h.hosts.len()), (3, Some(Tid::from_bytes([3; 15])), Some(src), 1));
        let h = back.hints.get(&LabelId([2; 16])).unwrap();
        assert_eq!((h.via, h.inbox), (None, None));
    }

    // spec/sync.md §5: a followed label keeps the key actor it follows for when an inbox
    // payload names the same label first (its static entry is still tried).
    #[test]
    fn inbox_hint_keeps_followed_key_actor_spec_sync_5() {
        let mut s = State::default();
        let (l, t, k) = (LabelId([1; 16]), Tid::from_bytes([2; 15]), Tid::from_bytes([3; 15]));
        s.add_hint(l, Hint { thing: t, index: 0, hosts: Vec::new(), via: Some(k), inbox: None });
        s.add_hint(l, Hint { thing: t, index: 0, hosts: Vec::new(), via: None, inbox: None });
        assert_eq!(s.hints.get(&l).and_then(|h| h.via), Some(k));
    }

    fn rows(e: &mut Engine, p: &[u8]) -> usize {
        let mut n = 0;
        e.run(|tx| {
            tx.scan(p, |_, _| {
                n += 1;
                Ok(())
            })
        })
        .unwrap();
        n
    }

    // spec/sync.md §5: an entry a host holds under a useless wrap places nothing, and stays
    // useless past `TOMBSTONE_LIFETIME` while the host holds it.
    #[test]
    fn useless_entry_held_nowhere_spec_sync_5() {
        let (h1, h2, l, b) = ([7u8; 32], [8u8; 32], LabelId([1; 16]), BlobId([2; 32]));
        let mut s = State { now: 1_000, ..State::default() };
        s.set_present(h1, l, b, true);
        assert!(s.held_anywhere(&l, &b));
        s.set_doubtful(h1, l, b, [3; WRAP_LEN]);
        assert!(s.present_anywhere(&l, &b) && !s.held_anywhere(&l, &b));
        s.set_present(h2, l, b, true);
        assert!(s.held_anywhere(&l, &b));
        s.expire_tombs(1_000 + osis_base::format::TOMBSTONE_LIFETIME_MS);
        assert!(s.is_gone_at(&h1, &l, &b), "still held there");
        s.set_present(h1, l, b, false);
        assert!(s.doubts.is_empty(), "the wrap goes with the entry");
        s.expire_tombs(1_000 + osis_base::format::TOMBSTONE_LIFETIME_MS);
        assert!(!s.is_gone_at(&h1, &l, &b));
    }

    // spec/sync.md §5, §7 (growth, notes/growth.md): a host's tombstoned answer is forgotten
    // after `TOMBSTONE_LIFETIME`, a dropped
    // body's carriers once no entry of it (or of a body they carry) is left and they are that
    // old, a certificate placement once its commit's parts are all dropped; each round trips
    // until then.
    #[test]
    fn records_dropped_after_their_lifecycle_spec_sync_7() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 965, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let life = osis_base::format::TOMBSTONE_LIFETIME_MS;
        let (h, l, b) = ([7u8; 32], LabelId([1; 16]), BlobId([2; 32]));
        let (body, mid, snap, other) = (CommitId([3; 32]), CommitId([4; 32]), CommitId([5; 32]), CommitId([6; 32]));
        let mut s = State { now: 1_000, ..State::default() };
        s.set_present(h, l, b, true);
        s.set_doubtful(h, l, b, [3; WRAP_LEN]);
        // body carried by mid, itself dropped and carried by snap; other's carrier stands alone
        s.set_entry(l, BlobId([9; 32]), Entry { wrap: [1; WRAP_LEN], stamp: None, cert: false, salt: None, kind: Kind::Commit { commit: body, parts: vec![0], ais: vec![0] }, memory: false });
        s.set_carrier(body, mid);
        s.set_carrier(mid, snap);
        s.set_carrier(other, snap);
        s.add_cert(l, body);
        s.add_cert(l, other);
        s.flush(e).unwrap();
        let mut s = State::load(e).unwrap();
        assert_eq!(s.gone.get(&(h, l, b)), Some(&1_000));
        assert_eq!(s.doubts.get(&(h, l, b)), Some(&[3; WRAP_LEN]));
        assert_eq!(s.carriers.get(&body).map(|c| (c.by.clone(), c.at)), Some((vec![mid], 1_000)));
        s.expire_tombs(1_000 + life - 1);
        s.sweep_carriers(1_000 + life - 1);
        s.set_present(h, l, b, false);
        s.flush(e).unwrap();
        assert_eq!((rows(e, GONE), rows(e, CARRIER)), (1, 3));
        assert_eq!(rows(e, DOUBT), 0);
        s.expire_tombs(1_000 + life);
        s.sweep_carriers(1_000 + life);
        s.sweep_certs(|c| *c == body);
        s.flush(e).unwrap();
        assert_eq!((rows(e, GONE), rows(e, CARRIER), rows(e, CERT)), (0, 2, 1), "body's chain kept, other's carrier and certificate gone");
        assert!(s.carriers.contains_key(&body) && s.carriers.contains_key(&mid));
        s.drop_entry(l, BlobId([9; 32]));
        s.sweep_carriers(1_000 + life);
        s.sweep_certs(|_| false);
        s.flush(e).unwrap();
        assert_eq!((rows(e, CARRIER), rows(e, CERT)), (0, 0));
        let back = State::load(e).unwrap();
        assert!(back.gone.is_empty() && back.carriers.is_empty() && back.certs.is_empty());
    }

    fn logged(e: &mut Engine) -> Vec<osis_store::NodeEvent> {
        e.run(|tx| Ok(tx.txn.log_read(None, 100)?)).unwrap().events.into_iter().map(|x| x.event).collect()
    }

    /// Bytes held for an entry: their blob ID.
    fn bytes(e: &mut Engine, seed: u8) -> BlobId {
        let blob = vec![seed; 40];
        let id = osis_label::blob_id(&blob);
        e.put_blobs(vec![(id, blob)]).unwrap();
        id
    }

    fn entry(wrap: u8) -> Entry {
        Entry { wrap: [wrap; WRAP_LEN], stamp: None, cert: false, salt: None, kind: Kind::Unknown, memory: false }
    }

    // spec: none (issues/net-reconnect.md, One node log): what a peer would be sent is one event;
    // a change only of what this node knows of the blob, or an ephemeral entry, is none.
    #[test]
    fn entries_write_log_events_with_their_flush() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 962, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let mut s = State { now: 5, ..State::default() };
        let (l, b) = (LabelId([1; 16]), bytes(e, 2));
        use osis_store::NodeEvent::{Added, Deleted};
        s.set_entry(l, b, entry(1));
        s.flush(e).unwrap();
        assert_eq!(logged(e), [Added(l, b)]);
        s.set_entry(l, b, Entry { kind: Kind::Bad, ..entry(1) });
        assert!(s.log.is_empty(), "what the blob turned out to be says nothing new to a peer");
        s.set_entry(l, b, entry(3));
        s.flush(e).unwrap();
        let end = e.run(|tx| Ok(tx.txn.log_end()?)).unwrap();
        assert_eq!(end, 2, "a new wrap is an event");
        s.set_entry(l, BlobId([3; 32]), Entry { memory: true, ..entry(1) });
        assert!(s.log.is_empty(), "an ephemeral entry draws nothing");
        s.remove_entry(l, b);
        s.flush(e).unwrap();
        assert_eq!(logged(e), [Deleted { label: l, blob: b, at: 5 }]);
        // expiry and junk go without a tombstone, by the same event
        let c = BlobId([4; 32]);
        s.set_entry(l, c, entry(1));
        s.drop_entry(l, c);
        s.flush(e).unwrap();
        assert!(logged(e).contains(&Deleted { label: l, blob: c, at: 5 }));
    }

    // spec: none (issues/net-reconnect.md, Built): an `Added` is logged when an entry becomes
    // servable: no event while its bytes are absent, one when they arrive, whichever comes first
    // of row and bytes, and an entry that keeps changing is one event of the log.
    #[test]
    fn an_entry_is_logged_when_its_bytes_are_held() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 964, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let mut s = State::default();
        let l = LabelId([1; 16]);
        let (blob, other) = (vec![7; 40], vec![8; 40]);
        let (b, c) = (osis_label::blob_id(&blob), osis_label::blob_id(&other));
        use osis_store::NodeEvent::Added;
        s.set_entry(l, b, entry(1));
        s.flush(e).unwrap();
        assert!(logged(e).is_empty(), "known, not servable: nothing");
        s.set_entry(l, b, entry(2));
        s.flush(e).unwrap();
        assert!(logged(e).is_empty(), "a new wrap of an absent entry is still nothing");
        let end = e.run(|tx| Ok(tx.txn.log_end()?)).unwrap();
        // bytes stored while the row is queued too: one event, at the arrival
        s.set_entry(l, c, entry(1));
        s.flush_storing(e, vec![(b, blob.clone()), (c, other)]).unwrap();
        assert_eq!(logged(e), [Added(l, c), Added(l, b)], "the arrivals log, once each");
        assert_eq!(e.run(|tx| Ok(tx.txn.log_end()?)).unwrap(), end + 2);
        // the same bytes again make nothing new
        s.flush_storing(e, vec![(b, blob)]).unwrap();
        assert_eq!(e.run(|tx| Ok(tx.txn.log_end()?)).unwrap(), end + 2);
        // the row arriving second, bytes held: one event by the set_entry path
        let d = bytes(e, 9);
        let m = LabelId([2; 16]);
        s.set_entry(m, d, entry(1));
        s.flush(e).unwrap();
        for w in 3..9 {
            s.set_entry(m, d, entry(w));
            s.flush(e).unwrap();
        }
        assert_eq!(logged(e).iter().filter(|x| **x == Added(m, d)).count(), 1, "compaction keeps one event per entry");
    }

    // spec: none (issues/net-reconnect.md, One node log): a label forgotten logs no deletion
    // (this node stopped holding it, nobody deleted its entries) and leaves the log with nothing of it.
    #[test]
    fn forgetting_drops_a_labels_events_without_a_deletion() {
        let mut lp = crate::local_peer::LocalPeer::new(1, 963, osis_base::WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let mut s = State::default();
        let (l, m) = (LabelId([1; 16]), LabelId([2; 16]));
        let (x, y) = (bytes(e, 1), bytes(e, 2));
        s.set_entry(l, x, entry(1));
        s.set_entry(m, y, entry(1));
        s.flush(e).unwrap();
        e.run(|tx| forget_records(tx, &BTreeSet::from([l]), &BTreeSet::new(), &BTreeSet::new(), &BTreeMap::new(), BTreeSet::new())).unwrap();
        assert_eq!(logged(e), [osis_store::NodeEvent::Added(m, y)]);
    }

    // spec: none (issues/net-reconnect.md, One node log; core/test/tla/net/ASSUMPTIONS.md: log and
    // record are one atomic unit): a crash at any write of a flush leaves the entry row and its
    // event both or neither.
    #[test]
    fn crash_during_flush_never_splits_entry_and_event() {
        let (l, b) = (LabelId([1; 16]), osis_label::blob_id(&[2; 40]));
        let ek = key(ENTRY, &[&l.0, &b.0]);
        let (mut seen_absent, mut seen_present) = (false, false);
        for k in 0..64 {
            let faults = osis_store::Faults::new();
            let backend = osis_store::MemoryBackend::with_faults(faults.clone());
            let root = osis_store::MemoryRoot::with_faults(faults.clone());
            let clock: std::sync::Arc<dyn osis_base::Clock> = std::sync::Arc::new(osis_base::ManualClock::new(osis_base::WallMs(1_700_000_000_000)));
            let mut e = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), crate::Config::default(), clock.clone(), Box::new(osis_crypto::SeededRng::from_u64(9))).unwrap();
            let mut s = State::default();
            e.put_blobs(vec![(b, vec![2; 40])]).unwrap();
            s.set_entry(l, b, entry(1));
            faults.at(k, osis_store::Fault::Crash);
            let crashed = s.flush(&mut e).is_err();
            let wrote = faults.writes();
            drop(e);
            faults.revive();
            let mut e = Engine::open(Box::new(backend), Box::new(root), crate::Config::default(), clock, Box::new(osis_crypto::SeededRng::from_u64(10))).unwrap();
            let present = e.run(|tx| Ok(tx.txn.get_local(&ek)?)).unwrap().is_some();
            assert_eq!(present, !logged(&mut e).is_empty(), "crash at write {k}: the entry and its event split");
            seen_absent |= !present;
            seen_present |= present;
            if !crashed && k > wrote {
                break;
            }
        }
        assert!(seen_absent && seen_present, "the crash points reach both outcomes");
    }
}
