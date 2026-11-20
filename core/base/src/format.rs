//! Format constants (spec/wire.md §2, §12; spec/versioning.md §1). All are fixed by format version
//! 1 unless marked otherwise.

/// Format version this build writes and the newest it reads (spec/wire.md §2). fixed.
pub const FORMAT_VERSION: u64 = 1;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const MINUTE_MS: u64 = 60 * 1000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;

// CBOR tags (spec/data-model.md §5).
/// Set: tag 258 around a sorted array. fixed.
pub const TAG_SET: u64 = 258;
/// Retired, never reused: a decoder rejects it. fixed.
pub const TAG_RETIRED: u64 = 1616;
/// Enum: tag around `[case]` or `[case, payload]`. fixed.
pub const TAG_ENUM: u64 = 1617;
/// Link: tag around `[content hash, blob ID, suite || key]`. fixed.
pub const TAG_LINK: u64 = 1618;
/// Reserved for structs, unused. fixed.
pub const TAG_STRUCT_RESERVED: u64 = 1619;
/// A strong reference (spec/data-model.md §5, §8).
pub const TAG_STRONG: u64 = 1620;
/// A weak reference (spec/data-model.md §5, §8).
pub const TAG_WEAK: u64 = 1621;
/// A ticket (spec/data-model.md §5, §8 Tickets).
pub const TAG_TICKET: u64 = 1622;

/// Largest blob, prefix and ciphertext (spec/wire.md §2, §5). fixed.
pub const MAX_BLOB: usize = 8 * MIB;
/// Account rotations one Prove or one boxes payload carries (spec/wire.md §2, §9, §11.2).
pub const MAX_ROTATIONS: usize = 256;
/// Atomic values and header lists whose canonical encoding exceeds this are chunked
/// (spec/wire.md §2, §4; spec/data-model.md §6). fixed.
pub const CHUNK_THRESHOLD: usize = 128 * KIB;
/// Canonical bytes of one linked header list (spec/wire.md §2, §4): a resolved header lives in
/// memory at every node. Resource bound; past it a writer refuses and a receiver refuses the
/// commit as bad input; 0 would leave lists inline-only, infinity a hostile header unbounded
/// memory. Tess's choice; about 140 GB of chunks in one commit, 1.9e6 frontier IDs. fixed.
pub const MAX_LIST_BYTES: usize = 64 * MIB;
/// Levels of an account rotation's list tree (spec/wire.md §2, §4 List tree): at most 2^32 thing
/// lists per rotation. Resource bound: a rotator listing more things refuses the rotation; 0 lets
/// a rotation list one thing, infinity makes paths unbounded. Fixed at its largest useful size,
/// so a path (32 hashes) shows nothing of how many things a rotator lists. fixed.
pub const LIST_TREE_DEPTH: u32 = 32;
/// A fragment's links are grouped into link pages above this (spec/wire.md §2, §6). fixed.
pub const PAGE_TARGET: usize = 64 * KIB;
/// Sequence elements in runs without `Content` per writer's delta, pages included: bounds
/// the records a small delta can create (spec/crdt.md §3.3 rule 7, spec/wire.md §2). fixed.
pub const MAX_DELTA_BARE: u64 = 1 << 18;
/// Most items in a durable delta's root fragment or one of its pages: one per CBOR head, one
/// more per byte of a text string, so never more than the blob's bytes (spec/crdt.md §8,
/// spec/wire.md §2). fixed. Resource bound on what one blob decodes to (about 100-300 bytes per
/// item): an honest page or root fragment counts at most about 1.4 x 2^20 (notes/crdt.md, Page
/// items); 0 refuses every delta, infinity lets one 8 MiB blob decode to GBs.
pub const MAX_PAGE_ITEMS: usize = 1 << 21;

// Chunker (spec/wire.md §2, §6), shared by chunk trees and pages.
/// Smallest chunk or page, except the last. fixed.
pub const CHUNK_MIN: usize = 16 * KIB;
/// Largest chunk; a page closes at or above it. fixed.
pub const CHUNK_MAX: usize = 256 * KIB;
/// A cut needs the top this many bits of the gear hash zero (`h >> 48 == 0`, spec/wire.md §6). fixed.
pub const CHUNK_MASK_BITS: u32 = 16;
/// Most links per tree node or link page (spec/wire.md §2, §6). fixed.
pub const TREE_FANOUT: usize = 512;
/// Highest chunk tree level (spec/wire.md §6, §12). fixed.
pub const TREE_MAX_LEVEL: u64 = 48;

/// Blob framing version (spec/wire.md §5). fixed.
pub const BLOB_FRAMING_VERSION: u8 = 1;
/// Bytes of a blob prefix before its commitment groups: version, salt, expiry, class, le16 group count
/// (spec/wire.md §5).
pub const PREFIX_FIXED_LEN: usize = 28;
/// Bytes of one prefix commitment: level, then the 32-byte blinded delete key (spec/wire.md §5).
pub const COMMITMENT_LEN: usize = 33;
/// Delete levels (spec/crypto.md §7): keys derived from the thing's admin secret, from the write
/// secret of the commit's purge author, from the thing's write secret. fixed.
pub const DELETE_ADMIN: u8 = 1;
/// See `DELETE_ADMIN`. fixed.
pub const DELETE_AUTHOR: u8 = 2;
/// See `DELETE_ADMIN`. fixed.
pub const DELETE_WRITER: u8 = 3;
/// Most keys in a claim set (spec/wire.md §2, §8). fixed.
pub const MAX_CLAIMS: usize = 65_536;

/// Largest relay-only blob, prefix included (spec/wire.md §2, spec/sync-ids.md §6, spec/sync-compaction.md §2). fixed.
/// Resource bound: each relay goes to every subscriber, so it bounds the traffic one relay
/// causes (0: no ephemeral signals; `MAX_BLOB`: 8 MiB pushed per relay per subscriber).
pub const MAX_RELAY_BLOB: usize = 64 * KIB;

/// A commit more than this ahead of the receiver's wall clock is parked (spec/wire.md §2,
/// spec/crdt.md §2.2). fixed.
pub const MAX_DRIFT_MS: u64 = HOUR_MS;
/// Role-class deltas are kept at least this long after replaced (spec/wire.md §2,
/// spec/commits.md §5). fixed.
pub const ROLE_KEEP_MS: u64 = 90 * DAY_MS;
/// How long an inbox keeps its external-signal fires (spec/wire.md §2, spec/sync-inbox.md §1). fixed.
pub const INBOX_LIFETIME_MS: u64 = 90 * DAY_MS;
/// Deposits an admin leaves waiting under a sync ID per peer (spec/wire.md §2, spec/sync-inbox.md §4
/// Clearing deposits): half the recommended minimum budget, so the rest stays free. Resource bound
/// against a fill by a stranger (an inbox) or a reader; past it those with no expiry go first,
/// then earliest to expire. 0: nobody unconnected can fire on an inbox, and a reader's deposit
/// not judged yet may go; infinity: a filler holds the budget for good.
pub const DEPOSITS_WAITING: usize = 32;
/// See `DEPOSITS_WAITING`, in bytes: that many recommended budget entries of 32 KiB.
pub const DEPOSITS_WAITING_BYTES: usize = DEPOSITS_WAITING * 32 * 1024;
/// Most mint-admin links from a thing up its record chain to its key actor
/// (spec/wire.md §2, spec/permissions.md §1). fixed.
pub const MAX_CHAIN_DEPTH: usize = 64;
/// Most things listed in one stated path (spec/wire.md §2, §4 `Path`; spec/permissions.md §1).
/// Resource bound against hostile input: each listed thing costs a reader a point query per hop
/// and, while unjudgeable, a wait on its record. 0: no write through a holder; unbounded: a junk
/// path parks a commit on as many records as its writer lists. Matches `MAX_CHAIN_DEPTH`. fixed.
pub const MAX_PATH_THINGS: usize = 64;

/// The hops of a stated path marked direct (spec/wire.md §4 `marks`; notes/a1-spec/permissions.md §1 Path, Direct mark):
/// bit j marks hop j, joining members j and j + 1. A path has at most `MAX_PATH_THINGS` + 1 hops.
pub type PathMarks = u128;

/// Node policy default, not a format constant (spec/wire.md §2).
pub const TOMBSTONE_LIFETIME_MS: u64 = 30 * DAY_MS;

// Decoder limits (spec/wire.md §12, spec/data-model.md §5). Depth counts the arrays, maps and
// tags on the deepest path; scalars add nothing.
/// Deepest nesting of a value. fixed.
pub const MAX_VALUE_DEPTH: usize = 64;
/// Deepest nesting of any wire object; values inside it still obey `MAX_VALUE_DEPTH`. fixed.
pub const MAX_OBJECT_DEPTH: usize = 512;
/// Largest value encoding a decoder accepts by default: a value lives in one blob.
pub const MAX_VALUE_BYTES: usize = MAX_BLOB;
/// Longest AK or signal kind in bytes (spec/wire.md §4, §12). fixed.
pub const MAX_AK_BYTES: usize = 1024;
/// Most entries in the `rules` of one `retention^.0` delta (spec/commits.md §5); past it the
/// delta is no setting. Every node keeps what one says in memory, for every such delta. 0: no
/// setting can name an aspect; unbounded: `MAX_VALUE_BYTES` of AKs in every node's memory per
/// delta. fixed.
pub const MAX_RETENTION_ENTRIES: usize = 64;

/// Items by author in one purge request. Each walks its aspect's history, whoever asks (its right is
/// judged per delta), so this bounds one commit's cost to a few walks against one per item of a whole
/// list. 0: no purge by author; infinity: one small commit stalls every node for its items times the
/// aspect's length. More goes in further commits, at a write's price each.
pub const MAX_AUTHOR_ITEMS: usize = 32;
/// Longest URL (spec/wire.md §10, §12). fixed.
pub const MAX_URL_BYTES: usize = 256;

/// Largest node-to-node frame (spec/wire.md §11.1): protocol version 1, not a format constant.
pub const MAX_MESSAGE: usize = 9 * MIB;

/// Tid length in bytes: 120 bits (spec/data-model.md §1). fixed.
pub const TID_LEN: usize = 15;
/// Text form length of a tid: 20 base64url characters. fixed.
pub const TID_TEXT_LEN: usize = 20;
