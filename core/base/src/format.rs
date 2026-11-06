//! Format constants (spec/wire.md §2, §13; spec/versioning.md §1). All are fixed by format version
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
/// Tid: tag around a 15-byte byte string. fixed.
pub const TAG_TID: u64 = 1616;
/// Enum: tag around `[case]` or `[case, payload]`. fixed.
pub const TAG_ENUM: u64 = 1617;
/// Link: tag around `[content hash, blob ID, suite || key]`. fixed.
pub const TAG_LINK: u64 = 1618;
/// Reserved for structs, unused. fixed.
pub const TAG_STRUCT_RESERVED: u64 = 1619;

/// Largest blob, prefix and ciphertext (spec/wire.md §2, §5). fixed.
pub const MAX_BLOB: usize = 8 * MIB;
/// Atomic values and header lists whose canonical encoding exceeds this are chunked
/// (spec/wire.md §2, §4; spec/data-model.md §6). fixed.
pub const CHUNK_THRESHOLD: usize = 128 * KIB;
/// Canonical bytes of one linked header list (spec/wire.md §2, §4): a resolved header lives in
/// memory at every node. Resource bound; past it a writer refuses and a receiver refuses the
/// commit as bad input; 0 would leave lists inline-only, infinity a hostile header unbounded
/// memory. Tess's choice; about 140 GB of chunks in one commit, 1.9e6 frontier IDs. fixed.
pub const MAX_LIST_BYTES: usize = 64 * MIB;
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
/// Highest chunk tree level (spec/wire.md §6, §13). fixed.
pub const TREE_MAX_LEVEL: u64 = 48;

/// Blob framing version (spec/wire.md §5). fixed.
pub const BLOB_FRAMING_VERSION: u8 = 1;
/// Bytes of a blob prefix before its commitment groups: version, salt, expiry, class, le16 group count
/// (spec/wire.md §5).
pub const PREFIX_FIXED_LEN: usize = 28;
/// Bytes of one prefix commitment: level, then the 32-byte blinded delete key (spec/wire.md §5).
pub const COMMITMENT_LEN: usize = 33;
/// Delete levels (spec/crypto.md §7): keys derived from the thing's admin secret, from the write
/// secret of the actor directly above the author node (the author chain), from the thing's write
/// secret. fixed.
pub const DELETE_ADMIN: u8 = 1;
/// See `DELETE_ADMIN`. fixed.
pub const DELETE_AUTHOR: u8 = 2;
/// See `DELETE_ADMIN`. fixed.
pub const DELETE_WRITER: u8 = 3;
/// Most keys in a claim set (spec/wire.md §2, §8). fixed.
pub const MAX_CLAIMS: usize = 65_536;

/// Largest relay-only blob, prefix included (spec/wire.md §2, spec/sync.md §5, §9). fixed.
/// Resource bound: each relay goes to every subscriber, so it bounds the traffic one upload
/// causes (0: no signals; `MAX_BLOB`: 8 MiB pushed per upload per subscriber).
pub const MAX_RELAY_BLOB: usize = 64 * KIB;

/// A commit more than this ahead of the receiver's wall clock is parked (spec/wire.md §2,
/// spec/crdt.md §2.2). fixed.
pub const MAX_DRIFT_MS: u64 = HOUR_MS;
/// Role-class deltas are kept at least this long after replaced (spec/wire.md §2,
/// spec/commits.md §5). fixed.
pub const ROLE_KEEP_MS: u64 = 90 * DAY_MS;
/// Inbox blob lifetime (spec/wire.md §2, §9). fixed.
pub const INBOX_LIFETIME_MS: u64 = 90 * DAY_MS;
/// Deposits an admin leaves waiting under an inbox label per host (spec/wire.md §2, spec/sync.md
/// §5): half the recommended minimum budget, so the rest stays free. Resource bound against a
/// stranger's fill; past it what is no invite request goes first, then the requests earliest to
/// expire (a sender re-sends after `INBOX_LIFETIME`). 0: nobody unconnected can invite; infinity:
/// a stranger holds the budget for `INBOX_LIFETIME`.
pub const INBOX_WAITING: usize = 32;
/// See `INBOX_WAITING`, in bytes: that many recommended budget entries of 32 KiB.
pub const INBOX_WAITING_BYTES: usize = INBOX_WAITING * 32 * 1024;
/// Heartbeat bounds (spec/wire.md §2, spec/permissions.md §4). fixed.
pub const HEARTBEAT_MIN_LIFETIME_MS: u64 = DAY_MS;
/// See `HEARTBEAT_MIN_LIFETIME_MS`. fixed.
pub const HEARTBEAT_MAX_LIFETIME_MS: u64 = 14 * DAY_MS;
/// See `HEARTBEAT_MIN_LIFETIME_MS`. fixed.
pub const HEARTBEAT_MIN_INTERVAL_MS: u64 = 6 * HOUR_MS;
/// Most suspect aspects one heartbeat reports (spec/wire.md §2, spec/permissions.md §4); the
/// rest wait for those to clear. fixed.
pub const MAX_HEARTBEAT_SUSPECTS: usize = 32;
/// Most links (owner and first-admin) from a thing up its record chain to its key actor
/// (spec/wire.md §2, spec/permissions.md §1). fixed.
pub const MAX_OWNER_DEPTH: usize = 64;

/// Host policy default, not a format constant (spec/wire.md §2).
pub const TOMBSTONE_LIFETIME_MS: u64 = 30 * DAY_MS;

// Decoder limits (spec/wire.md §13, spec/data-model.md §5). Depth counts the arrays, maps and
// tags on the deepest path; scalars add nothing.
/// Deepest nesting of a value. fixed.
pub const MAX_VALUE_DEPTH: usize = 64;
/// Deepest nesting of any wire object; values inside it still obey `MAX_VALUE_DEPTH`. fixed.
pub const MAX_OBJECT_DEPTH: usize = 512;
/// Largest value encoding a decoder accepts by default: a value lives in one blob.
pub const MAX_VALUE_BYTES: usize = MAX_BLOB;
/// Longest AK or signal kind in bytes (spec/wire.md §4, §13). fixed.
pub const MAX_AK_BYTES: usize = 1024;
/// Most entries of one `required.0^` delta (spec/commits.md §5); past it, or with a prefix past
/// `MAX_AK_BYTES`, the delta requires nothing. Every node keeps what one says in memory, for
/// every such delta. 0: no setting can say anything; unbounded: `MAX_VALUE_BYTES` of prefixes in
/// every node's memory per delta. fixed.
pub const MAX_REQUIRED_ENTRIES: usize = 64;

/// Items by author in one purge request. Each walks its aspect's history, whoever asks (its right is
/// judged per delta), so this bounds one commit's cost to a few walks against one per item of a whole
/// list. 0: no purge by author; infinity: one small commit stalls every node for its items times the
/// aspect's length. More goes in further commits, at a write's price each.
pub const MAX_AUTHOR_ITEMS: usize = 32;
/// Longest URL (spec/wire.md §10, §13). fixed.
pub const MAX_URL_BYTES: usize = 256;

/// Largest node-to-node frame (spec/wire.md §11.1): protocol version 1, not a format constant.
pub const MAX_MESSAGE: usize = 9 * MIB;

/// Tid length in bytes: 120 bits (spec/data-model.md §1). fixed.
pub const TID_LEN: usize = 15;
/// Text form length of a tid: 20 base64url characters. fixed.
pub const TID_TEXT_LEN: usize = 20;
