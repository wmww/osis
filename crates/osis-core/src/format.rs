//! Format constants (spec/overview.md, Conventions; spec/versioning.md §1). Each says whether the
//! spec fixes it (`fixed`) or plans/protocol-spec.md still has to (`provisional`).

/// Format version this build writes and the newest it reads. provisional (no version 1 freeze yet).
pub const FORMAT_VERSION: u64 = 1;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const MINUTE_MS: u64 = 60 * 1000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DAY_MS: u64 = 24 * HOUR_MS;

// CBOR tags (spec/data-model.md §5).
/// Set: tag 258 around a sorted array. fixed.
pub const TAG_SET: u64 = 258;
/// Tid: tag around a 15-byte byte string. provisional (TBD in 256..65535, IANA check pending).
pub const TAG_TID: u64 = 41500;
/// Enum: tag around `[case]` or `[case, payload]`. provisional.
pub const TAG_ENUM: u64 = 41501;
/// Link: tag around `[content hash, blob ID, suite || key]`. provisional.
pub const TAG_LINK: u64 = 41502;
/// Reserved for structs, unused. provisional.
pub const TAG_STRUCT_RESERVED: u64 = 41503;

/// Largest blob (spec/data-model.md §6, "a few MB"). provisional.
pub const MAX_BLOB: usize = 4 * MIB;
/// Atomic values whose canonical encoding exceeds this are chunked (spec/data-model.md §6,
/// "a few hundred KB"). provisional.
pub const CHUNK_THRESHOLD: usize = 256 * KIB;
/// A fragment's element array is paged above this (spec/crdt.md §8). fixed.
pub const PAGE_TARGET: usize = 64 * KIB;

// Chunker (spec/crdt.md §8, shared with spec/data-model.md §6). Sizes fixed; gear table and mask
// provisional (see `chunker`).
/// Smallest chunk or page, except the last. fixed.
pub const CHUNK_MIN: usize = 16 * KIB;
/// Average chunk or page size. fixed.
pub const CHUNK_AVG: usize = 64 * KIB;
/// Largest chunk. fixed.
pub const CHUNK_MAX: usize = 256 * KIB;

/// A commit more than this ahead of the receiver's wall clock is parked (spec/crdt.md §2.2). fixed.
pub const MAX_DRIFT_MS: u64 = HOUR_MS;
/// Membership deltas are kept at least this long after replaced (spec/commits.md §5). fixed.
pub const MEMBERSHIP_KEEP_MS: u64 = 90 * DAY_MS;
/// Inbox blob lifetime (spec/sync.md §2; notes/sync.md). provisional (90 days proposed).
pub const INBOX_LIFETIME_MS: u64 = 90 * DAY_MS;
/// Heartbeat bounds (spec/permissions.md §4). fixed.
pub const HEARTBEAT_MIN_LIFETIME_MS: u64 = DAY_MS;
/// See `HEARTBEAT_MIN_LIFETIME_MS`. fixed.
pub const HEARTBEAT_MAX_LIFETIME_MS: u64 = 14 * DAY_MS;
/// See `HEARTBEAT_MIN_LIFETIME_MS`. fixed.
pub const HEARTBEAT_MIN_INTERVAL_MS: u64 = 6 * HOUR_MS;
/// Blind-node policy default, not a format constant (spec/overview.md; notes/sync.md).
pub const TOMBSTONE_LIFETIME_MS: u64 = 30 * DAY_MS;

// Decoder limits (plans/protocol-spec.md item 8 fixes per-object limits). provisional.
/// Deepest nesting of a value (arrays, maps, tags each count one level).
pub const MAX_VALUE_DEPTH: usize = 128;
/// Largest value encoding a decoder accepts by default: a value lives in one blob.
pub const MAX_VALUE_BYTES: usize = MAX_BLOB;

/// Tid length in bytes: 120 bits (spec/data-model.md §1). fixed.
pub const TID_LEN: usize = 15;
/// Text form length of a tid: 20 base64url characters. fixed.
pub const TID_TEXT_LEN: usize = 20;
