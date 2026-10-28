//! Format constants (spec/wire.md §2, §13; spec/versioning.md §1). All are fixed by format version
//! 1 unless marked otherwise.

use crate::SchemaId;

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
/// A fragment's links are grouped into link pages above this (spec/wire.md §2, §6). fixed.
pub const PAGE_TARGET: usize = 64 * KIB;
/// Sequence elements in runs without `Content` per writer or import delta, pages included: bounds
/// the records a small delta can create (spec/crdt.md §3.3 rule 7, spec/wire.md §2). fixed.
pub const MAX_DELTA_BARE: u64 = 1 << 18;

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
/// Most keys in a claim set (spec/wire.md §2, §8). fixed.
pub const MAX_CLAIMS: usize = 65_536;

/// A commit more than this ahead of the receiver's wall clock is parked (spec/wire.md §2,
/// spec/crdt.md §2.2). fixed.
pub const MAX_DRIFT_MS: u64 = HOUR_MS;
/// Membership deltas are kept at least this long after replaced (spec/wire.md §2,
/// spec/commits.md §5). fixed.
pub const MEMBERSHIP_KEEP_MS: u64 = 90 * DAY_MS;
/// Added to the relative keep-at-most bound of a body with a live write (spec/wire.md §2,
/// spec/commits.md §5). fixed.
pub const AT_MOST_GRACE_MS: u64 = HOUR_MS;
/// Inbox blob lifetime (spec/wire.md §2, §9). fixed.
pub const INBOX_LIFETIME_MS: u64 = 90 * DAY_MS;
/// Heartbeat bounds (spec/wire.md §2, spec/permissions.md §4). fixed.
pub const HEARTBEAT_MIN_LIFETIME_MS: u64 = DAY_MS;
/// See `HEARTBEAT_MIN_LIFETIME_MS`. fixed.
pub const HEARTBEAT_MAX_LIFETIME_MS: u64 = 14 * DAY_MS;
/// See `HEARTBEAT_MIN_LIFETIME_MS`. fixed.
pub const HEARTBEAT_MIN_INTERVAL_MS: u64 = 6 * HOUR_MS;
/// Most import resolution hops (spec/wire.md §2, spec/permissions.md §7). fixed.
pub const RESOLUTION_HOPS: usize = 8;
/// Most owner links from a thing up to its key actor (spec/wire.md §2, spec/permissions.md
/// §1). fixed.
pub const MAX_OWNER_DEPTH: usize = 64;
/// Canonical bytes of the distinct linked tenure frontiers of one roster snapshot (spec/wire.md
/// §2, spec/permissions.md §6). fixed.
pub const MAX_LINKED_FRONTIERS: usize = 64 * MIB;
/// Core schema ID (spec/wire.md §2, spec/data-model.md §9). fixed.
pub const CORE_SCHEMA_ID: SchemaId = SchemaId([0; 16]);
/// Current core schema revision (spec/wire.md §2, spec/data-model.md §9); bumped on each core publish.
pub const CORE_SCHEMA_REVISION: u64 = 2;

/// Blind-node policy default, not a format constant (spec/wire.md §2).
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
/// Longest URL (spec/wire.md §10, §13). fixed.
pub const MAX_URL_BYTES: usize = 256;

/// Largest node-to-node frame (spec/wire.md §11.1): protocol version 1, not a format constant.
pub const MAX_MESSAGE: usize = 9 * MIB;

/// Tid length in bytes: 120 bits (spec/data-model.md §1). fixed.
pub const TID_LEN: usize = 15;
/// Text form length of a tid: 20 base64url characters. fixed.
pub const TID_TEXT_LEN: usize = 20;
