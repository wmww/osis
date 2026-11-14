//! Protocol version 1 limits and the sync side's node policy (spec/wire.md §2), and the
//! per-message caps and decoder limits of spec/wire.md §11-§13. Format constants live in
//! `osis_base::format`; a value here is the spec's, so its 0/∞ case is the spec's (spec/wire.md
//! §2, notes/arbitrary-values-table.md).

pub use osis_base::format::{MAX_BLOB, MAX_MESSAGE, MAX_OBJECT_DEPTH, MAX_VALUE_DEPTH};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

/// The greatest `max_reply`, and the bound on a peer's untaken bytes for a push (spec/wire.md §2).
pub const REPLY_BUDGET: usize = MAX_MESSAGE - 64 * KIB;
/// The smallest `max_reply`, and the reply allowance of every kind without its own (spec/wire.md §2).
pub const SMALL_REPLY: usize = 16 * KIB;
/// Bytes a requester keeps in flight per connection (spec/wire.md §2, spec/sync-streams.md §1).
pub const WINDOW: usize = 16 * MIB;
/// Live subscriptions per connection (spec/wire.md §2).
pub const MAX_SUBS: usize = 4096;
/// Authenticated sessions of one client actor (spec/wire.md §2).
pub const MAX_CONNS_PER_CLIENT: usize = 8;
/// Actor proofs in one Prove or Proved (spec/wire.md §2).
pub const MAX_PROOFS: usize = 256;
/// Account rotations in one Prove (spec/wire.md §2, §11.2 Prove).
pub const MAX_PROVE_ROTATIONS: usize = 256;
/// Tags in one Resume: ⌊(`MAX_MESSAGE` − 64) / 34⌋, a tag's encoding 34 bytes (spec/wire.md §2).
pub const MAX_RESUME_TAGS: usize = (MAX_MESSAGE - 64) / 34;

/// Protocol versions one Hello lists (spec/wire.md §11.1).
pub const MAX_HELLO_VERSIONS: usize = 16;
/// The Hello frame, its 4-byte length included (spec/wire.md §11.1).
pub const MAX_HELLO_FRAME: usize = 256;
/// Request ids are below 2^32 (spec/wire.md §11.1).
pub const MAX_ID: u64 = u32::MAX as u64;
/// The top bit of the ids of the shared set's and the stream's requests (spec/wire.md §11.2,
/// Shared-set request ids).
pub const TOP_BIT: u32 = 1 << 31;
/// NoRecord's one id (spec/wire.md §11.2).
pub const NO_RECORD_ID: u32 = TOP_BIT;

/// Items in one Delete, and so codes in its Status (spec/wire.md §11.2, Per-message caps).
pub const MAX_DELETE_ITEMS: usize = 1024;
/// Blob IDs in one Fetch, and so items in its FetchReply (spec/wire.md §11.2).
pub const MAX_FETCH_IDS: usize = 1024;
/// Items in one Offer or Lost, and so answers in its Shared (spec/wire.md §11.2).
pub const MAX_OFFER_ITEMS: usize = 1024;
/// Hits in one ByRole item (spec/wire.md §11.2 Offer).
pub const MAX_ITEM_HITS: usize = 256;
/// Sync IDs in one Members page (spec/wire.md §11.2 Digest).
pub const MAX_MEMBERS: usize = 4096;
/// An opaque node-log cursor (spec/wire.md §11.2 Pull, Lost).
pub const MAX_CURSOR_BYTES: usize = 256;
/// A client-port bearer secret, exactly (spec/wire.md §11.2 Client port).
pub const CLIENT_SECRET_LEN: usize = 32;
/// A client-port session id, exactly (spec/wire.md §11.2 Client port).
pub const SESSION_ID_LEN: usize = 16;
/// A suspect entry's digest, exactly (spec/wire.md §11.2 Stranded and Suspect).
pub const SUSPECT_DIGEST_LEN: usize = 16;

/// A step's greatest canonical encoding: nine fixed-size items, `prev` present (spec/wire.md §8).
pub const MAX_STEP_BYTES: usize = 323;
/// A step's greatest encoding as a byte string in a message (spec/wire.md §11.2 Offer: 326).
pub const MAX_STEP_WIRE: usize = MAX_STEP_BYTES + 3;
/// Steps a Behind item's answer carries at most: ⌊`REPLY_BUDGET` / 326⌋ (spec/wire.md §11.2
/// Offer, the step bound; past it the item is answered 4).
pub const MAX_BEHIND_STEPS: usize = REPLY_BUDGET / MAX_STEP_WIRE;

/// Golomb-Rice parameter of a beacon filter (spec/wire.md §11.2 Beacons).
pub const BEACON_P: u32 = 8;
/// Entries in one filter; past it the connection closes (spec/wire.md §11.2 Beacons).
pub const MAX_FILTER_ENTRIES: u64 = 1 << 22;
/// The narrowest filter: `f` of an empty or one-entry filter (spec/wire.md §11.2 Beacons).
pub const MIN_FILTER_WIDTH: u8 = BEACON_P as u8;
/// The widest filter: `ceil(log2(MAX_FILTER_ENTRIES)) + 8` (spec/wire.md §11.2 Beacons).
pub const MAX_FILTER_WIDTH: u8 = 22 + BEACON_P as u8;

/// CBOR data items in one message, counted before it is decoded (spec/wire.md §13).
pub const MAX_MESSAGE_ITEMS: usize = 1 << 20;

// Node policy (spec/wire.md §2) the sync side applies. `TOMBSTONE_LIFETIME_MS` is
// `osis_base::format`'s, `RECORD_BUDGET` and `INCARNATIONS_KEPT` osis-store's, `MAX_DELIVERED`
// and `LOST_HEARD_WAIT_MS` the engine's, where each is used.

/// How long a complete pass waits for a peer whose record holds the sync ID: recommended
/// 1 hour (spec/wire.md §2, spec/sync-status.md §1).
pub const PASS_WAIT_MS: u64 = 60 * 60 * 1000;
/// The recommended minimum deposit budget of a sync ID whose current step lists `claims`
/// claims: `64 + 4 × claims` entries and that many × 32 KiB bytes (spec/wire.md §2,
/// spec/sync-inbox.md §3).
pub fn deposit_budget(claims: usize) -> (usize, usize) {
    let entries = 64 + 4 * claims;
    (entries, entries * 32 * KIB)
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/wire.md §2 (protocol version 1 limits): the derived limits are the spec's numbers
    #[test]
    fn derived_limits_spec_wire_2() {
        assert_eq!(MAX_MESSAGE, 9_437_184);
        assert_eq!(REPLY_BUDGET, 9_437_184 - 65_536);
        assert_eq!(MAX_RESUME_TAGS, 277_562);
        assert_eq!(MAX_BEHIND_STEPS, 28_747);
        assert_eq!(deposit_budget(4), (80, 80 * 32 * 1024));
    }
}
