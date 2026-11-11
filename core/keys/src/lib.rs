//! osis-keys: per-role epochs with forks, `keys.0` and `secrets.0` writes, box production and
//! opening, history boxes, derived secrets, the covers rule, holder actors (sealing, staleness, key
//! access), possession, the things a removal reaches, wrap epoch
//! choice, label epochs and delete keys (spec/crypto.md §3–§5, §7; spec/permissions.md §3).
//! Layer 3 (notes/architecture.md). Notes: notes/crypto.md (osis-keys).
#![forbid(unsafe_code)]

pub mod account;
pub mod aspects;
pub mod covers;
pub mod delete;
pub mod epoch;
pub mod members;
pub mod error;
pub mod names;
pub mod open;
pub mod planner;
pub mod possession;
pub mod produce;
pub mod wrap;

pub use covers::{Departure, Holder, Maker, covers, fork_merger, may_encrypt_under, merge_due, named, reseal_missing, reseal_needed, uncovered};
pub use members::{Grant, Keysets, Seal, boxing_keyless, key_access, seal_keyset, stale};
pub use account::{account_epoch, account_keysets};
pub use aspects::{KeysWrite, SecretsWrite, keyset, may_compact_secrets, observe_secrets, snapshot_keyed};
pub use epoch::{ActorEpochs, EpochInfo, MAX_FREE_N, MAX_READING, MAX_READING_PER_AUTHOR, Provenance, ROLES, RoleEpochs, SUITE, UNKNOWN_AUTHOR, Unchecked, is_newer, newest_of};
pub use names::{AllHeld, Held, Key, Name, Names, NamesDigest, Own};
pub use error::Error;
pub use open::{HistoryAlts, Opened, Opener, ingest, ingest_with, open_boxes, open_histories};
pub use osis_crypto::Epoch;
pub use planner::{Graph, MemoryGraph, PermGraph, lost_access, reached};
pub use delete::{delete_candidates, delete_key};
pub use wrap::{label_role, newer_than_head, registered_epoch, registered_secret, registration_epochs, wrap_epoch};
pub use produce::{HistoryBox, HistoryBoxes, HolderKeys, LeftOut, Recipient, Rotated, Rotation, box_epoch, box_holder, history_adds, history_boxes, roles_up_to, rotate, rotate_leaving_out, symmetric_box};
