//! osis-keys: per-role epochs with forks, `/keys` and `/secrets` writes, box production and
//! opening, history boxes, derived secrets, the covers rule, the rotation planner, wrap epoch
//! choice, label epochs and delete keys (spec/crypto.md §3–§5, §7; spec/permissions.md §3).
//! Layer 3 (notes/architecture.md). Notes: notes/crypto.md (osis-keys).
#![forbid(unsafe_code)]

pub mod aspects;
pub mod covers;
pub mod delete;
pub mod epoch;
pub mod error;
pub mod open;
pub mod planner;
pub mod produce;
pub mod wrap;

pub use covers::{Carries, Departure, HeldActors, Member, MemoryHeldActors, Via, covers, expired, may_encrypt_under, reseal_needed, rotate_first, uncovered};
pub use aspects::{KeysWrite, SecretsWrite, keyset, may_compact_secrets, observe_keys, observe_secrets, snapshot_keyed};
pub use epoch::{ActorEpochs, EpochInfo, MAX_FREE_N, MAX_READING, MAX_READING_PER_AUTHOR, Provenance, ROLES, RoleEpochs, SUITE, UNKNOWN_AUTHOR, Unchecked, is_newer, newest_of};
pub use error::Error;
pub use open::{HistoryAlts, Opened, Opener, ingest, ingest_with, open_boxes, open_histories};
pub use osis_crypto::Epoch;
pub use planner::{Entry, Graph, MemoryGraph, PermGraph, Plan, lost_access, plan_departure, plan_inside, reached};
pub use delete::{delete_candidates, delete_key};
pub use wrap::{WrapEpoch, label_role, newer_than_head, registered_epoch, registered_secret, registration_epochs, wrap_epoch};
pub use produce::{MemberKeys, Recipient, Rotated, Rotation, box_member, reseal_member, roles_up_to, rotate};
