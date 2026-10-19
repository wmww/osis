//! osis-keys: per-role epochs with forks, `/keys` and `/secrets` writes, box production and
//! opening, history boxes, derived secrets, the covers rule, the rotation planner, wrap epoch
//! choice, label epochs and token secrets (spec/crypto.md §3–§5, §7; spec/permissions.md §3).
//! Layer 3 (notes/architecture.md). Plan: plans/keys.md.
#![forbid(unsafe_code)]

pub mod aspects;
pub mod covers;
pub mod epoch;
pub mod error;
pub mod open;
pub mod planner;
pub mod produce;
pub mod tokens;
pub mod wrap;

pub use covers::{Departure, Member, covers, expired, may_encrypt_under, reseal_needed, rotate_first, uncovered};
pub use aspects::{KeysWrite, SecretsWrite, keyset, observe_keys, observe_secrets};
pub use epoch::{ActorEpochs, EpochInfo, ROLES, RoleEpochs, SUITE, is_newer, newest_of};
pub use error::Error;
pub use open::{MemorySecretStore, Opened, Opener, SecretStore, ingest, open_boxes, open_histories};
pub use osis_crypto::Epoch;
pub use planner::{Entry, Graph, MemoryGraph, PermGraph, Plan, lost_access, plan_departure, plan_inside};
pub use tokens::{levels, token_candidates, token_secrets};
pub use wrap::{WrapEpoch, label_role, newer_than_head, registered_epoch, registration_epochs, wrap_epoch};
pub use produce::{MemberKeys, Recipient, Rotated, Rotation, box_member, roles_up_to, rotate};
