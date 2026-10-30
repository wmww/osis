//! Delete keys by level (spec/crypto.md §7).

use crate::epoch::{ActorEpochs, RoleEpochs};
use osis_base::format::{DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER};
use osis_crypto::{DeleteSecret, Epoch, Secret32, VerifyingKey};

fn source<'a>(level: u8, thing: &'a ActorEpochs, author_actor: Option<&'a ActorEpochs>) -> Option<&'a RoleEpochs> {
    match level {
        DELETE_ADMIN => Some(&thing.admin),
        DELETE_AUTHOR => author_actor.map(|a| &a.write),
        DELETE_WRITER => Some(&thing.write),
        _ => None,
    }
}

/// The delete key of a level for a new delta: from the newest current secret held; `None` when
/// none is held. `thing` is the epochs of the actor whose keys the thing uses (itself, or the
/// nearest owner with secrets of its own), `author_actor` the actor directly above the author
/// node (none for an import).
pub fn delete_key(level: u8, thing: &ActorEpochs, author_actor: Option<&ActorEpochs>) -> Option<VerifyingKey> {
    source(level, thing, author_actor)?.newest_held().map(|(_, s)| DeleteSecret::derive(s).verifying_key())
}

/// Candidate secrets for re-deriving a level's delete key: every held epoch, newest first (a
/// holder tries its epochs, spec/crypto.md §7).
pub fn delete_candidates<'a>(level: u8, thing: &'a ActorEpochs, author_actor: Option<&'a ActorEpochs>) -> Vec<(Epoch, &'a Secret32)> {
    source(level, thing, author_actor).map(|re| re.held_newest_first()).unwrap_or_default()
}
