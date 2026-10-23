//! Delete keys by level (spec/crypto.md §7).

use crate::epoch::{ActorEpochs, RoleEpochs};
use osis_crypto::{DeleteSecret, Epoch, Secret32, VerifyingKey};

/// Delete levels: 1 admin secret of the thing, 2 write secret of the actor above the author
/// node, 3 write secret of the thing.
pub const LEVEL_ADMIN: u8 = 1;
pub const LEVEL_AUTHOR: u8 = 2;
pub const LEVEL_WRITER: u8 = 3;

fn source<'a>(level: u8, thing: &'a ActorEpochs, author_actor: Option<&'a ActorEpochs>) -> Option<&'a RoleEpochs> {
    match level {
        LEVEL_ADMIN => Some(&thing.admin),
        LEVEL_AUTHOR => author_actor.map(|a| &a.write),
        LEVEL_WRITER => Some(&thing.write),
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
