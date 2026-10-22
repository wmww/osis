//! Token secrets of a delta by its retention (spec/crypto.md §7).

use crate::epoch::{ActorEpochs, RoleEpochs};
use crate::Error;
use osis_core::Role;
use osis_crypto::{Epoch, Secret32};
use osis_schema::PurgeBy;

/// Token levels: 1 admin secret of the thing, 2 write secret of the actor above the author
/// node, 3 write secret of the thing.
pub const LEVEL_ADMIN: u8 = 1;
pub const LEVEL_AUTHOR: u8 = 2;
pub const LEVEL_WRITER: u8 = 3;

/// The levels a retention calls for. `imported`: no level 2 (spec/crypto.md §7).
pub fn levels(by: PurgeBy, imported: bool) -> Vec<u8> {
    let mut v = Vec::new();
    if by >= PurgeBy::Admin {
        v.push(LEVEL_ADMIN);
    }
    if by >= PurgeBy::Author && !imported {
        v.push(LEVEL_AUTHOR);
    }
    if by >= PurgeBy::Writer {
        v.push(LEVEL_WRITER);
    }
    v
}

fn source<'a>(level: u8, thing: &'a ActorEpochs, author_actor: Option<&'a ActorEpochs>) -> Option<(&'a RoleEpochs, Role)> {
    match level {
        LEVEL_ADMIN => Some((&thing.admin, Role::Admin)),
        LEVEL_AUTHOR => author_actor.map(|a| (&a.write, Role::Write)),
        LEVEL_WRITER => Some((&thing.write, Role::Write)),
        _ => None,
    }
}

/// Token secrets for a new delta: per level, the newest current secret held; level 1 is
/// omitted when the admin secret is not held. `thing` is the
/// thing's epochs (derived for a plain thing), `author_actor` the actor directly above the
/// author node (none for an import).
pub fn token_secrets(by: PurgeBy, thing: &ActorEpochs, author_actor: Option<&ActorEpochs>) -> Result<Vec<(u8, Epoch, Secret32)>, Error> {
    let mut out = Vec::new();
    for l in levels(by, author_actor.is_none()) {
        let Some((re, role)) = source(l, thing, author_actor) else { continue };
        let Some((e, s)) = re.newest_held() else {
            // A writer that does not hold the admin secret omits level 1 (provisional,
            // issues/token-admin-secret.md); the other levels' secrets it must hold.
            if l == LEVEL_ADMIN {
                continue;
            }
            return Err(Error::NoSecret(role));
        };
        out.push((l, e, s.clone()));
    }
    Ok(out)
}

/// Candidate secrets for re-deriving a level's token: every held epoch, newest first (a token
/// holder tries its epochs, spec/crypto.md §7).
pub fn token_candidates<'a>(level: u8, thing: &'a ActorEpochs, author_actor: Option<&'a ActorEpochs>) -> Vec<(Epoch, &'a Secret32)> {
    source(level, thing, author_actor).map(|(re, _)| re.held_newest_first()).unwrap_or_default()
}
