//! Which epoch to wrap under (spec/crypto.md §5) and which epochs label role keys come from
//! (spec/sync-ids.md §2, spec/sync-ids.md §6). osis-label derives and uses the keys.

use crate::epoch::{ActorEpochs, RoleEpochs};
use osis_base::Role;
use osis_crypto::{Epoch, LabelRole, Secret32, SigningSecret, VerifyingKey, label_role_key};

/// The wrap epoch for an upload: the newest current (established) read epoch whose secret is
/// held. None: the node is stranded and places nothing (spec/crypto.md §5).
pub fn wrap_epoch(read: &RoleEpochs) -> Option<Epoch> {
    read.newest_held().map(|(e, _)| e)
}

/// The epochs a registration uses: the newest (established) of each role in `Role::ALL` order,
/// with its secret (spec/permissions.md §3): the sync, write and admin epochs derive the step's
/// keys, the read epoch its claim set. None when a role's newest is not held (only an admin,
/// holding every role, registers).
pub fn registration_epochs(a: &ActorEpochs) -> Option<[(Epoch, &Secret32); 4]> {
    let get = |r: Role| -> Option<(Epoch, &Secret32)> {
        let re = a.role(r);
        let e = re.newest()?;
        re.secret(&e).map(|s| (e, s))
    };
    Some([get(Role::Sync)?, get(Role::Read)?, get(Role::Write)?, get(Role::Admin)?])
}

/// The held epoch of `l`'s group role whose label key is `key` (a host head's
/// registered key): the node talks to that host with it (spec/sync-ids.md §2). Any held secret,
/// established or not: opening a label is not encrypting under (spec/crypto.md §4). A stamp,
/// step or delete under it needs `RoleEpochs::is_established`.
pub fn registered_epoch(a: &ActorEpochs, l: LabelRole, key: &VerifyingKey) -> Option<Epoch> {
    registered_key(a, l, key).map(|(e, _)| e)
}

/// `registered_epoch` with the label key it derives (reading-only secrets included): found by
/// deriving each held secret's, so the one found is not derived again.
pub fn registered_key(a: &ActorEpochs, l: LabelRole, key: &VerifyingKey) -> Option<(Epoch, SigningSecret)> {
    a.role(l.role()).held_newest_first().into_iter().map(|(e, s)| (e, label_role_key(l, s))).find(|(_, k)| k.verifying_key() == *key)
}

/// Whether an admin holds an established epoch newer than a head registers, per label role
/// (spec/sync-ids.md §6): it then issues the next step there. `head` gives the head's epoch per
/// label role (`LabelRole::ALL`: sync, write, delete) where the admin holds it; a role whose
/// head epoch it does not hold returns false (it walks first), and so does an unestablished head
/// admin epoch (the step is signed under its delete key: encrypting under, spec/crypto.md §4;
/// the admin downloads its rotation commit first).
pub fn newer_than_head(a: &ActorEpochs, head: [Option<Epoch>; 3]) -> bool {
    let mut newer = false;
    for (r, h) in LabelRole::ALL.map(LabelRole::role).into_iter().zip(head) {
        let Some(h) = h else { return false };
        if r == Role::Admin && !a.role(r).is_established(&h) {
            return false;
        }
        if let Some(n) = a.role(r).newest()
            && a.role(r).is_newer(&n, &h)
        {
            newer = true;
        }
    }
    newer
}
