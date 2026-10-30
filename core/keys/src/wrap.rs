//! Which epoch to wrap under (spec/crypto.md §5) and which epochs label role keys come from
//! (spec/sync.md §2, §5). osis-label derives and uses the keys.

use crate::epoch::{ActorEpochs, RoleEpochs, is_newer};
use osis_base::Role;
use osis_crypto::{Epoch, LabelRole, Secret32, VerifyingKey, label_role_key};

/// The wrap epoch for an upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapEpoch {
    /// The newest current (established) read epoch whose secret is held.
    Current(Epoch),
    /// No current secret held: only the stranded heartbeat is placed, under the newest
    /// established secret held (spec/permissions.md §4).
    Stranded(Epoch),
    /// No established read secret at all.
    None,
}

pub fn wrap_epoch(read: &RoleEpochs) -> WrapEpoch {
    if let Some((e, _)) = read.newest_held() {
        return WrapEpoch::Current(e);
    }
    match read.newest_secret() {
        Some((e, _)) => WrapEpoch::Stranded(e),
        None => WrapEpoch::None,
    }
}

/// The label role a group role secret derives.
pub fn label_role(r: Role) -> LabelRole {
    match r {
        Role::Read => LabelRole::Sync,
        Role::Write => LabelRole::Write,
        Role::Admin => LabelRole::Delete,
    }
}

/// The epochs a registration uses: the newest (established) of each role, with its secret
/// (spec/permissions.md §3). None when a role's newest is not held (only an admin, holding all three, registers).
pub fn registration_epochs(a: &ActorEpochs) -> Option<[(Epoch, &Secret32); 3]> {
    let get = |r: Role| -> Option<(Epoch, &Secret32)> {
        let re = a.role(r);
        let e = re.newest()?;
        re.secret(&e).map(|s| (e, s))
    };
    Some([get(Role::Read)?, get(Role::Write)?, get(Role::Admin)?])
}

/// The held epoch of role `r` whose label key at `index` is `key` (a server head's registered
/// key): the node talks to that server with it (spec/sync.md §2). Any held secret, established
/// or not: opening a label is not encrypting under (spec/crypto.md §4). A stamp, step or delete
/// under it needs `RoleEpochs::is_established`.
pub fn registered_epoch(re: &RoleEpochs, r: Role, index: u64, key: &VerifyingKey) -> Option<Epoch> {
    registered_secret(re, r, index, key).map(|(e, _)| e)
}

/// `registered_epoch` with the secret that derives `key` (reading-only ones
/// included).
pub fn registered_secret<'a>(re: &'a RoleEpochs, r: Role, index: u64, key: &VerifyingKey) -> Option<(Epoch, &'a Secret32)> {
    re.held_newest_first().into_iter().find(|(_, s)| label_role_key(label_role(r), s, index).verifying_key() == *key)
}

/// Whether an admin holds an established epoch newer than a head registers, per role
/// (spec/sync.md §5): it then issues the next step there. `head` gives the head's epoch per role
/// (read, write, admin) where the admin holds it; a role whose head epoch it does not hold returns
/// false (it walks first), and so does an unestablished head admin epoch (the step is signed
/// under its delete key: encrypting under, spec/crypto.md §4; the admin downloads its rotation
/// commit first).
pub fn newer_than_head(a: &ActorEpochs, head: [Option<Epoch>; 3]) -> bool {
    let mut newer = false;
    for (r, h) in [Role::Read, Role::Write, Role::Admin].into_iter().zip(head) {
        let Some(h) = h else { return false };
        if r == Role::Admin && !a.role(r).is_established(&h) {
            return false;
        }
        if let Some(n) = a.role(r).newest()
            && is_newer(&n, &h)
        {
            newer = true;
        }
    }
    newer
}
