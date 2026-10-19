//! Departures and the covers rule (spec/crypto.md §4), re-seal triggers (spec/permissions.md §3).

use crate::aspects::{box_key, from_schema};
use crate::epoch::{ActorEpochs, ROLES};
use osis_core::format::MAX_DRIFT_MS;
use osis_core::{Role, Tid, WallMs};
use osis_crypto::Epoch;
use osis_schema::core_types::{BoxKey, SecretBox, Secrets};
use std::collections::BTreeSet;

/// A departure from an actor A (spec/crypto.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Departure {
    /// Member M removed, demoted below `from`, or past its `until`: it lost `from` and above.
    Member { member: Tid, from: Role },
    /// A departure inside member M (a device of M, a member of an actor under M), after which
    /// M's keysets rotated.
    Inside { member: Tid },
}

impl Departure {
    /// The departure an edge change makes: `old` and `new` are the member's roles before and
    /// after (none = no edge, or `until` passed).
    pub fn of_change(member: Tid, old: Option<Role>, new: Option<Role>) -> Option<Departure> {
        let from = match new {
            None => Role::Read,
            Some(Role::Read) => Role::Write,
            Some(Role::Write) => Role::Admin,
            Some(Role::Admin) => return None,
        };
        (old >= Some(from)).then_some(Departure::Member { member, from })
    }

    /// The roles of A it concerns.
    pub fn roles(&self) -> BTreeSet<Role> {
        match self {
            Departure::Member { from, .. } => ROLES.into_iter().filter(|r| r >= from).collect(),
            Departure::Inside { .. } => ROLES.into_iter().collect(),
        }
    }
}

/// `until <= wall_ms` of the corrected clock (spec/crypto.md §4): the edge counts as removed.
pub fn expired(until: Option<WallMs>, now: WallMs) -> bool {
    until.is_some_and(|u| u <= now)
}

/// The box keys of `member` that may carry role `r` at epoch `e`: its box at (r, e), and a
/// key-actor box (sealed, no keyset) keyed at a higher role's current epoch, which carries every
/// role written with it (spec/crypto.md §4; it cannot be opened to check which epoch it holds).
fn boxes_for<'a>(secrets: &'a Secrets, epochs: &ActorEpochs, member: &Tid, r: Role, e: &Epoch) -> Vec<(&'a BoxKey, &'a SecretBox)> {
    let exact = box_key(*member, r, e);
    secrets
        .boxes
        .iter()
        .filter(|(k, b)| {
            k.member == *member
                && (**k == exact
                    || (k.role > r
                        && matches!(b, SecretBox::Sealed(s) if s.keyset.is_none())
                        && from_schema(&k.epoch).is_ok_and(|ke| epochs.role(k.role).is_current(&ke))))
        })
        .collect()
}

/// Does epoch `e` of role `r` cover departure `d`? A member's departure: `e` holds no box for it.
/// A departure inside M: M's box at `e` names the newest keyset epoch of M for `r` the node
/// holds (`newest_keyset`; none known counts as named).
pub fn covers(secrets: &Secrets, epochs: &ActorEpochs, r: Role, e: &Epoch, d: &Departure, newest_keyset: &dyn Fn(&Tid, Role) -> Option<Epoch>) -> bool {
    if !d.roles().contains(&r) {
        return true;
    }
    match d {
        Departure::Member { member, .. } => boxes_for(secrets, epochs, member, r, e).is_empty(),
        Departure::Inside { member } => {
            let Some(newest) = newest_keyset(member, r) else { return true };
            match secrets.boxes.get(&box_key(*member, r, e)) {
                None => true,
                Some(SecretBox::Sealed(s)) => s.keyset.as_ref().is_none_or(|k| from_schema(k).is_ok_and(|k| k == newest)),
                Some(SecretBox::Symmetric(s)) => from_schema(&s.epoch).is_ok_and(|k| k == newest),
            }
        }
    }
}

/// The known departures epoch `e` of role `r` does not cover. A node that may rotate `r`
/// rotates first when this is non-empty (spec/crypto.md §4); the rotation commit's own wrap is
/// the one exception (`Rotation::wrap_epoch`).
pub fn uncovered<'a>(
    secrets: &Secrets,
    epochs: &ActorEpochs,
    r: Role,
    e: &Epoch,
    departures: &'a [Departure],
    newest_keyset: &dyn Fn(&Tid, Role) -> Option<Epoch>,
) -> Vec<&'a Departure> {
    departures.iter().filter(|d| !covers(secrets, epochs, r, e, d, newest_keyset)).collect()
}

/// Whether a node that may rotate `r` may encrypt under `e`: current and usable (an epoch whose
/// rotation commit is pending or invalid never is), and covering every known departure.
pub fn may_encrypt_under(
    secrets: &Secrets,
    epochs: &ActorEpochs,
    r: Role,
    e: &Epoch,
    departures: &[Departure],
    newest_keyset: &dyn Fn(&Tid, Role) -> Option<Epoch>,
) -> bool {
    epochs.role(r).is_current(e) && uncovered(secrets, epochs, r, e, departures, newest_keyset).is_empty()
}

/// The roles of an actor a node must rotate before encrypting under each role's newest held
/// epoch: those whose newest held current epoch is missing or uncovered, among `may_rotate`.
pub fn rotate_first(
    secrets: &Secrets,
    epochs: &ActorEpochs,
    roles: &BTreeSet<Role>,
    may_rotate: &BTreeSet<Role>,
    departures: &[Departure],
    newest_keyset: &dyn Fn(&Tid, Role) -> Option<Epoch>,
) -> BTreeSet<Role> {
    roles
        .iter()
        .filter(|r| may_rotate.contains(r))
        .filter(|r| match epochs.role(**r).newest_held() {
            Some((e, _)) => !may_encrypt_under(secrets, epochs, **r, &e, departures, newest_keyset),
            None => false,
        })
        .copied()
        .collect()
}

/// A current member as a re-sealer sees it: role on the actor (an owner: admin) and `until`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub member: Tid,
    pub role: Role,
    pub until: Option<WallMs>,
}

/// Re-seal trigger (spec/permissions.md §3): members lacking a box at a current epoch of a role
/// they hold, with the roles to re-seal. Never a member whose `until` is within `MAX_DRIFT`.
/// The caller decides after a sync pass of the actor's labels that fetched everything, and
/// only for roles it may rotate.
pub fn reseal_needed(secrets: &Secrets, epochs: &ActorEpochs, members: &[Member], now: WallMs) -> Vec<(Tid, BTreeSet<Role>)> {
    let mut out = Vec::new();
    for m in members {
        if m.until.is_some_and(|u| u.0 <= now.0.saturating_add(MAX_DRIFT_MS)) {
            continue;
        }
        let roles: BTreeSet<Role> = ROLES
            .into_iter()
            .filter(|r| *r <= m.role)
            .filter(|r| epochs.role(*r).current().iter().any(|e| boxes_for(secrets, epochs, &m.member, *r, e).is_empty()))
            .collect();
        if !roles.is_empty() {
            out.push((m.member, roles));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/crypto.md §4: a departure is a removal, a demotion below r, or `until` passing.
    #[test]
    fn departures() {
        let m = Tid::from_bytes([1; 15]);
        assert_eq!(Departure::of_change(m, Some(Role::Admin), Some(Role::Read)), Some(Departure::Member { member: m, from: Role::Write }));
        assert_eq!(Departure::of_change(m, Some(Role::Read), None), Some(Departure::Member { member: m, from: Role::Read }));
        assert_eq!(Departure::of_change(m, Some(Role::Read), Some(Role::Write)), None);
        assert_eq!(Departure::of_change(m, None, None), None);
        assert_eq!(Departure::Member { member: m, from: Role::Write }.roles(), [Role::Write, Role::Admin].into_iter().collect());
        assert!(expired(Some(WallMs(5)), WallMs(5)) && !expired(Some(WallMs(6)), WallMs(5)) && !expired(None, WallMs(5)));
    }
}
