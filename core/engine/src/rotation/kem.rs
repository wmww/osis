//! Published KEM keys (spec/crypto.md §3): which keysets carry a KEM key when written (`bare`),
//! when a thing's rotation is due for one (`due`, KEM key due), and the granter's check on the
//! holder (spec/permissions.md §2 Granting to a thing: `grant_holder`, `grant_keys`).
//!
//! Invariant: a keyset carries a KEM key wherever something may seal to it: the thing is minted
//! with a key, holds that role or above on some thing for keys (or is granted it in this
//! transaction), a card of it stands, or, for read, its current setting enables an external
//! signal. Nothing seals to a keyset without one (`members::sealing_at`: no candidate, so a newer
//! KEM-less keyset leaves the holder out rather than sealing at an older one, which a party
//! removed since may hold).
//! Who writes each input: the grants are their writers' (judged by the timelines, with key
//! access); the setting is the thing's own; the creation record the minter's. A writer that may
//! grant H a role makes H's keysets due for KEM keys, nothing more (one rotation by H's rotator).

use super::{members, may_rotate};
use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_base::{Role, Tid};
use osis_keys::ROLES;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// Whether a keyset of role `r` of `t` written now carries its KEM key (spec/crypto.md §3,
/// Published KEM keys), judged by what this node holds and `publishing` (what the transaction
/// gives things, `Tx::publishing`).
pub(crate) fn publishes(core: &Core, publishing: &[(Tid, Role)], t: &Tid, r: Role) -> bool {
    core.created(t).is_some_and(|c| c.key().is_some())
        || publishing.iter().any(|(h, role)| h == t && *role >= r)
        || holds_for_keys(core, t, r)
        || crate::apply::validity::setting_now(core, t).and_then(|s| by_setting(&s)).is_some_and(|x| x >= r)
}

/// Whether `t` holds `r` or above on some thing for keys, with key access (an edge or a record
/// edge, `Core::edge_holders`: every `until` disregarded, as keys read no clock).
fn holds_for_keys(core: &Core, t: &Tid, r: Role) -> bool {
    let on: Vec<Tid> = core.ix.held.named_on(t).copied().collect();
    on.iter().any(|y| core.edge_holders(y).into_iter().any(|(h, role)| h == *t && members::keyed_role(core, y, t, role).is_some_and(|k| k >= r)))
}

/// The greatest role whose keysets setting `s` of a thing makes carry KEM keys: read where it
/// enables an external signal (spec/sync-inbox.md §1). Interim (notes/public-and-cards-brief.md
/// piece 6, cards): every role where it enables `grant@~0`, as the card a thing taking grants
/// from outside will have makes them.
pub(crate) fn by_setting(s: &ct::RetentionSetting) -> Option<Role> {
    let grants = osis_base::Ak::new("grant@~0").is_ok_and(|k| s.enables(&k));
    match grants {
        true => Some(Role::Admin),
        false => s.rules.keys().any(|k| s.enables(k)).then_some(Role::Read),
    }
}

/// The roles of `roles` a rotation of `a` now writes without a KEM key (`publishes`).
pub(crate) fn bare(tx: &Tx<'_>, a: &Tid, roles: &BTreeSet<Role>) -> BTreeSet<Role> {
    roles.iter().copied().filter(|r| !publishes(tx.core, &tx.publishing, a, *r)).collect()
}

/// Whether `a`'s current keyset of role `r` lacks a KEM key `publishes` gives one written now
/// (spec/crypto.md §3, KEM key due): a current epoch of `r`, not foreign, whose held keyset
/// carries none. An epoch whose keyset is not held is judged once it is.
pub(crate) fn due(tx: &Tx<'_>, a: &Tid, r: Role) -> bool {
    let Some(epochs) = tx.core.epochs(a) else { return false };
    let lacking = epochs.role(r).current().into_iter().filter(|e| !epochs.role(r).is_foreign(e)).any(|e| tx.core.keyset(a, r, &e).is_some_and(|k| k.kem_in.is_none()));
    lacking && publishes(tx.core, &tx.publishing, a, r)
}

/// The rotation KEM key due makes (`due`) of the roles of `a` this node may rotate, made now
/// rather than at the next pass's end (spec/permissions.md §3: it may rotate eagerly).
fn rotate_due(tx: &mut Tx<'_>, a: Tid, done: &mut crate::flows::Done) -> Result<()> {
    let me = tx.core.me();
    let may = may_rotate(tx.core, &me, &a);
    let roles: BTreeSet<Role> = ROLES.into_iter().filter(|r| may.contains(r) && due(tx, &a, *r)).collect();
    if roles.is_empty() {
        return Ok(());
    }
    super::rotate_alone(tx, me, a, &roles, done)
}

impl crate::engine::Engine {
    /// The rotation KEM key due makes of `a` (spec/crypto.md §3), now (harnesses: a holder
    /// readied for grants from outside without waiting for a pass's end).
    #[doc(hidden)]
    pub fn kem_key_due(&mut self, a: &Tid) -> Result<crate::flows::Done> {
        let a = *a;
        self.run(|tx| {
            let mut done = crate::flows::Done::default();
            rotate_due(tx, a, &mut done)?;
            Ok(done)
        })
    }
}

/// Whether `a`'s current keyset of role `r`, as its `keys.0` holds it here, carries a KEM key
/// (none held: none to seal to).
fn carries(tx: &mut Tx<'_>, a: &Tid, r: Role) -> Result<bool> {
    let keys = crate::engine::Core::keys_in(tx, a)?;
    Ok(keys.as_ref().and_then(|k| osis_keys::aspects::keyset_of(k, r)).is_some_and(|ks| ks.kem_key.is_some()))
}

/// The granter's check (spec/permissions.md §2 Granting to a thing) for a grant or change of
/// `role` naming holder `h`, a thing, by this node, first half: it may write `h` or holds a card
/// of it; else refused. From here the transaction's keysets of `h` up to `role` carry KEM keys
/// (`publishing`), its making independent among them. Run before anything of the grant is made.
pub(crate) fn grant_holder(tx: &mut Tx<'_>, h: Tid, role: Role) -> Result<()> {
    let me = tx.core.me();
    if tx.core.role_now(&me, &h) < Some(Role::Write) && !card_held(tx, &h)? {
        return Err(Error::Permission { tid: h, needs: Role::Write });
    }
    tx.publishing.push((h, role));
    Ok(())
}

/// The granter's check, second half (after `grant_holder`, `h` independent and its due
/// rotations made): `h`'s current keyset of each role the write boxes it at carries a KEM key,
/// or this node rotates those roles of `h` now, in the grant's transaction (their keysets then
/// carry KEM keys); else refused.
///
/// Invariant: a grant is written only to a holder whose keysets something may seal to, so its
/// holder is never left out for want of a KEM key by the granter's own doing; a co-writer's
/// rotation of `h` made before it learns the grant still may, and KEM key due ends that.
pub(crate) fn grant_keys(tx: &mut Tx<'_>, h: Tid, role: Role, done: &mut crate::flows::Done) -> Result<()> {
    let me = tx.core.me();
    let mut lacking = BTreeSet::new();
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        if !carries(tx, &h, r)? {
            lacking.insert(r);
        }
    }
    if lacking.is_empty() {
        return Ok(());
    }
    if !lacking.is_subset(&may_rotate(tx.core, &me, &h)) {
        return Err(Error::Misuse("the holder's keys carry no KEM key and this node may not rotate them"));
    }
    super::rotate_alone(tx, me, h, &lacking, done)
}

/// Whether this node holds a card of `h` (spec/sync-inbox.md §1 Card). Interim (piece 6 of
/// notes/public-and-cards-brief.md): `h`'s `keys.0` held here, which its public key record
/// brings, stands for its card.
fn card_held(tx: &mut Tx<'_>, h: &Tid) -> Result<bool> {
    Ok(crate::engine::Core::keys_in(tx, h)?.is_some())
}
