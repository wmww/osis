//! Published KEM keys (spec/crypto.md §3): which keysets carry a KEM key when written (`bare`),
//! when a thing's rotation is due for one (`due`, KEM key due), and the granter's check on the
//! holder (spec/permissions.md §2 Granting to a thing: `grant_holder`, `grant_keys`).
//!
//! Invariant: a keyset carries a KEM key wherever something may seal to it: the thing is minted
//! with a key, holds that role or above on some thing for keys (or is granted it in this
//! transaction), a card of it stands, or, for read, its current setting enables an external
//! signal; and wherever the keyset it supersedes carries one (core/test/tla/rotation/KemKeys.tla
//! `sticky`: a grant the rotator never learned of keeps its holder sealable). Nothing seals to a keyset without one (`members::sealing_at`: no candidate, so a newer
//! KEM-less keyset leaves the holder out rather than sealing at an older one, which a party
//! removed since may hold).
//! Who writes each input: the grants are their writers' (judged by the timelines, with key
//! access); the setting is the thing's own; the creation record its minting's; a card a writer's
//! of its host along a path through the thing (`flows::cards`). A writer that may
//! grant H a role makes H's keysets due for KEM keys, nothing more (one rotation by H's rotator).

use super::{members, may_rotate};
use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_base::{Role, Tid};
use osis_keys::ROLES;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// Whether a keyset of role `r` of `t` written now carries its KEM key (spec/crypto.md §3,
/// Published KEM keys), judged by what this node holds and what the transaction gives things
/// (`Tx::publishing`): minted with a key, holding `r` or above for keys, a card of it standing
/// here (`flows::cards`), for read a setting enabling an external signal, or its current keyset
/// of `r` carrying one (sticky: a holder granted beside this node's knowledge stays sealable).
pub(crate) fn publishes(tx: &mut Tx<'_>, t: &Tid, r: Role) -> Result<bool> {
    let core = &*tx.core;
    let cheap = core.created(t).is_some_and(|c| c.key().is_some())
        || tx.publishing.iter().any(|(h, role)| h == t && *role >= r)
        || holds_for_keys(core, t, r)
        || crate::apply::validity::setting_now(core, t).and_then(|s| by_setting(&s)).is_some_and(|x| x >= r);
    Ok(cheap || crate::flows::cards::stands(tx, t)? || carries(tx, t, r)?)
}

/// Whether `t` holds `r` or above on some thing for keys, with key access (a grant or a record
/// grant, `Core::grant_holders`: every `until` disregarded, as keys read no clock).
fn holds_for_keys(core: &Core, t: &Tid, r: Role) -> bool {
    let on: Vec<Tid> = core.ix.held.named_on(t).copied().collect();
    on.iter().any(|y| core.grant_holders(y).into_iter().any(|(h, role)| h == *t && role >= r && members::keyed(core, y, t)))
}

/// The greatest role whose keysets setting `s` of a thing makes carry KEM keys: read where it
/// enables an external signal (spec/sync-inbox.md §1).
pub(crate) fn by_setting(s: &ct::RetentionSetting) -> Option<Role> {
    s.rules.keys().any(|k| s.enables(k)).then_some(Role::Read)
}

/// The roles of `roles` a rotation of `a` now writes without a KEM key (`publishes`).
pub(crate) fn bare(tx: &mut Tx<'_>, a: &Tid, roles: &BTreeSet<Role>) -> Result<BTreeSet<Role>> {
    let mut out = BTreeSet::new();
    for r in roles {
        if !publishes(tx, a, *r)? {
            out.insert(*r);
        }
    }
    Ok(out)
}

/// Whether `a`'s current keyset of role `r` lacks a KEM key `publishes` gives one written now
/// (spec/crypto.md §3, KEM key due): a current epoch of `r`, not foreign, whose held keyset
/// carries none. An epoch whose keyset is not held is judged once it is.
pub(crate) fn due(tx: &mut Tx<'_>, a: &Tid, r: Role) -> Result<bool> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(false) };
    let lacking = epochs.role(r).current().into_iter().filter(|e| !epochs.role(r).is_foreign(e)).any(|e| tx.core.keyset(a, r, &e).is_some_and(|k| k.kem_in.is_none()));
    Ok(lacking && publishes(tx, a, r)?)
}

/// The rotation KEM key due makes (`due`) of the roles of `a` this node may rotate, made now
/// rather than at the next pass's end (spec/permissions.md §3: it may rotate eagerly).
fn rotate_due(tx: &mut Tx<'_>, a: Tid, done: &mut crate::flows::Done) -> Result<()> {
    let me = tx.core.tid();
    let may = may_rotate(tx.core, &me, &a);
    let mut roles = BTreeSet::new();
    for r in ROLES.into_iter().filter(|r| may.contains(r)) {
        if due(tx, &a, r)? {
            roles.insert(r);
        }
    }
    if roles.is_empty() {
        return Ok(());
    }
    super::rotate_alone(tx, me, a, &roles, done)
}

impl crate::engine::Engine {
    /// Whether a current keyset of held actor `a`, of a role this node may rotate, lacks the KEM
    /// key the rule gives (`due`; spec/crypto.md §3 KEM key due): noted as a cause a complete pass
    /// waits after (`Cause::Kem`), so one is wanted (`pass_wanted`) and its end makes the rotation
    /// (`pass_end`), whatever else wants a pass: what makes it due (a setting enabling a signal, a
    /// card, a role for keys) may be an own write, which wants none otherwise. A value of the
    /// state, followed per held actor by sync's `Life`; the place is forgotten once not due.
    pub fn kem_due(&mut self, a: &Tid) -> Result<bool> {
        let a = *a;
        let due_now = self.read(|tx| {
            let me = tx.core.tid();
            let may = may_rotate(tx.core, &me, &a);
            for r in ROLES.into_iter().filter(|r| may.contains(r)) {
                if due(tx, &a, r)? {
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        self.judge_cause(crate::sync::held::Cause::Kem(a), due_now)?;
        Ok(due_now)
    }

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
/// `role` naming holder `h`, a thing, by this node, first half: it may write `h` or holds `h`'s
/// current `keys.0`, the newest it holds (a card of `h` brings them, as `h`'s public key record
/// does a fellow holder); else refused. From here the transaction's keysets of `h` up to `role` carry KEM keys
/// (`publishing`), its making independent among them. Run before anything of the grant is made.
pub(crate) fn grant_holder(tx: &mut Tx<'_>, h: Tid, role: Role) -> Result<()> {
    let me = tx.core.tid();
    if tx.core.role_now(&me, &h) < Some(Role::Write) && crate::engine::Core::keys_in(tx, &h)?.is_none() {
        return Err(Error::Permission { tid: h, needs: Role::Write });
    }
    tx.publishing.push((h, role));
    Ok(())
}

/// The granter's check, second half (after `grant_holder`, `h` independent and its due
/// rotations made): `h`'s current keyset of each role the write boxes it at, and its read keyset
/// where this node may rotate it, carries a KEM key,
/// or this node rotates those roles of `h` now, in the grant's transaction (their keysets then
/// carry KEM keys); else refused.
///
/// Invariant: a grant is written only to a holder whose keysets something may seal to, so its
/// holder is never left out for want of a KEM key by the granter's own doing; a co-writer's
/// rotation of `h` made before it learns the grant still may, and KEM key due ends that.
pub(crate) fn grant_keys(tx: &mut Tx<'_>, h: Tid, role: Role, done: &mut crate::flows::Done) -> Result<()> {
    let me = tx.core.tid();
    let may = may_rotate(tx.core, &me, &h);
    let mut lacking = BTreeSet::new();
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        if !carries(tx, &h, r)? {
            lacking.insert(r);
        }
    }
    // the read keyset too, where this node may rotate it: the grant's claim is sealed to its KEM
    // key (spec/sync-ids.md §3 Claims; one left out is written by a re-seal)
    if role == Role::Sync && may.contains(&Role::Read) && !carries(tx, &h, Role::Read)? {
        lacking.insert(Role::Read);
    }
    if lacking.is_empty() {
        return Ok(());
    }
    if !lacking.is_subset(&may) {
        return Err(Error::Misuse("the holder's keys carry no KEM key and this node may not rotate them"));
    }
    super::rotate_alone(tx, me, h, &lacking, done)
}

