//! Possession (spec/crypto.md §4, Holder actors): a symmetric box to a holder actor M shows that
//! its author holds the secret of the keyset of M it boxes at, by a signature with that keyset's
//! possession key; a rotation, or a removal of a box to M, counts its author's role on the actor
//! through M only where it shows that (Authority). Without it a party removed from M, where its
//! removal is unknown, could rotate the actor sealing M at M's new keyset (which it cannot open),
//! or replace a stale box with one so sealed, and so make an epoch it holds look fresh
//! (issues/keys-depth0-removed-member-rotates.md). A box alone is never judged: it opens for
//! whoever holds the keyset it names whatever its validity, so judging it would only hide what it
//! discloses from the rules that judge boxes (stale, keyless; model `D0_box_rule`).
//! Pure: the engine gathers the roles and keysets.

use crate::aspects::from_schema;
use crate::Error;
use osis_base::{Role, Tid};
use osis_crypto::{BoxSlot, Domain, Epoch, Secret32, Signature, SigningSecret, VerifyingKey, kdf};
use osis_schema::core_types::{self as ct, BoxKey, SecretBox};
use std::collections::BTreeSet;

/// The possession signing key of role secret `s`: Ed25519 with seed `kdf("possession key", s)`.
pub fn possession_secret(s: &Secret32) -> SigningSecret {
    SigningSecret::from_seed(&kdf::kdf(kdf::POSSESSION, s.expose(), b""))
}

/// The possession key a keyset publishes for its epoch's secret `s`.
pub fn possession_key(s: &Secret32) -> VerifyingKey {
    possession_secret(s).verifying_key()
}

/// The possession signature of a symmetric box at `slot` wrapped under the holder's secret `s` of
/// epoch `epoch_s` (spec/wire.md §7).
pub fn sign(s: &Secret32, slot: &BoxSlot, epoch_s: Epoch, wrap: &[u8]) -> Result<Signature, Error> {
    Ok(possession_secret(s).sign(Domain::Possession, &slot.possession_digest(epoch_s, wrap)?))
}

/// What a box written to a holder shows, read from the delta alone: the keyset of the holder it
/// names and, for a symmetric box carrying a possession signature, the signed digest and the
/// signature. Checked against the keyset's possession key once the node holds it (`verifies`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Shown {
    pub holder: Tid,
    pub role: Role,
    pub keyset: Epoch,
    pub signed: Option<([u8; 32], [u8; 64])>,
}

impl Shown {
    /// The box `b` of `actor` keyed `key`. `None` for a box naming no keyset (a key actor's
    /// sealed box) or one that does not decode: it shows nothing.
    pub fn of(actor: &Tid, key: &BoxKey, b: &SecretBox) -> Option<Shown> {
        let (keyset, signed) = match b {
            SecretBox::Sealed(x) => (from_schema(x.keyset.as_ref()?).ok()?, None),
            SecretBox::Symmetric(x) => {
                let epoch_s = from_schema(&x.epoch).ok()?;
                let slot = BoxSlot::Secrets { actor: *actor, holder: key.holder, role: key.role, epoch: from_schema(&key.epoch).ok()? };
                let signed = match &x.possession {
                    Some(ct::Signature::Ed25519(sig)) => Some((slot.possession_digest(epoch_s, &x.wrap).ok()?, <[u8; 64]>::try_from(sig.as_slice()).ok()?)),
                    None => None,
                };
                (epoch_s, signed)
            }
        };
        Some(Shown { holder: key.holder, role: key.role, keyset, signed })
    }

    /// Whether it carries a possession signature valid under `pk` (the keyset's possession key).
    pub fn verifies(&self, pk: &VerifyingKey) -> bool {
        self.signed.as_ref().is_some_and(|(d, s)| pk.verify(Domain::Possession, d, &Signature(*s)).is_ok())
    }
}

/// What judging a `secrets.0` delta of actor A for possession needs besides its boxes
/// (spec/crypto.md §4): read just before its commit's key, by the node judging.
pub trait View {
    /// Whether `t` is a key actor (boxed by its one KEM key or seed, never a holder actor).
    fn key_actor(&self, t: &Tid) -> bool;
    /// The author's role on `t`, on paths not through A (through it, `t` holding a role on A, is
    /// a cycle: no key access).
    fn author_on(&self, t: &Tid) -> Option<Role>;
    /// The holder actors of A the node holds a keyset of (its first admin included while its
    /// record edge stands): those a box shows possession of.
    fn holder_actors(&self) -> BTreeSet<Tid>;
    /// The author's role on A on paths through none of `avoid`.
    fn role_on_actor(&self, avoid: &BTreeSet<Tid>) -> Option<Role>;
    /// The possession keys the held valid bodies of keyset `k` of role `r` of `m` publish;
    /// `None` when none is held.
    fn keys(&self, m: &Tid, r: Role, k: &Epoch) -> Option<Vec<VerifyingKey>>;
}

/// Whether a `secrets.0` delta showing `shown` and removing boxes of `removed` (holder, role)
/// passes possession (spec/crypto.md §4, Authority): when it `rotates` or removes a box of role r
/// to a holder actor the author holds r or above on without putting it again with a valid
/// signature, the author does not hold `needed` on the actor only through holder actors it does
/// not box with a valid signature.
pub fn holds(shown: &[Shown], removed: &[(Tid, Role)], rotates: bool, needed: Role, v: &dyn View) -> bool {
    // a keyset the node holds no valid body of is not judged by (a box naming it is not stale
    // either: within the stated limit until the body arrives, and judged again then)
    let valid = |s: &Shown| v.keys(&s.holder, s.role, &s.keyset).is_none_or(|pks| pks.iter().any(|pk| s.verifies(pk)));
    let actors = || shown.iter().filter(|s| !v.key_actor(&s.holder));
    // a rotation through a holder actor counts only where the author shows it is in
    // that actor now (a removed party, its removal unknown here, holds no new keyset's secret);
    // so does a removal of a box to a holder actor the author holds that role on, unless it puts
    // that box again signed (else it could take a stale box away, to have it re-sealed fresh)
    let replaced = |m: &Tid, r: Role| actors().any(|s| s.holder == *m && s.role == r && valid(s));
    let removes = removed.iter().any(|(m, r)| !v.key_actor(m) && v.author_on(m) >= Some(*r) && !replaced(m, *r));
    if !rotates && !removes {
        return true;
    }
    // (where the author holds no such role at all, the rest of §5.2 judges it: re-grants, frontiers)
    let shown_in: BTreeSet<Tid> = actors().filter(|s| valid(s)).map(|s| s.holder).collect();
    let avoid: BTreeSet<Tid> = v.holder_actors().difference(&shown_in).copied().collect();
    avoid.is_empty() || v.role_on_actor(&avoid) >= Some(needed) || v.role_on_actor(&BTreeSet::new()) < Some(needed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::aspects::to_schema;
    use osis_crypto::wrap_symmetric_box;
    use std::collections::{BTreeMap, BTreeSet};

    fn tid(b: u8) -> Tid {
        Tid::from_bytes([b; 15])
    }

    const A: u8 = 1;
    const M: u8 = 2;
    const X: u8 = 3;

    /// M's epoch k with secret s, and a box of A's epoch e (role r) to M symmetric at k.
    fn boxed(s: &Secret32, k: Epoch, r: Role, signed_by: Option<&Secret32>) -> (BoxKey, SecretBox) {
        let e = Epoch::derive(&tid(A), r, 2, &Secret32::from_bytes([9; 32])).unwrap();
        let slot = BoxSlot::Secrets { actor: tid(A), holder: tid(M), role: r, epoch: e };
        let wrap = wrap_symmetric_box(s, &slot, k, &Secret32::from_bytes([9; 32])).unwrap().to_vec();
        let possession = signed_by.map(|p| ct::Signature::Ed25519(sign(p, &slot, k, &wrap).unwrap().0.to_vec()));
        (BoxKey { holder: tid(M), role: r, epoch: to_schema(&e) }, SecretBox::Symmetric(ct::SymmetricBox { epoch: to_schema(&k), wrap, possession }))
    }

    struct V {
        author_on_m: Option<Role>,
        m_on_a: Option<Role>,
        direct: Option<Role>,
        keys: BTreeMap<(Tid, Role, Epoch), VerifyingKey>,
    }

    impl View for V {
        fn key_actor(&self, t: &Tid) -> bool {
            *t == tid(X)
        }
        fn author_on(&self, t: &Tid) -> Option<Role> {
            (*t == tid(M)).then_some(self.author_on_m).flatten()
        }
        fn holder_actors(&self) -> BTreeSet<Tid> {
            BTreeSet::from([tid(M)])
        }
        // the author holds A directly (`direct`) or through M
        fn role_on_actor(&self, avoid: &BTreeSet<Tid>) -> Option<Role> {
            let via = if avoid.contains(&tid(M)) { None } else { self.author_on_m.min(self.m_on_a) };
            self.direct.max(via)
        }
        fn keys(&self, m: &Tid, r: Role, k: &Epoch) -> Option<Vec<VerifyingKey>> {
            self.keys.get(&(*m, r, *k)).map(|pk| vec![*pk])
        }
    }

    fn setup() -> (Secret32, Epoch, V) {
        let s = Secret32::from_bytes([5; 32]);
        let k = Epoch::derive(&tid(M), Role::Write, 3, &s).unwrap();
        let v = V { author_on_m: Some(Role::Write), m_on_a: Some(Role::Write), direct: None, keys: BTreeMap::from([((tid(M), Role::Write, k), possession_key(&s))]) };
        (s, k, v)
    }

    fn shown(b: &(BoxKey, SecretBox)) -> Vec<Shown> {
        vec![Shown::of(&tid(A), &b.0, &b.1).unwrap()]
    }

    #[test]
    fn signed_box_gives_authority() {
        let (s, k, v) = setup();
        let b = boxed(&s, k, Role::Write, Some(&s));
        assert!(holds(&shown(&b), &[], true, Role::Write, &v));
    }

    #[test]
    fn unsigned_box_shows_nothing() {
        let (s, k, v) = setup();
        let b = boxed(&s, k, Role::Write, None);
        assert!(!holds(&shown(&b), &[], true, Role::Write, &v), "a rotation only through M");
        // a box alone is never judged, by a member or not
        assert!(holds(&shown(&b), &[], false, Role::Write, &v), "a member's grant or re-seal");
        let v = V { author_on_m: None, direct: Some(Role::Admin), ..v };
        assert!(holds(&shown(&b), &[], true, Role::Write, &v), "a direct admin's rotation");
    }

    #[test]
    fn signature_by_another_secret_fails() {
        let (s, k, v) = setup();
        let b = boxed(&s, k, Role::Write, Some(&Secret32::from_bytes([6; 32])));
        assert!(!holds(&shown(&b), &[], true, Role::Write, &v));
    }

    #[test]
    fn unknown_keyset_is_not_judged_by() {
        let (s, k, mut v) = setup();
        v.keys.clear();
        let b = boxed(&s, k, Role::Write, None);
        assert!(holds(&shown(&b), &[], true, Role::Write, &v));
    }

    #[test]
    fn signature_binds_the_box() {
        let (s, k, v) = setup();
        let (key, b) = boxed(&s, k, Role::Write, Some(&s));
        let SecretBox::Symmetric(mut x) = b else { unreachable!() };
        x.wrap[0] ^= 1;
        assert!(!holds(&[Shown::of(&tid(A), &key, &SecretBox::Symmetric(x)).unwrap()], &[], true, Role::Write, &v), "another wrap");
        let moved = BoxKey { holder: tid(M), role: Role::Write, epoch: to_schema(&Epoch::derive(&tid(A), Role::Write, 2, &Secret32::from_bytes([8; 32])).unwrap()) };
        assert!(!holds(&[Shown::of(&tid(A), &moved, &boxed(&s, k, Role::Write, Some(&s)).1).unwrap()], &[], true, Role::Write, &v), "another epoch of A");
    }

    #[test]
    fn rotation_leaving_the_holder_out_has_no_authority() {
        let (_, _, v) = setup();
        assert!(!holds(&[], &[], true, Role::Write, &v), "only through M, M not boxed");
        assert!(holds(&[], &[], false, Role::Write, &v), "a re-seal of another holder");
        let v = V { direct: Some(Role::Write), ..v };
        assert!(holds(&[], &[], true, Role::Write, &v), "a direct holder");
    }

    #[test]
    fn authority_is_capped_by_the_holders_role() {
        let (s, k, v) = setup();
        let b = boxed(&s, k, Role::Write, Some(&s));
        let v = V { m_on_a: Some(Role::Read), direct: Some(Role::Write), ..v };
        assert!(holds(&[], &[], true, Role::Write, &v), "direct write");
        let v = V { direct: Some(Role::Read), ..v };
        assert!(holds(&shown(&b), &[], true, Role::Read, &v));
        // write through M capped at read: no path gives write, so Authority leaves it to §5.2
        assert!(holds(&[], &[], true, Role::Write, &v));
    }

    #[test]
    fn removal_by_a_member_needs_authority() {
        let (s, k, v) = setup();
        let gone = [(tid(M), Role::Write)];
        assert!(!holds(&[], &gone, false, Role::Write, &v), "a bare removal, only through M");
        let b = boxed(&s, k, Role::Write, Some(&s));
        assert!(holds(&shown(&b), &gone, false, Role::Write, &V { m_on_a: None, ..setup().2 }), "put again signed");
        assert!(holds(&[], &gone, false, Role::Write, &V { direct: Some(Role::Write), ..setup().2 }), "a direct holder");
        let v = V { author_on_m: None, ..v };
        assert!(holds(&[], &gone, false, Role::Write, &v), "a non-member removes");
    }

    #[test]
    fn key_actor_boxes_show_nothing_needed() {
        let (s, k, v) = setup();
        let (_, b) = boxed(&s, k, Role::Write, None);
        let key = BoxKey { holder: tid(X), role: Role::Write, epoch: to_schema(&k) };
        let v = V { author_on_m: Some(Role::Admin), direct: Some(Role::Admin), ..v };
        assert!(holds(&[Shown::of(&tid(A), &key, &b).unwrap()], &[], true, Role::Write, &v));
    }
}
