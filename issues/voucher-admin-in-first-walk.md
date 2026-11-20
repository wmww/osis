# A voucher holds admin by a share only a vouch removes
> Summary: A vouch counts by its voucher's admin in the first walk (every vouch unread), where a lowering kept only by a vouch is dropped: a removed party keeping admin on a holder thing makes a key admin of it and vouches by a share of that holder it removed itself, keeping a backdated write the reading gives no right to.
> Priority: normal
> Tags: perm, security

notes/path-model-findings.md 39, roles-model `repro_a_voucher_holds_admin_by_a_share_only_a_vouch_removes`: X, admin of A and of A2, removes A2's share of T1 before the theft (B received it and vouches for it). After H removes X from A, X makes Z an admin of A2 (its right), backdates a grant of write on T1 to Z through [A], and Z vouches for it on T1 along [A2]. In the first walk X's removal of A2's share is dropped (only B's vouch keeps it), so Z's vouch applies and counts; in the reading A2 has no share and Z never held admin on T1, yet Z's grant applies.

Reaches the stated-path design (notes/a1-spec/permissions.md §5.1 Vouches, First walk) and `osis_perm::paths`, which agrees with the model on it. Today's rule judges "W could write c" in its first walk the same way; not checked against the engine. Reading the voucher's authority in the walk its vouch changes has no fixpoint (finding 2); the fix needs a reading where what other counting vouches keep binds the voucher (Open 5 there). The story's move 52 skips these worlds (`Setup::x_role` 2) until then.
