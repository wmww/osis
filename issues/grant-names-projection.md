# A grant held only as a projection carries no names to its holder
> Summary: Study C3 is closed only where the boxer holds the grant's `secrets.0` part. A node holding the grant's `roles.0` part alone (a certificate copy; the label copy withheld) sees the holder actor N current, holds none of the grant's names, and boxes N at a keyset a departed admin of N forged. The simple fix (a held grant whose `secrets.0` part is missing counts as unmet) strands single-use link redeemers.
> Tags: security, keys, engine

Repro: `rotation::tests::repro_grant_projection_names_unheld_spec_crypto_4` (osis-engine, ignored): `grant_names_before_boxing_holder_spec_crypto_4` with X given the grant without its `secrets.0` part on A; X's rotation of A boxes N at D's forged keyset and D, never a holder of A, opens X's epoch.

Tried in review: `grant_names_held` returning false while such a commit's `secrets.0` part on the target is missing (`CommitMeta::missing`; dropped parts count as held). Closes the repro, but breaks `deposit_queue::projection_applies_when_k_never_gets_it_spec_commits_4`: a sharer applies a single-use link redemption from its chain copy (the `secrets.0` part only reaches K's label by the redeemer's deposit), then rotates K for the link's removal leaving the redeemer's person out; the deposit never reaches it after that, so the person is never re-sealed.

Directions: carry the grant's names in the `roles.0` part (plaintext keys there would expose the holder closure's churn to every holder of the certificate); make the sharer's rotation box the redeemer when the grant came from its own link (the link's grant names are the redeemer's own); or wait for the part only where the label copy is expected (not for deposits).
