# Opening a sync ID: every box is an entry
> Summary: The approved design (Tess, to build after the sync-ID-at-minting job) for how a node gets into and opens a sync ID: an entry with each box, one open rule, `Head(S)`; what it deletes, what was checked, costs, and rejected directions.

**Principle:** a grant's box to its holder is also the holder's way in. The commit that boxes a holder carries the holder's entry, so grant and entry are one write and never diverge; nothing is kept with the holder, and a grant nobody is told of still holds nothing (the holder must find S by a signal, a stub or a locator).

## Design
- **Entry**: a claim plus W, in the blob's store-visible part. W: the commit's blob key sealed (hybrid) to the holder's KEM key; for a sync-only holder, its own boxes in the commit (it never sees the roster). The public's entry: a claim anyone computes, W in clear. Each role commit carries an entry block, padded to a power of two (at least one dummy), signed by the sync key of the epoch it is bound to. Writers: grants, re-seals, rotations, snapshots, becoming independent (all readers).
- **Claim**: DH of the sync epoch's claim key and the holder's X25519 key. The claim key is per sync epoch, its private half from that epoch's sync secret plus a read roles secret named in its keyset (readers derive it, stores cannot); the step's `step_key` is its public half (no fresh step key, nothing erased).
- **One open rule**: a credential of the head opens S whole: the sync proof, or a claim in an entry block bound to the head's sync epoch. An older step's sync proof opens S served only up to that step's end (how a removed node learns its removal: the removal's rotation is wrapped under an epoch it holds).
- **`Head(S)`**: any node holding S answers with its path, no credential needed.
- **A grantee gets in**: `Head(S)`, its claim at the head, open at any store, find W by its claim, read its grant, take its boxes. No reader online.
- **Concurrent step and grant**: steps list nothing and claims bind to the sync epoch, so a step without rotation changes nothing; a sync rotation that missed the grant leaves the holder out and the re-seal rule writes its entry at the new epoch.
- **Fits**: chains (node → account → realm) claim with the realm's KEM key (sticky KEM keys); link keys are ordinary holders (KEM key from the seed); locators use `Head` and the public's claim or the redeemer's own; a stub holder opens by its holder's claim in the stub class; a removed sync-only node learns the public's grant by the public's claim and clear W.
- **With it (Tess)**: a node holding X's stub follows X's sync ID; holders a node reads through are synced for their role entries; stores may learn a padded holder count.

## Deletes
J as an open proof and the Departed rule; read-secret credentials; static and public entries; ByRole in every form; notices in every form; claim sets and their hash in steps, entry boxes; the step without rotation listing readers; step-key erasure; Behind and the claim walk; lapsed secrets and the reader-tells-departed rules; sync copies and holders by copies; message kinds ByRole, Static, Notice, Behind; `ROLE_KEEP` for claim sets.

## Checked
Explicit-state model over every interleaving of grant, rotation removing a sync-only node, re-seal, step without rotation, logging to two stores, Register and store-to-store sync, public or not, with only stores serving: a store holding the grantee's entry lets it in alone; after an admin's pass the grantee holds the current epoch; the removed node gets nothing past its removal; public X: the removed node reads its removal and the public's grant. Controls fail as they should: no entry in the grant, claims bound to the step, no public entry. Not modelled: forks, holder actors and joint boxes, floors and cuts, compaction, padding, filters.

## Costs
About 1.2 KB per holder per boxing commit (a rotation +30-100%; sharing the KEM encapsulation with the holder's box could cut it), one dummy entry on role commits boxing nobody. Every node holding S shows all head claims in its filter: filter size grows with holders (measure at n and 10n). `Head(S)` shows anyone naming S that the node keeps S, and the head's public values (rotation timing). A sync-only granter with may-grant holds no wrap key and logs nothing (an existing gap).

## Rejected
- Claims signed apart from the grant: a copy that lags and needs repair.
- Claim-only child steps: concurrent ones are siblings needing a fix-up.
- Claims bound to the step: a step without rotation strands the grantee.
- Claim key from the sync secret: stores hold it and could link a holder's card to the thing.
- One stable claim key per thing: a removed reader poses as any holder forever.
- Store-visible boxes found by trial decryption: a trial per box, unpadded counts.
- Entry carrying the earlier epoch's secret: breaks floors for a grant without history.
- W from the claim's X25519 alone: loses post-quantum protection.
