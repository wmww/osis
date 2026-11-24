# A departed party reads later role parts and the fresh deposit seed
> Summary: A commit giving read epochs (rotation, grant, re-seal) is wrapped under an epoch they supersede, so a party removed at epoch e opens their role parts (who was granted, keysets, the fresh deposit seed; never a box or content) while it still opens S at a peer lacking S's step for e. The deposit seed also travels in `keys.0` copies under other things' sync IDs the departed party may still read. Decided (Tess): within the requirements; judged again at stage A5, as a bug to fix or a weaker property.
> Priority: normal
> Tags: security, crypto, engine, sync

**Decided (Tess):** within the requirements' key-step rule (a removed holder stops reading new content once the keys have changed and a writer has written since), role parts included; no fix sought before A5. Study and rejected candidates: notes/keys-establishment.md, The superseded-epoch wrap.

## The two leaks
- **Role parts of commits giving e** (spec/crypto.md §5, Who wraps under what, the exception): wrapped under the epoch e supersedes, whose roles secret X still holds, until S's step for e reaches the peers X uses (admin-only, so after a writer's removal until an admin next writes). Smallest: X removed from S at the rotation minting e; Y grants Z read on S; X opens the grant's role parts (Z's name, the box keys). The wrap exists because a recipient may hold only an older epoch and have no inbox to be told another way.
- **The fresh deposit seed** of a read rotation of M sits in M's `keys.0`, which also goes as a certificate copy under the sync ID of each thing M holds a role on (spec/permissions.md §4) and with A's rotations sealing M (spec/crypto.md §4, Carried). X removed from M but still reading such a sync ID (a direct holder on A) reads the seed and can keep depositing junk under M's sync IDs, filling their deposit budgets (a non-writer's deposit is never promoted, spec/sync-inbox.md §4). Where: core/engine/src/rotation/mod.rs `refreshes_deposit`, `fresh_deposit_seed`.

## At A5
A5 gives every enabled thing an inbox as a card aspect and replaces `keys.0`'s inbox field by the card and an admin-only aspect naming a thing's inbox and cards: the wrap can then go under the newest epoch with delivery to an older-epoch recipient by its inbox, and the seed can live sealed under the new epoch. Whether a link key is such a thing is A5's spec.
