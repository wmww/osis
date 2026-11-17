# A removed party reads the role parts of grants and re-seals made after its removal
> Summary: A commit giving read epochs (rotation, grant, re-seal) wraps under an epoch they supersede, so a party removed at epoch e, still holding the superseded epoch's roles secret, opens the role parts (who was granted, keysets, the deposit seed; boxes stay sealed) of the rotation, grants and re-seals giving e while it still opens S: until S's step for e reaches the peers it uses. Study (notes/keys-establishment.md, The superseded-epoch wrap): no structural close at a sane cost; proposed to Tess as a stated limit.
> Priority: normal
> Tags: security, crypto, engine, tess-call

## The gap
- spec/crypto.md §5 (Who wraps under what, the exception): a commit giving read epochs of an actor is wrapped under the epoch they supersede with the greatest n whose roles secret the node holds.
- A party removed from the actor at the rotation minting e holds the roles secret of the epoch e supersedes. Every grant and re-seal giving e is wrapped there, so the removed party opens their role parts (`roles.0`, `keys.0`, `secrets.0`: who was granted, the sealed boxes) as it opens e's rotation, for as long as it opens S: until S's step for e reaches the peers it uses (admin-only, so for a writer's removal until an admin next writes).
- Not accepted in the spec (Tess); tolerated in code for now.

## Why it exists
A recipient may hold only an older epoch: a link left out of a profile rotation has no inbox and reads its re-seal only from the sync ID (osis-sync `keep::a_taken_inbox_*`, `growth::a_lowered_writers_*`; notes/crypto.md, A commit giving read epochs). Wrapping under the newest epoch would leave it unable to open the commit that gives it that epoch.

## Decision wanted (Tess)
Every candidate (per-recipient wrap, a wrap derived from e, the plain rule with inbox delivery, splitting the role section) either shrinks the leak (box keys still show who was boxed; the header stays readable) or needs anonymous per-holder delivery with trial decryption of every box (O(holders^2) per rotation) and a new entry form: notes/keys-establishment.md, The superseded-epoch wrap. Proposal: state it in spec/crypto.md §5 as a limit bounded by the step (role parts only, never a secret or content) and close this issue.
