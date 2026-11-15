# A removed party reads the role parts of grants and re-seals made after its removal
> Summary: A commit giving read epochs (rotation, grant, re-seal) wraps under an epoch they supersede, so a party removed at epoch e, still holding the superseded epoch's roles secret, opens the role parts (who was granted, sealed boxes) of grants and re-seals giving e until the next rotation.
> Priority: normal
> Tags: security, crypto, engine

## The gap
- spec/crypto.md §5 (Who wraps under what, the exception): a commit giving read epochs of an actor is wrapped under the epoch they supersede with the greatest n whose roles secret the node holds.
- A party removed from the actor at the rotation minting e holds the roles secret of the epoch e supersedes. Every grant and re-seal giving e is wrapped there, so the removed party opens their role parts (`roles.0`, `keys.0`, `secrets.0`: who was granted, the sealed boxes) as it opens e's rotation, until a rotation past e.
- Not accepted in the spec (Tess); tolerated in code for now.

## Why it exists
A recipient may hold only an older epoch: a link left out of a profile rotation has no inbox and reads its re-seal only from the sync ID (osis-sync `keep::a_taken_inbox_*`, `growth::a_lowered_writers_*`; notes/crypto.md, A commit giving read epochs). Wrapping under the newest epoch would leave it unable to open the commit that gives it that epoch.

## Candidate fixes
- Wrap under the newest epoch (the plain rule) and give recipients that lack it a direct delivery path: the inbox for actors with one, and a delivery path for recipients without an inbox (links: e.g. an inbox-like slot keyed by the link's own key, or the box carried in the link's sync ID under a key derived from the link seed).
- Wrap the role parts under a key only the given epoch's recipients and current holders open (per-recipient wrap of the section key), keeping the older-epoch wrap for nothing a removed party may read.
