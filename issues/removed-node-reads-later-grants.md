# A departed party reads later role parts
> Summary: A commit giving read epochs (rotation, grant, re-seal) is wrapped under an epoch they supersede, so a party removed at epoch e opens their role parts (who was granted, keysets, box keys; never a box or content) while it still opens S at a peer lacking S's step for e. Tess: a violation of the strict model, accepted for shipping; take any fix that adds no complexity or other tradeoff.
> Priority: low
> Tags: security, crypto, engine, sync

**Decided (Tess):** a violation of the strict model, not to be acted on before shipping; fix it if a way comes up with no added complexity or other tradeoff. In practice a lag or ordering effect: with everyone online and an admin removing, the step for e is issued at once and registered at each store as the rotation reaches it, readers serve a departed member its notices alone, so the removed party fetches nothing later; it shows only through a store behind the step, a rotation by a writer (no step until an admin acts), or a grant made before the step spreads. Study and rejected candidates: notes/keys-establishment.md, The superseded-epoch wrap.

## The leak
Role parts of commits giving e (spec/crypto.md §5, Who wraps under what, the exception): wrapped under the epoch e supersedes, whose roles secret X still holds, until S's step for e reaches the peers X uses (admin-only, so after a writer's removal until an admin next writes). Smallest: X removed from S at the rotation minting e; Y grants Z read on S; X opens the grant's role parts (Z's name, the box keys). The wrap exists because a recipient may hold only an older epoch and have no inbox to be told another way.

The fresh deposit seed in a rotation's `keys.0` is no leak of its own: a deposit is signed with the key a thing's deposit seed derives (spec/sync-inbox.md §2), and the seed rides in the thing's current `keys.0` commits, which every holder of its public key record or a card of it holds by design; a removed party holding it can do what any such party can (spec/sync-hostile.md §2: anyone able to deposit can fill the deposit budget).

## What closing needs
Cards are built (a thing's inbox is the one its cards name, spec/sync-inbox.md §1); the wrap exception stands. The candidate A5 opened: the plain rule (wrap under e) with recipients lacking e taking their box by inbox. At a rotation every holder lacks e, so every rotation becomes one sealed delivery per holder; only a holder whose admins enabled `grant@~0` has an inbox to take it, and a link key has none. Other candidates and their costs: notes/keys-establishment.md, The superseded-epoch wrap.

The cost above was judged too high to close it now.
