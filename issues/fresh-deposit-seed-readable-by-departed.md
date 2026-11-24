# A departed party can read the fresh deposit seed
> Summary: The fresh deposit seed an admin's read rotation of M writes sits in M's `keys.0`, which travels wrapped under epochs the departed party still holds in three places: the rotation commit itself (wrapped under the epoch it supersedes, spec/crypto.md §5), the keyset commits a rotation, grant or re-seal of a thing M holds a role on carries (spec/crypto.md §4, Carried), and M's current `keys.0` commits, carried as certificate copies under the sync ID of each thing M holds a role on (spec/permissions.md §4, the grantee's current keys). A party that sees one can keep depositing under M's sync IDs (filling their deposit budgets) until the seed is refreshed again. No clean fix exists without moving the seed out of `keys.0`, which those copies carry; the rotation-commit path is the superseded-epoch wrap, studied in notes/keys-establishment.md (no structural close). Judged again at stage A5 (notes/redesign-plan.md), as a bug to fix or a weaker property.
> Priority: low
> Tags: security, sync, engine

spec/crypto.md §3 asks for a fresh seed in each read rotation but does not claim it stops a departed party.

Repro (the rotation commit path): osis-engine (ignored): peer 0 removes reader peer 1 from thing t; peer 1 opens the removal's entry under t's sync ID (`seal_body` at peer 0, `open_entry` at peer 1) with the epoch it still holds and reads the fresh `deposit_seed` in t's `keys.0` (one blob: the boxes need the old wrap, `keys.0` does not). A holder who read the thing through another sync ID does not learn it. By the same design (a holder's new `keys.0` goes under its targets' sync IDs, spec/permissions.md §3, §4) a reader of target S learns holder T's current seed with no right on T; a revoke brings no keyset of a thing no chain of roles connects to the sync ID.

Severity: low (junk deposits only; a deposit of valid closure content by a non-writer is never promoted, spec/sync-inbox.md §4: junk fills a sync ID's deposit budget, grants wait, admins delete junk; anyone holding a thing's `keys.0` can already do this to its inbox, notes/sync-inbox.md).

Windows, for X departing M (rotation by an admin writing M's fresh seed):
- **Before the new step**: the rotation commit (a closure body, wrapped under the superseded epoch) is logged before the Register of the new step (spec/sync-ids.md §6: role commits before the step). Until the step lands at a peer keeping M's sync ID unread, X can open there under the old sync key and fetch it; the new head (another sync key, X in no claim set) then ends X's open.
- **Carried** (spec/crypto.md §4): for X's departure from M where M holds a role on A, A's rotation, grant or re-seal sealing M at its new keyset logs M's rotation commit (its `keys.0`, seed included) under A's sync IDs, wrapped under A's epochs X may still read (A is not rotated for a departure inside M). Lasts while X can open that entry there.
- **Grantee keys elsewhere**: M's current `keys.0` commits (seed included) go as certificate copies under the sync ID of every thing M holds a role on, so every admin there can seal to M; if X still reads such a sync ID (X removed from M, an organization, still a direct holder on a project H that M holds a role on), X reads the seed for as long as it reads that sync ID.

Why no fix: a seed-only commit wrapped under the new epoch would still be one of M's current `keys.0` commits, carried as the others are; deriving the seed from the newest read secret plus a public nonce breaks inbox deposits (senders hold only `keys.0`). The refresh therefore only stops a departed party that sees none of the above. Not yet weighed: sealing the seed in the rotation's boxes rather than in `keys.0` (who deposits then needs a box).

Where: core/engine/src/rotation/mod.rs `refreshes_deposit` / `fresh_deposit_seed`; the Register order in core/sync/src/inbox/register.rs.

## Where the fix lands
Stage A5 (notes/redesign-plan.md A5): the only clean fix moves the seed out of `keys.0`, and A5 replaces `keys.0`'s inbox field by a card aspect and an admin-only aspect naming a thing's inbox and cards, where a seed can be sealed under the new epoch. A3's keyset seed moves only demotions (no `keys.0`).
