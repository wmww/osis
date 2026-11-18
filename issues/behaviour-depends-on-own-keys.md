# Behaviour depends on whether a thing has own keys
> Summary: Tess: whether a thing derives its keys from its first admin (dependent) or has its own (independent) may change cost, never behaviour; promotion is implicit, and once independent the first admin is an admin like any other. Three behaviours differ today, and the first admin stays special in two ways.
> Priority: normal
> Tags: api, cli, perm, engine

The rule (Tess): no API behaviour depends on it. Docs may state the cost difference where it matters, hedged and without the internal terms (notes/api-design.md, Public docs). The mint admin of an independent thing has no significance: any trick treating it specially must be unobservable.

Docs to rewrite to that: `Write::create` (core/osis/src/write.rs), `osis create --admin` (cli/src/args.rs), `Osis::hold` (core/osis/src/share.rs); notes/api.md and notes/chat.md quote byte figures for app-facing choices.

Behaviour that differs:
- **Removing the last admin** of a dependent thing is refused (`flows::edges::leaves_no_admin`, spec/permissions.md §1); on an independent one the same write goes through and leaves it adminless. One rule for both is owed (Tess: either, but the same).
- **A thing made under an account** is independent at birth (spec/permissions.md §3, spec/sync-set.md §2) and in no sync unit unless a ticket carries it; one made under the account root is dependent and synced with it. `osis create --admin me` reaches it. An account is a key actor; why nothing may derive from its epochs is not written down. Make it an ordinary case or keep apps from reaching it.
- **Sharing what a tag holds**: a strong grants nothing, so an app sharing a tag of n things makes n grants itself (issues/many-sync-ids-cost.md). To check whether that counts.

The first admin staying special after it is removed (to study):
- **Depth**: a delta on a thing more than `MAX_CHAIN_DEPTH` (64) links down its record chain is invalid (spec/permissions.md §1), however many of the things between are independent or have removed their first admins.
- **The record names it for good**: the tid commits to the first admin, so every holder of the record learns who made the thing under what, after that admin is gone.

## Terms (Tess; the rename is one pass, issues/deprecated-terms.md)
- **dependent thing** (derives its secrets) and **independent thing** (has its own), for plain and own keys / keyed / secrets of its own.
- **mint admin** for first admin: a term to grep, and it is treated specially inside.
- No "made under X" or "under X": the positional picture is not kept to elsewhere (what holds a thing is another matter). Say "minted with admin X", "one of X's dependents".
- **base actor** (spec/crypto.md §3) is one link up, so it is a dependent thing's mint admin: one of the two words goes. **reader actor** (spec/sync-judgement.md §1) is the nearest independent actor up the chain and stays.
- None of these words reach the API or its docs.
