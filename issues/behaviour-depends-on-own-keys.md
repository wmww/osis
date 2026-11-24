# Behaviour depends on whether a thing is independent
> Summary: Tess: whether a thing derives its keys from its mint admin (dependent) or has its own (independent) may change cost, never behaviour; promotion is implicit, and once independent the mint admin is an admin like any other. Two behaviours differ today, and the mint admin stays special in two ways.
> Priority: normal
> Tags: api, cli, perm, engine

The rule (Tess): no API behaviour depends on it. Docs may state the cost difference where it matters, hedged and without the internal terms (notes/api-design.md, Public docs). The mint admin of an independent thing has no significance: any trick treating it specially must be unobservable.

notes/api.md and notes/chat.md quote byte figures for app-facing choices.

Behaviour that differs:
- **A thing minted with admin an account** is independent at birth (spec/permissions.md §3, spec/sync-set.md §2), because an account is in no sync unit. It becomes an ordinary dependent once the account is an ordinary independent thing (stage A4; notes/write-path-design.md §5); until then `osis create --admin me` reaches it.
- **Sharing what a tag holds**: a strong grants nothing, so an app sharing a tag of n things makes n grants itself (issues/many-sync-ids-cost.md). To check whether that counts.

The mint admin staying special after it is removed (to study):
- **Depth**: a delta on a thing more than `MAX_CHAIN_DEPTH` (64) links down its record chain is invalid (spec/permissions.md §1), however many of the things between are independent or have removed their mint admins.
- **The record names it for good**: the tid commits to the mint admin, so every holder of the record learns which admin the thing was minted with, after that admin is gone.

Accounts being a special kind of thing (the birth-independence above is one symptom): issues/actors-one-mechanism.md.
