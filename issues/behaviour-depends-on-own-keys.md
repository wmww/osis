# Behaviour depends on whether a thing is independent
> Summary: Tess: whether a thing derives its keys from its mint admin (dependent) or has its own (independent) may change cost, never behaviour; promotion is implicit, and once independent the mint admin is an admin like any other. Open: sharing what a tag holds, external signals on a dependent thing, and two ways the mint admin stays special.
> Priority: normal
> Tags: api, cli, perm, engine

The rule (Tess): no API behaviour depends on it. Docs may state the cost difference where it matters, hedged and without the internal terms (notes/api-design.md, Public docs); notes/api.md and notes/chat.md quote byte figures for app-facing choices. The mint admin of an independent thing has no significance: any trick treating it specially must be unobservable.

- **Sharing what a tag holds**: a strong grants nothing, so an app sharing a tag of n things makes n grants itself (issues/many-sync-ids-cost.md). To check whether that counts.
- **External signals on a dependent thing**: they are specified for independent things only (spec/sync-inbox.md §1: sealed to the thing's own keyset, deposited under its sync ID). Enabling one on a dependent thing must work, or make the thing independent without the caller seeing it; refusing or doing nothing is this issue's bug (Tess). What the engine does is not checked. notes/stubs.md, For the spec piece, has the inbox's case.
- **Depth** (to study): a delta on a thing more than `MAX_CHAIN_DEPTH` (64) links down its record chain is invalid (spec/permissions.md §1), however many of the things between are independent or have removed their mint admins.
- **The record names the mint admin for good** (to study): the tid commits to it, so every holder of the record learns which admin the thing was minted with after that admin is gone.
