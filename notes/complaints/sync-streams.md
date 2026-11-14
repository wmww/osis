# sync-streams
> Summary: workflow notes from building the streams module.

- The store and opens branches were in review on other bases; coding against them meant a throwaway merge (opens conflicts with session) before the store landed. A module brief that names its dependencies' merge order would save the detour.
- Opens' `stopped` mixes logs: on this side's own close it keeps the peer's reported cursor (a cursor of this node's log) as the member's rejoin position, which is a cursor of the peer's log. Streams asks opens through `Shared::rejoin` instead; opens needs `Rejoin::From(None)` after a digest difference and the Lost's cursor only after a Lost.
