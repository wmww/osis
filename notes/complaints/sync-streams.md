# sync-streams
> Summary: workflow notes from building the streams module.

- The store and opens branches were in review on other bases; coding against them meant a throwaway merge (opens conflicts with session) before the store landed. A module brief that names its dependencies' merge order would save the detour.
- Opens' `stopped` mixes logs: on this side's own close it keeps the peer's reported cursor (a cursor of this node's log) as the member's rejoin position, which is a cursor of the peer's log. Streams asks opens through `Shared::rejoin` instead; opens needs `Rejoin::From(None)` after a digest difference and the Lost's cursor only after a Lost.
- Review: the worker's report (its five readings, its three O(members) costs) was not passed on to the reviewer; the reviewer had to infer them from the code. A brief that names report items should paste them or point at a file.
- Review: two controls' tests passed with the rule broken (SN_joinans: an empty source log keeps the requester's cursor none, so every Pull is a whole listing and the join path never runs; SN_lostolder: no stream position was reported, so a premature merge was invisible). Breaking each rule in code caught both; reasoning had not.
