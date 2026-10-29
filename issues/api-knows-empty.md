# A thing with no content yet reads as deleted
> Summary: `knows(t)` now means "here and has content" (api-asks-1), so a durable thing that is only created and placed, a group synced before any write, or the person actor reads `knows == false`, the same as a deleted thing; and `remove_subgroup(home, g)` while `g` stays an item can still leave its items unsynced (only placements are checked).
> Tags: api

Options for the first: deletion leaves a marker the engine can tell from "never written" (then deleted = marker, not emptiness), or accept and document "write before relying on `knows`". The second: refuse a subgroup removal that leaves a durable item reaching no synced group (checks every item of `g`), or leave it documented (notes/api.md). Both suit the owner's whole-API review.
