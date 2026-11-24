# Making a deep dependent independent is slow
> Summary: `Engine::make_independent` on a thing at the bottom of a 64-deep record chain of dependents (minted with the node thing at the top) takes about 15 s in a debug test, and syncing it after about 8 s; the same chain made independent at its top costs well under a second. Work should follow what the rotation boxes, not the chain's depth squared or worse.
> Priority: normal
> Tags: engine

Seen building `edge_on_deep_thing_not_held_spec_permissions_1` (core/engine/src/apply/tests_validity.rs), which now makes the chain's top independent instead. Count the work (records read, epochs derived, rotations considered) at depth 8 and 64 to find what grows.
