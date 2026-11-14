# A link joiner never leaves K once K left the target
> Summary: `Engine::joined_links_ended` finds the ended links, but nothing in production calls it, so no joiner's leave (spec/permissions.md §7) is ever written: a joiner keeps K's grant after the sharer takes K off the target.
> Priority: normal
> Tags: sync, engine

## Reproducer
osis-sync `links::repro_a_joiner_leaves_k_once_k_left_the_target_spec_permissions_7` (ignored): node 1 redeems node 0's link to its profile; node 0 removes K's edge on the profile; node 1 holds that removal and `joined_links_ended(None)` at node 1 lists K, yet node 1's account still holds K at both nodes.

## Fix
Call it where role commits on a joined K or its target apply (its doc: "the caller leaves each K", O(touched)), e.g. the driver after an engine step with the touched things, and write each leave as a self-removal from K (once per account: idempotent across its nodes).
