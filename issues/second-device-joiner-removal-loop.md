# Sync does not settle after a joiner's removal when the sharer has a second device
> Summary: If the person who made a share link pairs a second device and then removes someone who joined by that link, the devices never stop syncing: the in-process world never goes quiet (over 2 minutes in a debug build). It works when the second device is paired after the removal. The cause is not found yet; it may be the joiner removal (`revoke_joiner`) racing with the new device, or the rotation loop.
> Tags: sync, node, tests

Repro: in crates/osis/tests/sync.rs `demote_link_joiner_content_spec_permissions_9`, move the pairing of `alice2` (and its `demote` check) before `alice.demote(g, bob…)`. The `w.run()` after the next `item(&alice, g, …)` never returns. As committed, the test pairs after the removal and passes.

- Setup: one server; alice, bob and carol are persons; alice owns a synced group `g` with a multi-use read link; bob and carol redeem it. Then alice pairs a second device, and `alice.demote(g, bob, Remove, Required)` succeeds. That call is one commit removing bob and the link key from K.
- Look first at: K's rotation as the second device sees it (it holds K's admin through the person and was never in `links`); the re-seal and rotation triggers (notes/node.md, rotation loop); and issues/reseal-triggers.md.
