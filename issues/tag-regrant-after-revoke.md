# A tag's access cannot be granted again after it was taken back
> Summary: After `demote(thing, my_tag, Remove)` every later grant on the thing fails "another node must rotate first": each of my nodes acts through my own tag, so by spec/crypto.md §2 no rotation of mine covers the tag's departure. Re-tagging into a shared tag after a revocation leaves the thing tagged, unshared, with an error.
> Tags: core-ask, owner-call, crypto, permissions, app

Repro (core calls; the app test that showed it went with the app's sharing logic): Alice's thing `n`, her tag `tag` shared with Bob; `grant(n, tag, Write)`, then `demote(n, tag, Remove)`, then `grant(n, tag, Read)`: the last grant fails.

- Cause (likely): "An epoch whose rotation commit was written by a departed party (or a node acting through it) does not cover that party's departure" (spec/crypto.md §2). The tag is a group actor I own, so my nodes act through it; the demotion's own rotation then covers nothing, and no other node may rotate (Bob is the tag's member too). The thing is stuck: no node may encrypt under the uncovered role, so no grant to anyone succeeds again.
- The rule exists for a member that rotates on its way out. It should not apply when the remover reaches the departed actor only as its owner or admin (the remover is not leaving), or the departure should count as covered by a rotation that excludes the departed actor's own box. Needs a spec decision (crypto/permissions), then core.
- App side: `add_tag` places before it grants, so the placement stays when the grant fails (placing after a failed grant would be the safe order only if a failed placement could not leave the grant behind).
