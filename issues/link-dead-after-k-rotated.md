# A link cannot be redeemed once K has rotated
> Summary: After K rotates (a joiner leaves, the sharer removes a device) `redeem` never ends: the redeemer takes only K's newest read secret from the entry box, and everything it needs (L's edge, K's creation record, L's boxes and history box) is wrapped under older epochs, the rotation included (spec/crypto.md §5). The link stays listed as working.
> Tags: permissions, node-sync, chat

Honest flows, on main too. Repro on the sim: `alice.make_link(g, ..)`, Bob redeems, `bob.demote(k, bob, Remove)` (or `alice.remove_device(..)` with no redemption yet), `w.advance(70 s)`, Carol redeems: the first wait in `Osis::redeem` times out. Carol then holds one read epoch of K, and does not know K (`knows(k)` false, `roster(k)` empty, commits pending).

spec/permissions.md §9 says the redeemer takes the read secret from the entry box, "download K's label and L's boxes", which the wrap rule forbids for L's boxes of the rotation. `Osis::restore` after a device removal, with no other device online, does work, by a route not traced here: look there first. Way out to weigh: a re-seal of L by the rotator in a commit wrapped under the new epoch (a re-seal writes the history box again, so the redeemer then opens all of K).
