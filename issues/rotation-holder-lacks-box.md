# A holder actor stays left out when an invalid keyset breaks its descent
> Summary: A holder actor M of A is left out of A at a role for good when the only chain from M's newest keyset back to the keyset A's boxes anchor at runs through a keyset held invalid (spec/crypto.md §4 Descends: an invalid keyset passes nothing on), and every later rotation of A records M left out again; nothing makes M's rotators rotate. Seen as `rotation_holds_large_spec_crypto_4` seed 147083058899 ("a holder … with key access lacks a box").
> Priority: normal
> Tags: engine, keys, tests

Replay: `OSIS_ROTATION_START=147083058899 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`. Liveness only: nobody reads what they should not.

The shape (all at peer 0, mint admin and admin of actors 1 and 2; actor 2 holds Write on actor 1):
- A's (actor 1's) Read epoch boxes M (actor 2) at M's Read n1 (its creation record's keyset).
- Peer 4, a writer of M, rotates M's Read to n2 listing n1; that rotation is concurrent with peer 4's removal from what gave it write, so its `keys.0` is held invalid everywhere. A later valid rotation of M (n3, by peer 0, which held n2 current then) lists only n2; n4 lists n3.
- Descent from n1 is broken at n2, so at A's next rotation Seal finds no candidate past the anchor n1 and leaves M out at Read and Write, recording n1. Each later rotation of A records it again, so no keyset of M made before A's latest rotation is past it; only a fresh rotation of M would be, and no rule makes one due. Re-seals then find M lacking boxes and write nothing (`reseal_scan` asks `members::sealed`, which says Out).

Candidate fixes (needs a decision on the spec): a node that may rotate M at r rotates M when some A leaves M out at r with no candidate past its anchors or records (a fresh keyset is ordered after every record); or descent through an invalid keyset where the valid keyset listing it was made by a rotator holding the earlier epoch's secret (its history box carries it; rejected so far because a forgery lists everything, notes/holder-actors.md).

Not a regression: the seed passes at f05663598 and fails from 7685c494 (the property's X step fed by what its sync IDs carry), a harness change that reached this shape.
