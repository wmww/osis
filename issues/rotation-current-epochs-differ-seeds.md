# rotation_holds seeds 469, 630, 765: holders count different current epochs
> Summary: Seeds 469, 630 and 765 of `rotation_holds_large_spec_crypto_4` (in the default 0..1000) end with two holders of one role disagreeing on the current epochs after the due rotations (469 Read, 630 and 765 Sync). Fails alike on main at f867a57b9 without the forged-epoch-opens changes; not triaged (a possible convergence bug: a holder may keep encrypting under an epoch the others count superseded).
> Priority: normal
> Tags: tests, rotation, keys

- Replay: `OSIS_ROTATION_START=<seed> OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`.
- Start at: which epoch one peer counts current and the other not, and whether the difference is a superseding rotation one holds without its secret (Supersedes reads the history box only with e's secret) or a recent change to box/maker departures per role (828991752).
- Seed 469 (Read): peer 1 made n2, then, while a commit was withheld from it ("withheld at 1: 14"), n3 and n4. After settling, the first admin (peer 0) counts n2 and n4 current, peer 2 only n4: peer 0 likely lacks n3's rotation commit (the one superseding n2) or holds it unestablished, and n4 supersedes n2 only through it. If so, peer 0 sees a fork whose merger (peer 1, n2's maker) sees none: a convergence gap (a held-set difference the property never closes), not a leak. Check first whether the property's final sync delivers n3 to peer 0.
