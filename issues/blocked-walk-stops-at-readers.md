# Blocked walk stops at actors the node may not rotate
> Summary: M holds a role on A, A on G; E leaves M; R may rotate G and only reads A and M: G's epoch is not blocked at R (`rotation::blocked_epoch` descends only through actors R may rotate), so R writes G content E opens. Model confirms (`D0_readers`). Descending through every held epoch ("out") is not enough: a second G admin not reading A re-seals A where R left it out, opening R's writes (also on main for alone-above, `D0_above_g2`). Candidate: the rotation records the keyset it left A out at ("mark"); unfinished.
> Tags: security, keys, engine

Found in review of alone-above. On main at every height, not only while a removal goes alone: the
model's shortest trace has m1 remove E from M with M's rotation carried; R holds M's new keyset, but
A's box to M names M's old one, and R, not A's rotator, writes G under its first epoch, which E
opens through A and M. Window: until M's rotator and then A's rotator next sync, then R finds G's
box to A stale.

## Model (core/test/tla/rotation/Depth0.tla, constant `Walk`)
`NoLeakAbove` now covers chains: a writer knowing a removal from any actor below the written one
(`KClos`), holding every epoch of it and of each actor between (and every re-seal box of the epoch
at write time), writes nothing the removed device opens. Instance `vActs` (Depth0MC.tla): G {R, A},
A {a1, M}, M {m1, R, E}; R the one admin of G, reading A only through M; m1 removes E from M (alone
or carried, `Alone = "any"`). `Walk` values:
- `"rotator"` (main): `D0_readers` **fails** in 4 steps (above).
- `"out"` (candidate a): the box clause descends through every epoch whose secret the node holds;
  stale and keyless stay rotators' only; Seal leaves A out. `D0_readers_out` passes (2,827 states;
  probes: a knowing write and a rotation of G leaving A out are reachable).
- `"wait"`: as "out", but a node that may not rotate A makes no rotation leaving it out.
  `D0_readers_wait` passes (202 states). Rejected: every rotation of G at R (a removal from G
  included) waits on M's and A's rotators, where "out" only keeps A's members from G meanwhile.
- But "out" **fails** with g2, a second admin of G reading neither A nor M (`D0_readers_g2`, 249
  states): R rotates G leaving A out and writes; g2, unable to judge A's keyset, re-seals A at it
  into R's epoch (the re-seal trigger cannot tell a deliberate leave-out from a missing box, as in
  notes/permissions.md R1), and E opens R's write. **Main has the same hole for alone-above**
  (`D0_above_g2`, Walk "rotator": a1 removes E alone, rotates G leaving A out, writes; g2 re-seals A
  at A's uncovered keyset; fails in 6 steps).
- `"mark"`: as "out", and a rotation records, per actor it leaves out, the blocked keyset (or the
  marks it was left out at before); Seal, at every node, then takes only a keyset of A that lists
  each mark at A's current epochs (strict descent). `D0_readers_g2_mark` passes (693,353 states, 19
  min, 4 workers). `D0_above_g2_mark` **fails** when a2, A's other admin, rotates A without knowing
  the removal (g2 re-seals A at that ignorant keyset, which lists the mark): the existing stated
  limit for ignorant rotations (spec/crypto.md §4 Holder actors), now reaching a knowing writer's
  content. Without that ignorant rotation (`u2Eager`): see State below.

## Options
- (a) "out" alone: does not hold with a second rotator of G (common: G's admins rarely all read
  every member group). Not recommended.
- (a+) "mark": closes the re-seal hole; leaks only through a rotation of A made without knowing the
  departure (stated limit). Costs a wire field (left-out holder actor + keyset in a rotation's
  `secrets.0` delta, carried as a certificate so others can judge descent), a Seal clause, and
  A's members miss G's new content until A rotates (as alone-above). Also fixes alone-above's hole.
- (b) stated limit: the window until M's then A's rotators sync (and, for alone-above, any G admin
  not reading A reopens it). Simplest; Tess prefers a clearly stated problem to a workaround.

Placement must not be blocked by the walk (any option binding readers): binding readers through
stale boxes earlier stopped R placing W's revoke under G, so G's admin never learned (osis-node
`revokes::revoke_about_author_placed_spec_permissions_4`). In the model placement never consults
`Blocked`. For a node that may not rotate r, the box clause would block content, boxes, grants and
re-seals, not placing revokes, roster snapshots or chain certificates (no secret of r in them).

## State for the next coordinator
- Unfinished runs: `D0_above_g2_mark` with `u2Eager` (no ignorant rotation of A) was at 141k
  states, unfinished, when stopped; `D0_readers_live` ("out", liveness) was stopped at ~1,900 states
  after 30 min (liveness here is very slow per state: fairness ENABLED over 3 learners x 3 actors);
  no mark liveness run yet. Run.sh lists the instances as `all` with expected results from the
  finished runs only.
- Decide (a+) vs (b) (likely a Tess question: it extends question 12's bend and adds a wire field).
  If (a+): rerun the two unfinished checks first, then build steps:
  1. spec/crypto.md §4: box clause for every holder of the secret (stale, keyless stay rotators');
     placements exempt for non-rotators; Seal: a rotation leaving holder actor M out records M and
     the keyset (spec/wire.md), Seal takes only keysets listing each such mark at A's current
     epochs; spec/permissions.md §3 line 95 to match.
  2. `rotation::blocked_epoch`: `may_rotate` gates only `stale_at`/`keyless_at`; descend always.
  3. `NodeSync::placing` (core/node/src/sync/mod.rs): skip the box clause for roles the node may
     not rotate.
  4. `members::sealed` / `recipients`: write and honour marks.
  5. Tests with the `openable` oracle, failing with each step reverted: three levels with R a
     reader of M only; a second G admin not reading A re-sealing (both shapes); keep the two revoke
     tests passing.
