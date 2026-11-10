# A sealer that cannot judge a holder actor seals what a departed party opens
> Summary: what a rotation seals to is judged only from what the sealer holds. Two holes remain where the knowledge sits at another node: a co-writer re-seals a holder actor a knowing node left out (models `D0_readers_g2`, `D0_above_g2`), and a node knowing a departure from M but holding none of M's secrets seals M at M's pre-departure keyset. Options: a left-out mark (wire field), judging by order (needs the left-out-holder fix), or stated limits (today).
> Priority: normal
> Tags: security, keys, engine, tess-call

## The rule (built)
A node never encrypts under, or seals at, what it can tell from held data that a departed party
opens: an epoch not covering a departure it knows, or one boxing a holder actor at such an epoch,
followed through every box at an epoch whose secret it holds, whatever its role (spec/crypto.md §4
Encrypting under; notes/crypto.md Blocked through holder actors). Rights decide only who must
rotate (stale, keyless) and what may be placed (certificates, revokes, own role commits:
`Walk::Place`). An account's epoch is uncovered at its own nodes by a later removal from its devices
actor. Both holes below are where the knowledge needed is not held by the node acting.

## Hole 1: the co-writer re-seal (both models fail on main)
G {R, g2, A}, A {a1, M}, M {m1, R, E}. m1 removes E from M. R (reads M) rotates G leaving A out and
writes. g2, a second admin of G reading neither A nor M, sees A without a box at G's epoch and
re-seals it at A's keyset, which still boxes M at the keyset E opens: E reads R's writes. The
re-seal trigger cannot tell a deliberate leave-out from a missing box. Same for a removal going
alone (`D0_above_g2`: a1 removes E alone, leaves A out of G, g2 re-seals). Depends on incidental
order: whether g2's re-seal comes before A's knowing rotation.
- (a) **Mark**: a rotation records, per holder actor it leaves out, the keyset it was blocked at;
  Seal at every node then takes only a keyset of A listing each mark at A's current epochs.
  `D0_readers_g2_mark` passes (693,353 states, 19 min, 4 workers). `D0_above_g2_mark` fails only
  when a2 rotates A without knowing the removal (the existing ignorant-rotation limit, now reaching
  a knowing writer's content); with no ignorant rotation (`u2Eager`) it was unfinished at 141k
  states. Cost: a wire field (holder actor + keyset in the rotation's `secrets.0` delta, carried as
  a certificate so others judge descent), a Seal clause; A's members miss G's new content until A
  rotates (as now). A liar (a G writer) can only keep A out until A rotates.
- (b) **Stated limit** (built: spec/crypto.md §4, "leaving a holder actor out records nothing").
  Window: until A's knowing rotation reaches the co-writer.

## Hole 2: a departure from an actor whose secrets the node lacks
X administers A, which holds M; X holds none of M's secrets (not a member, or a keyless role in a
cycle), yet knows E left M (a revoke placed under A's labels, say). M has not rotated (a
self-removal, or a removal going alone). X seals M at M's keyset made before the departure; E opens
A's new epochs until M's rotation reaches X. Found by `rotation_holds` seed 200451083602 (peer 0
keyless on H in a cycle, H's only admin hostile: no rotation ever comes, so the window never
closes). The property now excuses a rotator holding no secret of the boxed actor (the limit);
`departure_from_an_unread_holder_is_judged_by_its_next_keyset_spec_crypto_4` shows the recovery.
- (c) **Order**: a keyset none of whose held bodies is ordered after the departure cannot cover
  it (HLC: its rotator held no commit ordered after it), judged without the secret. Checked by building it: it leaves M out where X cannot follow M (X reads none of M's labels, M's
  members, left out, hold no current epoch of A to place M's new keyset under), so M is cut off
  from A for good: issues/left-out-holder-unreachable.md's shape for a node never in M. Sound only
  with that issue's recommended fix (a stranded notice carrying M's `keys.0`).
- (d) **Stated limit** (today: "a node does not judge an epoch whose secret it lacks").

## Decision wanted
Hole 1: (a) mark or (b) the limit. Hole 2: (c) together with the left-out-holder fix, or (d).
Both holes are "the node acting does not hold the knowledge"; marks carry it in the commit, the
left-out fix carries the keysets the leaver needs.

## Model state
core/test/tla/rotation/Depth0.tla constant `Walk`: `"out"` is what is built (the box clause through
every held epoch; Seal leaves out; placement never consults Blocked). `D0_readers_out` passes,
`D0_readers` (`"rotator"`, the old walk) fails in 4 steps. Unfinished: `D0_above_g2_mark` with
`u2Eager`, `D0_readers_live` (liveness of "out", about 1,900 states in 30 min). Hole 2 and the
order rule are not modelled (Depth0 judges only epochs whose secret the node holds).
