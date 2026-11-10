# A sealer that cannot judge a holder actor seals what a departed party opens
> Summary: what a rotation seals to is judged only from what the sealer holds. A co-writer of A holding none of the epochs a knowing node's box walk followed re-seals a holder actor that node left out (models `D0_readers_g2`, `D0_above_g2`), and the knowing node rotates again for each re-seal, endlessly while the holder never rotates. Options: a left-out mark (wire field) or the stated limit (today).
> Priority: normal
> Tags: security, keys, engine, tests, tess-call

## The rule (built)
A node never encrypts under, or seals at, what it can tell from held data that a departed party
opens: an epoch not covering a departure it knows, or one boxing a holder actor at such an epoch,
followed through every box at an epoch whose secret it holds, whatever its role (spec/crypto.md §4
Encrypting under; notes/crypto.md Blocked through holder actors). Rights decide only who must
rotate (stale, keyless) and what may be placed (certificates, revokes, own role commits:
`Walk::Place`). An account's epoch is uncovered at its own nodes by a later removal from its devices
actor. The hole below is where the knowledge needed is not held by the node acting.

## The co-writer re-seal (both models fail on main)
G {R, g2, A}, A {a1, M}, M {m1, R, E}. m1 removes E from M. R (reads M) rotates G leaving A out and
writes. g2, a second admin of G reading neither A nor M, sees A without a box at G's epoch and
re-seals it at A's keyset, which still boxes M at the keyset E opens: E reads R's writes. The
re-seal trigger cannot tell a deliberate leave-out from a missing box. Same for a removal going
alone (`D0_above_g2`: a1 removes E alone, leaves A out of G, g2 re-seals). Depends on incidental
order: whether g2's re-seal comes before A's knowing rotation. It is also a livelock: G's epoch
is blocked at R again after each re-seal, so R rotates G once per re-seal of g2's, for as long
as A's knowing rotation does not reach g2 (for good where A's rotators are gone: `rotation_holds`
seed 515999791879, A's only admin hostile). Closed where g2 holds M's knowing keyset (Seal skips
a keyset with a stale box, `co_writer_seals_no_keyset_with_a_stale_box_spec_crypto_4`); open
while M has not rotated (a removal going alone) or M's new keyset has not reached g2.
- (a) **Mark**: a rotation records, per holder actor it leaves out, the keyset it was blocked at;
  Seal at every node then takes only a keyset of A listing each mark at A's current epochs.
  `D0_readers_g2_mark` passes (693,353 states, 19 min, 4 workers). `D0_above_g2_mark` fails only
  when a2 rotates A without knowing the removal (the existing ignorant-rotation limit, now reaching
  a knowing writer's content); with no ignorant rotation (`u2Eager`) it was unfinished at 141k
  states. Cost: a wire field (holder actor + keyset in the rotation's `secrets.0` delta, carried as
  a certificate so others judge descent), a Seal clause; A's members miss G's new content until A
  rotates (as now). A liar (a G writer) can only keep A out until A rotates.
- (b) **Stated limit** (built: spec/crypto.md §4, "leaving a holder actor out records nothing").
  Window: until A's knowing rotation reaches the co-writer; R and g2 alternate a rotation and a
  re-seal each pass meanwhile. (a) ends both.

## Decision wanted
(a) mark or (b) the limit. "The node acting does not hold the knowledge": a mark carries it in the
commit.

## Oracle
osis-engine `rotation::tests_property` excuses a departed peer opening an epoch through a box to a
holder actor of which the rotator held no secret (`Made::blind`). The order rule narrows that limit
to keysets ordered after the departure; the excuse could narrow with it (computed from the
generated history).

## Model state
core/test/tla/rotation/Depth0.tla constant `Walk`: `"out"` is what is built (the box clause through
every held epoch; Seal leaves out; placement never consults Blocked). `D0_readers_out` passes,
`D0_readers` (`"rotator"`, the old walk) fails in 4 steps. Unfinished: `D0_above_g2_mark` with
`u2Eager`, `D0_readers_live` (liveness of "out", about 1,900 states in 30 min).
