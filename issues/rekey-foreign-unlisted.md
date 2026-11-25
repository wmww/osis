# Re-key may repeat while a foreign keyset stays recorded
> Summary: `left_out` and `rekey_due` judge a holder actor's keysets current by keyset lists alone, so a foreign keyset no keyset lists stays "current" for good; A's record of M left out at it keeps `rekey_due` true after M's re-key, and M may rotate at every pass end while A's writers are idle. Suspected from reading; not reproduced.
> Priority: normal
> Tags: engine, crypto

**Property** (spec/crypto.md §4 Holder actors: Foreign, Left out, Re-key; `rekey_due`'s own doc: at most one rotation of M per rotator of M): a foreign keyset is carried in a rotation's history box and listed in no keyset; once M's re-key supersedes it (history box), it is no current keyset of M, and the record no longer leaves M out.

**Code**: core/engine/src/rotation/members.rs `rekey_due` (~394) and `left_out` (~536) count a held valid keyset current unless some non-foreign keyset's list names it; a foreign one is never listed (it goes in the history box), so it is current to them forever. ForkDepth.tla's `RotUDue`/`LeftU` judge over `CurU`, which counts history boxes.

**World** (an honest race making f foreign at side Q, as ForkDepth "race" / `tests_foreign::fork_below_g`): W, a writer of A who may not rotate M, rotates A; Seal gives a keyset stale under f, so A records M left out at f with rotation-commit causes (which stand for good). R, a rotator of M syncing A who may not rotate A, re-keys M at A's pass end; W re-seals M. At R's next pass end `rekey_due` is true again, and so on while A's writers stay idle.

**Fix**: judge current in `rekey_due` from the rotator's own view of M (`epochs(m).role(r).is_current(q)`, counting the history box), or never record a foreign keyset (it is never an anchor or Seal candidate). Test: a `fork_below_g` variant where G's writer may not rotate A and A's rotator may not rotate G; five pass ends of G with its writer idle rotate A at most once.
