# Do rotations converge under a permanent admin fork?
> Summary: Under a permanent admin fork where each side holds the other side's keysets invalid, a holder actor M of A may re-key once each time the other side rotates A (left out, with that rotation as the cause), and A itself may already rotate back and forth between sides; no model checks that rotations stop under a fork that never settles.
> Priority: normal
> Tags: rotation, tests

Forks are permanent (notes/principles.md): no rule may wait for one to settle. With two admin sides of A each holding the other's rotations of A (or of M) invalid, the reviewer of left-out causes found:
- A rotation cause stands while held, valid or invalid (spec/crypto.md §4 Left out). So each rotation of A by one side that leaves M out, recorded with the other side's rotation as its cause, keeps M out at that keyset at the other side until M re-keys: one re-key of M per such rotation of A, for as long as the fork lasts.
- The reviewer believes A already ping-pongs without left-out records: each side finds the other side's keyset of A invalid, so its boxes to holder actors at it are stale or blocked there, and it rotates A; the other side does the same in turn.

Settle with a model before changing a rule: LeftOut.tla, or the rotation models (core/test/tla/rotation/, Depth0.tla's fork configs), extended with two admin sides that each hold the other's rotations invalid for good, checking that rotations of A and M stop once no one writes (a bounded-churn property like `NoChurn`). If they do not stop, the fix is a rule that stops them (or a stated requirements limit for Tess), not a wait for the fork to end.
