# Build foreign keysets: rotations stop under a permanent fork
> Summary: Under a permanent fork on a holder actor M of A (A's writers holding A directly), the built rules make the two sides rotate A in turn forever; the spec's Foreign rule (an epoch whose own box names a keyset held invalid supersedes nothing and makes nothing due) stops it, model-checked in ForkRot.tla, not built.
> Priority: normal
> Tags: rotation, engine

The rule: spec/crypto.md §4 Holder actors, Foreign (with Epochs, Supersedes and the knowing re-key). Why: notes/disputes.md, Rotations under a fork. Model: core/test/tla/rotation/ForkRot.tla (`run.sh forkrot`; `FR_m_now` is the built behaviour and fails `Quiet`).

The loop as built: p's rotation of A boxes M at p's keyset kP; q holds kP invalid, so p's epoch has a stale box there and the knowing re-key makes q rotate, boxing kQ and listing p's epoch; at p that rotation supersedes p's epoch and is stale in turn. No left-out record is needed. The same loop one level down (M unforked, a holder actor of M forked) also re-keys M once per round through left-out records whose cause is a keyset held invalid.

Build:
- A held valid keyset is foreign at the node when a `keys.0` body writing it records a box at that epoch naming a keyset held invalid or foreign (box records: `rotation::members` already reads held invalid keysets, `invalid_writers`). Recursive up the holder actor chain.
- Supersession (core/keys `epoch.rs`, the current set) skips foreign rotations; the node needs the foreign set from the engine, since it rests on holder actors' validity.
- `rotation_due` skips foreign epochs for the knowing re-key; they stay current, blocked by their stale box (`blocked_epoch` already blocks them), listed by the next rotation and re-sealed into.
- To a thing above, a foreign keyset counts as held invalid: Descends, Anchors, Seal candidates, Stale, Left out.
- Hand tests (engine `rotation`, built on the dispute fixtures): a fork on a holder actor M of A, each side rotating A once and receiving the other's, leaves no rotation due on either side; a later rotation by q lists p's epoch (its history kept); a re-seal by the other side into a shared epoch costs one rotation, then none.
