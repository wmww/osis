# Two orders pick "the" fork of a forked epoch
> Summary: A box to a forked holder actor M names M's `keys.0` keyset (LWW of the forks' writes) at a node holding no secret of M, but the newest fork by nonce at a holder; the covers rule wants the newest. `fork_named` (rotation-livelock) papers over it by rotating M; one agreed choice would remove the extra rule.
> Tags: permissions, engine, keys

`rotation_due` rotates a forked role of M when a current box to M names a fork other than M's newest (`fork_named`, spec/permissions.md §3). That ends the A/M rotation livelock, but only by making a fork-ending rotation: two of M's rotators acting concurrently fork again, and a later box from a non-holder can trigger it once more (terminates as soon as one rotation lands alone; no test makes rotators persistently concurrent).

The root is that the same forks are ordered two ways: `keys.0` keeps one keyset per role by LWW, `RoleEpochs::newest` orders by (order n, lower nonce). A non-holder can only seal to the `keys.0` keyset. Candidates for one choice both sides compute:
- order forks of one n by which one `keys.0` names (nonce only when it names none current): touches every `newest` use (label keys, registration branch, covers verdicts and the walk's class merge, which the worker says is exact only at the newest);
- a node indexes each rotation delta's keyset per epoch, so a non-holder can seal to the newest fork (spec §4 already says "M's newest `keys.0` keyset it holds"); residual once the deltas are compacted away;
- a `keys.0` keyset merge by epoch order instead of LWW (a CRDT register type osis lacks).

Decide whether any is simpler than keeping `fork_named`; if one is, drop `fork_named` and its spec sentence.

Review of reseal-livelock: one fork order would remove `fork_named` only. The re-seal fork rule (a re-sealer needs a missing fork's secret) comes from holders keeping every fork's secret, not from which fork is newest, so it stays under any order. A `keys.0` keyset merged by epoch order is a max register, which a planted n near 2^63 would pin for good (LWW lets the next valid write replace it). The rule that would remove both is "forks do not persist" (a node holding every fork ends it by rotating), rejected once for the single-use link loop; revisit only with a rule that stops concurrent fork-enders re-forking.
