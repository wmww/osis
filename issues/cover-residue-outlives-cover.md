# A residue taken from a cover outlives the cover's validity
> Summary: a covered delta that is then purged gets its value-less residue (`w/`) from a covering snapshot's copies (item 184); if that snapshot later turns invalid, the delta goes missing again through `uncover` but the stored residue stays and a later rebuild joins it back, so writes the node no longer holds by any valid route may return.
> Tags: engine, retention

Found reading the valueless-keys review (not reproduced). Check: does `uncover` (or the reopen helper) delete the part's residue row when the residue came from a cover, and does a refetched copy then rebuild it from the body? Repro shape: write, cover by snapshot S, purge (residue from S), S turns invalid (author demoted with an earlier frontier), rebuild; compare against the order where S is invalid on arrival. Related: forged misstating snapshots over dropped expired deltas also leave order-dependent copies (review note; near issues/forged-creation-copies.md).
