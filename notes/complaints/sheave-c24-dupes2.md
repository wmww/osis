# sheave-c24-dupes2
> Summary: Workflow snags of the core rule-dupes cleanup.

- issues/core-rule-dupes.md said a writer "accepts a write that it then holds invalid". It did not: `apply_local` already refused a write its own apply judged invalid, after applying, as `needs: Write`. My first test showed no drift and I spent a round finding why. An issue stating a drift could name the observable (here: the wrong role in the error, refused after applying), checked by a one-line probe before it is filed.
- The drift-bound item said an own commit could wait in `still_waits`; own commits never pend (pending ones are re-examined as `Origin::Remote`). Same cure: check the claimed path is reachable before filing.
