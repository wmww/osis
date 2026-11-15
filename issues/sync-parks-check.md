# The differential's parking check looks at no entry
> Summary: `World::parks` (`Follow::lost_parks`) checks only entries whose commit the engine knows yet neither holds nor pends; 20 faulted convergence seeds produce none, so the check never fires, and the entries that truly wait for a read secret (never opened, no commit known) are outside it. A stronger predicate meets ~1,600 unexplained unparked entries.
> Priority: low
> Tags: sync, tests

`lost_parks` (core/sync/src/store/follow.rs) counts an entry lost when `blob_commit` is known, `waits` holds and it is not parked. An entry that did not unwrap (`Opened::NotOpen`) has no commit known, so the main parking failure (a NotOpen entry not parked) is invisible to it. A probe over `convergence::histories_converge` (20 faulted seeds, at every step end) found 0 entries the check examines.

Parking is tested directly: `flows::a_read_secret_arriving_examines_only_what_did_not_open_spec_sync_2` asserts the parked entry is examined as the secret arrives (a `park` that does nothing fails it).

Stronger predicate tried (probe, not committed): a non-own entry, no commit known, unparked, whose wrap opens under none of `Engine::read_secrets(thing)`. Over the same 20 seeds it matched ~1,600 entry-checks (all with bytes; ~200 deposited) while every history converged. Unclassified: they may be legitimate (an entry that opened to records, lists, a linked blob or inbox, whose secret left since) or real lost parks masked by the commit arriving another way. Classifying them (log the `Opened` each entry last gave) decides whether the check can be made real or should be dropped (it costs a full scan per step).
