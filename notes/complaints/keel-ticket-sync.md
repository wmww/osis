# keel-ticket-sync
- main moved under the task (second closure tree, refs keyed by AK, keying at creation): a rebase of units.rs could not be merged textually; porting by hand onto the new file was faster than resolving.
- A single hung test (an engine-side livelock: lost-access drop and the walk retaking a stale ticket, forever) gave no stack: no gdb on the box. Found by a round counter in the driver's settle loop; a debug-build loop guard there would have named it at once.
- `cargo test -p osis-sync --test it a b` treats `b` as a second binary filter only after `--`; without it the run silently filtered nothing useful.
- The harness's card redeem (every multi-node fixture) failed on main, so most osis-sync tests showed one symptom ("redeems 1's card") for several causes: a link's K holding no strong to its target (its grant never reached a redeemer), ticket sync IDs never synced, and a third redeem still pending.
