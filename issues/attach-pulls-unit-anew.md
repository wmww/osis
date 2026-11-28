# Attaching a thing pulls the enclosing unit anew
> Summary: A strong newly reaching a thing outside the node closure whose minting was held before the pass in flight pulls the unit's sync IDs anew from every source (`units::refetch`), re-listing the whole unit: an attach of an existing thing costs in the size of what it is attached to (83 KB at 4 members, 141 KB at 40).
> Priority: normal
> Tags: sync, engine, performance

A thing minted by another node pulls nothing anew (its minting arrives in the pass the strong does: spec/sync-judgement.md §3 Dropped bodies, notes/node-closure.md Fetched again). An attach does: the thing's minting was held before, so something of it may have been forgotten (its content outside the node closure, a body judged outside the required set), and the whole unit is pulled anew.

**Attach**: a pull limited to the attached thing's entries, if it meets the spec's reason for the pull anew (what was forgotten of the thing is fetched again); else state why the spec needs the whole unit. The pass rule does not reach it: nothing local says what of the thing went, and notes/certificates.md rejects a durable mark per forgotten thing.

Re-measure under stubs (spec/sync-set.md §2).

Tests to add: an attach at n and 10n members of the enclosing unit and of the attached thing, in default tests (as sync `growth::an_independent_thing_another_node_makes_pulls_nothing_anew_*` for makes).
