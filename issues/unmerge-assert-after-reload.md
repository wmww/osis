# In-place un-merge check fails on an invalid late part after a reopen, text deleted
> Summary: `unmerged_as_rebuilt` panicked in debug on a late copy of an invalid body joined after a reopen: the state holds a deleted text element with its content gone, `rebuilt` still has the character. Found by dropping a broken body, reopening, receiving it again. Not diagnosed; probably the check's rebuild not applying the dead-creation rule, so a false alarm, but unproven.
> Tags: engine, crdt, tests

History (seed 8200196, order after the setup: commits 13, 10, 9, 12, 11; `drop_broken(None)` after each, `reload`, `rebuild_index`, then every package again): `h = vec![Require { by: 2, t: 0, op: 9, rule: 2 }, Breaking { by: 1, t: 0, op: 9, v: 1, fits: false }, Aim(Demote { by: 0, t: 0, holder: 2, at: 0, to_read: false }), Aim(Breaking { by: 2, t: 0, op: 9, v: 5, fits: false }), Sync { from: 1, to: 0 }, Aim(Breaking { by: 0, t: 0, op: 9, v: 3, fits: false })]`.

In memory before the reopen the element reads `content: Char('x')` with its delete; after `reload` `content: None`. The late join's un-merge then keeps `None`, the check's `rebuilt` gives `Char`. Worth finding out whether a late part after a reopen reaches it with no required retention (keep-bound drops, plain late parts). `order::required_drops_read_alike` reopens only after its comparisons so as not to stop here.
