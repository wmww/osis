# Read re-judges every (S, commit) at nearly every step
> Summary: `read`'s judged keys (one per sync ID x commit whose bodies or chain certificates go under it) are each re-judged about 20 times over a 40-step differential history, so a history's cost scales with (sync IDs x commits), not with what changed; a world of contacts made by cards (3 more sync IDs per node: each card's link actor K) costs about 2.5x more per history on the same deliveries.
> Priority: normal
> Tags: sync, tests

- Measured (core/sync differential, seed 5 of `history(seed, 3, 40, true)`, after the world): `read: judged` 3,056 on a world whose contacts were introduced by hand (4 sync IDs per node), 6,660 on one made by cards (7 sync IDs per node) with the same deliveries (about 1,800); keys per node about 50 and 110: each re-judged about 20 times in 40 steps. `read: toward` 160 against 2,354. Profile: `Read::settle_on` about 80% of the run, `Engine::sync_bodies_now` 37%, memo dependency recording (`Frame::note` hashing) 17%.
- spec/sync.md §2 (work in proportion to change): a step that writes thing X should re-judge only keys whose inputs X moved. Something `judge::body` reads (the sync set, `sync_bodies`, `Certs`, `read_facts`, sources) moves at most steps for every key; `memo::Table` has no name, so finding which needs a name per table (or a debug hook in `Effects::due` printing the failed `Dep`'s table).
- The card-made world carries every account's `keys.0` chain under each K's sync ID too (spec/sync-inbox.md §5 Contact card), which is right; the multiplier is the re-judging.
- The osis-sync binary: 2,859 G instructions with the hand-made contacts, 6,058 G with cards (worlds built once per (seed, n)).
