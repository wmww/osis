# Two concurrent lowerings of one holder: every knowing rotator merges
> Summary: two admins of t each demote the same writer b at once (each rotating): the departure is attributed to the newer lowering only, so the fork naming the older one covers nothing, `merge_due` fires at both admins, both merge concurrently (a second fork), and the merger merges again: 2 forks then 3 merges where 1 would do.
> Priority: low
> Tags: engine

Seen with osis-node `Net`: g = group(a, [(b, Read), (c, Read)]), t = item(a, g); a grants c admin
and b write on t; run; then `demote(a, t, b, Read)` and `demote(c, t, b, Read)` before any sync;
run. t's write role: a's and c's demotion rotations (forks at n3), then a and c both merge
(`merge_due`, forks at n4), then a merges again (`fork_merger`).

The fork merger rule gives one merge for forks that differ only by their maker; `merge_due`
(spec/crypto.md §4: any current epoch not covering a known departure) makes every knowing
rotator rotate, so two concurrent knowing rotations of one departure fork once more. Both
lowerings take b below write with nothing raising it between them, yet `Departure::at` names
only the newest (`departures::lowerings`), so the epoch naming the other covers nothing
(Frozen coverage, notes/crypto.md). Options: a departure covered by any lowering of the holder
not followed by a raising write; or `merge_due` only for epochs not newest when some current
epoch covers the departure (left to the merger, the newest blocked otherwise).

Same scenario at the sync layer: issues/concurrent-demotion-duplicate-entries.md.
