# A dated read inside a transaction scans its whole change log
> Summary: `leaving::dating_due`, asked by every date read on a dated aspect inside a transaction, builds `Commits::before()` over the transaction's whole log each time, so a transaction changing N commits with a dated read per commit (a pending backlog woken at once, a rebuild) costs O(N²).
> Priority: normal
> Tags: engine, performance

## What
`bounds::dated_replaced_at` reads a part's history row unless the running transaction may have moved it (`leaving::dating_due`): a `to_date` entry for the aspect, or any commit in `Commits::before()` with a part on it. `before()` copies the log into a `BTreeMap` per call, and the log holds an entry per commit changed per mark. Each read is O(the transaction's changes), not O(1).

## Fix
Keep the set of aspects the transaction's changed commits have parts on, grown as the log grows (a commit's aspects are its header's, fixed), reset at the transaction's end and rebuilt after a rollback truncates the log (a rollback then a push can leave the log as long as before with other entries, so a length cursor alone is wrong). A missed aspect reads a stale row (possibly no row: a body judged live, droppable under a cover), so the set must never under-cover; a debug check against the full scan keeps it honest.

## Test
A scale test: one transaction applying n and 10n commits on a kept aspect (a creation record waking a pending backlog), counting the log entries `dating_due` walks: flat per commit.
