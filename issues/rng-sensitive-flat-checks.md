# Two flat checks pass or fail by the store rng's draws
> Summary: engine `scale::kept_overwrite_dates_what_it_replaces_*` (held-writes pages written per overwrite: 1 at n, 5 at 10n) and osis-sync `growth::a_lowered_writers_invalid_writes_leave_nothing_*` (node 2 keeps one more deposited entry at 20 writes: a content `u:n.0` commit under one sync ID) fail once a role commit draws more randomness (a `secrets.0` in pieces: a nonce per piece, its records' order shuffled) and pass with the draws as before: each reaches its outcome by the seed's draws, a pinned seed in disguise.
> Priority: normal
> Tags: tests, engine, sync

notes/principles.md (Never pin a seed; how often is not whether): a count that moves with unrelated draws is either a real cost or a real leftover the old draws hid.

- **Held-writes pages**: over 4 overwrites, 6 pages written at n = 20, 16 at 10n: more than one page split per write at 10n, so likely a real growth of the held-writes rows' paging with the history held (`retention::bounds`, `osis_crdt::PagedRows`), not luck. Wanted: count pages written over several overwrites at n and 10n and find what grows.
- **Deposited entry kept**: at 20 lowered writes node 2 keeps a deposit (its commit a content `u:n.0` write) neither promoted nor cleared at quiet; at 10 it does not. Wanted: which rule should have cleared it (spec/sync-ids.md §6 deposits; `store::rows::DEPOSITED`), as a constructed seed-0 test.
