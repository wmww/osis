# chunk-blind
> Summary: footguns met building per-blob link blinds.

- `Net::label(a)` in node tests is the first non-home label, which under `account_pair` is not the group's: a "nothing left at the host" assertion over it passed vacuously. Use `group_labels(a)` filtered by the group, and assert the blobs were there first.
- Sabotage checks (break the fix, see the test fail) that restore the file in the same shell command are risky: a foreground run that overruns 2 min moves to the background and the restore waits for it.
- Testing forgetting under own replaces needs a value large enough that the compaction trigger stays off; otherwise a snapshot covers the commits first and the case under test never arises.
