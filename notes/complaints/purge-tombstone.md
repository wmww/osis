# purge-tombstone
> Summary: Mishaps met on the purge-tombstone branch.

- A name filter on a mutation loop hid a trigger test: its name lacked the filter word, so the mutation looked like a survivor. Filter by module and test name both.
- `Mutation::set` with the value already held writes nothing, so a purge commit with no other write fails "a purge request needs a delta": repeat purges in a test need fresh values.
