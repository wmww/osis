# inbox-one
> Summary: test premise hidden in a comment; tier 1 ten minutes under load.

- `inbox_life::readers_burst_under_a_group_inbox_stays_spec_sync_5` said "an ownerless group's label is its own inbox", but the group gets secrets of its own at its first grant; that is why its label is an inbox. Reading the comment literally sent me into a wrong fix (clearing at every label) that broke `junk_under_another_label_stays` and a fresh-node request test; a tier-1 round (6-10 min at load 25) each. Comment fixed.
