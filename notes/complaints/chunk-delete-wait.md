# chunk-delete-wait
- The brief asked for an ephemeral value large enough to chunk; ephemeral commits never chunk (spec/data-model.md §6), found only after the first test run. The reproducer is a durable purge instead.
- The two-host churn world hides the effect: the co-writer still counts the chunks present at the host it is cut from, so it never relinks. One host shows it.
