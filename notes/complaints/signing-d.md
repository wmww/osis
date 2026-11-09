# signing-d complaints
- Tier 1 took 873 s at load 20-23 (notes say about 2.5 min warm on a quiet box): the box was shared with other gates.
- The open-path assertion "headers decoded" fired as soon as judgment needed an account's signing chain at open: building it decodes rotation headers. Not obvious from the account view's docs; the fix was persisting the rule's per-epoch answer (`node/epochs`).
- A body dropped while its commit was invalid comes back only by fetching it again: a test that revalidates a write must sync the writer again before reading it.
