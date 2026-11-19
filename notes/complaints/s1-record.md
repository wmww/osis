# s1-record
> Summary: Mishaps and slow spots met on the S1 record-keyed restructuring.

- A `tools/heavy python3 tools/mutate.py` run waited on another agent's gate lock for minutes; single-test mutations by hand (edit, one `cargo test` filter, restore from a scratch copy) were faster and needed no lock.
- `idle::probe_counts` measured `sync set: entered` per thing at the first reconnect: an artefact of the fixture copy (`ThingsFeed`'s clone started over), not the product. A counter that grows only in the first measurement after `fixture(..)` is worth suspecting.
- The issue named engine `things_entered` re-wanting followed links as the cause; in the idle world no link is followed, so that count was 0 there. Check a named cause against the counter that names it before building on it.
