# cleanup-4
- `tools/heavy python3 tools/mutate.py ...` builds under the lock: while it waits (15 min behind a roles-model search) the mutated files are not yet written, but nothing in the crate can be edited until its build ends. `MUTATE_HEAVY=1` builds first, unlocked, then waits with copies: use it, not a wrapping `tools/heavy`.
- mutate.py takes one mutation per OLD site: two plants of one expression (a bound off by one and a bound shrunk) need two runs.
- Its Markdown rows contain the planted code's own `|` (closures, or-patterns): split rows on ` | ` from the right, not on `|`.
