# review-dating-2
> Summary: slow spots met re-reviewing, gating and landing dating-redesign.

- Nine mutants over `-p osis-crdt -p osis-engine` took 29 minutes beside a gate's hold (load 60-85): plant the crdt-only ones against `-p osis-crdt` alone and batch only the engine-reaching ones.
- A "none" row for a defensive clear (the page cache emptied on a step's rollback) was settled cheaply by a throwaway probe: a thread-local step depth, asserted zero where held pages are written, over one engine `cargo test` (no default test writes held pages inside a step).
- osis-crdt's lib test binary counts 46-47 G against its 48 G line (two counts 1.5% apart): any small crdt test addition will read NEW-COST.
- `merge-branch land` refuses a gate whose NEW failures were then shown on main and given known lines there (the summary re-read says KNOWN only): it takes `--fixed`, though nothing was fixed.
