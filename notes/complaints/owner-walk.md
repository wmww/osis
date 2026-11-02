# owner-walk complaints
> Summary: Mishaps met while replacing the owner-chain loops with `osis_base::owner_chain`.

- `wt`/`claudewait` still off PATH in subagent shells (used the plugin-cache fallback from notes/coordination.md).
- Naming the walk's step `Step` in osis-base clashed with `osis_label::Step` in a glob-free import (engine labeling): renamed `ChainStep`. Generic names exported from osis-base collide easily.
- The loops hid their bounds in three spellings (`0..=MAX_OWNER_DEPTH`, `0..MAX_CHAIN` with `MAX_CHAIN = MAX_OWNER_DEPTH + 1`, bare `0..64`/`0..16`) plus unbounded `while` walks with a seen set: grepping for the constant alone found about half.
- Review: `tools/bin-at main OUT -p osis-perm --test it --take core/perm/tests/it/queries.rs` showed the new perm tests fail on main in 12 s; smooth.
