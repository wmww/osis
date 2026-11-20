# order-lists
- `held_set_decides` swallowed every receive error (`let _ = p.receive`): an engine `Corrupt` on one commit showed up as a read difference after the sync exchange, far from its cause. Its receives now assert no local error (`received`). The clue was `OSIS_ORDER_DUMP`'s "no header" on a held commit.
- The shrink (5 min under the lock) also printed the real failure (`Corrupt` panics from `tick`) for candidates whose failure text did not match `OSIS_SHRINK_MATCH`; worth reading those lines.
