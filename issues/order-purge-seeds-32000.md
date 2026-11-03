# Purge order seeds failing on main at offset 32000
> Summary: `order::arrival_order_purge_rows_large_spec_perm_8` fails seeds 32003, 32017, 32032 and `order::arrival_order_purge_large_spec_commits_5` seed 32014, on main 392f6d34 and on order-batch alike. Not analysed.
> Tags: engine, retention, tests

Found by the order-batch review (default sizes, `OSIS_ORDER_START=32000`; the same offset of `arrival_order_alike_large` and `arrival_order_exhaustive_large` passed). Replay with `OSIS_ORDER_SHRINK=0 OSIS_ORDER_SEED=n` (`OSIS_ORDER_LEN=40` for rows, 60 for purge; seconds each).
- rows 32003, 32032: index `Commit` of an invalid content snapshot on `t:reg.0`, dropped at both: `stands_in: {0}` as made, `{}` at a partial set then the rest (32003) or a shuffle (32032). Shrunk 32003: `Compact` by 1 and 0, `Purge` by 1 and 0, a keep-at-most write (op 27), 1.1 s, a `Demote` of 1 by 2.
- rows 32017: index `Commit` differs after the bodies dropped before a flip were given again.
- purge 32014: as made, `dead body kept under keep at most 0` on a `t:reg.0` content body (death at its superseder's `ts`, no live write). History with `Breaking`, `Nested` (compact), `Forged`, `NewTop`.
