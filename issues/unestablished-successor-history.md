# An epoch that falls back to current after its successor loses establishment leaks through that successor's history box
> Summary: A rotation e2 boxes holder actor X at a keyset its rotator then holds valid, later found forged by a removed admin D (its removal R_P arrives). e2's keyset name is then unmet, e2 is no longer established, and the epoch e1 it superseded is current again. e1 covers D's departure by its own box (X at an honest keyset), so the node encrypts under e1, which D opens from e2's history box.
> Tags: security, keys, engine, tla

Reproduced: `rotation::tests::repro_unestablished_successor_history_leaks_spec_crypto_4` (osis-engine, ignored) and TLA `MC_keyset_forge_write` (expected failure, `DevNoLeak`). Independent of names: the rotator itself is the victim; it boxed D's keyset because it had not yet received R_P (nothing names it a departure there yet).

The covers rule judges an epoch by its own boxes; e1's secret also sits in the history box of every epoch that superseded it. That is harmless while the successor stays current (writers use the newest), not once it falls out of establishment while its boxes are out.

Directions (not tried): (a) an epoch carried in the history box of a held epoch (established or not) whose boxes do not cover a departure does not cover it either; (b) supersession counted from every valid held rotation commit, established or not (the node then has no current epoch and must rotate: needs a rule for the new n); (c) establishment sticky once met at a node (breaks following invalid rotation commits).
