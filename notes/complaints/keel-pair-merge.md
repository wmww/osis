# keel-pair-merge
> Summary: Mishaps met building pairing beside an unmerged removal.

- I ran single-crate `cargo test` runs (unlocked, as allowed) while my own `tools/heavy` search (custody 8000 + custody-exh) held the lock: load 22, and the heavy wall-time limit tripped (891 s against 598 s). Run unlocked tests before or after one's own heavy run, not during it.
