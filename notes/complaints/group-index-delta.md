# group-index-delta
- A group of 1000 tids is not paged (0 pages loaded): a scale test at 10^3 / 10^4 compares 0 against 39 and fails for the wrong reason. Paged sizes start around 4000 tids (as `tid_removals` uses).
- Peers of `common::net(2, _)` cannot write each other's things without `set_edge`: the Permission error names only the tid.
