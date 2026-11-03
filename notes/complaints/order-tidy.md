# order-tidy
- Shrinking a LARGE purge seed (3050, fix disabled) runs single-threaded: each passing check of a 60-step history costs ~20 s, so the shrink took over 20 min. Shrink candidates could run in parallel (`par_map`) like seeds do; `OSIS_ORDER_SHRINK=0` skips it (found only afterwards, in `run`).
- Building a regression test for a purged killer: packaging a commit after a later purge gives a package without its body (the author dropped it), so a fresh node never gets the write. Package each commit as it is made, as `play` does; cost me a false "engine bug" chase.
- Box at load 35-40 throughout; wall times of oracle runs are not comparable to the 5-minute rule's "quiet box", only CPU-s are.
- Review: subagent shells have no git identity; the worker's commits were authored `AI <ai@pop-os.localdomain>` (reviewer reset them to Sophie Winter [AI]). A probe `eprintln!` in a harness check needs `--nocapture` on passing tests; a first probe run silently printed nothing.
