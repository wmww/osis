# deposit-storm
- The reported storm was already gone on main: log-liar (898c183e2, merged after 09530d432) bounds it. Measuring the brief's claim on origin/main first (tools/icount, then tools/bin-at at the suspect commits) saved a redundant fix; briefs built from another branch's measurement should name the commit measured.
- `tools/bin-at` needs a clean tree, so every old-vs-new comparison costs a wip commit.
