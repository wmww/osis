# eph-expiry-vanish
- `OSIS_SEED_TIMEOUT_SECS` exits the whole test process at the first hung seed, so "300 seeds with timeout 60 around the livelock" stops at seed 39 (143039 hangs, on main too). Ran one process per seed (`xargs -P 14`) instead: 300 seeds in 4 min. A runner option to skip a timed-out seed and go on would make the brief's form work.
