# eph-dead-entry
> Summary: the issue was already fixed on main when briefed.

- issues/eph-set-into-dead-entry.md was stale: 65a84554 (an expired ephemeral write vanishes whole) had already made its repro pass; the commit that fixed it did not run or retire the ignored repro. When a fix changes a rule, grep issues/ for repros it may settle.
