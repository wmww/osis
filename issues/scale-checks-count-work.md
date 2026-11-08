# Scale checks measure seconds, not growth
> Summary: The tier-2 `scale::`, `bench::` and `budget_*` timing checks need release builds and long runs, and report wall time on a shared box, which says little. Turn each into a fast tier-1 check that counts work (bodies read, commits walked, bytes stored) at n and 10n and asserts the growth spec/requirements.md Scale allows; delete the timing ones and their numbers in notes/testing.md. Size budgets in bytes (`budget_minimal_commit` etc.) stay.
> Priority: low
> Tags: tests
