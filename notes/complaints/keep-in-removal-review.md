# keep-in-removal-review
> Summary: Mishaps on the keep-in-removal review.

- A one-way oracle can sit silent on the mutation it looks made for: `any_order_until` passes with the default read at arrival, since "no more than the whole" misses what only keeps less. Mutate before citing a seed.
- An `OSIS_ORDER_SEED` replay at length 60 costs 2-3 min; my `tail -8` cut its failure text and I ran it again. Log to a file first.
- `arrival_order_alike_large` failed at a fresh offset (733028) on main too: a branch's oracle run can't tell without main's binary, so `tools/bin-at origin/main` before the run saves a detour.
- `ls -t` on the tasks dir to find my gate's ID picked another agent's task (the dir is shared): use the ID the start printed.
