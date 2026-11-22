# Attaching a thing costs in the size of what it joins
> Summary: Attaching an existing independent thing to a root's unit (one strong added) cost 83 KB, 63 deliveries and 42 signs at 4 members and 141 KB at 40 (146 KB, 85 deliveries, 92 signs, 371 transactions with 20 dependents under it), measured in debug at main 6e38bcd03; detaching it 7 to 14 KB and 17 to 80 entries. Why does attaching one thing cost in the size of the enclosing unit, and how much of it is inherent to carrying the thing under the unit it joins?
> Priority: normal
> Tags: sync, engine, perf

## Measured
Throwaway debug test on the sync harness (`history::world_of(0, 3, 3)`, script steps, `osis_base::costs`, `net.between`, store `scan_local`), main at 6e38bcd03, not kept. World: one root with 4 or 40 members, each an independent thing promoted from a dependent, made by node 0, read by node 2, kept unread by node 1.
- **Detaching a member** (removing the root's strong to it): 7.0 KB, 47 deliveries, 17 entries leaving the maker's store; with 20 dependents under the member 13.9 KB, 70 deliveries, 80 entries.
- **Attaching it again**: 82.8 KB, 63 deliveries, 42 signs at 4 members; **140.8 KB at 40 members**; with 20 dependents 145.8 KB, 85 deliveries, 92 signs, 371 transactions.
- What was seen: the enclosing sync ID is pulled anew (spec/sync-judgement.md §3 Dropped bodies, the pull anew at a new strong; engine `units::refetch`), so the cost follows the size of what encloses. Not traced further.

## The question
spec/requirements.md Cost: every operation costs in proportion to what it changes, never to the size of what holds it. What is inherent in an attach is the retag (spec/sync-judgement.md §1 Retag): the thing's live blobs, and those of what it reaches, entered under the enclosing sync ID, one entry each; and its role data placed there as certificates where the bodies do not carry it. That is in the size of the attached thing, once per enclosing unit. The part in the size of the enclosing unit (the 58 KB between 4 and 40 members) is not: find what the pull anew re-sends or re-judges, and whether a pull limited to the attached thing's entries meets the spec. Count at n and 10n members and at n and 10n dependents of the attached thing in a default test.
