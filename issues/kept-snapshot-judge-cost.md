# Kept snapshots: judgment cost and retention on an edited aspect
> Summary: On a frequently edited keep-for-D aspect every held snapshot is judged at every death (O(bodies since its earliest dead write) each, 69 ms at about 700 bodies), and a snapshot dated at its latest death stays held while any write it carries keeps dying within D, so an edited aspect keeps every snapshot it was compacted to.
> Priority: normal
> Tags: engine, retention, tess-call

## Cost
`scale::kept_snapshots_rejudged_per_death_cost_spec_commits_5` (release, 300 set elements, one removal and one add per edit, a snapshot every 10 edits, about 700 bodies, load 2-5): judging every held snapshot after one edit, as `mark_killed` asks node-sync to, took 69 ms per snapshot, 1.38 s with 20 held (counting death reports, which dated early, 0.48 s). `first_deaths` of a snapshot walks every held body of the aspect from its earliest dead write twice and recounts afresh; at 10^4 commits per aspect one snapshot judged is about 1 s, against the 100 ms per sync pass budget (notes/testing.md Performance budgets).

## Retention
A snapshot is replaced at the latest death of the writes it carries (spec/commits.md §5). Each snapshot of an aspect carries its long-lived writes, so every removal of one moves the date of every snapshot carrying it: while some carried write dies at least once per D, no snapshot passes its bound and none drops as covered. A set edited daily under a one-day keep holds every snapshot it was ever compacted to, each the size of the aspect. The probe above holds all 20.

Question: should a snapshot's keep promise stop for a write a later held snapshot also carries (the history is then kept there), or should the date be the latest death among the writes no later held body carries? Either bounds held snapshots by the D window instead of by edit rate, and either needs a rule Tess decides.
