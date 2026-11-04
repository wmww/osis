# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2.

## 8. A limit on how big one change can be
Not a limit of 8 MiB of data: 4 GiB in one value is tested. A commit's header lists every chunk it adds, about 38 bytes each, and that list is capped at 8 MiB because a node holds it whole in memory. Chunks average about 80 KB, so the real limit is about 17 GB in one commit (estimated from those two numbers, not run), or about 220,000 chunks or parts. Past it the writer gets a plain refusal.
Tess: a commit should be able to upload GBs of data. Open: is about 17 GB enough? Otherwise raise the cap, which costs memory per header and lets a hostile header hold that much, or stream the lists, which is a build.
Recommendation: keep it now and write the number down; whole commits may change this list anyway.
