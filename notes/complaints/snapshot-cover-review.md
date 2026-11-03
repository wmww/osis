# snapshot-cover-review
> Summary: a cost probe at 10^5 chars ran 7 min per round, and a harness comparing a control node without redelivery cost a false alarm.

- A probe's text size picked without a smaller trial first: 447 s per round, stopped. Start at 200 bodies.
- gap_cover's first demotion check redelivered bodies to one node only: `t:gonemap.0` is at most 0, so the other had dropped a body at its death. Looked like a bug, failed alike under the old rule; run a differential on the old rule first.
