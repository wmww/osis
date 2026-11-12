# A source's echo judges the label's bodies again
> Summary: each peer that cannot read L showing a write back passes L and judges its bodies again, so a write's judgments grow with the number of sources.
> Priority: normal
> Tags: node-sync, tests

issues/net-one-peer.md 3h2 promises one pass per label that judges this node's store once, then each source over what its stream showed. Measured (`scale::repro_one_pass_judges_a_change_for_every_source`, ignored, run by name): one more write to a settled label with a writer and a reader, at 1 and at 3 sources:

- writer: passes 2 / 4, bodies judged 2 / 4, entries judged 2 / 7;
- reader: passes 1 / 4, bodies judged 1 / 1, entries judged 1 / 9.

The writer's own pass judges the write; each source's Added echo then marks the label, and that pass runs the own part again (bodies judged once per echo) before the per-source part. Even at one source the echo re-judges the body. What the echo changes is presence at one source (`known`), which only that source's part reads.

Wanted: an arrival that moves only presence at source s runs s's part alone, from the verdicts the own part last reached (kept with the work set until a touch of the commit invalidates them). Then bodies judged per change is flat in sources and passes are one per change plus at most one cheap per-source step per echo. The test asserts full passes and bodies judged equal at 1 and 3 sources.
