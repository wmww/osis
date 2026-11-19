# m1-promote
> Summary: Workflow notes from modelling promotion in held-model `unit`.

- `Net::deliver` decides by the truth which units a writer syncs, so a writer that cannot know a sync ID (a forked promotion's greater one) still gets commits under it: a hand world had to deliver by hand to show the gap. A model knob worth knowing before trusting a "reaches everyone" result.
- Suite timing swung 6.8 s to 10.6 s to 4.6 s on the same code with box load; judge the unit suite's budget on a quiet box or by counting work.
- `View` clones in the memo (`truth`, writer views) were the hot path of the over-time tests; they sit behind `Rc` now.
