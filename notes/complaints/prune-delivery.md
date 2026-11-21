# prune-delivery
> Summary: Footguns met while pruning eager delivery from the engine evidence module, held-model and the A3 notes.

- The brief said `wt claim`; the coordinator's later rule said `tools/claim`. Claiming twice (release, then reclaim under another branch name) cost a release cycle: give one claim command in the brief.
- held-model's "holds everything" properties rest on the errand inside `Rule::fixed`, not only on `Stage::A3`: a probe making `Rule::fixed` errand-free turned 9 non-errand default tests red. A prune brief naming "the A3 stage's errand" understated how deep it sits.
