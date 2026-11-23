# Complaints: review-order-seeds
> Summary: review of order-seeds: a carve-out for own commits hid a writer error mapping; the spec's Unjudgeable wording and held-model's evidence model read the same clause differently.

- Removing the own-commit carve-out took one engine run (324 s) to see that only hostile-writer tests and one writer error kind relied on it; a test helper forging commits "as received" would have made the hostile cases obvious without a run.
- spec/commits.md §4 Unjudgeable cited a reading ("the latest such is itself unjudgeable") that held-model's evidence model implements as `Pend::Any` and its main model does not; two models citing one spec clause with different rules is easy to miss.
