# held-model drops late parts on a destroyed thing where the spec waits
> Summary: spec/commits.md §5 counts a part stamped after a thing's destruction as a part on an unknown thing (wait, or throw out and fetch again); held-model gives `MustDrop(Destroyed)` while the creation is held, for purge and (since 64171ee4f) expiry alike. Reads are the same; the model and spec should still say one thing.
> Priority: low
> Tags: tests, held-model

Decide which is the model's rule (the engine is the third party to check), make model, spec and engine agree, with a hand world for a late part on a destroyed thing.
