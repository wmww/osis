# parts-seeds
> Summary: Mishaps on the parts-seeds task.

- `examine` takes aside parts out of its `blob` when Ready (`blob.parts = rest`): code judging "the parts held" after it has to add `Waiting.parts` back. It cost a wrong first fix (a commit left part-less, `WaitDeltas`).
- `parts_differential` prints a failure cut to 300 chars, and without the steps or the delivery order; a seed needs a local probe to see them.
