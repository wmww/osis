# Own secrets again waits on an unrelated pass
> Summary: a dependent thing due secrets of its own (spec/permissions.md §3) is decided only at a pass end of its independent's sync IDs; when what made it due, or what it failed for, arrives on neither the thing nor its independent, it waits for a pass something else wants.
> Priority: low
> Tags: engine, sync

`held::note_arrival` wants a pass of the independent G (`reader_of`) for a role commit on a dependent thing T or writing an edge to it. Two cases want none:
- T's only keyset part turns invalid by a commit on another thing (a removal of its author on a thing holding admin on G, ahead of the rotation of G it requires).
- `own_secrets` of T failed (`OwnWriteFailed`: a holder's `keys.0` not held, an intermediate uncovered); the missing commit arrives on the holder's actor.
Until a role commit on G or its dependents arrives, T stays dependent: its holders read nothing new of it, and nothing new through it. A fix: a cause judged per candidate (`held::Cause`, as `Lost`) whose place wants the pass, without wanting a pass per failed try.
