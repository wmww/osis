# A holder writing role commits steadily holds a removed node's drop off
> Summary: The lost-access drop waits for a complete pass begun after the newest role commit applied from elsewhere on any actor in `reaching(a)` (spec/permissions.md §3 When it learns it). A party with authority on one of those actors (say a contact account holding an edge on `a`, rotating its own devices) that writes a role commit the node applies about once per pass, and keeps each pass open until `PASS_WAIT_MS` by staying a source that never catches up, keeps the node from ever dropping `a`.
> Priority: low
> Tags: security, engine, sync

Harm is bounded: the node holds only epochs it held before its removal (a removal's rotation leaves it out, `may_take` takes no later box), so it reads nothing new; what it keeps longer is what it already read. Each single pass is bounded by `PASS_WAIT_MS`.

A fix keeping one rule: count, for the drop, only arrivals that can give the role back (a commit writing an edge on a path to the node, or boxes to it), or cap the passes a drop waits to one per cause seen when the loss was first judged. Either needs a spec line in spec/permissions.md §3.
