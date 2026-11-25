# Miskeyed parts are held outside Pending storage
> Summary: A commit listing delete keys no held step places is applied with its parts held as bodies flagged not valid, not kept under Pending storage; nothing bounds them, so a reader pushing made-up keys grows a node's store without limit, and every step change rescans them all.
> Priority: normal
> Tags: security, engine

**Property** (spec/commits.md §4 Unjudgeable, Pending storage): a part unjudgeable for a key that is not right waits under Pending storage, counted as not received; a commit whose every held part is unjudgeable pends; past the unvouched bounds a node keeps neither the entry nor what pends from it.

**Code**: `apply::examine` (core/engine/src/apply/mod.rs ~640-660) never puts a miskeyed part in `unjudged`. The commit applies, header included; its parts are held bodies with `valid_at` false, not in `ix.pending`, with no carriers, and `forgettable` (retention/mod.rs) never counts them gone. `validity::rejudge_once` and `sync_ids::steps` (`grew`) scan all of `ix.miskeyed` on each pass or step change.

**World**: R reads T. R signs commits on T listing made-up level-1 keys and pushes them to reader N as an unvouched peer. N applies each and keeps its body; the entry leaves the unvouched budget once logged elsewhere or dropped, so R repeats without bound. (Listing the real keys, which are public, would get each judged invalid and dropped.)

**Fix**: hold a miskeyed part under Pending storage like any unjudgeable part (carried by its entry, bounded per source), and a commit whose every held part is miskeyed pending as its header alone; `rejudge` reads the pending set. Test in osis-sync `it`: an unvouched peer pushing k such commits leaves the reader holding at most the bound once the entries go.
