# lost-content
> Summary: Workflow notes from fixing the untaken-grant loss (class 180's 9-step script).

- The differential's `why_role` printed no node closure state, so "content held with no secret" could be a copy, a left thing or a stale apply; it now prints contexts, left, reads and content held. A copy (`copy_of`) still shows only through `content held` without `reads`: worth printing the kept marks too.
- Probes print from every engine of a world interleaved with no node name: prefix them with `tx.core.id.tid()` from the start.
