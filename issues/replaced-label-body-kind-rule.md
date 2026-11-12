# A replaced label's desired bodies go by commit kind, its content entries by parts
> Summary: under a replaced label `bodies_under`/`bodies_in` keep role-kind commits only (`Body::role_commit`), while `judge`'s dropped-body path, `replaced_leftovers`, `retire_at` and spec/sync.md §2 call an entry content by its parts (`replaced_content`). An entry of a content-kind commit holding only role-class, `created.0`, `node.0` or `reach.0` parts is not content by the spec, yet the plain judge path deletes it (not desired) and `retire_at` does not wait for it.
> Priority: low
> Tags: sync

- Reachable shape: a group's first commit (`created.0`, `label.0`, `group.0`, content) whose copy under the nearest actor's home label carries only the `created.0` and `label.0` parts (spec/sync.md §2), when that home label is replaced; also `node.0`/`reach.0` bodies under a replaced D home label.
- No stuck state or loss found: the new label holds what the deleted entry carried. The gap is two rules for one question; pick one (parts, as the spec says, or kind, then reword the spec) and use it in all four sites.
