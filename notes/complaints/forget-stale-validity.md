# forget-stale-validity
> Summary: workflow notes from fixing the forgotten-invalid-addendum stale assert.

- The assert names only the stale thing, not who marked it: finding the source took a temporary eprintln around `unindex_commit`. Naming the marking site (or the commit) in the panic would save a build round.
