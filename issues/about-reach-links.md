# The About facet lists a link's actor as a person
> Summary: `reach` in libs/kit/src/facets/about.rs walks `grants` and names every non-tag holder, so a link's K shows as "someone"; it should use `holders`' `kind` (Actor, Link, Key) and read a link's joiners through K.
> Priority: low
> Tags: kit, app

`Holder.kind` is on `holders`, not `grants`: the fix is a reshape of the walk around `holders`, not a one-liner, and the app rule (notes/app.md) is checked there.
