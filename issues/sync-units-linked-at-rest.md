# A node keeping units unread can group one writer's sync units
> Summary: Whatever is logged as one blob under several sync IDs has one blob ID in each, so a node keeping those units unread sees, at rest, that they share an item: an account's certificates today, a node's evidence and a public profile under the account redesign. Tess: an open issue, not an accepted property; osis may be paying for a privacy it does not have.
> Priority: normal
> Tags: tess-call, sync, security, spec

- Today: a certificate copy of the same parts is one blob wrapped under each sync ID (spec/sync-judgement.md §1), and an account's chain is logged under every sync ID it writes in, so its units are a cluster to any node storing several of them. spec/requirements.md (Data a node cannot read) lets such a node learn how units overlap; that sentence was written for commits spanning units, not for a per-writer marker.
- Under issues/actors-one-mechanism.md the same holds for the evidence of a node's grant and for a public profile strongly referenced from each thing its owner writes in. A change to either shows in all of them at once as well.
- A fresh encryption per sync ID hides it at rest and costs the sharing (a copy per unit stored and downloaded). Tess: not for profiles alone; decide once for everything shared this way.
- Question for Tess, to discuss: what a node keeping data unread should be unable to learn about who writes where, given what connections already show it.

The second question is decided: a sync unit becomes one independent thing and its dependents (notes/sync-unit-scope.md, issues/sync-unit-dependent-tree.md). What stays open here is the first: under that model a writer's evidence and public profile are still one thing referred to from every unit the writer writes in, so a node keeping several of them unread can still group them.
