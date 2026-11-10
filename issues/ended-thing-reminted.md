# A fresh minting of an ended thing's record brings it back
> Summary: `created.0` is valid whoever acts (`validity::part`), and a thing is ended only while every held `created.0` delta of it is value-less, so anyone holding the record who can get a commit to a node can mint the record again in a durable commit of their own: the ending falls there and the thing reads again with its kept edges, also after an ending by purge, which the spec says stands for good. Record blobs (spec/wire.md §3) give every reader of a dependent's label the record.
> Priority: normal
> Tags: engine, permissions, security

- Read, not run. spec/commits.md §2 says `created.0` is carried by the thing's first durable commit, but no receiver rule enforces it; a purge request names one commit's delta, so it does not cover another minting.
- Not new with record blobs (anyone who held a copy of the creation had the record), but they widen who holds it.
- Directions: a `created.0` delta counts only in a commit whose author or actor may create under the record's first admin (as a node names as first admin only its account or an actor it holds write on, spec/permissions.md §1); or an ending by purge covers every minting of the record (the request names the thing, not one commit).
