# API to read an aspect's history
> Summary: Reads give an aspect's merged state; `CommitEntry` has no value or validity. Chat design E (notes/chat-designs/e.md) reads held bodies as the chat, so it needs one: held bodies of an aspect with verified author, time, received time and validity, paged by time, plus a change event per commit, covering memory commits too. Also what an audit log or any append-style app would use.
> Tags: api, osis, engine

Without it there is no E chat. Pair with issues/partial-history-fetch.md (a gap in held history must read as "not fetched", not absent). The sender field is the header actor, checked by validity (spec/permissions.md §5.2). Reading is fine for a superseded body: un-merge already does it. Design question: per-aspect index cost at 10^6 commits.
