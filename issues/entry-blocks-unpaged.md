# Entry blocks do not page: a commit boxes at most about 4000 holders
> Summary: a commit's entries sit in its blob's clear prefix (spec/wire.md §5 Entry blocks), which does not page as deltas do, so a rotation of a thing with more than about 4000 holders (8 MiB / 1,233 bytes per entry, padded to a power of two) cannot be made; options below.
> Priority: normal
> Tags: sync

`secrets.0` pieces page (spec/wire.md §4 Pieces), so boxes scale with holders; the entry block beside them is one prefix field bounded by `MAX_BLOB`. A thing granted directly to thousands of holders (an organization's realm granting each member) then cannot rotate, a removal included. This breaks spec/requirements.md's removal property at that size, not a cost to accept.

Options:
- **Entry pages**: the prefix carries a block of links to entry pages (blobs of entries, stored and served as the commit's page blobs are), each page signed by the sync key; stores index the pages' claims. Same model, more store work per role commit.
- **Split the boxing commit**: a rotation's boxes and entries spread over several role commits (the rotation plus re-seal-shaped commits carrying the rest); needs the rotation to hold without all its boxes in one commit (holders left out until their part arrives).
- **Grants through holders**: keep direct holders few by design (realms hold members, things grant the realm); a nudge in API/UX, not a fix in core.

Chosen (Sheave): entry pages, the boxes' own paging applied to entries (one mechanism with `secrets.0` pieces); not a limit to accept, and not a nudge.
