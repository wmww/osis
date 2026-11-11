# A deleted message's tombstone outlives its expiry
> Summary: in a disappearing chat (the setting's expiry on signals kept forever), a message deleted before its expiry still lists as `Body::Purged` after it: the purged-part clause of spec/commits.md §7 (listed while its keep rule would keep it) wins over "expired: not listed", and forever keeps it forever. Its versions' tombstones too.
> Priority: normal
> Tags: osis, retention, chat

- Seen: post, `Purge::Commit` it, advance past the expiry: `fired` still lists it, purged (plain delete and an edited message alike). An expired message never deleted is gone as it should be.
- What users see: a disappearing chat keeps a "deleted" line (sender, time) for every deleted message, for good; the expiry promised it gone.
- Likely rule: a purged part is listed by the purge clause only until its own expiry (the leftover already drops as covered there, spec/commits.md §5). Check the held-model and the listing (`listing::listed_part`) agree, then the chat test `flows::disappearing_spec_commits_6` can assert the tombstone goes.
