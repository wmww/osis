# Purge everything by one author, and invalid bodies
> Summary: Moderating a flood needs an admin to erase one member's writes: today a purge names deltas one by one (about 75 B each, 8 MiB per list) or a whole aspect. Add a purge item by (aspect, author), judged within each delta's own purge rights.
> Tags: spec, permissions, engine, commit

From notes/chat-designs/e-review.md. Rights judged per delta as today. Check: a by-author item against later writes (only those held at the request? its `ts`?), order independence with a commit arriving after the request, and the validity flip of an invalid body whose purge already ran. Pair with issues/purge-rights-not-nested.md.

Owner: purge settings have no exceptions. Author-only and `nobody` mean what they say; if the consequences (a flood stays) are unwanted, don't use the setting, which is why it is not the default. So no admin override, for invalid bodies either. Consequence: a hostile member writing `nobody` in a chat that did not choose it stores junk for good. Fix: issues/required-retention.md.
