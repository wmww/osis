# Purge everything by one author, and invalid bodies
> Summary: Moderating a flood needs an admin to erase one member's writes: today a purge names deltas one by one (about 75 B each, 8 MiB per list) or a whole aspect. Add a purge item by (aspect, author), and let admins purge an invalid delta's body whatever its retention, or a kicked member's `nobody` junk stays on every device for good.
> Tags: spec, permissions, engine, commit

From notes/chat-designs/e-review.md. Rights judged per delta as today. Check: a by-author item against later writes (only those held at the request? its `ts`?), order independence with a commit arriving after the request, and the validity flip of an invalid body whose purge already ran. Pair with issues/purge-rights-not-nested.md.
