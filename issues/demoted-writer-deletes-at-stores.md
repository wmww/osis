# A writer lowered to read can keep its old writes out of stores that cannot read
> Summary: Lowering a writer to read rotates write but not sync, and a level-2 Delete needs only the head's sync key, so with its own (never revoked) level-2 key the former writer deletes its earlier writes at any node keeping the sync ID unread, with no purge request and no author's right left. Holders log each back once; its second Delete stands until the sync key moves. Decided (Tess): option 1 if easy.
> Priority: normal
> Tags: security, sync

**Decided (Tess):** option 1 if it is easy, with spec/requirements.md Deletion's "anyone who ever held the right" becoming "anyone holding write now" (approved); left as it is if it turns out a mess.

What a user sees: Bob writes messages in a chat, then is made a reader. Bob can still delete his old messages from a server that only stores the chat. People who have them keep them; a new node syncing only through that server never gets them. (Pinned: osis-sync `delete_keys::a_demoted_writers_old_keys_keep_its_writes_out_of_an_unread_store_*`.)

Why: a lowering below write rotates write, not sync (spec/permissions.md §3 Required rotation); a Delete by levels 1 or 2 is signed with the head's sync key, by level 3 with its write key (spec/sync-ids.md §6 Delete); level 2 is the purge author's own write secret (spec/crypto.md §7), which no lowering revokes. The model gives the author's right only while it holds write (spec/permissions.md §6).

Options:
1. A level-2 Delete needs the head's write key, as level 3 does; the lowering's write rotation then ends it. One rule (spec/sync-ids.md §6, `osis_blob::key_for_levels`). A demoted author's honest request made before its lowering then reaches stores only through a current writer's or admin's node.
2. Re-log the demoted writer's blobs at each lowering under keys it lacks: work in its whole history per lowering, and level 2 stops meaning the author's right.
3. Accept: availability, not erasure; the requirements' "Malicious readers can only waste storage" then needs "or, having written, delete their own earlier writes at stores".

Option 1 does not reach chunks a writer framed itself: chunk links are not checked against their delta (notes/delete-keys.md, Links), so a writer can frame its own write's chunks with a level-1 key of its own, and a level-1 Delete needs only the head's sync key, which lowering to read keeps. Closing that too needs a rule such as: a snapshot carrying a value re-frames (re-encrypts) each chunk whose prefix is not its own framing, as reuse does; or option 3 stated for chunks.
