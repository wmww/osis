# A writer lowered to read can keep its old writes out of stores that cannot read
> Summary: lowering a writer to read rotates write but not sync, and a level-2 Delete goes with the head's sync key, so with its own (never revoked) level-2 key the former writer deletes its earlier writes at any node keeping the sync ID unread, with no purge request and no author's right left; holders log each back once and its second delete stands until the sync key moves. Nothing is erased while a reader holds the body, but a reader syncing only through such a store lacks those writes. May a writer demoted to reader still erase its own earlier writes from stores?
> Priority: normal
> Tags: security, sync

**Decided (Tess):** option 1 if it is easy, with spec/requirements.md Deletion's "anyone who ever held the right" becoming "anyone holding write now" (approved); left as it is if it turns out a mess.

**The question (Tess)**: may a writer demoted to reader still erase its own earlier writes from stores?

What a user sees: Bob writes messages in a chat, then is made a reader. Bob can still delete his old messages from a server that only stores the chat (cannot read it). People who already have them keep seeing them; a new device that syncs only through that server never gets them. Removed outright, Bob can do nothing there.

Today (pinned: osis-sync `delete_keys::a_demoted_writers_old_keys_keep_its_writes_out_of_an_unread_store_*`):
- A lowering below write rotates write on the thing (spec/permissions.md §3 Required rotation) but not sync: the reader keeps the head's sync key.
- A Delete by levels 1 or 2 is signed with the head's sync key, by level 3 with its write key (spec/sync-ids.md §6 Delete). Level 2 is the commit's purge author's own write secret (spec/crypto.md §7), which no lowering on the thing revokes.
- The model gives a purge author the author's right only while it holds write on the thing (spec/permissions.md §6), and spec/requirements.md says a node that cannot read "acts on a deletion by anyone who ever held the right" and "Malicious readers can only waste storage": the store here acts on a Delete with no purge at all, by a party that is now a reader.
- Holders log a body a store lost back once (spec/sync-judgement.md §4); the second Delete stands until S's head moves its sync key or a part falls.

Options (one line of cost each):
1. A level-2 Delete needs the head's write key, as level 3 does: the lowering's write rotation then ends it at once (code 9). Cost: one rule (spec/sync-ids.md §6, `osis_blob::key_for_levels`); a demoted author's honest request made before its lowering reaches stores only through a current writer's or admin's node applying it (they hold level 1 or their own keys), never its own; "anyone who ever held the right" narrows to anyone holding write now, a requirements wording change.
2. Stores honour a level-2 Delete only against a commitment of the current epoch: commitments are fixed when a blob is written, so this needs (3) to mean anything.
3. On a lowering, holders re-log the demoted writer's blobs committing to keys it lacks: work in its whole history at every store per lowering, and the new level-2 commitment cannot be its own purge author's key, so level 2 stops meaning the author's right.
4. Accept: availability, not erasure (notes/purge-model.md For Tess 4); the requirements' "Malicious readers can only waste storage" then needs "or, having written, delete their own earlier writes at stores".

A writer that, while a writer, listed its own key at level 1 lists a key no step bears: its part applies at no reader (spec/crypto.md §7 Checked keys; issues/delete-key-levels-unchecked.md), so its level-1 Delete, which needs only the sync key, loses nothing a reader keeps.
