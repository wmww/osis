# A writer or admin lowered to read can keep its old writes out of stores that cannot read
> Summary: A Delete by levels 1 or 2 goes with the head's sync key, which no lowering to read rotates, so a former writer (its own level-2 key) or former admin (old step delete keys, level 1) deletes its era's writes at stores keeping the sync ID unread with no right left; second Delete stands. Option 1 (every level needs the head's write key) costs deletes at stores of a sync ID whose thing is not the write's delete base.
> Priority: normal
> Tags: security, sync, tess-call

**Open design problem (Tess):** both options as stated are broken. Option 1 is not "anyone holding the right now": at a store of another unit R carrying D it is "someone current on R who holds a D key", a rule that depends on which units carry the thing (a store cannot tell its own thing's blobs from a carried thing's). Option 3 leaves a lowered writer able to erase its own past writes at stores until it is removed. Option 2 may be too expensive. Not blocking the alpha; wants a design pass.

What a user sees: Bob writes messages in a chat, then is made a reader. Bob can still delete his old messages from a server that only stores the chat. People who have them keep them; a new node syncing only through that server never gets them. (Pinned: osis-sync `delete_keys::a_demoted_writers_old_keys_keep_its_writes_out_of_an_unread_store_*`.)

Why: a lowering below write rotates write, not sync (spec/permissions.md §3 Required rotation); a Delete by levels 1 or 2 is signed with the head's sync key, by level 3 with its write key (spec/sync-ids.md §6 Delete); level 2 is the purge author's own write secret (spec/crypto.md §7), which no lowering revokes. The model gives the author's right only while it holds write (spec/permissions.md §6).

The same hole at level 1: a former admin lowered to read keeps its admin-era step delete keys and S's sync key, and deletes `admin`/`author_or_admin` writes of that era at stores. The rule that is wrong: at a store only the head's keys prove a right now (every purge right needs write now, spec/permissions.md §6); a level key proves only "held once", and the sync key is no purge right.

**Cost of option 1**: the store's head is S's, and S's thing need not be the write's delete base D (an independent D carried in another thing R's sync unit, R holding read on D, is under R's sync ID too, spec/sync-set.md §2). Today a D admin or author who only reads R deletes D's blobs at R's stores (level 1/2 + R's sync key; notes/sync-reasons.md gives this as the reason for the sync key). Under option 1 its purges and compactions reach R's stores only through an R admin (head delete key) or an R writer holding a D level key; until then the purged ciphertext stays there (readers never fetch it: must-not-hold). And a former D right holder who still writes R keeps deleting D writes at R's stores, while D's own sync ID (which every D reader syncs) keeps them. No credential a store of R can check proves a right on D now (it holds only R's steps).

Options:
1. Every Delete by levels needs the head's write key (level 2 as level 3 does; level 1 too); the lowering's write rotation then ends it. One rule (spec/sync-ids.md §6, `osis_blob::key_for_levels`). A demoted author's honest request made before its lowering then reaches stores only through a current writer's or admin's node.
2. Re-log the demoted writer's blobs at each lowering under keys it lacks: work in its whole history per lowering, and level 2 stops meaning the author's right.
3. Accept: availability, not erasure; the requirements' "Malicious readers can only waste storage" then needs "or, having written, delete their own earlier writes at stores".

Chunks a writer framed itself (chunk links are not checked against their delta, notes/delete-keys.md, Links) are covered by option 1 for any lowering below write: every level then needs the head's write key. What stays is a current writer deleting chunks it framed for itself, its own bytes, as a link to a never-stored blob is.
