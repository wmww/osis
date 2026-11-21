# Receivers never check which delete keys a header lists per level
> Summary: A node checks only how many delete keys a header lists per level and that one level-2 key serves the whole commit, never which keys (notes/sync-reasons.md, Delete keys). A hostile writer can list its own key at level 1 or 3 and so delete its own blob at nodes keeping S unread where only an admin's key was due (purge-by admin), or list junk so no admin can delete it there by levels (only S's head delete key can).
> Priority: normal
> Tags: security, sync

Assessment: a writer, not a reader or stranger (the header is inside its own signed blob). It reaches only blobs it wrote: commitments are fixed by the writer's own prefix. Effects at nodes keeping S unread:
- it erases its own writes there although purge-by gave that right to admins only; holders log each body back once, its next Delete stands (the same shape as issues/demoted-writer-deletes-at-stores.md);
- it can make its blob deletable at stores by nobody but a holder of S's head delete key.
Readers hold the body anyway, so nothing a reader holds is lost; a reader syncing only through such a store lacks it.

What would fix it: readers judge a header's listed keys against the thing's published keys at each level (`keys.0`, spec/crypto.md §7) as part of the commit's validity, so a header listing the wrong keys makes the commit invalid for every reader; a store, which cannot read, then relies on readers dropping and deleting it. Check first whether engine validity already does part of this (the note's claim is the receivers' check in osis-blob and the store).
