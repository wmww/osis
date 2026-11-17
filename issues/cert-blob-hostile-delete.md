# A hostile writer's delete of a needed certificate blob stands
> Summary: A writer of S can Delete the one record or list blob a store keeping S unread holds; nothing logs it there again until S's certificates of that kind change, so a reader pulling from that store alone lacks those records meanwhile.
> Priority: low
> Tags: sync, security

Honest writers delete a certificate blob at a store only beside a winner shown there (spec/sync-ids.md §6 Certificate blobs), so none deletes a needed one. A hostile writer holds the level-3 key and can. Relogging whenever a store shows an own certificate blob deleted with no winner there storms: a store also drops entries for room and past a peer's budget (one on an older head drops each fresh blob), and its stream does not tell that from a Delete. A fix bounds the relog as spec/sync-judgement.md §4 bounds bodies: once per source per change of ground (head move, certificate change), its state in the peer's record.
