# A full peer that cannot read L takes no role commit, so nothing frees its room
> Summary: Under pull, a peer at its entry or ephemeral cap drops what it pulls past the cap and never takes it again. A role commit it drops (a purge request, a compaction's role view) holds back every delete there (`roles_behind`), so no purge or compaction frees its room. Letting deletes go once the peer read past the role commit loops instead: a holder that learns roles only through that peer re-places each deleted body.
> Priority: normal
> Tags: node-sync

Repro: osis-node `sync_review::repro_a_purge_frees_room_at_a_full_peer_spec_sync_7`. The pull side of `ephemeral::` caps has the same shape (a compaction's cover never fits, so the covered entries never go).

Candidate rules:
- Role-class commits are never refused for room at such a peer (a cap carve-out: the role commits are what judges every delete).
- A skipped entry is pulled again once room appears (the hub remembers what it skipped per source), plus a delete order that frees room before the role commit: still needs the role commit first.
