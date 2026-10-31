# A removal of a group's edge can miss its members while its admins act on it
> Summary: a removal of group G's edge reaches G's members through the author's placement under G's labels or G's admins' copy of G's inbox blob. An author who syncs no label holding G and holds no `/keys` of G sends neither, so G's members never learn. If a delete-key holder of G learns it another way, it deletes the target's bodies under G and the members who don't know upload them again on every pass, forever.
> Tags: permissions, sync

Repro: tied.rs `repro_group_admin_learns_removal_elsewhere` (ignored). Dave is admin of Bob's card T only through his own tag H. T is placed in G and H. Dave removes G's edge on T. Dave doesn't sync G's label and doesn't hold G at all, so `deliver_parts` finds no keyset (no inbox blob), and `Delivery::Removal` finds no label holding G. Alice, G's admin and a reader of H, applies the removal from H and deletes T's bodies under G as `Outside`. Carol still holds G's edge and uploads a fresh encryption of T's bodies under G on each pass (one per hour of sim time in the repro, unbounded).

Without Alice in H (Dave only), nobody in G learns. That is stale but consistent: no storm, and T's rotation keeps new data from G.

What is already covered:
- An author who syncs a label holding G places the removal there (spec/permissions.md §2).
- An author who holds G's `/keys` sends the inbox blob. G's admins open it at G's inbox (its owner's home label, spec/sync.md §2) and copy G's parts under G's own label (spec/sync.md §3).

Root-cause directions:
- Any node that applies a removal of X's edge and syncs a label holding X places it there (as a certificate copy without `/secrets` and `/keys`, with the author's chain, after `SETTLE_MS`), not only the author. `revoke_certificates` almost does this, but it skips targets in the label's closure (a placed T stays in G's closure), and `certificates()` never copies closure aspects. The copy must bypass both.
- Or the deleter places the reason: before deleting a body under G's label as `Outside` because a removal took G's reading away, it places that removal there.

Smaller remaining case: an admin of G that opens G's inbox blob less than `INBOX_LIFETIME` / 2 before expiry (offline 45+ days) applies it but makes no copy under G's label (`INBOX_COPY_MIN_LEFT`). This gives the same storm, but only for an author with G's `/keys` who syncs no label holding G.
