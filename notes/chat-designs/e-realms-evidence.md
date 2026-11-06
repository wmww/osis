# Evidence for E realms
> Summary: Citations for notes/chat-designs/e-realms.md and notes/realms.md: realm = actor with members, nesting by grants, the chat app's layout as data, content by grant or ownership, removal and step duty, and the review's corrected costs.

"Traced" = read in spec, notes or the review. "Estimated" = arithmetic from cited sizes. "Unverified" = inferred.

## Realm as an actor
- Role on an actor covers what it owns and, through grants, the path minimum; effective role is the maximum over paths (spec/permissions.md §1). So a parent's grant on a child gives the parent's members the minimum of their role on the parent and the parent's role on the child; admin passes only through admin. Traced.
- Admins of an actor are equal and may remove each other (§1): a role realm's members manage it. Delete-only mods: "An admin edge on a plain thing grants changing its role grants and purge on that thing" (§1), purge judged per thing (§8); messages on a thing owned by the chat (e-realms-review.md §6). Traced.
- Ownerless actors: built (notes/permissions.md Ownerless things). An ownerless realm may own things (its admins hold owner-chain authority on them).
- Layout as data (the chat app's aspect on R): a tid in a value is a bare reference (spec/data-model.md §1); closure runs only through `group.0` and `placed.0~` (§8, spec/sync.md §3), so a child named in an aspect is not in the parent's closure and nothing of it goes under the parent's label. Traced.
- Private child leaks: a grant on K to a role realm is a role commit on K, delivered to the role's inbox (its own label) (§2, spec/sync.md §3); frontier heads name (tid, ak) (notes/frontier-study.md) and the kick certificate is copied under labels the kicked party could read (§3); a purge request's header names its deltas' things (spec/commits.md §1). Traced.
- Content by grant or ownership: entitlement needs the group's actor to read the thing (spec/sync.md §3), true for a thing owned by F (plain, secrets derived from F, spec/crypto.md §3) or granted to F. A thing synced as a group of itself gets a label whose keys derive from its owner's (spec/sync.md §2). `group.0` is ordinary and writable by writers (notes/api.md Writes), so the unplace hole of e-review §3 returns for placed content (with plain edges, unplacing only stops the auto-sync; notes/realms.md open question 1). Traced.

## Removal and steps
- Rotation of F in the removal commit; children must rotate transitively, by any writer (§3). Eager on sync passes: e-realms-review.md §1 (`ensure_rotated` on `pass`), about 11 KB per child, forks possible. Traced by the review.
- Registration admin-only (spec/sync.md §2, §5); `step_due` at the end of a pass by an admin holding the label (notes/permissions.md Implementation "issue_step per host head"); receipts-only reads refuse to register (review §1). Until stepped the removed holder keeps sync, write and deposit keys (notes/sync.md Limits; crypto §3 for the seed). Invalid bodies stay in the required set (review §1). Traced.
- Device loss and leaves are departures inside a holder (§3, spec/crypto.md §4); a self-removal carries no rotation, so the next writer rotates (§3). Mod removal: all three roles rotate on everything the mod administered, admin only (§3). Traced.

## Costs
- Per label a syncing node places its chain certificates (11.5 KB per person) and node card (about 1.5 KB) on each pass whether or not it writes, and heartbeats (0.4 KB, four a day) (review §3, pass/mod.rs:300; spec/permissions.md §4). At 1000: about 13 MB once plus 2.4 MB a day; at 100,000: about 1.4 GB plus 240 MB a day. Estimated from the review.
- Default sync of every labeled group whose secret the node holds (review §4, `compute_labels`; `GroupPolicy::receipts_only` is the only opt-out). Traced by the review.
- Unread counts: log events carry no kind (spec/sync.md §4), so heartbeats and certificates count; a per-child latest-time register on the parent is cheaper (review §8). Mentions need bodies. Traced.
- Sizes: review verdict, with issues fixed: 1000 to a few thousand comfortable, about 10,000 outside limit, 100,000 needs pure readers placing nothing and cheaper rotation. If issue keyset-names-placement-rosters (closed by keys depth 0: no names below an actor) stays unfixed, about 1000.

## Two-thing shape compared
- The list thing S and the "everyone" actor EV of e-realms-review.md are replaced by the realm's edges (its contents) and the realm itself; the review's rules "the list must hold no role on channels" and "list in a separate commit" no longer arise, since nothing is listed by group membership. Host admission per ownerless label (spec/data-model.md §9 `admit`) is one fewer label per server. Traced.
