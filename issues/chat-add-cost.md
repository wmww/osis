# A chat's join and add cost O(members)
> Summary: A node joining a chat fetches and judges every member's role commits before it reads the newest page, and every member costs every node tens of KB stored (its first commit, its add, its `keys.0` states, the blob copies of each under the sync ID). Measured on an older build: recount first.
> Priority: low
> Tags: engine, sync, performance

- **A joiner**: linear in members by constants (each member's role commits, about 16 KB) plus about 0.1 ms per message listed (the stamp's signature most of it). Recount how often a received commit's body is opened and its header decoded (an older build did each more than once: work done twice, not growing).
- **An add at a node**: loads several pages of `secrets.0` (`ingest_secrets_keys`).
- **Store per member at every node**: a member needs only its record's `created.0` and `keys.0` at a reader, but every node keeps its first commit, its add and its `keys.0` states, and each again as a blob under the sync ID (one commit stored twice: notes/thing-cost.md, Survey).

Fix by recounting at n and 10n members (counting: notes/accounts-switch-brief.md, Left), then cutting what scales with members and is not needed.
