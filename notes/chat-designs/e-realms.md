# Chat design E: servers, channels and roles as realms
> Summary: What notes/realms.md means for chat. A server or team is a realm, a channel is a chat the realm holds write on (or owns), a mod role is a realm holding admin; a plain chat is no realm. Chat E needs no change; the study's directory and tied content are no longer part of the concept. Target: 10,000 members (Tess). Corrections from `e-realms-review.md` applied. Citations: `e-realms-evidence.md`.

## Mapping
- **Server, team**: a realm R. Members hold write on R (taking part needs write), admins admin.
- **Channel**: a chat (as built, its own label) with an edge for R at write, or owned by R. Members post at the path minimum. Read-only announcements: R holds read on that chat.
- **Mod role**: a realm M holding admin on R or on some channels; its members hold admin on M, since admin passes only through admin. A mods' channel is a chat granted to M.
- **Nesting**: a realm granted a role on another; members inherit at the path minimum, any depth, several parents.
- **Private channel**: granted only to a role realm. Leaks left: its hosts see its label, a device-removal frontier head names its tid under public labels, a purge across channels shows their tids.
- **Sidebar**: the realm's contents are its edges, which every member holds through R's inbox copies. Categories, order and names of channels not synced are a chat-app layout aspect on R (app schema, admin-written), not part of the realm concept.
- **Documents in a server**: any thing with an edge for R; small ones placed in R's group to sync under R's label.

## What this means for E
- **Shape**: unchanged. A plain chat is an ownerless actor with members; it is no realm.
- **E must not preclude**: a realm's edge on a chat; a chat owned by a realm; a role realm holding admin on a chat. Nothing in E forbids these.
- **Core asks for big realms** (needed later, now realm-wide, not chat-only): default-off sync of a realm's things; a settle rule for cascade rotations (today any writer's next sync pass re-keys a child, eagerly, and online writers may fork); pure readers placing no chains, cards or heartbeats under big labels (about 130 MB once and 24 MB a day per device at 10,000 under the top realm's label, estimated); frontier heads by commit ID so private channels' tids do not leak in kick certificates.
- **Removal, stated once**: one commit protects new content everywhere (notes/realms.md Removal); cutting the removed member's sync and upload keys at hosts needs an admin step per channel per host, by whichever admin device next syncs that label (a realm wanting prompt cut-off runs an admin node that is usually online).

## Later (not traced to depth)
Per-channel mute and timeouts (client-honored; no deny by rights), delete-only mods (messages on a chat-owned thing with an admin edge), hidden-channel leaks (above), unread counts (a latest-time register per channel on R), mentions in unsynced channels (fetch after a wake), the audit log (an ownerless realm's role history), device churn and mod removal costs, read-only channels filling deposit budgets, host admission per ownerless label.
