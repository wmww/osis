# Chat design E: factions
> Summary: One concept for servers, teams, channels, roles and chats: a **faction** is an actor with members, and a chat is a faction with a message aspect. Nesting is a grant from parent to child (roles inherit by the path minimum), the directory is data on the parent (no bodies under its label), tied content is anything the faction may write. The reduction holds and changes nothing in E's shape or core asks; E must only not preclude nesting, tied documents and roles as factions. Target: 10,000 members (Tess). The full rollout follows chat; details below the chat level are left for later. Corrections from `e-factions-review.md` applied. Citations: `e-factions-evidence.md`.

## The one concept, and the verdict

A faction F is an ownerless actor with a label; its holders are its members (write) and admins (admin). A chat is a faction with `chat:msgs`; a 1:1, a group chat, a channel, a server, a team and a mod role are all factions.

- **Nesting.** Grant parent P a role on child K; a member's role on K is the minimum along the path, so members of P write K if P holds write there. Any depth, several parents, no unnamed "everyone": the top faction is everyone.
- **Roles.** A role is a faction holding admin on what it moderates; its members hold admin on it, since admin passes only through admin. Its message aspect is the mods' channel for free.
- **Directory.** `faction:children.0^` on P: a map of child tid to name and category, admin-written. Children are not in P's group, so nothing of theirs is in P's closure or under P's label; the sidebar needs no extra read; a member syncs a child only by choosing it (needs the default-off sync policy, a core ask). A private child is granted and listed only in a role faction.
- **Tied content.** A document anyone in F may edit is a thing F owns or holds write on. In F's group it syncs to every member under F's label; listed in the directory with its own label it syncs on demand. In F's group every writer can also unplace it: the add-only list hole again, so default is the directory.

**Verdict: one concept holds.** What remains is not a concept: one label per faction (osis's unit), an empty group unless content is auto-synced, and two conventions: a big faction keeps its messages in a child so the parent's label is roster and directory only, and a role is an admin-holding faction. Against the two-thing shape it removes the list thing and the "everyone" actor with their labels and host admissions, and the review's listing traps; nothing costs more.

## What this means for E now

- **Shape:** unchanged. A plain chat is a faction with no children, an empty group and no directory.
- **Core asks:** unchanged for chat. For factions at the 10,000 target, needed later: default-off sync of children; a settle rule for cascade rotations (today any writer's next sync pass re-keys a child, eagerly, and online writers may fork); pure readers placing no chains, cards or heartbeats under big labels (about 130 MB once and 24 MB a day per device at 10,000 under the top faction's label, estimated); frontier heads by commit ID so private children's tids do not leak in kick certificates.
- **E must not preclude:** granting a faction a role on another (already plain grants); a data directory aspect on the chat thing; things owned by or granted to the chat beyond messages (documents, polls); a role faction holding admin on a chat; the chat's group holding auto-synced things. Nothing in E forbids any of these.
- **Removal, stated once:** one commit protects new content everywhere; cutting the removed member's sync and upload keys at hosts needs an admin step per child per host, by whichever admin device next syncs that label (a faction wanting prompt cut-off runs an always-on admin device).

## Later (not traced to depth)

Per-channel mute and timeouts (client-honored; no deny by rights), delete-only mods (messages on a chat-owned thing with an admin edge), hidden-channel leaks (hosts, frontier heads, cross-child purges), unread counts (a latest-time register per child on the parent), mentions in unsynced channels (fetch after a wake), the audit log (an ownerless faction's role history), device churn and mod removal costs, read-only channels filling deposit budgets, host admission per ownerless label.
