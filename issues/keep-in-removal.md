# The removal states whether the removed holder keeps a copy; a thing holds the default
> Summary: Owner's design, replacing `keep` on the role edge (d36): any thing with roles may hold a default, and every removal states keep or erase explicitly, filled from the default unless the remover overrides. Not chat-specific.
> Tags: spec, permissions, engine, node-sync

Owner: "have a default value on the chat/faction, and then put it explicitly in the removal. the default value simply feeds the in-removal setting if no override is specified. also this should very much not be chat-specific."

- Default: an admin-only setting on any thing, absent means erase. Works for any group, actor or item, with no chat code. A device's removal from its person erases because the person holds no keep default.
- Removal: the role commit carries the value. A removed node reads it from the removal, so a default changed after it lost access cannot be missed, and changing the default never touches past removals. Grants stop carrying `keep`.
- To settle: an edge ending by `until` and a self-removal have no remover, so what do they read (the default in force at the ending's key, on the timeline, seems simplest; a self-removal may not raise it); invite and link flows (`keep` bound by an inviter's edge goes away); the rule "erase wins along a path, keep across paths" and holder records stay; a move; what `until: 0` override writes now.
- Remove what the edge field needed: `EdgeOpts::keep`, `LinkOpts::keep`, `Edge::keep`, `grant --keep`, `edge --keep`, `link make --keep`, the invite binding. Keep `Demotion::keep`, as an override.
- Update the requirements line ("unless the edge it lost said to keep"), notes/chat-designs/e.md.
