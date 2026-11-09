# UI state in osis: every node-state write re-reads the whole tree
> Summary: node state lives in map aspects on the window (`ui:week.0`, `osis_app:draft.0`, ...); a write to one entry fires the thing watch on the window and the shell re-renders every node (models compare equal and are dropped). Measured: each typing pause in a chat's composer re-renders the whole open chat, up to four times on a synced store. Fix is listener-design steps 5 and 8.
> Priority: normal
> Tags: core-ask, app

Design: notes/listener-design.md (proposal): a path listener `db.at(t, k).path(p).on_change` at any depth, the address `get` already has, no changed-paths report and no map-only watch; kit re-renders per node through it (build steps 5 and 8).

Measured (debug build, a chat of 400 messages, 40 answering the first, composer typing in osis-app under guibox, one refresh logged per inbox drain):
- Each typing pause commits the draft through its text session (`idle_commit`), which fires the window's thing watch: one whole-tree refresh, the open chat's stream re-read (`recent`, NEWEST messages plus the walk back to the oldest quote).
- On a store with a peer the same commit also changes `status()` three times (its sync to the peer), and `on_status_change` posts the same whole-tree refresh: two refreshes per pause where the inbox drains between them.
- The opener renders its content view once to learn `has_foot`, and the shell renders it again as its own node: the content is rendered twice per refresh.
After the per-quote walks were removed (osis_chat::find_all) one refresh of that chat is about 0.4 s in a debug build on a loaded box; it still grows with the page and with the distance to the oldest message the page quotes, and is paid on every pause though nothing the chat shows changed.

Note from tess: if you decide to do this, be sure to think through the implications on the overall API philosophy, and let whatever changes to that ripple through the rest of the design. if you add a second, unrelated listener function that specifically works for a toplevel map and nothing else I will hit you with a stick /s
