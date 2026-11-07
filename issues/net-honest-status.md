# Honest status and waits
> Summary: Status, `wait_synced`, the pre-sync, catching up for `set_role` and history `complete` judge only saved peers, so with peers only they report wrong things (audit rows 13-18). Judge over one idea of a group's sources. No wire change. Part of issues/net-rework.md.
> Priority: normal
> Tags: api, node, sync

- A group's sources: every node it syncs with, saved or direct. States, `wait_synced`, the pre-sync, `set_role`'s catching up and history `complete` all judge over them.
- `Synced`: a finished pass with each source reachable within the timeout. `Unsynced` only at the timeout. Served sessions count as connected. Nobody connected: not synced, shown as no peers; a wait keeps waiting to its timeout (Tess).
- `wait_synced(Thing)` stops failing at once (row 16); `AllWithSavedPeers` becomes all groups; `Connected` goes (row 17).
- History `complete` true only after a pass with a source (row 18).

Unsure:
- (design) What a `Required` wait promises when no single node holds every write. Proposed: a pass with the holder's own node if reachable, else any node that reads the group, else `Unsynced` at the timeout.
- (design) Whether a source the node knows of but cannot reach (offline, never met) counts against `Synced`. The decided meaning says only connected ones do.
