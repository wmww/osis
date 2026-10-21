# A move fails when an import delta would exceed MAX_DELTA_BARE content-less elements
> Summary: Moving a thing imports each origin's writes as one delta; a text or list origin holding more than `MAX_DELTA_BARE` (2^18) content-less elements (deleted elements, or bare anchors that imported writes reference) gives an import delta its own encoder rejects, so `move_thing` fails. No import path splits a delta.
> Tags: node, crdt, permissions

Repro: no test; e.g. a text with 300k deleted characters in one commit or snapshot, then `Engine::move_thing` ("more than MAX_DELTA_BARE elements without content").

## Technical details
spec/crdt.md §3.3 rule 7 bounds content-less runs in writer and import deltas; spec/permissions.md §7 allows splitting an import into one commit per origin only. Options: split one origin's import into several import commits (needs a rule for which elements go where and dot mapping per piece), exempt imports from the bound (a small delta could then create many records), or leave deleted elements out of imports where nothing anchors at them (as bare anchors already are).
