# API pieces not built yet
> Summary: What an app developer cannot do with the `osis` crate yet, and the workaround: list or search things (read the group and every item), restore deleted text or cut/paste it (undo), read a link without an account (redeem it), stream a huge value in (it is read into memory), see pending uploads in status (`wait_synced`), pair over a direct connection (carry three texts). Client conveniences; nothing on the wire depends on them.
> Priority: low
> Tags: api

Repro: osis-cli `unbuilt_commands_say_so_plan_cli_4` (the CLI reports queries not built); no failing test.

- **Queries** (`query(in_group, with, order, page)`): need local rebuildable indexes per aspect (notes/local-store.md) and a live result over the dispatcher; a design pass first (notes/api.md, Open; backlinks set the paged-and-live shape). Apps list group items with `members(g)` plus per-thing reads meanwhile (O(items) per change); `Osis::created(t)` gives a sort time. The CLI's `ls` reports not built.
- **`undelete` and text cut/paste**: a deleted text range is named by its elements' dots, which no visible range reaches, so an API needs an opaque clipboard handle remembered across edits (`cut(range) -> Clip`, `paste(clip, at)`: a move plus undelete when the clipboard still matches, notes/crdt.md; osis-crdt's `Op::Paste` exists). Workaround: undo.
- **Bearer `open_link`**: read-only use of a link without an account (flows' `bear` exists).
- **Streaming writes**: `set_stream` reads the value into memory before the commit; a chunk tree built while reading needs the commit's framing (delete keys, header blind, expiry) known up front (osis-node write path).
- **`pending_uploads`** in `GroupSync`: a count of must-hold bodies not yet at a peer per sync ID costs a pass's body computation, and status is recomputed after every API call; it needs a count the pass caches.
- **Pairing over a direct connection**: the API is three carried texts; a convenience that listens on a transport and carries them itself (the shape's `Pairing { offer, done() }`) needs the offer to carry reach info.
- **From building osis-chat, not re-checked**: no lookup of one commit by id at an address: a lookup is a walk from `After(CommitPos::time(pos.at()))`, so an id must carry its place.
- **`remove_node`** stays as `set_role(me, node, None, ..)` for what it returns (working links). If apps find it no help, drop it: two lines at the caller.
