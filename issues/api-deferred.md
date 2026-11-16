# API pieces not built yet
> Summary: What an app developer cannot do with the `osis` crate yet, and the workaround: list or search things (read a container's references and every target), restore deleted text or cut/paste it (undo), read a link without an account (redeem it), stream a huge value in (it is read into memory), see writes not yet held elsewhere in status (`wait_synced`), pair over a direct connection (carry three texts). Client conveniences; nothing on the wire depends on them.
> Priority: low
> Tags: api

Repro: osis-cli `unbuilt_commands_say_so_plan_cli_4` (the CLI reports queries not built); no failing test.

- **Queries** (`query(in, with, order, page)`): need local rebuildable indexes per aspect (notes/local-store.md) and a live result over the dispatcher; a design pass first (notes/api.md, Open; backlinks set the paged-and-live shape). Apps read a container's references plus each target meanwhile (O(items) per change); `Osis::created(t)` gives a sort time. The CLI's `ls` reports not built.
- **`undelete` and text cut/paste**: a deleted text range is named by its elements' dots, which no visible range reaches, so an API needs an opaque clipboard handle remembered across edits (`cut(range) -> Clip`, `paste(clip, at)`: a move plus undelete when the clipboard still matches, notes/crdt.md; osis-crdt's `Op::Paste` exists). Workaround: undo.
- **Bearer `open_link`**: read-only use of a link without an account (flows' `bear` exists).
- **Streaming writes**: `set_stream` reads the value into memory before the commit; a chunk tree built while reading needs the commit's framing (delete keys, header blind, expiry) known up front.
- **Pending count** in status: how many own commits are not yet held elsewhere per thing; sync's `status` knows held elsewhere per commit (spec/sync-status.md §2), the API shows only whether a thing is synced.
- **Pairing over a direct connection**: the API is three carried texts; a convenience that listens on a transport and carries them itself (the shape's `Pairing { offer, done() }`) needs the offer to carry reach info.
- **From building osis-chat, not re-checked**: no lookup of one commit by id at an address: a lookup is a walk from `After(CommitPos::time(pos.at()))`, so an id must carry its place.
