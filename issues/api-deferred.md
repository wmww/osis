# API pieces not built yet
> Summary: What an app developer cannot do with the `osis` crate yet, and the workaround: list or search things (read the group and every item), find what references a thing, restore deleted text or cut/paste it (undo), set heartbeats per group (`sync_policy` has `publish_reach` only), read a link without an account (redeem it), stream a huge value in (it is read into memory), see pending uploads in status (`wait_synced`), pair over a direct connection (carry three texts). Client conveniences; nothing on the wire depends on them.
> Tags: api

Repro: osis-cli `unbuilt_commands_report_unsupported_plan_cli_4` (the CLI reports them unsupported); no failing test.

- **Queries and backlinks** (`query(in_group, with, order, page) -> Live`, `backlinks(tid)`): need local rebuildable indexes per aspect (notes/local-store.md) and a live result over the dispatcher; a design pass first (notes/api.md, Open). Apps list group items with `get(g, /group)` plus per-thing reads meanwhile (O(items) per change); `Osis::created(t)` gives a sort time. The CLI's `ls`/`backlinks` report Unsupported.
- **`undelete` and text cut/paste**: a deleted text range is named by its elements' dots, which no visible range reaches, so an API needs an opaque clipboard handle remembered across edits (`cut(range) -> Clip`, `paste(clip, at)`: a move plus undelete when the clipboard still matches, notes/crdt.md; osis-crdt's `Op::Paste` exists). Workaround: undo.
- **`sync_policy` heartbeats**: `sync_policy(group, GroupPolicy { publish_reach })` exists (stored per group in node-sync); a per-group `heartbeats` field is not built (`SyncConfig.heartbeats` is per node and read in `sync/pass.rs`), so `osis group policy` (CLI) still reports Unsupported.
- **Bearer `open_link`**: read-only use of a link without an account (flows' `bear` exists).
- **Streaming writes**: `set_stream` reads the value into memory before the commit; a chunk tree built while reading needs the commit's framing (tokens, expiry) known up front (osis-node write path).
- **`pending_uploads`** in `GroupSync`: a count of must-hold bodies not yet at a server per label costs a pass's body computation, and status is recomputed after every API call; it needs a count the pass caches.
- **Pairing over a direct connection**: the API is three carried texts; a convenience that listens on a transport and carries them itself (the shape's `Pairing { offer, done() }`) needs the offer to carry reach info.
- A database created without servers has no recovery card; `add_server` later makes its home label reachable, but the recovery seed existed only at `create` (osis keeps none), so that person can only be recovered through another device.
