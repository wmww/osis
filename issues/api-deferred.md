# API pieces not built in the MVP pass
> Summary: Parts of notes/api.md's shape the osis crate does not provide yet: queries and backlinks, `undelete`, cut/paste in text sessions, per-group heartbeat policy, bearer `open_link`, streaming writes, `pending_uploads` in status, a direct-connection pairing convenience, server-list changes of existing labels. Client conveniences; nothing on the wire depends on them.
> Tags: api

Repro: osis-cli `unbuilt_commands_report_unsupported_plan_cli_4` (the CLI reports them unsupported); no failing test.

- **Queries and backlinks** (`query(in_group, with, order, page) -> Live`, `backlinks(tid)`): need local rebuildable indexes per aspect (notes/local-store.md) and a live result over the dispatcher. Apps list group items with `get(g, /group)` plus per-thing reads meanwhile (O(items) per change). The CLI's `ls`/`backlinks` report Unsupported.
- **`undelete`** path op: the crdt has undelete only inside `Paste`; a standalone undelete of a deleted range needs an op over remembered dots (osis-crdt).
- **Text sessions**: no cut/paste with remembered ranges (move plus undelete when the clipboard matches, notes/crdt.md); idle commit happens on the next edit after `idle_commit`, not on a timer.
- **`sync_policy` heartbeats**: `sync_policy(group, GroupPolicy { publish_reach })` exists (stored per group in node-sync); a per-group `heartbeats` field is not built, so `osis group policy` (CLI) still reports Unsupported.
- **Bearer `open_link`**: read-only use of a link without an account (flows' `bear` exists).
- **Streaming writes**: `set_stream` reads the value into memory before the commit; a chunk tree built while reading needs the commit's framing (tokens, expiry) known up front (osis-node write path).
- **`pending_uploads`** in `GroupSync`: needs a count of must-hold bodies not yet present per label (cost: a pass's body computation).
- **Pairing over a direct connection**: the API is three carried texts; a convenience that listens on a transport and carries them itself (the shape's `Pairing { offer, done() }`) needs the offer to carry reach info.
- **Server lists**: `add_server`/`remove_server` change the dial set and future labels; existing labels (and the person's `/keys` inbox servers) keep theirs. A store created without servers has a home label nobody can reach until it is replaced.
