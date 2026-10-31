# An often-changed expiring value costs one entry per change
> Summary: Each change of an expiring ephemeral value (a cursor kept alive with `osis::KeepAlive::set` at mouse rate) is its own ephemeral commit, uploaded alone and held by the server and every holder until its expiry: 30 moves a second at a 30 s expiry is about 900 held entries per author, and about 900 live map entries at the key. The presence covers this replaced kept one. Repro: osis-node `ephemeral::repro_moving_cursor_entry_per_move`.
> Tags: ephemeral, sync, engine

- Why: expiring commits are never covered (notes/ephemeral.md Own covers) and `unsent` groups by (actor, absolute expiry), so writes with distinct expiries never coalesce while an upload is in flight; `Put` makes a fresh map entry per write, each going only at its own expiry.
- Effect: upload traffic per move; at a label's ephemeral cap (16 MB default) further uploads are refused (code 12), so with enough moving authors cursors stop updating; holders' state and reads grow with rate times expiry.
- Lost coverage: presence-expiry removed `presence::many_authors_under_server_rates_spec_sync_9` (and `_large`), which ran 10 authors at 30 moves a second under the server's rates; nothing now checks many authors' frequent ephemeral writes against server caps and rates.
- Candidate answers: drop (and delete at servers) an own expiring commit once every write it carries is dead (superseded), as covered commits are; or let an expiring write absorb the author's earlier ones of the same positions (eph-unify step 5's at-most-0 retention). Apps can throttle meanwhile.
- Also: an expiry under the sync tick (1 s) still rewrites every half expiry, one upload per rewrite, while expiry is applied only per tick.
