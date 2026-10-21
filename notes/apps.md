# Example apps and end-to-end tests
> Summary: The headless example apps (examples/notes-app, chat, folder) that prove the stack over the `osis` API, what each scenario shows, how their end-to-end tests run (tier 1 in osis-sim's `World`, tier 2 cost budgets and the localhost CLI session), measured times, and the findings they produced.

## Shape
- Each example is a library of scenario functions over `&Osis` (async ones return the API's futures) plus a tiny binary walking it locally (`cargo run -p notes-app`). The library keeps workspace lints (no `unwrap`); tests and binaries may unwrap.
- Typed keys come from a `.osis` schema next to the crate by `build.rs` (`osis_schema::generate_file`, included in `mod schema` with `use osis::schema as osis_schema;`).
- **notes-app**: notebooks are groups owned by the person and synced; notes are owned by their notebook, so `grant(notebook, person, role)` shares every note (one actor shares a set). Title (`edit` merges), body (`text`, text sessions, one commit per pause), tags (set path op), a large markdown attachment (`set_stream`/`stream`, `TooLarge` on a whole read past the bound), undo/redo/history, pairing a second device.
- **chat**: notes/chat.md as built.
- **folder**: a root folder actor owning subfolders and files (one edge on the root covers the tree), reader/writer/invite holder, demotion, `move_thing` out (a copy), and the mirrored-edges variant (an edge for the folder's actor on each person-owned thing; notes/permissions.md Patterns).

## Tests
- Tier 1, `cargo test -p <example>`: `tests/e2e.rs` drives databases on `Runtime::Manual` against osis-server `Hub`s in process through `osis_sim::world::World` (one `ManualClock`, `run`/`advance`/`until`, `set_online` for partitions; offline databases still tick, so expiry and timeouts run). No sleeps, no network, seeded.
- Chat `costs_join_message_removal` (tier 2; upstream bytes per message kind via `World::start_tally`/`tally`, budgets from notes/chat.md; per-entry attribution with `OSIS_TRACE_UPLOADS=1`: `SyncEngine::trace` prints each uploaded or deposited entry (group, bytes, commit, kind, certificate flag, aspects) and the test prints a tid legend and per-step markers); crates/osis-cli/tests/localhost.rs (a real `osis serve` and three store directories through the binary: init, pair offer/join, link make/redeem, writes on three devices, sync, status, undo, bundle, inspect; about 35 s).
- Tier-1 time (idle 4 cores, debug): notes-app ≈ 5 s, chat ≈ 5 s, folder ≈ 3 s; persons and introductions cost ~1 s each in a debug build, so the cases over ~10 s (chat `removal_rotates`, `second_link_then_removal`; folder `invite_holder_shares_on`, `reader_writer_demotion`) are `#[ignore = "tier 2"]`.

## Findings (all filed)
- Undo stepped back once per register; fixed (spec/crdt.md §4.6 undo chains). The notes undo test still walks two aspects.
- `wait_synced` resolved while inbox deposits were still unanswered, and those live only in memory: a link made, synced and closed could not be redeemed. Fixed: `wait_synced` waits for `SyncEngine::deliveries_pending() == 0`; the CLI runs delivering commands networked and flushes before exit. The inbox outbox is stored since; `take_direct` packages are not (issues/node-sync-gaps.md).
- Chat costs: measured in notes/chat.md Costs; the wire-format knobs were declined by the owner.
- API frictions, all resolved in the API: expiring placements (`create_expiring`), path ops into an absent map key (spec/crdt.md §5.6), `now`, `owner_of`, `created` (the chat timeline sorts by it; no `sent` aspect), `demote` of a link joiner on the target, `on_signal_in`, `write_with` returning the closure's value, `expires(Option)`. Lists still read every item (issues/api-deferred.md, Queries).
- The mirrored-edges folder variant needs an edge for the folder's actor, not per member (notes/permissions.md Patterns, corrected).
