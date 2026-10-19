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
- Chat `costs_join_message_removal` (tier 2, passes in release; upstream bytes per message kind via `World::start_tally`/`tally`, design budgets from notes/chat.md; per-entry attribution: a temporary log in `SyncEngine::command` that classifies each Upload/Deposit/Delete entry from `state.entries` (kind, cert flag), the commit header and `get_commit` delta sizes, plus per-phase markers in the test); crates/osis-cli/tests/localhost.rs (a real `osis serve` and three store directories through the binary: init, pair offer/join, link make/redeem, writes on three devices, sync, status, undo, bundle, inspect; about 35 s).
- Tier-1 wall time (4 cores under load ~8, debug): notes-app ≈ 5 s alone, chat ≈ 11 s, folder ≈ 30 s before the deposit re-send fix (persons and introductions cost ~1 s each in a debug build).

## Findings (all filed)
- Undo steps back once per register (issues/undo-chain-register.md): the notes undo test walks two aspects.
- `wait_synced` resolved while inbox deposits were still unanswered, and those live only in memory: a link made, synced and closed could not be redeemed. Fixed: `wait_synced` waits for `SyncEngine::deliveries_pending() == 0`; the CLI runs delivering commands networked and flushes before exit. Persisting the outbox stays in issues/sync-inbox-delivery.md.
- Chat costs (issues/chat-costs.md; the non-settling removal is fixed, notes/node.md), API frictions (issues/api-app-frictions.md).
- The mirrored-edges folder variant needs an edge for the folder's actor, not per member (notes/permissions.md Patterns, corrected).
