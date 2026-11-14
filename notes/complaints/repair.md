# repair
- Large values did not travel at all in the rebuilt sync (no linked blob logged under S); found only when wiring repair. A world test writing a chunked value would have caught it early.
- A Delete from a reader was refused at a node keeping S unread (code 8) when S was open by the store's sync proof: `inbox::serve::store_credential` left out the sync proof that spec/sync-opens.md §4 counts as a store source. No world test sent a Delete before this branch.
- `Engine::get` returns a large value's root link, not the value; a test reads it with `read_large`.
