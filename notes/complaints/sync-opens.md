# sync-opens complaints
> Summary: workflow snags met building the opens module.

- Session, the store's transaction handle and every engine facade call opens reads (`sync_set`, `read_credentials`, `judge_peer`, `covers_departures`) were stubs, so nothing runs through the World harness; opens' rules run over a `Holds`/`Wire` seam with scripted peers instead. An end-to-end opens test waits for all three.
- `gen` is a reserved word in edition 2024: a struct field named `gen` fails to parse with a wall of errors.
