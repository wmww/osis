# sync-store
> Summary: footguns met folding the store's memory part into a second osis-store.

- osis-store's memory mode is not "everything to memory": the node log, records and `changed` rows write durably whatever the mode, and `Transaction::suspend` refuses memory rows. Neither was stated where memory mode is documented; finding out took reading `cat_put_to` call sites. Now in notes/local-store.md.
- Rust 2024 `impl Trait` returns capture every lifetime in scope: a helper returning a closure built from `&Env` kept `env` borrowed until `+ use<>` was added.
