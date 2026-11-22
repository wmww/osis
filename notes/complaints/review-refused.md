# Complaints: review-refused
> Summary: `Ciphertext`'s memory writes commit at once inside the engine's transaction, which no doc on `Stamps::undoable` or the store warned of; mutation probes of a memo marking cost a full rebuild each and the world tests catch none.

- The sync store is the engine's ciphertext store, and its memory part takes holds, releases and forgets with an immediate commit (`write_in(true, ..)`): "every store write in `Engine::run` is aborted with it" is false for it. Found by reading `core/sync/src/store/cipher.rs`; nothing on the engine side says so.
- `tools/bin-at` and `tools/mutate.py` both build in the worktree: run them one after the other (mutate's tests run from copies, so bin-at may start once mutate's build ended).
