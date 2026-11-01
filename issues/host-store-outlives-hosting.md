# The host store outlives hosting
> Summary: stopping hosting (`set_hosting(None)`) shreds the host secret but keeps the host's own store (`host.redb`, key root `host.root`): its entries stay on disk, readable with the root, and a later start, under a new host address, serves them again. Decide whether stopping erases the store. Low.
> Tags: host, node

- Today: the driver drops the hub when hosting stops; `Shared::host_store` reopens the same store on the next start (osis `net.rs`). Nothing was deleted, so spec/requirements.md Deletion is met; but nodes reach the old entries only by the old address, so they are dead weight, and a node that also reads a hosted label keeps live wraps it no longer needs.
- Option: a new host secret means a new store. Erase `host.root` (crypto-shred: `RootStorage` has no erase yet; `FileRoot` would overwrite both slots) and delete `host.redb` when hosting stops. A crash between the secret's shred and the erase leaves the old store, so the start side must also notice (e.g. the host key recorded in the store; a mismatch erases first).
- Option: keep the root as a node local record shredded with the host secret (one shred covers both), at the cost of a `RootStorage` over the node's store.
