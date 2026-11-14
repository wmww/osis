# minting-standin
> Summary: Footguns met on the minting-standin branch.

- A sibling made by `World::pair` gets every commit of the account at pairing, so it is no "late joiner" of a sync ID: a test needing a node that holds only what a sync ID carries has to grant a contact's account the group and run `history::accept` (the harness `run` does not accept).
- Advancing a day with a node partitioned off hits the 20 000-delivery storm cap (dial retries); a test about judgement past an expiry is cheaper read off the witness than by advancing.
- `OSIS_SYNC_TRACE=all:<token>` matches the brief form (`B` + 6 hex digits, e.g. `Bacf91e`), not a blob ID's raw hex: a raw-hex token prints nothing, silently. Node `Read::verdict` has no test accessor: probing a pulled entry's verdict needed a temporary one.
