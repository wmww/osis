# review-sync-store
> Summary: footguns met reviewing the sync store's memory part as a second osis-store.

- `CipherTx::release`'s `memory` flag names the transaction's mode, not the blob's part; a split by the flag alone strands a memory hold released from a durable-mode transaction. Easy to misread from the trait doc.
- `Faults::forbid_writes` makes a durable write fail the call (`Backend(Fault)`), so a test meant to count forbidden writes stops at the first one; the panic line names the op, which is the useful part.
