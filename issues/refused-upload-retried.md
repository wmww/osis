# A refused upload is sent again unchanged every pass
> Summary: A node whose upload a host refuses with code 9 (an operation under keys of a step it does not hold) sends the same blob under the same label again every pass, forever: a steady repeated cost (one request and one status per pass) after quiescence. A refused upload should wait for a change that could make it succeed (new head, new keys, a re-judgment).
> Priority: low
> Tags: node, sync

Seen in sim `demotion_unsynced` seed 995988053764 (`OSIS_SIM_TRACE=1 cargo run --bin sim-sweep -- --only demotion_unsynced --seeds 1 --from 995988053764`): from step 110, node 1 (demoted to read) sends `Upload` of blob 95f5f817 under label 6ddc5d8e every round and hub 0 answers `Status [Code(9)]` each time; the sim still counts it quiescent, since the state fingerprint does not change.

The rule to follow (spec/sync.md: a refusal under an older key, code 9, "is answered by the next pass under the new head"): a refusal under an older key is retried once the head or this node's usable keys change, not unchanged on the next pass. Where it is decided which uploads a pass sends (`pass/bodies.rs` `body_sends`, `conn.rs` `refused`) not traced.
