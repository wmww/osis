# chunk-list-in-tree complaints
- osis `runtime::a_paired_peer_serves_what_it_reads_in_process_spec_data_model_9` failed once (`Unsynced`) in a multi-crate `cargo test` at load and passed alone: wall-clock timing under load.
- A python edit of `cbor/values.vec` failed silently on the last case: the file ends without a blank line, so "find the next blank line" helpers miss it.
- Sim sweep 15 seeds from 0: only `label_replacement_offline` setup 0 seed 7 fails, the one issues/net-one-peer.md reports on main too (not in tools/known_failures.txt).
