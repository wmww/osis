# listener-5
> Summary: complaints from building path listeners (listener-design step 5).

- `osis_node::costs` spans are thread-local: counting dispatcher work needs `Dispatcher::Pump` so callbacks run on the test thread.
- Paging kicks in unevenly by size (500 entries of ~100 B unpaged, 1000 paged, 5000 fast, 10000 took 6 s to write in a debug test): a scaling test has to probe sizes first.
- A `cargo test -p osis --test it` with four filters ran past the 120 s tool timeout on a busy box (rebuild after a crdt change): start such runs in the background.
