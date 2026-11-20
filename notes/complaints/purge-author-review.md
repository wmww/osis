# purge-author review
- A peer-sent message in an osis-sync world test has no harness call: the scripted peers (`harness/scripted.rs`) cover opens only, and lies rewrite only what the node sends. `delete_keys::over_wire` frames a `Msg::Delete` by hand through `World::apply_as` on a live connection, with an id the sender's session never used (its reply is dropped); a `World::send_as(i, to, Msg)` helper would make hostile-peer requests one line.
- `tools/mutate.py` on `osis-blob` relinks the whole sync `it` binary per run (about 5 min each); batching both plants in one call halved it.
