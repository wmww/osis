# Sim ephemeral: a reader holds ephemeral commits no host lists after host restarts
> Summary: sim `ephemeral` setup 0 seed 43 fails on main: at quiescence node 3 (a reader on s1 only) reads `e:state` from two commits it holds with no entry at any host, which node 0 lacks; host 1 crashed and restarted around the writes, host 0 is lossy (capped).
> Priority: normal
> Tags: ephemeral, sync, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 43 --setup 0 --only ephemeral` (through `tools/heavy`).
- Failure: "ephemeral divergence on BMtll2cQol8NUj---Gl1: node 0 reads [... e:state+.0 None ...], node 3 reads [... e:state+.0 Some(..) ...]; held: node 3: CommitId(736af280..) [e:state+.0] entries [], node 3: CommitId(fcfd6b78..) [e:cursor+.0] entries []".
- Before quiescence: host 1 crashed and restarted three times within about 12 s of node 0's and node 2's last writes, node 0 crashed and restarted twice; hosts {0} keep out an entry that does not fit their cap.
- Not traced: why node 3, holding the bodies, does not deposit them again at host 1 after its restart (presence per connection, spec/sync.md §9 Held at a peer that cannot read L), or why node 0 dropped what node 3 still holds without node 3 dropping it.
