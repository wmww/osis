# A writer that cannot judge a departure inside a member rotates without end
> Summary: `ensure_rotated` rotates whenever `uncovered_roles` is non-empty and never checks that the rotation helps. A writer of C that holds no epochs of intermediate actor K1 judges a departure inside K1 as never covered (`covers`: missing knowledge counts as not covered). So it rotates C again and again, recursing through `take_done → place_all → place_certificate_in → uncovered → ensure_rotated`. The chat "second link, then remove a link joiner" case never settles because of this; it is not a sync storm.
> Tags: flows, keys, node, tests

- Repro (examples/chat, osis-sim `World`, deterministic seeds):
  ```rust
  let (alice, _others, c, ps, _) = chat_link(&mut w, 1); // o0 joins by link K1
  let late = person(&mut w, 99, 0);
  let k2 = invite(&alice, c, false).unwrap(); w.run();
  w.until(join(&late, &k2, "late"), 1000, 10).unwrap().unwrap(); w.run();
  w.until(remove(&alice, c, ps[1]), 1000, 20); // never returns
  ```
  Same as the cost test with `OSIS_CHAT_N=3` and a fresh link for the late joiner. Alice rotates K1 and C once, and C is covered for her. Late's node (a writer of C through K2, not a member of K1) then rotates C's read and write roles 274 times in 60 s (release build). After each rotation its `uncovered_roles(C)` is still {read, write} for `Departure { via: [K1], member: o0, from: read }`, because `held_actors` holds K1's epochs only for actors whose secrets the node holds. The stack grows by one `take_done/place_all/uncovered` frame per rotation. Almost no messages move, so `World::pump` looks idle while the CPU is busy.
- Costs beside the hang: each spurious rotation is a C rotation commit (about 4 KB, plus boxes per member of C) that every member downloads. A writer can also rotate an actor that an admin has just rotated correctly.
- spec/permissions.md §3 says where a node may not rotate an intermediate, it does not encrypt under A at all and is stranded until that intermediate rotates. It does not say what a node does when the intermediate has rotated but the node cannot see into it. Here K1's `/keys` (public keysets) is under C's label as a certificate. `covers` could compare C's box for K1 with the newest K1 keyset epoch known from `/keys`, plus K1's `/secrets` box keys, if those are readable without K1's secrets.
- Fix: (1) Progress guard: `ensure_rotated` does not rotate when its own fresh epoch would still leave the same departures uncovered. Such a departure is "not judgeable here": the node does not rotate, and it either trusts the newest epoch from an admin of the chain or strands (spec decision). (2) Judge departures inside an actor from its public `/keys` epochs where the node holds no secrets of it (needs spec text, spec/crypto.md §4). (3) `place_certificate_in` should not call `ensure_rotated`, which is what makes the loop recurse. Regression test: the repro above settles, and late rotates nothing.
