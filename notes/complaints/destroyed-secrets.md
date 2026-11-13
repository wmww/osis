# destroyed-secrets
- `Net::set_online(n, false)` also stops the node's ticks, so a "node forgets while it cannot reach the host" test has to call `net.sync(n).handle(Event::Tick)` by hand.
- `local_rows_naming(tid)` is too blunt for "nothing of t left": a destroyed group's own label leaves `y/e`, `y/G`, `s/` and `g/` rows naming it (issues/destroyed-group-label.md), so the test counts the secrets rows only.
- Review: a test that writes acting for a team which is later forgotten panics `check_index` at restart (issues/forgotten-rotation-epoch-intro.md), so the acting-for case has no end-to-end test; a valid acting write keeps its actor needed, so the window is hard to reach in a test anyway.
