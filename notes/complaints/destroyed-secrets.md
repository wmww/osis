# destroyed-secrets
- `Net::set_online(n, false)` also stops the node's ticks, so a "node forgets while it cannot reach the host" test has to call `net.sync(n).handle(Event::Tick)` by hand.
- `local_rows_naming(tid)` is too blunt for "nothing of t left": a destroyed group's own label leaves `y/e`, `y/G`, `s/` and `g/` rows naming it (issues/destroyed-group-label.md), so the test counts the secrets rows only.
- Review: a test that writes acting for a team which is later forgotten panics `check_index` at restart (issues/forgotten-rotation-epoch-intro.md) when the write is on a live thing; releasing the written thing with the team avoids it. A valid acting write keeps its actor needed, so the window where only the acting write's entries are known is hard to reach.
- Second review: hiding a commit's blobs from a node (`hide_blobs`) and handing it the commit makes the node place its own copies, so it cannot make a node hold a commit with no entry of it known.
- Second review: entries forgotten while unconnected are deleted only after a restart (issues/forgotten-unconnected-not-deleted.md); both destroyed-secrets tests restart for it.
