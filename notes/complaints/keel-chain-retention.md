# keel-chain-retention
- The osis-sync harness's world setup (card redeem) fails on main, so a release test there was impossible; found only after building one. Wrote it as an engine LocalPeer test instead. A line in the brief naming the known-broken harnesses would have saved an hour.
- `LocalPeer::deliver`/`spread` hand peers plaintext bodies of things they cannot read, so "held content" in engine tests is not what a real node holds: a rule keyed on held content needed a hand-built delivery in the test.
- Index-check diffs print "want" for the running node and "got" for the fresh open; I read them the other way round for a while.
- Reverted a whole file with `git checkout` meaning to drop one debug line: keep debug prints in a separate scratch patch.
