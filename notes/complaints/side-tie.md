# side-tie
> Summary: footguns met building the tie rule for dispute default sides.

- `LocalPeer` packages carry no certificates, but `fight`'s `spread` gives every existing peer the setup, so a "new node" test needs a peer pushed afterwards; and a new node's waits release in whatever order their records come, so "both at once" needs both waiting on one record (the thing's creation).
- Single-test runs of `osis-node --test it` take 3-4 min warm when the engine changed (relink of the big test binary); no way around it.
