# withdrawn-epoch complaints
- `wt claim withdrawn-epoch origin/main` reused an existing local branch 309 commits behind origin/main instead of starting from origin/main; had to fast-forward by hand.
- LocalPeer's `Package` is plaintext: a content-read test through `sync_all` "reads" content the reader holds no key for. Content-visibility tests must deliver label entries (`LocalPeer::sealed` / `deliver_sealed`), sealed at writing; nothing in the test helpers warns about it.
- TLC liveness over a delivery model blows up fast (8 nodes x 9 commits: millions of states); restrict each node's deliveries to what it judges with before adding fairness.
