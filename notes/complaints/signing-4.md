# signing-4 review
- `tools/gate.sh` took 539 s (notes say about 4 min warm); worktree was warm from a crate test run just before.
- Both the model's and the branch's "rotation from above" hand tests could not fail: the rotation superseded only the root and its own epoch, neither of which any rule can reject. Hand tests copied from the model inherit its blind spots; mutate each rule before trusting them.
