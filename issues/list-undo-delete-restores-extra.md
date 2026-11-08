# Undoing a list delete after a bootstrap shows an extra element
> Summary: `fuzz_seq::random_scripts_replay_spec_5_7` at `OSIS_CRDT_SEED=2854516606` (script 6) fails on main: undoing a replica's last commit (a list delete, after a bootstrap from another replica) reads four elements where the read before it had three.
> Priority: normal
> Tags: crdt, tests

Reproduce: `OSIS_CRDT_SEED=2854516606 cargo test -p osis-crdt --lib random_scripts_replay -- --include-ignored`. Shrunk (`OSIS_SHRINK=6 ... shrink_script`):

```
Script{list:true,steps:vec![Step::Ops{r:0,ops:vec![LocalOp::Set{item:165}],skew:0,per:0},Step::Ops{r:2,ops:vec![LocalOp::Edit{at:51284,del:139,item:98,stale:true},LocalOp::Set{item:239},LocalOp::Delete{at:29923,len:145}],skew:89,per:0},Step::Ops{r:1,ops:vec![LocalOp::Insert{at:23918,item:68}],skew:0,per:0},Step::Ops{r:0,ops:vec![LocalOp::Edit{at:12599,del:11,item:3,stale:false}],skew:0,per:0},Step::Ops{r:2,ops:vec![LocalOp::Edit{at:27135,del:76,item:223,stale:false}],skew:0,per:0},Step::Ops{r:0,ops:vec![LocalOp::Delete{at:55042,len:163}],skew:0,per:0},Step::Join{to:2,pick:44,n:2,per:0,merged:false},Step::Ops{r:0,ops:vec![LocalOp::Edit{at:59746,del:200,item:255,stale:false}],skew:0,per:0},Step::Ops{r:2,ops:vec![LocalOp::Set{item:110},LocalOp::Insert{at:11760,item:251}],skew:0,per:0},Step::Bootstrap{r:2,from:0},Step::Ops{r:2,ops:vec![LocalOp::Delete{at:58879,len:37}],skew:0,per:0},Step::Undo{r:2,back:0}]}
```

Read before the delete `[{1:3,2:0},{1:0,2:0},{1:0,2:2}]`; after its undo `[{1:3,2:0},{1:0,2:0},{1:0,2:3},{1:0,2:2}]`. Next: turn it into a hand-written tier-1 reproducer (notes/coordination.md Testing), then decide whether the undo or the test's `restores` expectation is wrong (spec/crdt.md §4.6).
