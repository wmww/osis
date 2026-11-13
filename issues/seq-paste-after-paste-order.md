# Two pastes in one commit read unlike a plain sequence
> Summary: `fuzz_seq::random_scripts_replay_spec_5_7` fails on main at `OSIS_CRDT_SEED=10971` (script 2): a commit of a move and two pastes of deleted runs places the second run's last char (`B2`) before the run, where a plain sequence inserts the run in its dots' order.
> Priority: normal
> Tags: crdt, tests

Shrunk (`OSIS_SHRINK=2`):

```
Script{list:false,steps:vec![Step::Ops{r:0,ops:vec![LocalOp::Edit{at:16717,del:161,item:203,stale:false}],skew:0,per:0},Step::Join{to:1,pick:43,n:2,per:0,merged:false},Step::Ops{r:1,ops:vec![LocalOp::Set{item:71}],skew:0,per:0},Step::Ops{r:1,ops:vec![LocalOp::Set{item:125}],skew:0,per:0},Step::Ops{r:1,ops:vec![LocalOp::Set{item:81}],skew:0,per:0},Step::Ops{r:1,ops:vec![LocalOp::Move{at:43,len:229,to:7725},LocalOp::Paste{run:12,at:14304},LocalOp::Paste{run:135,at:17017}],skew:0,per:0}]}
```

The harness picks paste runs (`deleted_runs`) from the state before the commit; the first paste re-anchors `B2` (it hung below the first run) so in the batch's placement `B2` no longer follows `C11`, and the second paste (`[C8..C11, B2]`) moves the placement slice, which now starts at `B2`. Read: `…bdbbedf`, plain: `…bbbeddf`. Next: decide whether the harness should take runs from the batch's view (the clipboard no longer matches, §5.7 paste) or `Paste` should refuse dots not adjacent in the current placement, then a hand-written reproducer.
