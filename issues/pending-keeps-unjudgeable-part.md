# A pending commit keeps the bytes of its unjudgeable parts
> Summary: A commit with an unjudgeable part beside a judgeable one that pends (drift, a missing epoch, pages) stores every part, the unjudgeable one included, until it applies or turns unjudgeable whole; spec/commits.md §4 keeps no byte of an unjudgeable part past the pass.
> Priority: low
> Tags: engine, node-sync

`apply::examine` throws a commit out only when every held part is unjudgeable; otherwise the `Exam::Pending` it returns for drift or an epoch (and `WaitBlobs` before it) stores the blob whole. Reads converge (the part applies when its record comes and the commit applies, as a refetched copy would), so nothing observable differs; the cost is bytes kept against the rule. A fix strips unjudged parts from the stored copy and has the carrier keep awaiting their records, as for an applied commit's unjudged slots (`settle_waits`).
