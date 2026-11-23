# Lists and texts keep a few bytes per element ever written
> Summary: A list or text element's place leans on its neighbour, so a deleted or expired element's record stays for good (a late insert may name it; appends chain through the whole history): a few bytes per element ever written, in memory and on disk, against spec/requirements.md Scale (no growth from churn). Positions that lean on nothing would end it but trade it for longer places on live elements, interleaving, harder moves and weaker run compression: no free lunch. Left open; may be resolved by a requirements update later.
> Priority: low
> Tags: crdt
