# kept-here complaints
- A paired node has no synced group of its own (`synced^.0` names only the first node), so a two-node test of "another node syncs it" must write one by hand.
- Redirecting a background run into the scratchpad before `mkdir -p` lands the log at the scratchpad root; easy to do by accident.
- Streams' presence (`Sources::present`) never shows a reader source's holdings (readers report positions instead): a leave rule built on presence for read sync IDs never fires. Status's durable held-elsewhere mark is the read-side answer.
