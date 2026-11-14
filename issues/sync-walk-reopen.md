# A reader never walks a store source on a step past its recorded path
> Summary: `NodeHolds::verify_steps` and `step_creds` answer nothing, so Behind answers carrying steps are never verified and a store source whose head moved past the reader's recorded path is never walked; `NodeHolds::behind` answering with steps has no passing test.
> Priority: normal
> Tags: sync, tests

- A reader asks Behind when its own test (a change, or a re-mark: the Lost ending its open when the source's head moved) finds nothing shown (spec/sync-ids.md §6 Test, Behind). What it cannot do yet is take the answer: `verify_steps` returns nothing, so the known steps never grow and the reader stays stranded there until its own recorded path catches up through another reader.
- Build both against spec/sync-ids.md §6 Known steps and Behind; the rule test is a reader whose recorded path lags a source that is its only route (`sims::a_reader_through_a_node_keeping_it_unread` with a rotation registered at node 2 while node 1 is away).
