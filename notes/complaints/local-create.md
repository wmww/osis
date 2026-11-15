# local-create
- First test wrote a local thing and a filed thing in one write and saw the local one reach the other node: a commit is one blob (spec/sync-judgement.md §1), so its parts travel together. Easy to miss; now a stated limit in spec/sync-set.md §1 and `Write::local`'s doc.
- Review: a two-account test of the sealed limit tripped a NotSynced false alarm on a plain item of home; `created(t)` answers from the header for a thing whose parts the node never opened, which looked like a leak until probed.
