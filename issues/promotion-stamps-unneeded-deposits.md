# A reader gets any number of copies of valid commits stamped for good
> Summary: Promotion stamps every deposited commit a writer applied once its chain is under the label, without asking whether the label must hold it or already holds it. A reader seals fresh encryptions of valid commits it holds (role commits, node cards) and deposits them; writers promote each, and the judge keeps duplicate role commits and cards as may-hold, so they stay stamped for good past the deposit budget. Clearing exempts deposits the admin judges valid, which is right only while every valid deposit gets promoted.
> Priority: normal
> Tags: security, sync

Seen with a probe (reader of a group, 20 fresh encryptions of each of its 12 commits under the group's label, deposited over the wire): 71 taken by the host, all 71 promoted stamped, all still there after hours of passes. Only the deposit budget's refusals bounded it; each promotion frees a slot, so over time it is bounded by the host's deposit rate and the label caps (2^20 entries, 16 GiB).

Where: `pass/promote.rs` `due_deposits`/`promote` take any `Kind::Commit` deposit whose commit is applied; `pass/delete.rs` `judge` returns may-hold for role commits and cards outside the closure, duplicates included (notes/inbox.md: concurrent writers' duplicates are may-hold). spec/sync.md §5 Promotion says "a deposited commit the label must hold", which the code does not check.

Direction: promote only a deposit the label must hold and does not hold yet at that host (same parts, any genuine stamped entry); then clearing should exempt only what this admin would promote (spec/sync.md §5 Clearing deposits: "a commit it judges valid" becomes "a commit it would promote"), else a valid unpromoted duplicate holds a slot for good. The same exemption already holds a slot for good for a valid deposit whose chain no writer can complete (a writer lacking the chain's bodies), rare and hostile-only.
