# Mailbox overflow
> Summary: A key actor's mailbox holds deposits only, so its deposit budget is its whole storage; an owner offline through many rotations finds the newest deliveries refused.
> Tags: owner-call, sync

A delivery is a deposit (spec/sync.md §3, §5); a key actor's mailbox has no writer to promote deposits, so the budget is the mailbox. After enough undrained deliveries the server refuses new ones, and the newest epoch, whose history boxes would make the older deliveries redundant, never arrives. The owner then recovers only P2P or when a member notices.

Options: let a server evict the oldest deposit of a mailbox label when the budget is full (one server rule; the newest delivery supersedes the rest through history boxes); or size mailbox budgets generously and accept the P2P fallback. Moot if gating is dropped (issues/sync-key-gating-cost.md).
