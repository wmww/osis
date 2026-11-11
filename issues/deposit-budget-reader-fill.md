# A reader can hold a label's deposit budget for good
> Summary: Any holder of a label's deposit key (every reader) can deposit commits it seals and signs itself that open but are invalid (it has no write role). No writer promotes them, the drop of an invalid delta is no right's (spec/permissions.md §6: nobody deletes it at hosts), inbox clearing exempts deposits that open as commits (spec/sync.md §5 Clearing an inbox) and applies only to inbox labels. About 72 such deposits refuse every later deposit there (invite grants, self-removals, node cards, readers' copies under a superseded stamp) until the deposit seed rotates. Needs a rule for when an unpromotable deposit leaves.
> Priority: normal
> Tags: security, sync, host, tess-call

Honest nodes do not do this: a reader deposits a body only while it judges it valid (spec/sync.md §6 Reader). A hostile reader can.

Options:
- **Writers delete deposits they judge invalid** (they hold the delete key). Conflicts with "the drop is no right's": a fork in validity (forks are permanent) lets one writer delete what another would promote; the author's node re-sends it, so it would cycle.
- **Deposits age out**: a host drops an unstamped entry a fixed time after it arrived. Simple and judgment-free; a deposit waiting for an offline writer longer than that is lost unless re-sent (own deposits are re-sent until answered; readers' copies are re-sent while the host lacks them). Needs the time to pass notes/arbitrary-values.md.
- **One clearing rule for every label**: extend inbox clearing (keep at most `INBOX_WAITING` of what a writer can do nothing with) to every label and stop exempting opened commits a writer judges invalid. Same fork caveat, bounded.
