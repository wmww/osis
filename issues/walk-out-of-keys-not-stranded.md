# A walk that runs out of keys without a claim is never stranded
> Summary: In `try_next`, a label walk that runs out of keys mid-walk without having tried any claim (`tried_claim` false) is not marked stranded, so no Stranded message or notice goes and no re-seal is asked for; the label stays Failed and every `resync_ms` retry builds the same keys. Proposal: running out of keys mid-walk is stranded (spec/permissions.md §4 Stranded widened), so a Failed label's retry changes something. Not reproduced (found reviewing link-race).
> Priority: normal
> Tags: sync, node, spec

Stranded today (spec/permissions.md §4): reached the head and cannot open its epoch after a complete pass, or a claim on the way was refused. A walk stopped earlier because the node had no key to try at a step meets neither, though it is the same situation for the user: the node cannot read the label's current epoch and only a holder's re-seal can fix it. Check the Stranded message's receivers can act on a step below the head (the re-seal names the current holder, so likely yes), and that a node with no claimants at all (not a holder) does not spam notices: the notice is once per head epoch already.
