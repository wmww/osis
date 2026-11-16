# A loss by an `until` drops on a refusal from before it
> Summary: spec/permissions.md §2 counts any ByRole refusal or walk stop held now as "a source refuses it", also one from before the loss or from a reader that simply does not sync S; with own writes from before the `until` held nowhere else, the node drops them though a peer that would take them is still to come.
> Priority: normal
> Tags: sync, permissions

Case: node N reads S until U. While cut off from the owner it writes w (before U). A reader R that does not sync S (or has not filed it yet) refused N's ByRole on S on a connection that stays up. At U, `Hears::timed_heard` finds `Opens::refused(S)` and N drops S's thing at once; w is held nowhere else and is gone. Without R's refusal N would have waited for the owner (a peer to be waited for), handed w over (`own_elsewhere`), then dropped.

Code 14 says nothing of why (spec/sync-opens.md §5), so a refusal by a peer judging N departed and one by a peer not syncing S look alike. What a fix must keep:
- No stall in the common case: the owner, clock a little ahead, finalizes, closes S with a Lost and refuses N's next ByRole before N's own clock reaches U; that refusal must count.
- Requiring a complete pass after the loss for the refusal path stalls: with no source and the refusing owner still a peer to be waited for, no pass ends (status `pass_now`).
- "A ByRole sent after the loss was judged" (a pass place per ByRole) needs a fresh ByRole after U, which nothing sends on a connection whose credentials did not move, and orders badly against the case above.
A refusal counted only while S has no source covers the case where an open source would take w, not the cut-off one.
