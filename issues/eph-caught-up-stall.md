# A label that cannot catch up stalls covers of earlier sessions' commits
> Summary: own covers absorb an earlier session's commits only once every label at a server caught up since start (`eph_caught_up`); a label whose servers are all down blocks that for every label, and each restart adds the previous session's covers to what stays uncovered; catching up at one server of several is also taken as the label's.
> Tags: node-sync, ephemeral

Measured (review of eph-partial-label, probe not kept): g1 at a live server, g2 at a blocked one, the same six keys rewritten each session: after restarts 1..5 the author held 1, 2, 3, 4, 5 commits (853 to 3077 bytes) of a state that did not grow. They sit at g1's server too, so with a server cap of about twice the covers the author's new entries get refused after a few restarts while g2 stays down (a decommissioned server still in `/label`).

Other side: catching up at S1 when the label is also at S2 is taken as caught up; a placement the author uploaded only to S2 (S1 down then, restart before S1 got it) comes back later, after the cover went under the other labels only: the loss of the deleted issue eph-cover-partial-label again. Requiring every server makes the stall above likelier.

Both go away with the rejected direction: judge the delete of an absorbed entry under a label by the labels the absorbed commit's entries are under, and place a cover under a label later when a thing it carries enters that label's closure (needs a bound for things that really left a label). Or bound the stall by time (notes/arbitrary-values.md: at 0 the loss, at infinity the pile-up).
