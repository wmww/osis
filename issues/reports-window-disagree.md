# Requester and server can disagree on what an Applied reports
> Summary: The server counts only the newest `REPORTS_KEPT` report-asking messages an Applied covers; the requester counts every one it applied. A listing from the start longer than that, or messages in hand dropped with their deferred Applieds, leaves the requester serving the peer nothing back of entries the server never counted. A refusal told before an earlier apply of the same report window is forgotten by the requester.
> Priority: normal
> Tags: sync, tests

Found by reading, not reproduced yet. Rule they break: both sides count the same sends (spec/sync-streams.md §4 Reports, Sends counted). The direction is safe for data (presence errs toward absent), but the server's `known` of that peer stays incomplete for good on the connection: the requester's `Serve::counted` keeps those entries out of everything it serves the peer, and its stream's cursor passes them.

## Long listings
A requester sends no Applied while a listing from the start is under way (no cursor stored). Each page asks a report, so `Serve::asked` holds every page and drops the oldest past `REPORTS_KEPT` (2 x `PENDING_CAP` = 128). The listing's last Applied counts only the newest 128 pages' `Added` entries at the server, while `Pulling::reporting` holds the held entries of every page and puts their marks in `Serve::counted`. A first sync of a big store hits this.

Test to write: a whole listing of more than `REPORTS_KEPT` pages, then check the server counts the requester holding every entry it holds (the `PresenceComplete` property). The spec's "reports" then must not depend on a server-local bound: either an Applied can be named mid-listing, or the requester learns which messages the server still counts.

## Messages in hand dropped
`Pulling::taken` or a connection drop discards messages in hand together with the Applieds deferred behind them (`Batch::after`). Check whether either side has already counted something the other then never does.

## A refusal told before an earlier apply
`Pulling::told_now` keeps only entries in `reporting` once each message is applied (that bounds it by entries held here). A refusal told for an entry not held, followed in the same report window (a listing's pages, or messages applied together before one Applied) by a send of that entry that is taken, leaves the requester counting it held while the server, which saw the refusal, does not. An exact bound needs the window bounded (the long-listing case above).
