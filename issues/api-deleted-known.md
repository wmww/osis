# A deleted thing still reads as known
> Summary: After a thing is deleted (locally or remotely) the API still reports it as known, with no clear "deleted" answer, so a UI keeps an editor open on it and has to infer deletion (the app checks whether it is still reachable from its groups).
> Tags: core-ask, api

Repro: delete a thing on device A, sync to B: `knows(t)` stays true on B.
Ask: a deleted/absent state readable on the thing (and a watch event for it).
