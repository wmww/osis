# A local listener re-reads as the node, not its subscriber
> Summary: a local `osis` listener's callback gets the node's own handle, not the subscribing handle, so on an `act_as` handle `on_grants_change` (and any watch that re-reads in the callback) re-reads as the node: it could tell grants the acting actor may not read. Unreached today (the port serves grants through its own path, which reads as the session's actor).
> Priority: normal
> Tags: osis, security

Found by the osis-cleanup-2 pass (bd1a12a12 + its follow-up). Fix: the callback re-reads with the subscriber's read limit and acting actor; a test that an `act_as` handle's grants watch tells only what that actor reads.
