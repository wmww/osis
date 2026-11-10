# A recorded label's walk leaves out an actor only a pending commit names
> Summary: unconfirmed: `claimants` adds actors the inbox blobs naming the thing grant or box only on hinted walks; a node with the label recorded whose only word of its actor's new grant is a pending inbox commit (deps behind the label it cannot open) claims without that actor, and its label stays Failed until a re-seal reaches it.
> Priority: low
> Tags: node-sync

Found reading `claimants` (core/node/src/sync/open.rs), no reproduction yet. Shape: the node holds `label.0` of g (it read g once through another actor), no held edge write on g names its actor P (P never held a role on g before), and P's new grant reaches it only in an inbox blob whose commit stays pending. Each `resync_ms` retry builds the same keys. The stranded route heals it only if a claim was tried and refused (`try_next`: no claim tried, not stranded).

At a recorded (verified) step another claim key leaks nothing (the host cannot derive it without the step private key), so the inbox-named actors could join every walk; the cost is a scan of the held inbox blobs per walk, which would want an index by thing first.
