# `wait_synced(All)` does not wait for sealed fires owed
> Summary: spec/sync-status.md §3 says a wait on all (or "on deliveries", a scope the API no longer has) waits until each sealed fire this node sends is delivered; `Status::wait` reads only the sync IDs held, so a grant to an outside holder (its `grant@~0` fire or sealed copy still owed) reports synced before any peer took it.
> Priority: normal
> Tags: sync

- Property: `wait_synced` says this node's writes are held elsewhere (spec/sync-status.md principle). A sealed fire is a write of this node's (a commit signed as its node thing) held nowhere else until a peer takes its Deposit item.
- Minimal world: node A grants thing T to B's account, a contact whose nodes A is not connected to; T is synced with A's other node. `wait_synced(All)` at A resolves; the fire is still owed (`Engine::fires_owed`). A user taking that as "done" and wiping A loses the grant's delivery (the fire is durable only at A).
- The spec line names a removed scope (a delivery scope, gone with inbox blobs) and was never rebuilt for sealed fires.
- Options: (1) build it: `Node::wait` on `Scope::All` stays `Pending` while `fires_owed` holds a fire whose delivery is pending (an own fire this node logs itself is held by its sync ID's rule already); a fire goes when its thing is no longer held, so nothing waits past what the node holds; check which osis/account/chat tests wait on All with a fire to a peer never met. (2) drop the line and state that fires are not waited on (weaker: a delivery has no API to wait on). (1) follows the model.
