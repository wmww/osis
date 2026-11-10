# A status listener loses groups sourced at another node
> Summary: `on_status_change` on a store asks no node at a change (the dispatcher never waits on another node), so a group whose source is another node shows in the first call and is absent from every later one, though its node is up; nor does a change at that node call the listener. A listener cannot follow such a group's state.
> Priority: normal
> Tags: osis, api

- Where: `Osis::on_status_change` (share.rs) delivers `merged_status` on the dispatcher, where `may_wait` is false, so `merged_status` skips every connection's `STATUS`. Same for groups a connection reports that this node does not sync.
- Rule it breaks: notes/api.md Sync configuration and status says status answers for where the group's calls go, absent only while that node cannot be asked; a listener sees it absent while the node can be asked.
- Likely shape: subscribe to each connection's status (the `STATUS` filter a thin client's `node_on_status_change` uses) and merge the latest each one sent, re-merged on a local change, a connection change or a node's notify; a down connection drops its groups.
